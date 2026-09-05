"""Cached user-input taint and reports over the shared positional summary service."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from types import MappingProxyType
from ..language.avm import STATE_WRITE_OPS
from . import pre_ir
from .taint_flow import (
    UNKNOWN_SOURCE, value_sources, source_label, transfer_fixpoint,
    _trusted_apparg, _intr, _invoke as _invoke,
    _scratch_unknown_write as _scratch_unknown_write,
)
from .summaries import compute_summaries


def _merge_unresolved(lifter, taint: Mapping | None) -> Mapping:
    """Return ``taint`` with representation TOP preserved."""
    if taint is None:
        return user_input_taint(lifter)
    result = {rid: set(sources) for rid, sources in taint.items()}
    for rid, sources in unresolved_taint(lifter).items():
        result.setdefault(rid, set()).update(sources)
    return result



def _return_summary(lifter, trusted_args=frozenset()) -> dict:
    """Legacy aggregate view. Production call transfers use positional results."""
    return {sid: (summary.internal_sources, summary.passthrough)
            for sid, summary in compute_summaries(lifter, trusted_args).items()}


def user_input_taint(lifter, trusted_args=frozenset()) -> Mapping[int, frozenset[str]]:
    """Forward taint from the user-input sources to a fixpoint over ``lifter``'s IR,
    returning ``{id(Register): frozenset(sources)}``; ``trusted_args`` indices are
    exempted from seeding per :func:`_trusted_apparg`.

    The completed lift is shared and read-only during an audit.  Cache by the
    only query input so each sink family consumes the same fixed point instead
    of recomputing it independently.
    """
    key = frozenset(trusted_args)
    frozen = getattr(lifter, '_analysis_frozen', False)
    cache = getattr(lifter, "_user_input_taint_cache", {}) if frozen else {}
    if frozen and key in cache:
        return cache[key]
    summary = compute_summaries(lifter, trusted_args)   # interprocedural param->return summary
    taint: dict = defaultdict(set)

    def _seed(src):
        lbl = source_label(src)
        return lbl if lbl and not _trusted_apparg(src, trusted_args) else None

    def _inv(o, inv, reg_t):
        outputs = ()
        changed = False
        callee = lifter.name2sub.get(inv.target)
        if callee is not None:
            # result <- the callee's summary: its internal-source returns
            # plus only the params that actually flow through.
            args = [reg_t(a) for a in inv.args]
            outputs = summary[callee.id].output_sources(args)
            for i, p in enumerate(callee.parameters):   # arg -> callee param
                if i < len(inv.args):
                    pt = reg_t(inv.args[i])
                    if pt - taint[id(p.register)]:
                        taint[id(p.register)] |= pt
                        changed = True
        else:                           # unknown callee: stay conservative
            unknown = {UNKNOWN_SOURCE}
            for a in inv.args:
                unknown.update(reg_t(a))
            outputs = tuple(unknown for _ in getattr(o, "targets", ()))
        return outputs, changed

    transfer_fixpoint(lifter, taint, seed_label=_seed, invoke_ins=_inv)
    result = MappingProxyType({k: frozenset(v) for k, v in taint.items() if v})
    if frozen:
        cache[key] = result
        lifter._user_input_taint_cache = cache
    return result


def unresolved_taint(lifter) -> Mapping[int, frozenset[str]]:
    """Register closure reached from any explicit ``Undefined`` value.

    Custom taint views (notably byte-interval taint) replace the normal input
    seed map, but they must not replace analysis TOP with clean.  Compute this
    once from the production interprocedural fixpoint and retain only the
    ``UNKNOWN_SOURCE`` component so callers can union it into any abstraction.
    """
    cached = getattr(lifter, "_unresolved_ir_taint", None)
    frozen = getattr(lifter, '_analysis_frozen', False)
    if frozen and cached is not None:
        return cached
    result = MappingProxyType({
        rid: frozenset({UNKNOWN_SOURCE})
        for rid, sources in user_input_taint(lifter).items()
        if UNKNOWN_SOURCE in sources
    })
    if frozen:
        lifter._unresolved_ir_taint = result
    return result


# Sensitive sinks: persistent-state writes, inner-txn fields (who gets paid, how
# much) and logs. `assert` is a sink too (user-controlled control flow) but is not an
# intrinsic, so each consumer below matches pre_ir.Assert separately.
_SINKS = STATE_WRITE_OPS | {"log", "itxn_field"}


def tainted_sinks(lifter, taint=None) -> list:
    """``(sources, sink_op, immediates)`` for every sink whose operands include a
    tainted value; pass a precomputed ``taint`` map or one is built."""
    taint = _merge_unresolved(lifter, taint)
    out = []
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            s = _intr(o)
            if s is not None and s.op in _SINKS:
                args, op, imm = s.args, s.op, s.immediates
            elif isinstance(o, pre_ir.Assert):
                args, op, imm = [o.condition], "assert", None
            else:
                continue
            hit = set()
            for a in args:
                hit |= value_sources(a, taint)
            if hit:
                out.append((frozenset(hit), op, imm))
    return out


# Sink categories, most-to-least security-relevant, for the report.
_CATEGORIES = [
    ("INNER-TRANSACTION FIELDS  (fund flow -- who gets paid, and how much)",
     frozenset({"itxn_field"})),
    ("PERSISTENT STATE WRITES", STATE_WRITE_OPS),
    ("EMITTED LOGS",
     frozenset({"log"})),
    ("ASSERTED CONDITIONS  (user-controlled control flow)",
     frozenset({"assert"})),
]


def taint_report(lifter, name: str = "<program>") -> str:
    """A human-readable taint report: every attacker-controlled value reaching a sink,
    grouped by category and annotated with the original TEAL line(s)."""
    taint = user_input_taint(lifter)
    present = {s for v in taint.values() for s in v}
    groups: dict = defaultdict(lambda: {"lines": set(), "sources": set()})
    cat_of = {op: i for i, (_, ops) in enumerate(_CATEGORIES) for op in ops}
    nflows = 0
    for sub in lifter.subs:
        for b in sub.body:
            for o in b.ops:
                s = _intr(o)
                if s is not None and s.op in _SINKS:
                    op, fld, line, args = s.op, (str(s.immediates[0]) if s.immediates
                                                 else ""), getattr(s, "line", 0), s.args
                elif isinstance(o, pre_ir.Assert):
                    op, fld, line, args = "assert", "", 0, [o.condition]
                else:
                    continue
                hit = set()
                for a in args:
                    hit |= value_sources(a, taint)
                if not hit:
                    continue
                present |= hit
                nflows += 1
                g = groups[(cat_of.get(op, 99), op, fld)]
                g["lines"].add(line)
                g["sources"] |= hit

    out = ["=" * 70,
           f"  USER-INPUT TAINT REPORT  --  {name}",
           "=" * 70, "",
           "Every value flowing from attacker-controlled input to a sensitive sink,",
           "traced through the lifted IR -- interprocedurally, with scratch flow",
           "resolved via the low-layer reaching-def. Sources are the inputs an",
           "attacker chooses at call time; line numbers are the original TEAL.", "",
           f"  Sources present   : {', '.join(sorted(present)) or '(none)'}",
           f"  Tainted IR values : {len(taint)}",
           f"  Sink flows        : {nflows}", ""]
    if not nflows:
        out.append("  No user-controlled value reaches a tracked sink.")
    for ci, (title, _) in enumerate(_CATEGORIES):
        keys = sorted((k for k in groups if k[0] == ci), key=lambda k: (k[1], k[2]))
        if not keys:
            continue
        out += ["-" * 70, title, "-" * 70]
        for key in keys:
            g = groups[key]
            label = f"{key[1]} {key[2]}".strip()
            lines = sorted(x for x in g["lines"] if x)
            loc = ("TEAL line " + ", ".join(map(str, lines[:10]))
                   + (" ..." if len(lines) > 10 else "")) if lines \
                else f"{len(g['lines'])} site(s)"
            out.append(f"  {label:28s} <- {'+'.join(sorted(g['sources'])):16s}  {loc}")
        out.append("")
    return "\n".join(out)


def render_with_taint(lifter, name: str = "<program>") -> str:
    """Render the lifted IR with taint inline: ``<== SOURCE X`` where an attacker
    input enters, ``<== tainted X`` downstream, ``<== SINK X`` at a sensitive op."""
    taint = user_input_taint(lifter)

    def note(o, is_phi=False):
        marks = []
        src = None if is_phi else _intr(o)
        outs = [o.register] if is_phi else (getattr(o, "targets", ()) or [])
        srclbl = source_label(src) if src is not None else None
        tt = set()
        for t in outs:
            tt |= taint.get(id(t), set())
        if srclbl:
            marks.append(f"SOURCE {srclbl}")
        elif tt:
            marks.append("tainted " + "+".join(sorted(tt)))
        sink_args = (src.args if src is not None and src.op in _SINKS
                     else [o.condition] if isinstance(o, pre_ir.Assert) else None)
        if sink_args is not None:
            hit = set()
            for a in sink_args:
                hit |= value_sources(a, taint)
            if hit:
                op = src.op if src is not None else "assert"
                marks.append(f"SINK {op} <- " + "+".join(sorted(hit)))
        return ("    <== " + " ; ".join(marks)) if marks else ""

    out = [f"; user-input taint on the lifted Puya IR  --  {name}",
           "; <== SOURCE/tainted/SINK mark attacker-controlled flow", ""]
    for sub in lifter.subs:
        kind = "main" if sub.is_main else "subroutine"
        out.append(f"{kind} {sub.id}:")
        for b in sub.body:
            out.append(f"  block@{b.id}:")
            for ph in b.phis:
                out.append(f"    {ph.render()}{note(ph, True)}")
            for o in b.ops:
                out.append(f"    {o.render()}{note(o)}")
            if b.terminator is not None:
                out.append(f"    {b.terminator.render()}")
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    import sys

    from ..ssa import SSAProgram
    from .lift import _Lifter
    _render = "--render" in sys.argv
    for _src in [a for a in sys.argv[1:] if not a.startswith("-")]:
        _lf = _Lifter(SSAProgram(_src))
        _lf.build()
        _nm = _src.rstrip("/").rsplit("/", 1)[-1]
        print(render_with_taint(_lf, _nm) if _render else taint_report(_lf, _nm))
