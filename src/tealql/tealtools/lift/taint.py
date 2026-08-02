"""Forward user-input taint over the lifted IR (see :mod:`lift`):
``user_input_taint(lifter) -> {id(Register): frozenset[str sources]}``.

HAZARD: the source set is the soundness boundary of every verdict built on it.
``ApplicationArgs`` (``txn``/``txna``/``txnas``/``gtxn*``/``gtxns*`` — a GROUP
SIBLING's args count too), ``LogicSigArgs`` (``arg``/``args``/``arg_0``..``arg_3``),
and ``ItxnLastLog`` (``itxn``/``gitxn`` ``LastLog``: the output of a contract this
app called, attacker-influenceable through that callee — NOT clean). Taint also
crosses scratch through the lifter's reaching-def (``load_stores``); drop that
bridge and flow through ``store``/``load`` is silently lost.
"""
from __future__ import annotations

from collections import defaultdict

from ..ssa import Phi, SSAVar
from ..avm import (
    STATE_WRITE_OPS,
    attacker_input_label as _attacker_input_label,
)
from . import pre_ir


#: Taint label for a value the lift could NOT resolve — a slot a callee consumed
#: out from under its caller, or a shallow return path padded out to a divergent
#: callee's declared width. It is TOP, never clean: "unknown" cannot be
#: discharged as "not attacker-controlled", and a may-analysis that reads an
#: unresolved value as clean turns every one into a SILENT false negative —
#: precisely the bug the narrow ``frame_dig`` fallback used to have.
UNKNOWN_SOURCE = "unresolved"


def source_label(intr) -> str | None:
    """The user-input source kind an intrinsic reads, or ``None`` — via
    :func:`tealql.tealtools.avm.attacker_input_label`, the ONE source table this
    shares with the SSA-level seeds so the two layers cannot disagree."""
    if not isinstance(intr, pre_ir.Intrinsic):
        return None
    imm = " ".join(str(i) for i in (intr.immediates or []))
    return _attacker_input_label(intr.op, imm)


def _trusted_apparg(src, trusted_args) -> bool:
    """True if ``src`` reads a CURRENT-txn ``ApplicationArgs[i]`` a caller pinned to a
    constant, so it is fixed on this call edge and must not seed taint.

    HAZARD: the only exemption in the whole analysis. It is restricted to
    ``txn``/``txna`` because ``gtxn*`` reads a GROUP SIBLING's args, which this
    appcall never passed — widening it to those would clear real attacker input."""
    if not trusted_args or not isinstance(src, pre_ir.Intrinsic):
        return False
    if src.op not in ("txn", "txna"):
        return False
    imm = [str(i) for i in (src.immediates or [])]
    if len(imm) != 2 or imm[0] != "ApplicationArgs":
        return False
    try:
        return int(imm[1]) in trusted_args
    except ValueError:
        return False


def _intr(o):
    if isinstance(o, pre_ir.IntrinsicOp) and isinstance(o.intrinsic, pre_ir.Intrinsic):
        return o.intrinsic
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
        return o.source
    return None


def _invoke(o):
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.InvokeSubroutine):
        return o.source
    if isinstance(o, pre_ir.IntrinsicOp) and isinstance(o.intrinsic, pre_ir.InvokeSubroutine):
        return o.intrinsic
    return None


def _return_summary(lifter, trusted_args=frozenset()) -> dict:
    """Per-subroutine taint summary ``{sub.id: (srcs, params)}`` — ``srcs`` = source
    labels reaching a returned value from INSIDE the sub, ``params`` = the parameter
    indices that pass through to a returned value.

    HAZARD: a call site must apply BOTH halves — ``srcs`` always, plus the taint of
    each passthrough arg. Using only the args UNDER-taints (it misses a sub that
    reads a source itself); tainting on any arg OVER-taints."""
    ssa_of = {id(r): sv for sv, r in lifter.regs.items()}
    subs = [s for s in lifter.subs if not s.is_main]
    taint: dict = defaultdict(set)
    for s in subs:                                  # seed each param with its marker
        for i, p in enumerate(s.parameters):
            taint[id(p.register)].add(("p", s.id, i))
    summary: dict = {s.id: [set(), set()] for s in subs}   # mutable accumulators

    def reg_t(v):
        if isinstance(v, pre_ir.Register):
            return taint.get(id(v), set())
        if isinstance(v, pre_ir.Undefined):
            return {UNKNOWN_SOURCE}          # TOP -- see UNKNOWN_SOURCE
        return set()

    changed = True
    while changed:
        changed = False
        for s in subs:
            for b in s.body:
                for ph in b.phis:
                    new = set()
                    for a in ph.args:
                        new |= reg_t(a.value)
                    if new - taint[id(ph.register)]:
                        taint[id(ph.register)] |= new
                        changed = True
                for o in b.ops:
                    ins = set()
                    src = _intr(o)
                    if src is not None:
                        lbl = source_label(src)
                        if lbl and not _trusted_apparg(src, trusted_args):
                            ins.add(lbl)                # honor the caller's pin here too
                        for a in src.args:
                            ins |= reg_t(a)
                        if src.op in ("load", "loads"):     # scratch reaching-def
                            out = o.targets[0] if getattr(o, "targets", None) else None
                            lv = ssa_of.get(id(out)) if out is not None else None
                            for sv in (lifter.load_stores.get(lv, ()) if lv is not None else ()):
                                if isinstance(sv, (SSAVar, Phi)):
                                    ins |= reg_t(lifter.reg(sv))
                    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                        ins |= reg_t(o.source)              # copy
                    inv = _invoke(o)
                    if inv is not None:
                        callee = lifter.name2sub.get(inv.target)
                        if callee is not None:              # resolve via the summary
                            csrcs, cparams = summary[callee.id]
                            ins |= csrcs
                            for i in cparams:
                                if i < len(inv.args):
                                    ins |= reg_t(inv.args[i])
                    for t in getattr(o, "targets", ()) or ():
                        if ins - taint[id(t)]:
                            taint[id(t)] |= ins
                            changed = True
            srcs, params = summary[s.id]                    # refine s's own summary
            for b in s.body:
                if isinstance(b.terminator, pre_ir.SubroutineReturn):
                    for rv in b.terminator.result:
                        for m in reg_t(rv):
                            if isinstance(m, tuple):
                                if m[1] == s.id and m[2] not in params:
                                    params.add(m[2])
                                    changed = True
                            elif m not in srcs:
                                srcs.add(m)
                                changed = True
    return {sid: (frozenset(sv[0]), frozenset(sv[1])) for sid, sv in summary.items()}


def user_input_taint(lifter, trusted_args=frozenset()) -> dict:
    """Forward taint from the user-input sources to a fixpoint over ``lifter``'s IR,
    returning ``{id(Register): frozenset(sources)}``; ``trusted_args`` indices are
    exempted from seeding per :func:`_trusted_apparg`."""
    # register -> its SSA var, to consult the scratch reaching-def on a `load`.
    ssa_of = {id(r): sv for sv, r in lifter.regs.items()}
    summary = _return_summary(lifter, trusted_args)   # interprocedural param->return summary
    taint: dict = defaultdict(set)

    def reg_t(v):
        if isinstance(v, pre_ir.Register):
            return taint.get(id(v), set())
        if isinstance(v, pre_ir.Undefined):
            return {UNKNOWN_SOURCE}          # TOP -- see UNKNOWN_SOURCE
        return set()

    changed = True
    while changed:
        changed = False
        for b in pre_ir.blocks(lifter.subs):
            for ph in b.phis:
                new = set()
                for a in ph.args:
                    new |= reg_t(a.value)
                if new - taint[id(ph.register)]:
                    taint[id(ph.register)] |= new
                    changed = True
            for o in b.ops:
                ins = set()
                src = _intr(o)
                if src is not None:
                    lbl = source_label(src)
                    if lbl and not _trusted_apparg(src, trusted_args):
                        ins.add(lbl)                # seed
                    for a in src.args:
                        ins |= reg_t(a)
                    if src.op in ("load", "loads"):  # scratch: reaching-def precise
                        out = o.targets[0] if getattr(o, "targets", None) else None
                        lv = ssa_of.get(id(out)) if out is not None else None
                        for sv in (lifter.load_stores.get(lv, ()) if lv is not None else ()):
                            if isinstance(sv, (SSAVar, Phi)):
                                ins |= reg_t(lifter.reg(sv))
                if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                    ins |= reg_t(o.source)          # copy
                inv = _invoke(o)
                if inv is not None:
                    callee = lifter.name2sub.get(inv.target)
                    if callee is not None:
                        # result <- the callee's summary: its internal-source returns
                        # plus only the params that actually flow through.
                        csrcs, cparams = summary.get(callee.id, (frozenset(), frozenset()))
                        ins |= csrcs
                        for i in cparams:
                            if i < len(inv.args):
                                ins |= reg_t(inv.args[i])
                        for i, p in enumerate(callee.parameters):   # arg -> callee param
                            if i < len(inv.args):
                                pt = reg_t(inv.args[i])
                                if pt - taint[id(p.register)]:
                                    taint[id(p.register)] |= pt
                                    changed = True
                    else:                           # unknown callee: stay conservative
                        for a in inv.args:
                            ins |= reg_t(a)
                for t in getattr(o, "targets", ()) or ():
                    if ins - taint[id(t)]:
                        taint[id(t)] |= ins
                        changed = True
    return {k: frozenset(v) for k, v in taint.items() if v}


# Sensitive sinks: persistent-state writes, inner-txn fields (who gets paid, how
# much) and logs. `assert` is a sink too (user-controlled control flow) but is not an
# intrinsic, so each consumer below matches pre_ir.Assert separately.
_SINKS = STATE_WRITE_OPS | {"log", "itxn_field"}


def tainted_sinks(lifter, taint=None) -> list:
    """``(sources, sink_op, immediates)`` for every sink whose operands include a
    tainted value; pass a precomputed ``taint`` map or one is built."""
    if taint is None:
        taint = user_input_taint(lifter)
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
                if isinstance(a, pre_ir.Register):
                    hit |= taint.get(id(a), set())
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
    present = sorted({s for v in taint.values() for s in v})
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
                    if isinstance(a, pre_ir.Register):
                        hit |= taint.get(id(a), set())
                if not hit:
                    continue
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
           f"  Sources present   : {', '.join(present) or '(none)'}",
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
                if isinstance(a, pre_ir.Register):
                    hit |= taint.get(id(a), set())
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

