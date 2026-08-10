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
_NO_SOURCES = frozenset()
_UNKNOWN_SOURCES = frozenset({UNKNOWN_SOURCE})


def value_sources(value, taint: dict):
    """Taint sources carried by one pre-IR value.

    Constants are clean, registers consult ``taint``, and ``Undefined`` is
    analysis TOP.  Keep this as the one value boundary: several report/sink
    helpers used to special-case only registers, so a direct unresolved sink
    disappeared even though both propagation fixpoints handled it correctly.
    """
    if isinstance(value, pre_ir.Register):
        return taint.get(id(value), _NO_SOURCES)
    if isinstance(value, pre_ir.Undefined):
        return _UNKNOWN_SOURCES
    return _NO_SOURCES


def _assignment_sources(op, taint: dict) -> tuple:
    """Direct value-provider sources per assignment target.

    Intrinsics and invokes are handled by their interprocedural rules. Bare
    values are copies, including ``Undefined``; a ``ValueTuple`` is positional
    and must not overtaint every target from every element.
    """
    if not isinstance(op, pre_ir.Assignment):
        return ()
    source = op.source
    if isinstance(source, pre_ir.ValueTuple):
        return tuple(value_sources(value, taint) for value in source.values)
    if isinstance(source, (pre_ir.Register, pre_ir.Undefined)):
        carried = value_sources(source, taint)
        return tuple(carried for _ in op.targets)
    return ()


def _merge_unresolved(lifter, taint: dict | None) -> dict:
    """Return ``taint`` with representation TOP preserved."""
    if taint is None:
        return user_input_taint(lifter)
    result = {rid: set(sources) for rid, sources in taint.items()}
    for rid, sources in unresolved_taint(lifter).items():
        result.setdefault(rid, set()).update(sources)
    return result


def _scratch_read_is_unknown(src, slots: set, dynamic: bool) -> bool:
    if src.op == "loads":
        return dynamic or bool(slots)
    if src.op != "load":
        return False
    key = str(src.immediates[0]) if src.immediates else None
    return dynamic or key is None or key in slots


def _scratch_unknown_write(src, reg_t) -> tuple[str | None, bool]:
    """``(static_slot, dynamic)`` for a synthetic scratch write storing TOP.

    Normal lifted stores carry an SSA origin and use the precise reaching-def
    bridge at their loads. This fallback is only for transform-inserted/custom
    pre-IR, where no such edge exists.
    """
    if getattr(src, "origin", None) is not None:
        return None, False
    if src.op == "store":
        value = src.args[0] if src.args else None
        if UNKNOWN_SOURCE not in reg_t(value):
            return None, False
        key = str(src.immediates[0]) if src.immediates else None
        return key, key is None
    if src.op == "stores":
        # Pre-IR intrinsic args retain public SSA's TOP-FIRST order: the
        # stored value is on top, with the dynamic slot underneath it.
        value = src.args[0] if src.args else None
        return None, UNKNOWN_SOURCE in reg_t(value)
    return None, False


def _lift_value(lifter, ssa_value):
    resolver = getattr(lifter, "value", None)
    return resolver(ssa_value) if resolver is not None else lifter.reg(ssa_value)


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
    ssa_of = getattr(lifter, "register_sources", {})
    subs = [s for s in lifter.subs if not s.is_main]
    taint: dict = defaultdict(set)
    for s in subs:                                  # seed each param with its marker
        for i, p in enumerate(s.parameters):
            taint[id(p.register)].add(("p", s.id, i))
    summary: dict = {s.id: [set(), set()] for s in subs}   # mutable accumulators
    unknown_scratch_slots: set = set()
    unknown_dynamic_scratch = False

    def reg_t(v):
        return value_sources(v, taint)

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
                        if _scratch_read_is_unknown(
                                src, unknown_scratch_slots, unknown_dynamic_scratch):
                            ins.add(UNKNOWN_SOURCE)
                        if src.op in ("load", "loads"):     # scratch reaching-def
                            out = o.targets[0] if getattr(o, "targets", None) else None
                            lvs = ssa_of.get(id(out), ()) if out is not None else ()
                            for lv in lvs:
                                for sv in lifter.load_stores.get(lv, ()):
                                    if isinstance(sv, (SSAVar, Phi)):
                                        ins |= reg_t(_lift_value(lifter, sv))
                        slot, dynamic = _scratch_unknown_write(src, reg_t)
                        if slot is not None and slot not in unknown_scratch_slots:
                            unknown_scratch_slots.add(slot)
                            changed = True
                        if dynamic and not unknown_dynamic_scratch:
                            unknown_dynamic_scratch = True
                            changed = True
                    direct = _assignment_sources(o, taint)
                    inv = _invoke(o)
                    if inv is not None:
                        callee = lifter.name2sub.get(inv.target)
                        if callee is not None:              # resolve via the summary
                            csrcs, cparams = summary[callee.id]
                            ins |= csrcs
                            for i in cparams:
                                if i < len(inv.args):
                                    ins |= reg_t(inv.args[i])
                    for index, t in enumerate(getattr(o, "targets", ()) or ()):
                        target_ins = (ins | direct[index]
                                      if index < len(direct) else ins)
                        if target_ins - taint[id(t)]:
                            taint[id(t)] |= target_ins
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
    exempted from seeding per :func:`_trusted_apparg`.

    The completed lift is shared and read-only during an audit.  Cache by the
    only query input so each sink family consumes the same fixed point instead
    of recomputing it independently.
    """
    key = frozenset(trusted_args)
    cache = getattr(lifter, "_user_input_taint_cache", None)
    if cache is None:
        cache = {}
        lifter._user_input_taint_cache = cache
    if key in cache:
        return cache[key]
    # register -> its SSA var, to consult the scratch reaching-def on a `load`.
    ssa_of = getattr(lifter, "register_sources", {})
    summary = _return_summary(lifter, trusted_args)   # interprocedural param->return summary
    taint: dict = defaultdict(set)
    unknown_scratch_slots: set = set()
    unknown_dynamic_scratch = False

    def reg_t(v):
        return value_sources(v, taint)

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
                    if _scratch_read_is_unknown(
                            src, unknown_scratch_slots, unknown_dynamic_scratch):
                        ins.add(UNKNOWN_SOURCE)
                    if src.op in ("load", "loads"):  # scratch: reaching-def precise
                        out = o.targets[0] if getattr(o, "targets", None) else None
                        lvs = ssa_of.get(id(out), ()) if out is not None else ()
                        for lv in lvs:
                            for sv in lifter.load_stores.get(lv, ()):
                                if isinstance(sv, (SSAVar, Phi)):
                                    ins |= reg_t(_lift_value(lifter, sv))
                    slot, dynamic = _scratch_unknown_write(src, reg_t)
                    if slot is not None and slot not in unknown_scratch_slots:
                        unknown_scratch_slots.add(slot)
                        changed = True
                    if dynamic and not unknown_dynamic_scratch:
                        unknown_dynamic_scratch = True
                        changed = True
                direct = _assignment_sources(o, taint)
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
                for index, t in enumerate(getattr(o, "targets", ()) or ()):
                    target_ins = (ins | direct[index]
                                  if index < len(direct) else ins)
                    if target_ins - taint[id(t)]:
                        taint[id(t)] |= target_ins
                        changed = True
    result = {k: frozenset(v) for k, v in taint.items() if v}
    cache[key] = result
    return result


def unresolved_taint(lifter) -> dict:
    """Register closure reached from any explicit ``Undefined`` value.

    Custom taint views (notably byte-interval taint) replace the normal input
    seed map, but they must not replace analysis TOP with clean.  Compute this
    once from the production interprocedural fixpoint and retain only the
    ``UNKNOWN_SOURCE`` component so callers can union it into any abstraction.
    """
    cached = getattr(lifter, "_unresolved_ir_taint", None)
    if cached is not None:
        return cached
    result = {
        rid: frozenset({UNKNOWN_SOURCE})
        for rid, sources in user_input_taint(lifter).items()
        if UNKNOWN_SOURCE in sources
    }
    try:
        lifter._unresolved_ir_taint = result
    except AttributeError:                  # compatibility with slotted stubs
        pass
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
