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

from ..ssa import Phi, SSAVar
from ..language.avm import (
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
    :func:`tealql.tealtools.language.avm.attacker_input_label`, the ONE source table this
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


def transfer_fixpoint(lifter, taint: dict, *, seed_label, invoke_ins,
                      per_round=None, subs=None) -> None:
    """THE taint transfer fixpoint — shared by :func:`user_input_taint`,
    :func:`summaries.compute_summaries`, which
    used to carry three near-verbatim ~80-line copies of this body, so every
    conservatism fix (the unknown-scratch series included) had to be mirrored
    by hand three times.

    ``taint`` maps ``id(Register) -> set`` and is mutated to the least
    fixpoint. The three knobs:

    * ``seed_label(intrinsic) -> label | None`` — the trusted-args exemption
      lives in the caller's lambda;
    * ``invoke_ins(o, inv, reg_t) -> (outputs: tuple[set, ...], changed: bool)`` — the
      interprocedural rule (summary lookup, param seeding, unknown-callee
      fallback);
    * ``per_round(reg_t) -> bool`` — the caller's per-round epilogue
      (return-marker / checked-param refinement), run after each sweep.
    """
    ssa_of = getattr(lifter, "register_sources", {})
    unknown_scratch_slots: set = set()
    unknown_dynamic = False

    def reg_t(v):
        return value_sources(v, taint)

    blocks = list(pre_ir.blocks(lifter.subs if subs is None else subs))
    changed = True
    while changed:
        changed = False
        for b in blocks:
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
                    lbl = seed_label(src)
                    if lbl:
                        ins.add(lbl)
                    for a in src.args:
                        ins |= reg_t(a)
                    if _scratch_read_is_unknown(
                            src, unknown_scratch_slots, unknown_dynamic):
                        ins.add(UNKNOWN_SOURCE)
                    if src.op in ("load", "loads"):     # scratch reaching-def
                        out = (o.targets[0]
                               if getattr(o, "targets", None) else None)
                        lvs = ssa_of.get(id(out), ()) if out is not None else ()
                        for lv in lvs:
                            for sv in lifter.load_stores.get(lv, ()):
                                if isinstance(sv, (SSAVar, Phi)):
                                    ins |= reg_t(_lift_value(lifter, sv))
                    slot, dynamic = _scratch_unknown_write(src, reg_t)
                    if slot is not None and slot not in unknown_scratch_slots:
                        unknown_scratch_slots.add(slot)
                        changed = True
                    if dynamic and not unknown_dynamic:
                        unknown_dynamic = True
                        changed = True
                direct = _assignment_sources(o, taint)
                inv = _invoke(o)
                if inv is not None:
                    direct, inv_changed = invoke_ins(o, inv, reg_t)
                    changed = changed or inv_changed
                for index, t in enumerate(getattr(o, "targets", ()) or ()):
                    target_ins = (ins | direct[index]
                                  if index < len(direct) else
                                  ins | {UNKNOWN_SOURCE} if inv is not None else ins)
                    if target_ins - taint[id(t)]:
                        taint[id(t)] |= target_ins
                        changed = True
        if per_round is not None and per_round(reg_t):
            changed = True
