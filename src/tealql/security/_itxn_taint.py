"""Inner-transaction field helpers, the shared user-input taint fixpoint, and
the cached Puya-IR lifter bridge the ir-* detector family runs on.

Split out of ``common.py``; import via :mod:`tealql.security.common`.
NOTE: tests monkeypatch ``common.ir_lifter``; detectors call it attribute-style
(``common.ir_lifter(...)``), which resolves through the facade — keep it so.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Assignment, Const, SSAProgram, SSAVar

from ._program_shape import file_match, global_field_reads, ssavar_outputs, txn_field_reads
from ._value_flow import (
    _frame_param_sources_cached,
    _operand_flows_from_field_var,
    _scratch_stores_for,
)

logger = logging.getLogger("tealql.security.common")

# ---------------------------------------------------------------------------
# Inner transaction helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InnerTxnFieldSet:
    """One ``itxn_field FIELD`` assignment, with the SSA value being
    written."""

    assignment: Assignment
    field: str
    value: object  # SSAVar | Phi | Const

    @property
    def value_const(self) -> Optional[Const]:
        v = self.value
        if isinstance(v, Const):
            return v
        cv = getattr(v, "const_value", None)
        if isinstance(cv, Const):
            return cv
        return None




def inner_txn_field_assigns(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[InnerTxnFieldSet]:
    """Iterate every ``itxn_field FIELD`` opcode. The set value is
    ``inputs[0]`` (top-of-stack at the itxn_field call)."""
    out: list[InnerTxnFieldSet] = []
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op != "itxn_field" or not a.inputs:
            continue
        field = a.immediates.strip()
        out.append(InnerTxnFieldSet(assignment=a, field=field, value=a.inputs[0]))
    return out




def _zero_address_seeds(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> set:
    """SSAVars that read ``global ZeroAddress`` — the canonical 32-zero-byte
    address source. Seeds for :func:`value_is_zero_address`."""
    return {
        out for a in global_field_reads(prog, "ZeroAddress", file=file)
        for out in a.outputs if isinstance(out, SSAVar)
    }




def value_is_zero_address(
    prog: SSAProgram, value, *, file: Optional[str] = None,
) -> bool:
    """``value`` provably resolves to the zero address: either a 32-byte all-zero
    bytes constant, or a value flowing (through phi / scratch / proto-frame, via
    :func:`_operand_flows_from_field_var`) from ``global ZeroAddress``.

    Used to suppress *safe* dangerous-field writes — setting ``itxn_field
    RekeyTo`` / ``CloseRemainderTo`` to the zero address is a defensive no-op
    (the field's default), not the drain/rekey antipattern."""
    cv = value if isinstance(value, Const) else getattr(value, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "bytes":
        hexpart = cv.value[2:] if cv.value.startswith("0x") else cv.value
        if len(hexpart) == 64 and set(hexpart) <= {"0"}:   # 32 zero bytes
            return True
    seeds = _zero_address_seeds(prog, file=file)
    if seeds and _operand_flows_from_field_var(prog, value, seeds):
        return True
    return False




def inner_txn_sets_nonzero_fee(field_set: InnerTxnFieldSet) -> bool:
    """``itxn_field Fee`` whose value resolves to a non-zero integer
    constant (a *known* non-zero int — dynamic values aren't
    flagged)."""
    if field_set.field != "Fee":
        return False
    cv = field_set.value_const
    if cv is None or cv.kind != "int":
        return False
    try:
        return int(cv.value) != 0
    except (TypeError, ValueError):
        return False




# ---------------------------------------------------------------------------
# User-input taint + itxn-field guard
#
# Shared by every detector that asks "does an attacker-controlled value reach
# a sensitive inner-transaction field without a dominating check?" — the
# tainted-fund-flow family (payment fields) and arbitrary-inner-appcall (the
# call target). The taint is a forward propagation over the PySSA
# def-use / phi / scratch relation, interprocedural via the frame-flow bridge
# (a value fed into a proto param is tainted from the caller args bound to it).
# ---------------------------------------------------------------------------


_CMP_OPS = frozenset({"==", "!="})




def source_label(op: str, imm: str) -> Optional[str]:
    """The user-input source family ``op`` (with immediates ``imm``) reads, or
    ``None``. ``ApplicationArgs`` (txn/gtxn array reads), LogicSig ``arg``s, and
    the ``itxn ... LastLog`` of a just-called sub-app are all attacker-steerable."""
    from tealql.tealtools.avm import TXN_SOURCE_OPS, ITXN_SOURCE_OPS, LSIG_ARG_OPS
    if op in TXN_SOURCE_OPS and "ApplicationArgs" in imm:
        return "ApplicationArgs"
    if op in LSIG_ARG_OPS:
        return "LogicSigArgs"
    if op in ITXN_SOURCE_OPS and "LastLog" in imm:
        return "ItxnLastLog"
    return None




def user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    """``{SSAVar|Phi: frozenset[(label, slot)]}`` — forward taint from the
    user-input sources over the SSA def-use / phi / scratch relation, where
    ``slot`` = ``(op, immediates)`` so two reads of the SAME input slot match
    (and ``ApplicationArgs[0]`` vs ``[1]`` don't).

    Interprocedural: each ``frame_dig`` param read inherits the taint of the
    caller args bound to it (:func:`frame_param_sources`), so a value fed INTO a
    subroutine parameter and consumed inside the callee is caught natively — no
    IR lift, no per-detector supplement.

    Memoised per ``(prog, file)``: the whole tainted-fund-flow family
    (tainted-fund-flow / partial / arbitrary-inner-appcall / -asset) shares one
    fixpoint instead of recomputing it per detector. Sound because the detectors
    only READ ``prog`` (no mutation between runs in a scan)."""
    cache = getattr(prog, "_sec_user_input_taint", None)
    if cache is None:
        cache = {}
        try:
            prog._sec_user_input_taint = cache
        except Exception:
            pass
    if file in cache:
        return cache[file]
    result = _compute_user_input_taint(prog, file)
    cache[file] = result
    return result




# Warn only once per process if the lift package itself fails to import
# (a real breakage — the pre-IR path is puya-free, so missing puya alone does
# NOT trip this); per-contract lift failures warn individually in ir_lifter.
_LIFT_IMPORT_WARNED = False




def ir_lifter(prog: SSAProgram, file: Optional[str] = None):
    """Build + cache the IR lifter for ``prog`` -- the lifted, Puya-shaped IR the
    interprocedural detectors (e.g. ``ir-tainted-fund-flow``) run on.

    Built from a FRESH ``SSAProgram`` off ``prog.source_path`` rather than ``prog``
    itself: the lift mutates its input CFG (``_prune_dead_assert_edges`` drops dead
    edges + rebuilds join phis), and the SSA-layer detectors read the SAME
    ``prog`` -- so lifting a copy keeps their substrate pristine. Returns the
    ``_Lifter`` instance (post-``build``, carrying ``.subs``/``.regs``/``.reg`` the
    taint + fund-flow analyses consume), or ``None`` when the contract doesn't lift
    (rare; the lift is ~99.9% robust on real mainnet). Cached per ``prog`` -- one
    lift shared by every IR detector in a scan.

    ``file`` is accepted for signature parity with the SSA analyses but unused: the
    lift is whole-program, and SSAPrograms are per-file (xcontract aside).

    Failure is NEVER silent: a per-contract lift failure warns with the
    reason, and a lift-package import failure (which should NOT happen just
    because puya is missing — the pre-IR taint path is puya-free) warns once.
    Either way the ir-* detectors degrade (SSA-sibling fallback or no
    findings), and the user must be able to see the reduced precision."""
    global _LIFT_IMPORT_WARNED
    sentinel = object()
    cached = getattr(prog, "_sec_ir_lifter", sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    try:
        from tealql.tealtools.lift.lift import _Lifter
    except ImportError as e:
        # The detector-facing lift is deliberately puya-free, so this is a
        # genuine breakage (not merely puya-not-installed), hence once-only.
        if not _LIFT_IMPORT_WARNED:
            _LIFT_IMPORT_WARNED = True
            logger.warning(
                "IR detections DISABLED — the lift package failed to import "
                "(%s). ir-* detectors with an SSA sibling fall back to it; "
                "the rest report nothing.", e)
    else:
        src = str(getattr(prog, "source_path", "") or "")
        if not src:
            logger.debug(
                "ir_lifter: program has no source path (in-memory build?) — "
                "IR layer skipped")
        else:
            from tealql.tealtools.errors import LiftError
            try:
                fresh = SSAProgram(src)
                fresh.propagate_constants()
                lf = _Lifter(fresh)
                lf.build()
                lifter = lf
            except LiftError as e:
                # EXPECTED coverage gap: a contract the lift can't reconstruct
                # (~0.1% of real mainnet). Info, not warning — the ir-* fallback
                # is the designed behaviour, not an anomaly.
                logger.info(
                    "Puya-IR lift did not cover %s (%s) — ir-* detections use "
                    "their SSA fallback; results may be less precise.", src, e)
            except Exception as e:
                # UNEXPECTED: the lift raised something other than a LiftError,
                # which points at a bug rather than a coverage limit. Louder.
                logger.warning(
                    "Puya-IR lift crashed UNEXPECTEDLY for %s (%s: %s) — this "
                    "is likely a bug; ir-* detections fall back. Please report.",
                    src, type(e).__name__, e)
    try:
        prog._sec_ir_lifter = lifter
    except Exception:
        pass
    return lifter




def _compute_user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    taint: dict = {}

    def t(o):
        return taint.get(o, frozenset())

    frame_src = _frame_param_sources_cached(prog)

    for a in prog.assignments:                       # seed
        if not file_match(a.location.file, file):
            continue
        lbl = source_label(a.op, a.immediates.strip())
        if lbl:
            key = (lbl, (a.op, a.immediates.strip()))
            for o in a.outputs:
                if isinstance(o, SSAVar):
                    taint[o] = t(o) | {key}

    changed = True
    while changed:
        changed = False
        for ph in prog.phis.values():                # phi: union of args
            new = set()
            for arg in ph.args:
                new |= t(arg)
            if new - t(ph):
                taint[ph] = t(ph) | new
                changed = True
        for dig_out, args in frame_src.items():      # callee param <- caller args
            new = set()
            for arg in args:
                new |= t(arg)
            if new - t(dig_out):
                taint[dig_out] = t(dig_out) | new
                changed = True
        for a in prog.assignments:
            if not file_match(a.location.file, file):
                continue
            ins = set()
            for inp in a.inputs:
                ins |= t(inp)
            if a.op == "load":                       # scratch reaching-def
                for o in a.outputs:
                    for s in (_scratch_stores_for(prog, o) or ()):
                        ins |= t(prog.var(*s))
            if not ins:
                continue
            for o in a.outputs:
                if isinstance(o, SSAVar) and (ins - t(o)):
                    taint[o] = t(o) | ins
                    changed = True
    return {k: frozenset(v) for k, v in taint.items() if v}




def sender_creator_vars(prog: SSAProgram, *, file: Optional[str] = None) -> set:
    """SSAVars reading ``txn Sender`` or ``global CreatorAddress`` — the seeds
    for the "this access is gated on who sent it" suppression."""
    return (
        ssavar_outputs(txn_field_reads(prog, "Sender", file=file))
        | ssavar_outputs(global_field_reads(prog, "CreatorAddress", file=file))
    )




def itxn_value_guarded(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    assignment: Assignment,
    sink_slots: frozenset,
    taint: dict,
    sender_vars: set,
) -> bool:
    """The inner-txn field write at ``assignment`` is dominated by a check of
    either the tainted value itself (a predicate derived from the SAME input
    slot — taint propagates through the comparison, so ``arg < N`` carries
    ``arg``'s slot) or of ``txn Sender`` (a sender/creator equality).

    A genuine sender guard AUTHENTICATES — it pins the caller's identity: an
    EQUALITY (``Sender == Creator`` / ``== <admin>``) that HOLDS on this path.
    A ``!=`` (e.g. the ``Sender != ZeroAddress`` sanity check) pins nothing, and
    a ``==`` taken on its FALSE edge (the explicitly non-matching arm) authorizes
    nothing — neither counts, or a real tainted write would read as guarded."""
    file = assignment.location.file
    preds = pp.predicates_at(file=file, line=assignment.location.line)
    for cond in preds:
        v = cond.value
        if taint.get(v, frozenset()) & sink_slots:        # value-check
            return True
        d = getattr(v, "defined_by", None)
        if (d is not None and d.op == "==" and cond.kind == "nonzero"
                and any(_operand_flows_from_field_var(prog, op, sender_vars)
                        for op in d.inputs)
                and not any(value_is_zero_address(prog, op, file=file)
                            for op in d.inputs)):       # sender IDENTITY pin
            return True
    return False
