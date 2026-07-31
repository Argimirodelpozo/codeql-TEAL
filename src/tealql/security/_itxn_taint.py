"""Inner-transaction field helpers, the shared user-input taint fixpoint, and the
cached Puya-IR lifter bridge the ir-* detector family runs on. Import via
:mod:`tealql.security.common`.

HAZARD: detectors must call ``common.ir_lifter(...)`` attribute-style so it
resolves through the facade — tests monkeypatch it there.
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
    """One ``itxn_field FIELD`` assignment plus the SSA value being written."""

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
    """Every ``itxn_field FIELD`` opcode; the value set is ``inputs[0]`` (top of stack)."""
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
    """SSAVars reading ``global ZeroAddress`` — seeds for :func:`value_is_zero_address`."""
    return {
        out for a in global_field_reads(prog, "ZeroAddress", file=file)
        for out in a.outputs if isinstance(out, SSAVar)
    }




def value_is_zero_address(
    prog: SSAProgram, value, *, file: Optional[str] = None,
) -> bool:
    """``value`` provably resolves to the zero address — a 32-byte all-zero constant,
    or a flow from ``global ZeroAddress``. Setting ``RekeyTo``/``CloseRemainderTo``
    to it is the field's default (a defensive no-op), not the drain antipattern."""
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
    """``itxn_field Fee`` set to a KNOWN non-zero int; dynamic values aren't flagged."""
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
# User-input taint + itxn-field guard: "does an attacker-controlled value reach a
# sensitive inner-txn field without a dominating check?" Forward propagation over
# the PySSA def-use / phi / scratch relation, interprocedural via the frame-flow
# bridge (a proto param is tainted from the caller args bound to it).
# ---------------------------------------------------------------------------


_CMP_OPS = frozenset({"==", "!="})




def source_label(op: str, imm: str) -> Optional[str]:
    """The user-input source family ``op``/``imm`` reads, or ``None``. Delegates to
    :func:`avm.attacker_input_label` — the ONE table, shared with the IR-level
    seeds; a second hand-kept copy silently drifts to an incomplete source set."""
    from tealql.tealtools.avm import attacker_input_label
    return attacker_input_label(op, imm)




def user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    """``{SSAVar|Phi: frozenset[(label, slot)]}`` — forward taint from the user-input
    sources, where ``slot`` = ``(op, immediates)`` so reads of the SAME input slot
    match and ``ApplicationArgs[0]`` vs ``[1]`` do not. Interprocedural: a
    ``frame_dig`` param read inherits the taint of the caller args bound to it.

    Memoised per ``(prog, file)`` so the whole fund-flow family shares one fixpoint
    — sound only because detectors READ ``prog`` and never mutate it mid-scan."""
    cache = getattr(prog, "_sec_user_input_taint", None)
    if cache is None:
        cache = {}
        try:
            prog._sec_user_input_taint = cache
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    if file in cache:
        return cache[file]
    result = _compute_user_input_taint(prog, file)
    cache[file] = result
    return result




# The pre-IR path is puya-free, so a lift-package ImportError is a real breakage,
# not merely puya-not-installed. Warned once per process.
_LIFT_IMPORT_WARNED = False




def ir_lifter(prog: SSAProgram, file: Optional[str] = None):
    """Build + cache the post-``build`` ``_Lifter`` the ir-* detectors run on, or
    ``None`` when the contract doesn't lift. Cached per ``prog``; ``file`` is taken
    for signature parity but unused (the lift is whole-program).

    Lifts ``prog`` ITSELF: the lift restores its input CFG on exit (the dead-edge
    prune + phi rebuild is save/restored inside ``_Lifter.build``), so the
    SSA-layer detectors reading the same ``prog`` are unaffected and no fresh
    re-parse is paid — this used to rebuild an ``SSAProgram`` from
    ``prog.source_path`` per lift, ~45% of the lift path's cost, and made
    programs without a source path unliftable.

    Failure is never silent: it warns, and the ir-* detectors then degrade to an
    SSA-sibling fallback or no findings, which the user must be able to see."""
    global _LIFT_IMPORT_WARNED
    sentinel = object()
    # Same ``_ir_lifter`` attribute as the query-side ``lift.build_lifter``, so a
    # program is lifted at most once when both a taint-query and the ir-* detectors
    # run: whichever builds first caches here, the other reuses.
    cached = getattr(prog, "_ir_lifter", sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    try:
        from tealql.tealtools.lift.lift import _Lifter
    except ImportError as e:
        if not _LIFT_IMPORT_WARNED:
            _LIFT_IMPORT_WARNED = True
            logger.warning(
                "IR detections DISABLED — the lift package failed to import "
                "(%s). ir-* detectors with an SSA sibling fall back to it; "
                "the rest report nothing.", e)
    else:
        src = str(getattr(prog, "source_path", "") or "<in-memory>")
        from tealql.tealtools.errors import LiftError
        try:
            prog.propagate_constants()
            lf = _Lifter(prog)
            lf.build()
            lifter = lf
        except LiftError as e:
            # EXPECTED coverage gap (~0.1% of real mainnet), so info: the
            # ir-* fallback is designed behaviour, not an anomaly.
            logger.info(
                "Puya-IR lift did not cover %s (%s) — ir-* detections use "
                "their SSA fallback; results may be less precise.", src, e)
        except Exception as e:
            # Anything but a LiftError points at a bug, not a coverage limit.
            logger.warning(
                "Puya-IR lift crashed UNEXPECTEDLY for %s (%s: %s) — this "
                "is likely a bug; ir-* detections fall back. Please report.",
                src, type(e).__name__, e)
    try:
        prog._ir_lifter = lifter
    except AttributeError:          # only if SSAProgram ever gains __slots__
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
    """SSAVars reading ``txn Sender`` / ``global CreatorAddress`` — seeds for the
    "this access is gated on who sent it" suppression."""
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
    """The inner-txn field write at ``assignment`` is dominated by a check of the
    tainted value itself (a predicate from the SAME input slot) or of ``txn Sender``.

    HAZARD: a sender guard counts only as an EQUALITY that HOLDS on this path. A
    ``!=`` (``Sender != ZeroAddress``) pins nothing, and a ``==`` taken on its FALSE
    edge authorizes nothing — crediting either makes a real tainted write read as
    guarded."""
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
