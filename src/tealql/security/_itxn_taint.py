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
from tealql.tealtools.ssa import (
    Assignment,
    Const,
    SSAProgram,
    SSAVar,
    binary_operands,
    const_bytes,
    const_int,
)

from ._program_shape import file_match, global_field_reads, ssavar_outputs, txn_field_reads
from ._value_flow import (
    _frame_gap_sources_cached,
    _operand_flows_from_field_var,
    _scratch_stores_for,
)

# Compatibility/monkeypatch hook retained under its established name; the
# default now supplies only edges absent from canonical SSA def-use.
_frame_value_sources_cached = _frame_gap_sources_cached

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
    ``None`` when the contract doesn't lift. A multi-file SSA collection is
    projected and cached per ``file``; a single-file program retains the shared
    ``_ir_lifter`` cache used by :func:`tealql.tealtools.lift.build_lifter`.

    A directory-backed collection independently rebuilds ``file``; otherwise
    this lifts ``prog`` itself. The lift restores its input CFG on exit (the
    dead-edge prune + phi rebuild is save/restored inside ``_Lifter.build``), so
    SSA-layer detectors are unaffected and no fresh re-parse is paid.

    Failure is never silent: it warns, and the ir-* detectors then degrade to an
    SSA-sibling fallback or no findings, which the user must be able to see."""
    global _LIFT_IMPORT_WARNED
    from tealql.tealtools.lift.cache import LifterRequest

    request = LifterRequest(prog, file)
    # Same ``_ir_lifter`` attribute as the query-side ``lift.build_lifter``, so a
    # program is lifted at most once when both a taint-query and the ir-* detectors
    # run: whichever builds first caches here, the other reuses.
    hit, cached = request.lookup()
    if hit:
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
            target = request.target()
            target.propagate_constants()
            lf = _Lifter(target)
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
    request.store(lifter)
    return lifter




def _compute_user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    taint: dict = {}

    def t(o):
        return taint.get(o, frozenset())

    frame_src = _frame_value_sources_cached(prog)  # ordinary SSA carries the rest

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




def sender_vars(prog: SSAProgram, *, file: Optional[str] = None) -> set:
    """SSAVars reading the current ``txn Sender``."""
    return ssavar_outputs(txn_field_reads(prog, "Sender", file=file))


def sender_creator_vars(prog: SSAProgram, *, file: Optional[str] = None) -> set:
    """Compatibility API: current ``txn Sender`` and ``CreatorAddress`` reads.

    New guard-classification code must use :func:`sender_vars`: creator is a
    sound identity to compare Sender *against*, but is not itself evidence that
    a condition checks who sent the transaction.
    """
    return (
        sender_vars(prog, file=file)
        | ssavar_outputs(global_field_reads(prog, "CreatorAddress", file=file))
    )


_GUARD_VALUE_OPAQUE_OPS = frozenset({"len", "bitlen", "bzero"})
_GUARD_EQ_OPS = frozenset({"==", "b=="})
_GUARD_NEQ_OPS = frozenset({"!=", "b!="})
_GUARD_CMP_OPS = frozenset({
    "==", "!=", "<", "<=", ">", ">=",
    "b==", "b!=", "b<", "b<=", "b>", "b>=",
})


def _value_predicate_checks_slots(value, kind: str, args: tuple,
                                  sink_slots: frozenset, taint: dict) -> bool:
    """Whether a forced predicate meaningfully constrains ``sink_slots``.

    Slot taint alone is insufficient: it also reaches length-only transforms,
    tautologies, and bypassable boolean arms.  Crediting any of those as a value
    guard suppresses the fund-flow finding even though the attacker still
    chooses the complete value.  This is the SSA counterpart of the lifted-IR
    guard classifier; it deliberately stays local so the public fallback keeps
    working when lifting fails.
    """
    seen: set[tuple[int, bool, bool, bool, bool]] = set()

    def value_origin(v):
        """Peel stack-copy ops whose several SSA outputs denote one value."""
        origin_seen: set[int] = set()
        while id(v) not in origin_seen:
            origin_seen.add(id(v))
            d = getattr(v, "defined_by", None)
            if d is None or d.op not in {"dup", "dupn"} or len(d.inputs) != 1:
                break
            v = d.inputs[0]
        return v

    if kind in {"neq", "not_in_range", "neq_all"}:
        return False                              # exclusions do not pin the value
    if (kind in {"eq", "lt", "le", "gt", "ge"} and args
            and value_origin(value) is value_origin(args[0])):
        return False                              # decomposed x OP x predicate

    def next_inputs(v, guaranteed: bool, value_ok: bool, sense: bool,
                    input_ok: bool):
        key = (id(v), guaranteed, value_ok, sense, input_ok)
        if key in seen:
            return ()
        seen.add(key)
        if not guaranteed or not value_ok or not input_ok:
            return ()

        d = getattr(v, "defined_by", None)
        if d is None or not d.inputs:
            return None if taint.get(v, frozenset()) & sink_slots else ()

        operands = binary_operands(d)
        if (d.op in _GUARD_CMP_OPS and operands is not None
                and value_origin(operands[0]) is value_origin(operands[1])):
            return ()                            # x OP x is a constant predicate
        if d.op == "%" and operands is not None and const_int(operands[1]) == 1:
            return ()                            # x % 1 is always zero

        breaks = "||" if sense else "&&"
        child_guaranteed = guaranteed and d.op != breaks
        child_value_ok = value_ok and d.op not in _GUARD_VALUE_OPAQUE_OPS
        child_sense = not sense if d.op == "!" else sense
        child_input_ok: bool = input_ok
        if ((d.op in _GUARD_NEQ_OPS and child_sense)
                or (d.op in _GUARD_EQ_OPS and not child_sense)):
            # Excluding one value does not meaningfully validate an attacker-
            # chosen payee/amount; equality only pins on the equality arm.
            child_input_ok = False
        return tuple(
            (inp, child_guaranteed, child_value_ok, child_sense,
             child_input_ok)
            for inp in d.inputs
        )

    # Legal TEAL can build definition chains deeper than Python's recursion
    # limit.  A detector crash is especially dangerous here because the public
    # runner isolates it and prints "no findings".  The predicate is an
    # existential walk, so a plain worklist preserves the recursive ``any``
    # semantics without a host-stack limit.
    pending = [(value, True, True, kind != "zero", True)]
    while pending:
        state = pending.pop()
        children = next_inputs(*state)
        if children is None:
            return True
        pending.extend(children)
    return False


def _identity_is_attacker_supplied(value, taint: dict,
                                   seen: Optional[set] = None) -> bool:
    """Whether ``value`` is not a trustworthy sender-equality counterpart."""
    if taint.get(value, frozenset()):
        return True
    raw = const_bytes(value)
    if raw is not None:
        # Sender is always a 32-byte non-zero address. A short/int/zero literal
        # makes the equality impossible rather than authorizing an identity.
        h = raw[2:] if raw.startswith("0x") else raw
        return len(h) != 64 or set(h) <= {"0"}
    if isinstance(value, Const):
        return True
    if seen is None:
        seen = set()
    if id(value) in seen:
        return False
    seen.add(id(value))
    d = getattr(value, "defined_by", None)
    if d is None:
        return False
    if d.op.startswith("gtxn"):
        return True                    # the attacker composes the sibling txn
    if (d.op == "global"
            and d.immediates.strip() in {
                "CallerApplicationID", "CallerApplicationAddress",
            }):
        return True                    # an attacker can deploy the caller app
    return any(_identity_is_attacker_supplied(i, taint, seen) for i in d.inputs)


def _sender_equality_pins_identity(prog: SSAProgram, cond, taint: dict,
                                   sender_vars: set, *, file: str) -> bool:
    """True only for an equality between Sender and one trusted identity."""
    operands = None
    if cond.kind == "eq" and cond.args:
        operands = (cond.value, cond.args[0])
    elif cond.kind == "nonzero":
        d = getattr(cond.value, "defined_by", None)
        if d is not None and d.op in _GUARD_EQ_OPS:
            operands = binary_operands(d)
    if operands is None:
        return False
    is_sender = [
        _operand_flows_from_field_var(prog, op, sender_vars) for op in operands
    ]
    if sum(is_sender) != 1:            # no Sender, or Sender == Sender tautology
        return False
    other = operands[0] if is_sender[1] else operands[1]
    return (
        not _identity_is_attacker_supplied(other, taint)
        and not value_is_zero_address(prog, other, file=file)
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
        if _value_predicate_checks_slots(
                v, cond.kind, cond.args, sink_slots, taint):
            return True
        if _sender_equality_pins_identity(
                prog, cond, taint, sender_vars, file=file):
            return True
    return False
