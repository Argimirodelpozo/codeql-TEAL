"""Field-validation reasoning: ``field_validated_on_all_paths`` and the
``approval_exit_protected_for_*`` family, parameterised on seed sets.

Every member asks the same MUST-reach question — does every entry→exit path CROSS
a block that ENFORCES a comparison of the seeds? A may-reach ("some enforcement
exists") lets a field compared in a dominator but asserted on only one branch read
as validated, leaving the other approving path unguarded.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.analysis.guard_coverage import counterpart_credits, every
from tealql.tealtools.language.avm import CMP_OPS
from tealql.tealtools.ssa import (Assignment, BasicBlock, SSAProgram, SSAVar,
                                  operand_const)

from ._enforcement import (
    _DISJUNCTION_OPS,
    _FORCING_SINK_OPS,
    _disjunction_is_enforcing,
    _label_to_bb_first_line,
    branch_gates_rejection,
    branch_reject_polarity,
    scratch_forward_map,
)
from ._program_shape import (
    _txna_reads,
    approving_exits,
    file_match,
    global_field_reads,
    gtxn_field_reads,
    ssavar_outputs,
    txn_field_reads,
)
from ._value_flow import _operand_flows_from_field_var



# ---------------------------------------------------------------------------
# Comparison-operand wiring
# ---------------------------------------------------------------------------


def is_comparison(a: Assignment) -> bool:
    """An ``Assignment`` whose op compares two stack values."""
    return a.op in CMP_OPS




def _collect_field_enforcement_bbs(
    prog: SSAProgram, var: SSAVar, label_lines: dict, out: set, seen: set,
    scratch_fwd: Optional[dict] = None, field_vars: Optional[set] = None,
) -> None:
    """Record the BASIC BLOCK of every enforcement site the SSA chain from a
    field-comparison result reaches (an ``assert``/``return`` sink, or a
    :func:`branch_gates_rejection` branch), walking through every consuming
    opcode that produces a def and through provably-preserving scratch
    round-trips. Collecting every site rather than answering yes/no is what lets
    the caller demand a MUST-reach. ``field_vars`` names the field seeds under
    test, which is what makes a ``||`` decidable."""
    if var in seen:
        return
    seen.add(var)
    if scratch_fwd is None:
        scratch_fwd = scratch_forward_map(prog)
    for fwd in scratch_fwd.get(var, ()):
        _collect_field_enforcement_bbs(prog, fwd, label_lines, out, seen,
                                       scratch_fwd, field_vars)
    for cons in var.uses:
        if cons.op in _FORCING_SINK_OPS:
            # `assert V`, or the approving exit `return V` — approving through
            # that block means V held.
            if cons.basic_block is not None:
                out.add(cons.basic_block)
        elif cons.op in ("bnz", "bz"):
            # Record the BRANCH's own block: every path continuing to an
            # approving exit crosses it whichever edge it takes.
            if (cons.basic_block is not None
                    and branch_gates_rejection(prog, cons, label_lines)):
                out.add(cons.basic_block)
        # A ``||`` carries enforcement to this arm only when every OTHER arm pins
        # the same field, else the other arm alone satisfies the assert and this
        # one is unconstrained.
        if cons.op in _DISJUNCTION_OPS and not _disjunction_is_enforcing(
                prog, cons, var, field_vars):
            continue
        for o in cons.outputs:
            if isinstance(o, SSAVar):
                _collect_field_enforcement_bbs(prog, o, label_lines, out, seen,
                                               scratch_fwd, field_vars)


def _collect_disequality_pin_bbs(
    prog: SSAProgram, var: SSAVar, label_lines: dict, out: set, seen: set,
    scratch_fwd: Optional[dict] = None,
) -> None:
    """Record the blocks where a ``!=``-spelled pin in ``var`` is ENFORCED as
    a pin — i.e. where its TRUTH rejects, so the surviving path carries the
    equality: ``X != safe; bnz reject`` / ``bz ok; err``, or ``!`` (which turns
    it into the equality and hands over to :func:`_collect_field_enforcement_bbs`).

    HAZARD: POLARITY is the whole point. ``assert(X != safe)``, ``return (X !=
    safe)`` and a branch rejecting on FALSE all demand the DISEQUALITY — the
    anti-pin — and must record nothing, which is why this cannot reuse the
    polarity-agnostic collecting twin directly."""
    if var in seen:
        return
    seen.add(var)
    if scratch_fwd is None:
        scratch_fwd = scratch_forward_map(prog)
    for fwd in scratch_fwd.get(var, ()):
        _collect_disequality_pin_bbs(prog, fwd, label_lines, out, seen, scratch_fwd)
    for cons in var.uses:
        if cons.op in ("bnz", "bz") and cons.basic_block is not None:
            _, rejects_true = branch_reject_polarity(prog, cons, label_lines)
            if rejects_true:
                out.add(cons.basic_block)
        elif cons.op == "!":
            for o in cons.outputs:
                if isinstance(o, SSAVar):
                    _collect_field_enforcement_bbs(prog, o, label_lines, out, seen,
                                                   scratch_fwd)


#: SAFE-VALUE rules for field enforcement (``safe=`` below). A field check
#: protects only when it constrains the field to a value that is safe for
#: that field — merely COMPARING it is not enough: ``RekeyTo != Sender``,
#: ``Fee > 0``, ``GroupSize >= K`` and ``XferAsset != 0`` all "compare" the
#: field and leave it attacker-chosen.
#:
#: ``address-pin``  — ``== ZeroAddress`` / a fixed (constant) address;
#: ``upper-bound``  — ``==``/``<``/``<=`` a trusted scalar, or ``!field``;
#: ``constant-pin`` — ``==`` a trusted scalar;
#: ``size-bound``   — ``==``/``<``/``<=`` a trusted scalar.
#: A ``!=`` counts only as a PIN — and, for the bound rules, ``>``/``>=`` only
#: as an upper bound — when its TRUTH rejects (``Fee > K; bnz reject``), via
#: the polarity-aware collector.
SAFE_RULES = {
    "address-pin": frozenset({"==", "b=="}),
    "upper-bound": frozenset({"==", "<", "<="}),
    "constant-pin": frozenset({"=="}),
    "size-bound": frozenset({"==", "<", "<="}),
}
_FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!=",
         "b==": "b==", "b!=": "b!="}
_TRUSTED_SCALAR_OPS = frozenset({"+", "-", "*", "/", "itob", "btoi", "addw", "mulw"})
_TRUSTED_GLOBALS = frozenset({"ZeroAddress", "MinTxnFee", "MinBalance",
                              "CreatorAddress", "CurrentApplicationAddress",
                              "CurrentApplicationID"})


def _trusted_scalar(prog: SSAProgram, v, depth: int = 0) -> bool:
    """``v`` is a value no transaction field or argument can choose: a
    constant, a protocol/app-identity ``global``, the app's own global state
    under a constant key, or arithmetic over those."""
    from ._value_flow import resolve_through_copies
    v = resolve_through_copies(prog, v)
    if operand_const(v) is not None:
        return True
    d = getattr(v, "defined_by", None)
    if d is None or depth > 8:
        return False
    if d.op == "global" and not d.inputs:
        return d.immediates.strip() in _TRUSTED_GLOBALS
    if d.op in ("app_global_get", "app_global_get_ex") and d.inputs:
        # The app's OWN global state under a constant key (a configured
        # asset id / fee cap): an `_ex` read must name the current app.
        if operand_const(resolve_through_copies(prog, d.inputs[0])) is None:
            return False
        if d.op == "app_global_get_ex":
            from tealql.tealtools.ssa import const_int
            app = resolve_through_copies(prog, d.inputs[1])
            ad = getattr(app, "defined_by", None)
            return const_int(app) == 0 or (
                ad is not None and ad.op == "global"
                and ad.immediates.strip() == "CurrentApplicationID")
        return True
    if d.op in _TRUSTED_SCALAR_OPS and d.inputs:
        return all(_trusted_scalar(prog, i, depth + 1) for i in d.inputs)
    return False


def _safe_field_comparison(prog: SSAProgram, cmp: Assignment, flows: list,
                           rule: str) -> "Optional[str]":
    """How ``cmp`` constrains the field under ``rule``: ``"truth"`` (its truth
    is the safe constraint), ``"reject-true"`` (its truth must REJECT: a
    ``!=`` pin, or ``>``/``>=`` for the bound rules), or ``None`` (not a safe
    constraint at all)."""
    if cmp.op == "!":
        return "truth" if rule == "upper-bound" else None
    if len(cmp.inputs) != 2 or sum(flows) != 1:
        return None
    from tealql.tealtools.ssa import binary_operands
    lhs, rhs = binary_operands(cmp)
    field_left = flows[1]                      # inputs are TOP-FIRST
    other = rhs if field_left else lhs
    op = cmp.op if field_left else _FLIP.get(cmp.op)
    if op is None or not _trusted_scalar(prog, other):
        return None
    if rule == "address-pin":
        k = operand_const(other)
        if k is not None and k.kind != "bytes":
            return None
    if op in ("!=", "b!="):
        return "reject-true"
    if op in (">", ">=") and rule in ("upper-bound", "size-bound"):
        return "reject-true"
    return "truth" if op in SAFE_RULES[rule] else None


def _field_enforcement_bbs(
    prog: SSAProgram, field_vars: set, *, file: Optional[str],
    allow_unary_cmp: bool = False,
    trusted_other: Optional[frozenset] = None,
    safe: Optional[str] = None,
) -> set:
    """BBs ENFORCING a comparison that consumes a field seed; empty when the field
    is never compared, or compared but never enforced. ``allow_unary_cmp`` also
    accepts a 1-input comparison (field against an inlined literal, e.g. an ABI
    selector).

    ``trusted_other`` (when given) is a POSITIVE set of seeds the comparison's
    OTHER operand must be a constant or provably flow from, else the comparison
    is not a gate: ``ApplicationArgs 0 == ApplicationArgs 1; assert`` is
    enforced, but the caller supplies BOTH sides, so any selector passes. The
    default (``None``) keeps the value-agnostic reading.

    ``safe`` (a :data:`SAFE_RULES` key) demands the comparison constrain the
    field to a SAFE value — see the table there."""
    revision = getattr(prog, "revision", 0)
    cached = getattr(prog, "_sec_field_enforcement", None)
    if cached is None or cached[0] != revision:
        cached = (revision, {})
        try:
            prog._sec_field_enforcement = cached
        except AttributeError:  # only if SSAProgram ever gains __slots__
            pass
    key = (frozenset(field_vars), file, allow_unary_cmp, trusted_other, safe)
    if key in cached[1]:
        return cached[1][key]

    out: set = set()
    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for cmp in prog.assignments:
        if not file_match(cmp.location.file, file):
            continue
        # `!` is a comparison against zero, and it is how a compiler spells `field === 0`:
        # puya-ts (Algorand TypeScript) emits `gtxns Fee; !; assert` for `assert(txn.fee === 0)`. Requiring a
        # two-operand CMP_OP missed that entirely, so a fee-pinned logicsig was reported as
        # having no fee check -- the exact drain finding it had explicitly guarded against.
        is_zero_test = cmp.op == "!"
        if not (is_comparison(cmp) or is_zero_test) or not cmp.outputs:
            continue
        n_in = len(cmp.inputs)
        if n_in != 2 and not is_zero_test and not (allow_unary_cmp and n_in == 1):
            continue
        if is_zero_test and n_in != 1:
            continue
        if not isinstance(cmp.outputs[0], SSAVar):
            continue
        flows = [_operand_flows_from_field_var(prog, op, field_vars)
                 for op in cmp.inputs]
        if not any(flows):
            continue
        if trusted_other is not None and n_in == 2:
            # The walker's input-vs-input rule: every counterpart (and at
            # least one — both sides from the field, `sel == sel`, is
            # vacuous) must be a constant or provably non-caller-chosen.
            if not every(counterpart_credits(
                    op, constant=lambda o: operand_const(o) is not None,
                    dependent=lambda o: not _operand_flows_from_field_var(
                        prog, o, trusted_other))
                    for op, f in zip(cmp.inputs, flows) if not f):
                continue
        if safe is not None:
            how = _safe_field_comparison(prog, cmp, flows, safe)
            if how is None:
                continue
            if how == "reject-true":
                _collect_disequality_pin_bbs(prog, cmp.outputs[0], label_lines,
                                             out, set(), scratch_fwd)
                continue
        _collect_field_enforcement_bbs(prog, cmp.outputs[0], label_lines, out,
                                       set(), scratch_fwd, field_vars)
    cached[1][key] = out
    return out


#: Reads whose VALUE the caller of an app call cannot choose: the app's own
#: state, boxes and protocol globals. The positive set a dynamically computed
#: "expected selector" must flow from (the same philosophy as
#: ``unvalidated_group_sibling._safe_receiver_targets``: an unmodelled source
#: fails SAFE, i.e. the comparison is not credited and the exit stays flagged).
_NON_CALLER_VALUE_OPS = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
    "box_get", "box_extract", "global",
})


def _non_caller_value_seeds(prog: SSAProgram, *, file: Optional[str]) -> frozenset:
    return frozenset(ssavar_outputs(
        a for a in prog.assignments
        if a.op in _NON_CALLER_VALUE_OPS and file_match(a.location.file, file)))


def _all_entry_paths_cross(
    prog: SSAProgram, exit_bb: BasicBlock, gates: set,
) -> bool:
    """Every path from a PROGRAM ENTRY to ``exit_bb`` crosses a ``gates`` BB —
    the shared backward walk, whose entry detection handles the self-loop
    entry and exit-is-entry shapes the old no-predecessor spelling silently
    credited as protected."""
    from ._program_shape import unguarded_entry_path_exists
    return not unguarded_entry_path_exists(
        prog, exit_bb, block_closed=lambda bb: bb in gates)


def _pinned_group_index(prog, *, file: Optional[str] = None) -> Optional[int]:
    """The value ``txn GroupIndex`` is pinned to on EVERY approving path, else
    ``None`` — any failure yields ``None``, crediting nothing as position-certain.

    ``global GroupSize == 1`` pins it too: a one-txn group has only position
    0, so ``gtxn 0 FIELD`` under that check IS the signer's own field — the
    commonest hand-written logicsig prologue, which read as an unpinned
    sibling read and flagged every drain-field check spelled ``gtxn 0``."""
    try:
        from tealql.tealtools.cfg import group as G
        from tealql.tealtools.ssa import const_int
        size_one = False
        for c in G.analyze(prog).constraints:
            if c.op != "==":
                continue
            if c.ref.slot == "this" and c.ref.field == "GroupIndex":
                return const_int(c.rhs)
            if (c.ref.slot == "global" and c.ref.field == "GroupSize"
                    and const_int(c.rhs) == 1):
                size_one = True
        if size_one:
            return 0
    except Exception:
        pass
    return None


def _signed_txn_field_reads(prog, field: str, *, file: Optional[str] = None) -> list:
    """Reads of the SIGNED transaction's own ``field``: ``txn FIELD``, ``gtxns
    FIELD`` indexed by ``txn GroupIndex``, and ``gtxn N FIELD`` only when
    ``GroupIndex == N`` is pinned.

    HAZARD: a bare ``gtxn N FIELD`` on an unpinned index reads a SIBLING, not the
    signer — crediting it would let a delegated logicsig be drained through a check
    that never touched the signed transaction."""
    from tealql.tealtools.cfg import group as G
    from tealql.tealtools.analysis import FactDomain
    facts = prog.facts(FactDomain.CONSTANTS)
    reads = list(txn_field_reads(prog, field, file=file))
    gtxn_reads = gtxn_field_reads(prog, field, file=file)
    for a in gtxn_reads:                                     # gtxns indexed by GroupIndex
        if a.op in ("gtxns", "gtxnsa", "gtxnsas") and a.inputs \
                and G.relative_slot(facts.resolve(a.inputs[0])) == "this":
            reads.append(a)
    # Only an ABSOLUTE ``gtxn N`` read needs the pin, so run the expensive
    # group-shape analysis only when one is present.
    abs_reads = [a for a in gtxn_reads if a.op in ("gtxn", "gtxna", "gtxnas")]
    if abs_reads:
        pinned = _pinned_group_index(prog, file=file)
        if pinned is not None:
            for a in abs_reads:
                toks = a.immediates.split()
                try:
                    n = int(toks[0])
                except (IndexError, ValueError):
                    continue
                if n == pinned:                             # gtxn N, GroupIndex==N pinned
                    reads.append(a)
    return reads


def field_validated_on_all_paths(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
    signed_txn_only: bool = False, safe: Optional[str] = None,
) -> bool:
    """The field is enforced on EVERY approving path (must-reach, seeded on the
    ENFORCEMENT SITE rather than the comparison).

    ``signed_txn_only`` restricts the seeds to :func:`_signed_txn_field_reads` for
    the delegated-LOGICSIG drain fields; the default also seeds sibling ``gtxn``
    reads, which is what app-mode wants."""
    exits = approving_exits(prog, file=file)
    if not exits:
        return False
    reads = (_signed_txn_field_reads(prog, field, file=file) if signed_txn_only
             else txn_field_reads(prog, field, file=file)
             + gtxn_field_reads(prog, field, file=file))
    field_vars = {out for a in reads for out in a.outputs if isinstance(out, SSAVar)}
    if not field_vars:
        return False
    gates = _field_enforcement_bbs(prog, field_vars, file=file, safe=safe)
    if not gates:
        return False
    return all(_all_entry_paths_cross(prog, exit_bb, gates) for exit_bb in exits)




def _approval_exit_protected_for_seeds(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    field_vars: set[SSAVar],
    *,
    file: Optional[str] = None,
    allow_unary_cmp: bool = False,
    trusted_other: Optional[frozenset] = None,
    safe: Optional[str] = None,
) -> bool:
    """Every path from an entry to ``exit_bb`` CROSSES a BB enforcing ``field_vars``
    — the shared core of the ``approval_exit_protected_for_*`` family."""
    if file is None:
        file = exit_bb.file
    if not field_vars:
        return False
    gates = _field_enforcement_bbs(
        prog, field_vars, file=file, allow_unary_cmp=allow_unary_cmp,
        trusted_other=trusted_other, safe=safe)
    return _all_entry_paths_cross(prog, exit_bb, gates)




def _txn_field_seeds(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
    include_gtxn: bool = False,
) -> set[SSAVar]:
    # Reads of THIS transaction's field, in every spelling: `txn F`, and `gtxns F` indexed by
    # GroupIndex -- which is what a compiler emits, and what the plain `txn_field_reads` misses, so
    # a guard written the compiled way counted as no guard at all. `_signed_txn_field_reads` also
    # refuses an unpinned `gtxn N`, which reads a SIBLING and must never be credited to the signer.
    reads = _signed_txn_field_reads(prog, field, file=file)
    if include_gtxn:
        # Some fields are validated on a SIBLING txn, not the app call itself (e.g.
        # AssetCloseTo on the deposit axfer). Opt-in, so the txn-only detectors
        # (rekey-to, fee, …) keep their app-call-scoped semantics.
        reads = reads + gtxn_field_reads(prog, field, file=file)
    return ssavar_outputs(reads)




def _global_field_seeds(
    prog: SSAProgram, gfield: str, *, file: Optional[str] = None,
) -> set[SSAVar]:
    return ssavar_outputs(global_field_reads(prog, gfield, file=file))




def approval_exit_protected_for_field(
    prog: SSAProgram, exit_bb: BasicBlock, field: str,
    *, file: Optional[str] = None, include_gtxn: bool = False,
    safe: Optional[str] = None,
) -> bool:
    """``exit_bb`` is protected for ``txn FIELD``; ``include_gtxn`` also seeds
    ``gtxn``/``gtxns`` reads, for fields validated on a sibling group txn."""
    if file is None:
        file = exit_bb.file
    return _approval_exit_protected_for_seeds(
        prog, exit_bb,
        _txn_field_seeds(prog, field, file=file, include_gtxn=include_gtxn),
        file=file, safe=safe,
    )


def approval_exit_protected_for_arg_reads(
    prog: SSAProgram, exit_bb: BasicBlock, immediates: str,
    *, file: Optional[str] = None,
) -> bool:
    """Protected for a ``txna`` array read, such as the ABI method selector.

    Unlike the path-predicate shortcut used for constant router edges, this
    accepts a dynamically computed expected value only when the comparison is
    actually enforced on every path to ``exit_bb`` AND the expected value is
    one the caller cannot choose (a constant or :data:`_NON_CALLER_VALUE_OPS`
    provenance) — ``ApplicationArgs 0 == ApplicationArgs 1`` is enforced and
    gates nothing.
    """
    if file is None:
        file = exit_bb.file
    seeds = {
        out for assignment in _txna_reads(prog, immediates, file=file)
        for out in assignment.outputs if isinstance(out, SSAVar)
    }
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, seeds, file=file, allow_unary_cmp=True,
        trusted_other=_non_caller_value_seeds(prog, file=file),
    )




def approval_exit_protected_for_global_field(
    prog: SSAProgram, exit_bb: BasicBlock, gfield: str,
    *, file: Optional[str] = None, safe: Optional[str] = None,
) -> bool:
    """Protected for ``global GFIELD`` (e.g. ``GroupSize``) rather than a txn field."""
    if file is None:
        file = exit_bb.file
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, _global_field_seeds(prog, gfield, file=file), file=file,
        safe=safe,
    )




def approval_exit_protected_for_any_txn_field(
    prog: SSAProgram, exit_bb: BasicBlock, fields: list[str],
    *, file: Optional[str] = None,
) -> bool:
    """Protected if ANY of ``fields`` is enforced on every path (``TypeEnum`` or
    ``Type`` both count as pinning the txn type)."""
    if file is None:
        file = exit_bb.file
    seeds: set[SSAVar] = set()
    for f in fields:
        seeds |= _txn_field_seeds(prog, f, file=file)
    return _approval_exit_protected_for_seeds(prog, exit_bb, seeds, file=file)
