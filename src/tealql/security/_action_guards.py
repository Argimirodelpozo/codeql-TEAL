"""Sender==creator and OnCompletion action guards, read off path predicates
(switch/match dispatch shapes included).

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar, const_int, is_field_var

from ._value_flow import resolve_through_copies



# ---------------------------------------------------------------------------
# OnCompletion constants (AVM spec)
# ---------------------------------------------------------------------------


ONC_NOOP = 0


ONC_OPTIN = 1


ONC_CLOSEOUT = 2


ONC_CLEAR_STATE = 3


ONC_UPDATE_APPLICATION = 4


ONC_DELETE_APPLICATION = 5




# ---------------------------------------------------------------------------
# Fee / GroupSize one-shot checks
# ---------------------------------------------------------------------------


def _is_txn_field_var(var, field: str) -> bool:
    return is_field_var(var, "txn", field)




def _is_global_field_var(var, field: str) -> bool:
    return is_field_var(var, "global", field)




#: State reads that yield an address the CONTRACT controls, not the caller.
_STATE_READ_OPS = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
})


def _is_trusted_address(var) -> bool:
    """``var`` holds an address the caller cannot choose, so pinning
    ``txn Sender`` against it is a real authorisation check.

    Three sources qualify:

    * ``global CreatorAddress`` — immutable, the original recognised shape.
    * an ``addr`` literal — hardcoded in the program.
    * an ``app_global_get`` / ``app_local_get`` read — an admin address the
      CONTRACT stores. This is how real Algorand apps do rotatable admin, since
      ``global CreatorAddress`` cannot be changed, and recognising only the
      immutable form is why `unprotected-updatable` fired on 82% of distinct
      mainnet contracts. A v2 app in the probe corpus is exactly this shape::

          label3:                       # OnCompletion == UpdateApplication
              txn Sender
              bytec_3                   # the global key, literally "Creator"
              app_global_get
              ==
              bnz ok
              err                       # everyone else is rejected

    What must NOT qualify is anything the caller supplies —
    ``txna ApplicationArgs k``, ``txn Accounts k``, a group sibling's
    ``Sender`` — since `Sender == <attacker's own value>` authorises nothing.
    Those are exactly the reads :func:`avm.attacker_input_label` names, so the
    trust line is drawn against that one table rather than a second list that
    can drift from it."""
    from tealql.tealtools.avm import attacker_input_label
    a = getattr(var, "defined_by", None)
    if a is None:
        return False
    if a.op == "global" and a.immediates.strip() == "CreatorAddress":
        return True
    if attacker_input_label(a.op, a.immediates or "") is not None:
        return False                      # caller-supplied: authorises nothing
    if a.op in _STATE_READ_OPS:
        return True
    # A hardcoded address literal: `addr AAAA...` (the parser records the
    # decoded bytes as a const), or a pushbytes of one.
    if a.op in ("addr", "byte", "pushbytes") and getattr(var, "const_value", None):
        return True
    return False


def _is_sender_eq_creator(cmp: Assignment) -> bool:
    """``cmp`` pins ``txn Sender`` to an address the caller cannot choose.

    Named for the original creator-only shape it recognised; it now accepts any
    trusted address source (see :func:`_is_trusted_address`)."""
    if cmp.op != "==" or len(cmp.inputs) != 2:
        return False
    a0, a1 = cmp.inputs
    return (
        (_is_txn_field_var(a0, "Sender") and _is_trusted_address(a1))
        or
        (_is_txn_field_var(a1, "Sender") and _is_trusted_address(a0))
    )




def sender_creator_guard_dominates(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    bb: BasicBlock,
) -> bool:
    """``bb`` is reached only along paths where ``txn Sender == global
    CreatorAddress`` was checked truthy.

    We read this off path predicates: if ``bb``'s path predicates
    include ``(V, "nonzero")`` for some SSAVar ``V`` produced by an
    ``==`` op consuming ``txn Sender`` and ``global CreatorAddress``,
    the guard dominates."""
    for cond in pp.predicates_at(bb.file, bb.first_line):
        if cond.kind != "nonzero":
            continue
        # See through a scratch round-trip / value-preserving phi to the
        # comparison the predicate really carries.
        v = resolve_through_copies(prog, cond.value)
        if not isinstance(v, SSAVar) or v.defined_by is None:
            continue
        if _is_sender_eq_creator(v.defined_by):
            return True
    return False


def _creator_enforcing_bbs(prog: SSAProgram) -> set:
    """Blocks that ENFORCE ``txn Sender == global CreatorAddress`` — the block
    holding an ``assert`` (or a branch to a rejection exit) whose condition is
    that comparison.

    Needed because path predicates describe what holds on ENTRY to a block, so
    the block performing the check never satisfies
    :func:`sender_creator_guard_dominates` about itself."""
    from ._enforcement import _label_to_bb_first_line, branch_gates_rejection
    label_lines = _label_to_bb_first_line(prog)
    out: set = set()
    for a in prog.assignments:
        if a.op not in ("assert", "bnz", "bz") or not a.inputs:
            continue
        if a.basic_block is None:
            continue
        v = resolve_through_copies(prog, a.inputs[0])
        if not isinstance(v, SSAVar) or v.defined_by is None:
            continue
        if not _is_sender_eq_creator(v.defined_by):
            continue
        if a.op == "assert" or branch_gates_rejection(prog, a, label_lines):
            out.add(a.basic_block)
    return out


def sender_creator_guard_covers_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    """Every path reaching ``exit_bb`` **with ``OnCompletion == action_int``**
    was creator-checked.

    :func:`sender_creator_guard_dominates` asks the same question of the exit
    block alone, which is too strong the moment the guarded branch REJOINS the
    unguarded one:

    .. code-block:: text

        txn OnCompletion; int UpdateApplication; ==; bz done
        txn Sender; global CreatorAddress; ==; assert   # only the Update path
        done:                                           # ...and both paths
        int 1; return                                   #    share this exit

    Path predicates at a join are the INTERSECTION of the incoming paths, so the
    creator check is invisible at ``done`` and the contract reads "updatable by
    anyone" — on 82% of distinct real mainnet contracts, at HIGH severity. A
    shared return epilogue is what every optimising compiler emits (this repo
    lifts one specially, see ``to_puya_ir._duplicate_shared_epilogues``); the
    same guard given its own exit block was recognised fine.

    So walk BACKWARD from the exit instead and close each path on either
    condition that makes it harmless: it was creator-checked, or its predicates
    already prove ``OnCompletion != action_int`` (so it is not an Update path at
    all). Reaching a program entry with neither witnesses a genuinely unguarded
    Update path. Same must-reach shape as
    ``_field_protection._all_entry_paths_cross``, with the action-consistency
    escape added."""
    enforcing = _creator_enforcing_bbs(prog)

    def _closed(bb: BasicBlock) -> bool:
        # Three ways a path stops mattering: the check already held on entry,
        # this very block performs it (path predicates describe a block's ENTRY
        # state, so the block CONTAINING the `assert` is not covered by the
        # first test), or the block cannot be on an ``action_int`` path at all.
        return (bb in enforcing
                or sender_creator_guard_dominates(prog, pp, bb)
                or approval_exit_guarded_for_action(prog, pp, bb, action_int))

    def _edge_excludes_action(pred: BasicBlock, succ: BasicBlock) -> bool:
        """The EDGE ``pred → succ`` proves this is not an ``action_int`` path.

        Reasoning per block instead of per edge is what makes the classic
        one-branch dispatch look unguarded: ``OC == Update; bz done`` leaves an
        entry block that is neither creator-checked nor action-excluded, yet
        BOTH its outgoing edges are fine — the taken edge carries ``OC !=
        Update`` and the fall-through leads into the guard. Blocks cannot
        express that; edges can."""
        try:
            conds = pp._edge_predicates(pred, succ)
        except Exception:
            return False
        return predicates_exclude_action(prog, conds, action_int)

    if _closed(exit_bb):
        return True
    # Backward over EDGES. An edge is closed when its predecessor is guarded /
    # action-excluded, or the edge itself excludes the action.
    visited: set = set()
    stack: list = [exit_bb]
    seen_blocks: set = {exit_bb}
    while stack:
        bb = stack.pop()
        for pred in bb.predecessors:
            if (id(pred), id(bb)) in visited:
                continue
            visited.add((id(pred), id(bb)))
            if _edge_excludes_action(pred, bb) or _closed(pred):
                continue
            if not pred.predecessors:
                return False        # an entry reached with neither -> unguarded
            if pred not in seen_blocks:
                seen_blocks.add(pred)
                stack.append(pred)
    return True




# ---------------------------------------------------------------------------
# OnCompletion guards
# ---------------------------------------------------------------------------


def _is_oncompletion_var(var) -> bool:
    return _is_txn_field_var(var, "OnCompletion")




def _oncompletion_eq_const_value(cmp: Assignment) -> Optional[int]:
    """If ``cmp`` is ``txn OnCompletion (==/!=) <const_K>`` (operands in
    either order), return ``K``. Otherwise ``None``. Used by the
    extended OC-guard analysis to recognise ``OC == K`` (or ``!= K``)
    for any ``K``, not just for the action under test."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = cmp.inputs
    if _is_oncompletion_var(a0):
        return const_int(a1)
    if _is_oncompletion_var(a1):
        return const_int(a0)
    return None




def approval_exit_guarded_for_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    """Every approving path to ``exit_bb`` proves ``OnCompletion !=
    action_int``.

    Recognised guard shapes (broader than a plain OnCompletion equality
    guard):

    1. **Direct equality / inequality** with the action under test:
       - ``V = OC == action_int``, on a path where V is false → guarded.
       - ``V = OC != action_int``, on a path where V is true → guarded.

    2. **Equality with some other constant K**:
       - ``V = OC == K``, on a path where V is true → ``OC == K`` →
         ``OC != action_int`` whenever ``K != action_int``. This is what
         catches ``bnz`` dispatch tables (``OC == 0; bnz handle_noop``
         → at handle_noop, ``OC == 0`` → guarded against any non-0 action).
       - Symmetric: ``V = OC != K``, V is false → ``OC == K`` → guarded
         when ``K != action_int``.

    3. **Switch dispatch on OnCompletion** (``txn OnCompletion; switch
       handler_0 handler_1 ...``):
       - On a target edge: predicate ``(OC, "eq", (Const(int, str(K)),))``
         → ``OC == K`` → guarded when ``K != action``.
       - On the fall-through edge: ``(OC, "not_in_range", (lo, hi))``
         → ``OC ∉ [lo, hi)``. Guarded when ``action ∈ [lo, hi)`` (the
         action would have routed to a target, but execution reached
         the fall-through, so OC isn't action).

    4. **Match dispatch on OnCompletion** (``... candidates ...; txn
       OnCompletion; match h0 h1 ...``):
       - On a target edge: predicate ``(OC, "eq", (candidate,))`` →
         ``OC == candidate``. Guarded when the candidate resolves to a
         const ``K != action``.
       - On the fall-through edge: ``(OC, "neq_all", (c0, c1, …))``.
         Guarded when any candidate resolves to ``action`` (the action
         would have matched but didn't, so OC isn't action).

    A plain OnCompletion equality guard only models case 1; everything
    else is a deliberate enhancement (real Algorand routers / Puya
    output use ``match`` dispatch on OC). This is deliberately tight —
    contracts that actually route OC=K to err are not flagged here."""
    return predicates_exclude_action(
        prog, pp.predicates_at(exit_bb.file, exit_bb.first_line), action_int)


def predicates_exclude_action(prog: SSAProgram, conds, action_int: int) -> bool:
    """``conds`` (a predicate set from anywhere — a block's entry state or a
    single CFG EDGE) proves ``OnCompletion != action_int``.

    Factored out of :func:`approval_exit_guarded_for_action` so the same case
    analysis can be applied per-edge: at a join block the predicate set is the
    INTERSECTION over incoming paths, which loses exactly the branch outcome
    that says whether a given path was an ``action_int`` path at all."""
    for cond in conds:
        # See through a scratch round-trip / value-preserving phi (a predicate
        # recorded on a `load` output or a phi hid every guard behind one).
        v = resolve_through_copies(prog, cond.value)

        # Case 0: a DIRECT truth constraint on the OnCompletion field var itself.
        # `txn OnCompletion; !; assert` (the NoOp-only idiom Puya emits, often
        # folded into `(OC == 0) && …`) leaves `(OC, "zero")` — OC == 0 — at the
        # guarded exit; `txn OnCompletion; assert` leaves `(OC, "nonzero")`.
        #   OC == 0  ⇒ guarded against any non-zero action (DeleteApplication=5,
        #              UpdateApplication=4, …).
        #   OC != 0  ⇒ guarded against the NoOp action (0) only (it could still be
        #              any of 1..5, so it does NOT guard Delete/Update).
        if _is_oncompletion_var(v):
            if cond.kind == "zero" and action_int != 0:
                return True
            if cond.kind == "nonzero" and action_int == 0:
                return True

        # Case 3 + 4: switch / match edge predicates against an
        # OnCompletion-typed key.
        if cond.kind == "eq" and _is_oncompletion_var(v) and cond.args:
            k = const_int(cond.args[0])
            if k is not None and k != action_int:
                return True
        if cond.kind == "not_in_range" and _is_oncompletion_var(v):
            lo, hi = cond.args
            if isinstance(lo, int) and isinstance(hi, int) and lo <= action_int < hi:
                return True
        if cond.kind == "neq_all" and _is_oncompletion_var(v):
            for cand in cond.args:
                if const_int(cand) == action_int:
                    return True

        # Cases 1 + 2: SSA-level recognition of ``V = OC ==/!= K``
        # whose truth/falsity is captured by the path predicate.
        if isinstance(v, SSAVar) and v.defined_by is not None:
            a = v.defined_by
            if a.op in ("==", "!="):
                k = _oncompletion_eq_const_value(a)
                if k is not None:
                    if a.op == "==":
                        # V is (OC == K). nonzero ⇒ OC == K. zero ⇒ OC != K.
                        if cond.kind == "nonzero" and k != action_int:
                            return True
                        if cond.kind == "zero" and k == action_int:
                            return True
                    else:  # "!="
                        # V is (OC != K). nonzero ⇒ OC != K. zero ⇒ OC == K.
                        if cond.kind == "nonzero" and k == action_int:
                            return True
                        if cond.kind == "zero" and k != action_int:
                            return True
    return False




def approval_exit_unguarded_for_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    return not approval_exit_guarded_for_action(prog, pp, exit_bb, action_int)
