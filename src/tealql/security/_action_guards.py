"""Sender==creator and OnCompletion action guards, read off path predicates
(switch/match dispatch shapes included).

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar, const_int, is_field_var



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




def _is_sender_eq_creator(cmp: Assignment) -> bool:
    if cmp.op != "==" or len(cmp.inputs) != 2:
        return False
    a0, a1 = cmp.inputs
    return (
        (_is_txn_field_var(a0, "Sender") and _is_global_field_var(a1, "CreatorAddress"))
        or
        (_is_txn_field_var(a1, "Sender") and _is_global_field_var(a0, "CreatorAddress"))
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
        v = cond.value
        if not isinstance(v, SSAVar) or v.defined_by is None:
            continue
        if _is_sender_eq_creator(v.defined_by):
            return True
    return False




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
    for cond in pp.predicates_at(exit_bb.file, exit_bb.first_line):
        v = cond.value

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
