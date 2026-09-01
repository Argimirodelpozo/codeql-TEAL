"""Sender==creator and OnCompletion action guards from path predicates."""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar, const_int, is_field_var

from ._value_flow import _constant_facts_cached, resolve_through_copies



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




#: State reads that yield an address the CONTRACT controls, not the caller.
_STATE_READ_OPS = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
})


def _is_trusted_address(prog: Optional[SSAProgram], var) -> bool:
    """``var`` holds an address the caller cannot choose, so pinning ``txn Sender``
    against it is a real authorisation check: ``global CreatorAddress``, an ``addr``
    literal, or an ``app_global_get``/``app_local_get`` read (rotatable admin).

    HAZARD: anything the CALLER supplies must NOT qualify — ``Sender == <attacker's
    own value>`` authorises nothing. The trust line is drawn against the single
    :func:`avm.attacker_input_label` table so it cannot drift from a second list."""
    from tealql.tealtools.language.avm import attacker_input_label
    if prog is not None:
        constant = _constant_facts_cached(prog).constant(var)
        if constant is not None:
            return constant.kind == "bytes"
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
    return False


def _guard_operand(prog: Optional[SSAProgram], value):
    """Resolve immutable aliases plus exact scratch/phi copy bridges."""
    if prog is None:
        return value
    facts = _constant_facts_cached(prog)
    value = facts.constant(value) or facts.resolve(value)
    return resolve_through_copies(prog, value)


def _sender_trusted_cmp(
    cmp: Assignment, prog: Optional[SSAProgram] = None,
) -> Optional[str]:
    """``cmp.op`` (``"=="`` or ``"!="``) when ``cmp`` compares ``txn Sender``
    against a :func:`_is_trusted_address`, else ``None``.

    Both spellings occur in the wild — ``==; assert`` and ``!=; bnz reject`` —
    and each is a guard only under the right POLARITY, so the caller must see
    which op it got rather than a collapsed boolean."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = (_guard_operand(prog, value) for value in cmp.inputs)
    if ((_is_txn_field_var(a0, "Sender") and _is_trusted_address(prog, a1))
            or (_is_txn_field_var(a1, "Sender")
                and _is_trusted_address(prog, a0))):
        return cmp.op
    return None


def _is_sender_eq_creator(
    cmp: Assignment, prog: Optional[SSAProgram] = None,
) -> bool:
    """``cmp`` pins ``txn Sender`` to any :func:`_is_trusted_address`, not just creator."""
    return _sender_trusted_cmp(cmp, prog) == "=="




def sender_creator_guard_dominates(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    bb: BasicBlock,
) -> bool:
    """``bb`` is reached only along paths where a sender/trusted-address check
    held: a ``==`` checked TRUTHY (``(V, "nonzero")``), or a ``!=`` checked
    FALSY (``(V, "zero")`` — the disequality failing IS equality holding)."""
    for cond in pp.predicates_at(bb.file, bb.first_line):
        if cond.kind not in ("nonzero", "zero"):
            continue
        # See through a scratch round-trip / value-preserving phi to the real cmp.
        v = resolve_through_copies(prog, cond.value)
        if not isinstance(v, SSAVar) or v.defined_by is None:
            continue
        op = _sender_trusted_cmp(v.defined_by, prog)
        if (op == "==" and cond.kind == "nonzero") or (
                op == "!=" and cond.kind == "zero"):
            return True
    return False


def _creator_enforcing_bbs(prog: SSAProgram) -> set:
    """Blocks holding an ``assert`` (or a branch to a rejection exit) on a sender guard.

    HAZARD: path predicates describe a block's ENTRY state, so the block PERFORMING
    the check never satisfies :func:`sender_creator_guard_dominates` about itself."""
    from ._enforcement import _label_to_bb_first_line, branch_reject_polarity
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
        op = _sender_trusted_cmp(v.defined_by, prog)
        if op is None:
            continue
        if op == "==":
            # `assert` demands the equality; a branch enforces it when EITHER
            # side rejecting leaves only the equality-holding path alive.
            if a.op == "assert":
                out.add(a.basic_block)
                continue
            rejects_false, _ = branch_reject_polarity(prog, a, label_lines)
            if rejects_false:
                out.add(a.basic_block)
            continue
        # `!=`: ONLY a rejection on TRUE proves equality on the surviving path.
        # `assert` (demanding disequality) and reject-on-FALSE are ANTI-guards.
        if a.op in ("bnz", "bz"):
            _, rejects_true = branch_reject_polarity(prog, a, label_lines)
            if rejects_true:
                out.add(a.basic_block)
    return out


def sender_creator_guard_covers_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    """Every path reaching ``exit_bb`` **with ``OnCompletion == action_int``** was
    creator-checked — a backward must-reach walk closing each path on either
    "creator-checked" or "predicates prove ``OnCompletion != action_int``".

    HAZARD: do NOT substitute :func:`sender_creator_guard_dominates` on the exit
    block. Path predicates at a join are the INTERSECTION of incoming paths, so a
    guarded branch REJOINING an unguarded one (the shared return epilogue every
    optimising compiler emits) hides the check and reads as "anyone can update"."""
    enforcing = _creator_enforcing_bbs(prog)

    def _closed(bb: BasicBlock) -> bool:
        # Three ways a path stops mattering: this very block performs the check
        # (entry-state predicates miss it), the check already held on entry, or
        # the block cannot be on an ``action_int`` path at all.
        return (bb in enforcing
                or sender_creator_guard_dominates(prog, pp, bb)
                or approval_exit_guarded_for_action(prog, pp, bb, action_int))

    def _edge_excludes_action(pred: BasicBlock, succ: BasicBlock) -> bool:
        """The EDGE ``pred → succ`` proves this is not an ``action_int`` path.

        HAZARD: this must stay per-EDGE. ``OC == Update; bz done`` leaves an entry
        block that is neither creator-checked nor action-excluded even though BOTH
        its out-edges are fine (one carries ``OC != Update``, the other leads into
        the guard) — reasoning per block reports that dispatch as unguarded."""
        try:
            conds = pp._edge_predicates(pred, succ)
        except Exception:
            return False
        return predicates_exclude_action(prog, conds, action_int)

    # Backward over EDGES via the shared walk: an edge is closed when its
    # predecessor is guarded / action-excluded, or the edge itself excludes the
    # action. Entry detection is the walk's — a one-block always-approve
    # program (the exit IS the entry) and a self-loop entry are both UNGUARDED,
    # which the old predecessor-based spelling silently credited as covered.
    from ._program_shape import unguarded_entry_path_exists
    return not unguarded_entry_path_exists(
        prog, exit_bb,
        block_closed=_closed,
        edge_closed=_edge_excludes_action,
    )




# ---------------------------------------------------------------------------
# OnCompletion guards
# ---------------------------------------------------------------------------


def _is_oncompletion_var(var) -> bool:
    return _is_txn_field_var(var, "OnCompletion")




def _oncompletion_eq_const_value(
    cmp: Assignment, prog: Optional[SSAProgram] = None,
) -> Optional[int]:
    """``K`` if ``cmp`` is ``txn OnCompletion (==/!=) <const_K>`` (either operand
    order), for any ``K`` — not just the action under test. Else ``None``."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = (_guard_operand(prog, value) for value in cmp.inputs)
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
    """Every approving path to ``exit_bb`` proves ``OnCompletion != action_int``
    (guard shapes enumerated in :func:`predicates_exclude_action`).

    Deliberately tight: a contract that routes ``OC == K`` to ``err`` is treated as
    guarded, so this under-reports rather than emitting a wrong verdict."""
    return predicates_exclude_action(
        prog, pp.predicates_at(exit_bb.file, exit_bb.first_line), action_int)


#: Lifecycle actions that can only ever apply to an app that ALREADY exists.
_EXISTING_APP_ACTIONS = frozenset({ONC_UPDATE_APPLICATION, ONC_DELETE_APPLICATION})


def _is_app_creation_path(prog: SSAProgram, conds) -> bool:
    """``conds`` proves ``txn ApplicationID == 0`` — the txn is CREATING an app.

    Deliberate FP suppression: a create handler does not inspect ``OnCompletion``,
    so its approving exit IS control-flow-reachable with Update/Delete, but the
    action then applies to the brand-new app the caller is creating and already
    controls. The deployed app is never touched.

    BOTH spellings must be recognised: the comparison form (``int 0; ==; bnz``,
    predicate kind ``eq``) and the direct truthiness branch (``bz create`` /
    ``!; bnz create``, kind ``zero``) — the branch form is the COMMONER one in
    deployed contracts, and missing it flagged fully creator-guarded routers
    as updatable by anyone."""
    for cond in conds:
        v = resolve_through_copies(prog, cond.value)
        if not _is_txn_field_var(v, "ApplicationID"):
            continue
        if cond.kind == "zero":
            return True
        if cond.kind == "eq" and cond.args and const_int(cond.args[0]) == 0:
            return True
    return False


def predicates_exclude_action(prog: SSAProgram, conds, action_int: int) -> bool:
    """``conds`` — a block's entry state or a single CFG EDGE — proves the path
    cannot perform ``action_int``. Recognises direct ``OC ==/!= K`` comparisons,
    truth constraints on the OC field var, and switch/match dispatch edges.

    Takes a raw predicate set (not a block) so it can be applied per-EDGE: at a
    join the set is the INTERSECTION over incoming paths, which loses exactly the
    branch outcome saying whether a path was an ``action_int`` path at all."""
    # An app-CREATION path cannot update or delete the deployed app, whatever
    # its OnCompletion says — see _is_app_creation_path.
    if action_int in _EXISTING_APP_ACTIONS and _is_app_creation_path(prog, conds):
        return True
    for cond in conds:
        # See through a scratch round-trip / value-preserving phi, or a predicate
        # recorded on a `load` output hides every guard behind one.
        v = resolve_through_copies(prog, cond.value)

        # Case 0: a DIRECT truth constraint on the OnCompletion field var. The
        # asymmetry is load-bearing:
        #   OC == 0 ("zero", from `txn OnCompletion; !; assert`) ⇒ guarded against
        #           every non-zero action.
        #   OC != 0 ("nonzero")                                  ⇒ guards NoOp ONLY;
        #           OC may still be any of 1..5, so NOT Delete/Update.
        if _is_oncompletion_var(v):
            if cond.kind == "zero" and action_int != 0:
                return True
            if cond.kind == "nonzero" and action_int == 0:
                return True

        # switch / match edge predicates against an OnCompletion-typed key.
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

        # SSA-level ``V = OC ==/!= K`` whose truth is captured by the predicate.
        if isinstance(v, SSAVar) and v.defined_by is not None:
            a = v.defined_by
            if a.op in ("==", "!="):
                k = _oncompletion_eq_const_value(a, prog)
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
