"""Sender==creator and OnCompletion action guards from path predicates."""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.cfg.exits import verdict_operand
from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa.producers import (is_current_sender_var,
                                            is_fixed_caller_app_pin,
                                            is_group_signer_var)
from tealql.tealtools.ssa import (Assignment, BasicBlock, Phi, SSAProgram,
                                  SSAVar, const_int, is_field_var)

from tealql.tealtools.analysis.guard_coverage import (
    NO_COVERAGE, OPAQUE, Coverage, CoverageWalker,
)

from ._value_flow import (_constant_facts_cached, cached_path_predicates,
                          resolve_through_copies)



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


def _is_trusted_address(prog: Optional[SSAProgram], var) -> bool:
    """Shared writer provenance; stored authority retains explicit premises."""
    if prog is None:
        return is_field_var(var, 'global', 'CreatorAddress')
    from tealql.tealtools.analysis.authority import authority_for
    return authority_for(prog).address(var).preserved


def _is_signer_principal(prog: Optional[SSAProgram], var) -> bool:
    """See :meth:`AuthorityAnalysis.signer_principal` (shape only; callers
    also require :func:`_is_trusted_address`)."""
    if prog is None:
        return is_field_var(var, 'global', 'CreatorAddress')
    from tealql.tealtools.analysis.authority import authority_for
    return authority_for(prog).signer_principal(var)


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
    """``cmp.op`` (``"=="`` or ``"!="``) when ``cmp`` compares ``txn Sender`` —
    or the sender of a fixed-position group member (``gtxn K Sender``: its
    signature covers the group id, so a trusted signer approved this call) —
    against a :func:`_is_trusted_address`, or pins ``global
    CallerApplicationID`` to a non-zero constant; else ``None``.

    Both spellings occur in the wild — ``==; assert`` and ``!=; bnz reject`` —
    and each is a guard only under the right POLARITY, so the caller must see
    which op it got rather than a collapsed boolean."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = (_guard_operand(prog, value) for value in cmp.inputs)
    if ((is_current_sender_var(a0) and _is_trusted_address(prog, a1))
            or (is_current_sender_var(a1)
                and _is_trusted_address(prog, a0))):
        return cmp.op
    # A fixed-position group member's sender counts (authorisation, not
    # identity): its signature covers the group id, so a trusted signer of
    # ANY member approved this call — see `avm.is_group_signer_read`. Only
    # against a SIGNING PRINCIPAL: an escrow lsig "signs" by its own logic.
    if ((is_group_signer_var(a0) and _is_signer_principal(prog, a1)
         and _is_trusted_address(prog, a1))
            or (is_group_signer_var(a1) and _is_signer_principal(prog, a0)
                and _is_trusted_address(prog, a0))):
        return cmp.op
    # Only the app with this fixed id can be the inner-txn caller.
    if is_fixed_caller_app_pin(a0, a1):
        return cmp.op
    return None


def _is_sender_eq_creator(
    cmp: Assignment, prog: Optional[SSAProgram] = None,
) -> bool:
    """``cmp`` pins ``txn Sender`` to any :func:`_is_trusted_address`, not just creator."""
    return _sender_trusted_cmp(cmp, prog) == "=="


def _disjunction_leaves(prog: SSAProgram, var) -> list:
    """The producing assignments of every NON-``||`` leaf under the ``||`` tree
    rooted at ``var`` (each seen through copies), or ``[]`` when any leaf is not
    a resolvable SSA definition — an unknown arm fails CLOSED, since one free
    arm alone satisfies the disjunction."""
    out: list = []
    seen: set = set()
    stack = [var]
    while stack:
        v = resolve_through_copies(prog, stack.pop())
        if not isinstance(v, SSAVar) or v.defined_by is None:
            return []
        if id(v) in seen:
            continue
        seen.add(id(v))
        d = v.defined_by
        if d.op == "||":
            stack.extend(d.inputs)
            continue
        out.append(d)
    return out


def _leaf_excludes_action(
    prog: SSAProgram, leaf: Assignment, action_int: int,
) -> bool:
    """The ``||`` leaf ``leaf`` being TRUTHY proves ``OnCompletion !=
    action_int`` — decomposed exactly as a taken branch on it would be, so
    every spelling :func:`predicates_exclude_action` knows is recognised."""
    out = leaf.outputs[0] if leaf.outputs else None
    if not isinstance(out, SSAVar):
        return False
    try:
        conds = cached_path_predicates(prog)._decompose_cond(out, taken=True)
    except Exception:
        return False
    return predicates_exclude_action(prog, conds, action_int)


class _SenderPinModel:
    """The SSA spelling of a condition tree for the shared coverage walker
    (:mod:`tealql.tealtools.analysis.guard_coverage`), asking ONE question:
    does a trusted-sender pin hold? Nodes are SSA vars / phis seen through
    proven copies; a comparison pins when :func:`_sender_trusted_cmp` accepts
    it, and the walker owns sense (``==`` must hold / ``!=`` must fail),
    joins (a phi or ``||`` holds only if EVERY live arm pins — ``Sender ==
    creator || Sender == admin`` is a real authorisation, ``|| btoi(arg)`` is
    not) and conjunctions.

    With ``action_int``, a join arm may instead EXCLUDE the action under test
    (dead on every ``action_int`` path): ``assert(Sender == Creator || OC !=
    UpdateApplication)`` forces the pin on every Update path, which is all the
    Update verdict asks. A join of pure exclusions has no live arm and credits
    nothing — an action guard, not an authorisation."""

    def __init__(self, prog: Optional[SSAProgram], action_int: Optional[int] = None):
        self.prog = prog
        self.action_int = action_int

    def _resolve(self, v):
        return resolve_through_copies(self.prog, v) if self.prog is not None else v

    def is_node(self, v) -> bool:
        return isinstance(v, (SSAVar, Phi))

    def definition(self, v):
        r = self._resolve(v)
        if r is not v and self.is_node(r):
            return "copy", None, (r,)
        if isinstance(r, Phi):
            return "phi", None, tuple(r.args)
        d = getattr(r, "defined_by", None)
        if d is None:
            return None, None, ()
        return "op", d.op, tuple(d.inputs)

    def returns(self, v):
        return ()

    def arm_value(self, v):
        r = self._resolve(v)
        k = const_int(r)
        if k is not None:
            return k
        return r if self.is_node(r) else OPAQUE

    def literal_int(self, v):
        return const_int(v)

    def leaf_credit(self, v, op, self_truthy, sender_ok):
        r = _guard_operand(self.prog, v)
        if sender_ok and (is_group_signer_var(r)
                          or is_field_var(r, "global", "CallerApplicationID")):
            # Under a pin `pins_sender` accepted, the pinned side may be a
            # fixed group member's sender or the caller app id (authorisation).
            return Coverage(sender=True)
        return NO_COVERAGE

    def pins_sender(self, v) -> bool:
        d = getattr(self._resolve(v), "defined_by", None)
        return d is not None and _sender_trusted_cmp(d, self.prog) is not None

    def dependent(self, v, state_ok=False) -> bool:
        return False

    def counterpart_ok(self, pinned, other) -> bool:
        return True

    def arm_dead(self, v, sense) -> bool:
        if self.action_int is None or not sense or self.prog is None:
            return False
        d = getattr(self._resolve(v), "defined_by", None)
        return d is not None and _leaf_excludes_action(self.prog, d, self.action_int)


def _sender_pin_holds(
    value, prog: Optional[SSAProgram], sense: bool = True,
    action_int: Optional[int] = None,
) -> bool:
    """A trusted-sender pin holds whenever ``value`` evaluates to ``sense``:
    ``Sender == trusted`` truthy, ``Sender != trusted`` falsy, a ``||`` / phi
    whose every live arm pins (see :class:`_SenderPinModel`). The bare
    disequality and the phi of separately computed pins (PyTeal ``If(c, S ==
    Creator, S == Creator)`` as an ``Assert`` operand) are the same rule."""
    return CoverageWalker(_SenderPinModel(prog, action_int)).cover(value, sense).sender


def _preds_prove_sender_guard(
    prog: SSAProgram, conds, action_int: Optional[int] = None,
) -> bool:
    """``conds`` — a block's entry state, a single CFG EDGE, or an approving
    ``return``'s operand decomposed — proves a sender/trusted-address check
    held: a ``==`` pin TRUTHY (``(V, "nonzero")``), or a ``!=`` pin FALSY
    (``(V, "zero")`` — the disequality failing IS equality holding).

    Takes a raw predicate set so the SAME recogniser serves block entries and
    edges: at a join the entry set is the INTERSECTION over incoming paths,
    which drops a guard proven on only one edge into a shared approve block.

    ``action_int`` admits the action-excluding join arms of
    :class:`_SenderPinModel`."""
    for cond in conds:
        if cond.kind not in ("nonzero", "zero"):
            continue
        if _sender_pin_holds(cond.value, prog, cond.kind == "nonzero", action_int):
            return True
    return False


def sender_creator_guard_dominates(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    bb: BasicBlock,
    action_int: Optional[int] = None,
) -> bool:
    """``bb`` is reached only along paths where a sender/trusted-address check
    held (see :func:`_preds_prove_sender_guard`)."""
    return _preds_prove_sender_guard(
        prog, pp.predicates_at(bb.file, bb.first_line), action_int)


def approving_return_conds(
    prog: SSAProgram, pp: PathPredicateAnalysis, bb: BasicBlock,
) -> frozenset:
    """Predicates that hold whenever ``bb``'s terminating ``return V`` APPROVES:
    an approving exit is an ``assert V`` edge, so ``V`` decomposes exactly like a
    branch condition (``&&``-truthy, ``!``, comparisons). Empty for any block not
    ending in a ``return`` with an operand, and for a constant operand.

    PyTeal ``Return(Txn.sender() == Global.creator_address())`` compiles to
    ``==; return`` — the comparison IS the approval, and reading the exit's
    entry predicates alone calls that guard absent. ``select`` with a constant-0
    arm pins its selector: ``int 0; int 1; C; select; return`` approves only
    when ``C`` is truthy (and with the 0 as the taken arm, only when falsy)."""
    operand = verdict_operand(bb)
    if operand is None:
        return frozenset()
    v = resolve_through_copies(prog, operand)
    truthy = True
    d = getattr(v, "defined_by", None)
    if d is not None and d.op == "select" and len(d.inputs) == 3:
        # TOP-FIRST: inputs = [C, B, A]; result is B when C != 0, else A.
        c, b_arm, a_arm = d.inputs
        if const_int(a_arm) == 0:
            v, truthy = resolve_through_copies(prog, c), True
        elif const_int(b_arm) == 0:
            v, truthy = resolve_through_copies(prog, c), False
    try:
        return pp._decompose_cond(v, taken=truthy)
    except Exception:
        return frozenset()


def _creator_enforcing_bbs(
    prog: SSAProgram, action_int: Optional[int] = None,
) -> set:
    """Blocks holding an ``assert`` (or a branch to a rejection exit) on a sender guard.

    HAZARD: path predicates describe a block's ENTRY state, so the block PERFORMING
    the check never satisfies :func:`sender_creator_guard_dominates` about itself.

    ``action_int`` admits the action-excluding ``||`` leaves of
    :class:`_SenderPinModel`, so the set is then specific to that action."""
    from ._enforcement import _label_to_bb_first_line, branch_reject_polarity
    label_lines = _label_to_bb_first_line(prog)
    out: set = set()
    for a in prog.assignments:
        if a.op not in ("assert", "bnz", "bz") or not a.inputs:
            continue
        if a.basic_block is None:
            continue
        # Sees through copies, an all-trusted `||` tree (finding 2.3), a phi
        # of pins and an action-excluding `||` leaf (2026-10-10 review 9/10).
        # The pin must hold on the SURVIVING side: `assert` keeps the truthy
        # side, a branch the side that does not reject. `assert(Sender !=
        # creator)` and a `!=` rejected on FALSE are ANTI-guards.
        when_true = _sender_pin_holds(a.inputs[0], prog, True, action_int)
        if a.op == "assert":
            if when_true:
                out.add(a.basic_block)
            continue
        when_false = _sender_pin_holds(a.inputs[0], prog, False, action_int)
        if not (when_true or when_false):
            continue
        rejects_false, rejects_true = branch_reject_polarity(prog, a, label_lines)
        if (rejects_false and when_true) or (rejects_true and when_false):
            out.add(a.basic_block)
    return out


def _verdict_pin_arm_edges(prog: SSAProgram, exit_bb: BasicBlock) -> set:
    """``(id(retsub_bb), id(phi_bb))`` for every ``retsub`` arm of the exit's
    verdict PHI whose returned value IS a trusted-sender ``==`` pin, computed
    in that same block.

    ``main: callsub approval_program; return`` with an Update arm `txn Sender;
    global CreatorAddress; ==; retsub` returns ``phi(Sender == Creator, 1)``:
    approving through that arm's edge into the phi's block proves the pin, so
    the EDGE is closed. The arm's block, NOT the edge, would be unsound: the
    same ``retsub`` also lands in other call sites' continuations, where the
    value may be popped. Requiring the comparison in the retsub block itself
    keeps it exact — nothing between the pin and the return can replace it."""
    operand = verdict_operand(exit_bb)
    v = resolve_through_copies(prog, operand) if operand is not None else None
    if not isinstance(v, Phi) or v.basic_block is None:
        return set()
    out: set = set()
    for a in v.args:
        d = getattr(a, "defined_by", None)
        bb = getattr(d, "basic_block", None)
        if (bb is None or not bb.assignments or bb.assignments[-1].op != "retsub"):
            continue
        if _sender_pin_holds(a, prog, True):
            out.add((id(bb), id(v.basic_block)))
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
    enforcing = _creator_enforcing_bbs(prog, action_int)
    # The exit's own `return V` is an `assert V` edge (finding 2.1): approving
    # through it proves V, which may BE the sender check.
    return_conds = approving_return_conds(prog, pp, exit_bb)
    pin_arm_edges = _verdict_pin_arm_edges(prog, exit_bb)

    def _closed(bb: BasicBlock) -> bool:
        # Four ways a path stops mattering: this very block performs the check
        # (entry-state predicates miss it), the check already held on entry,
        # the block cannot be on an ``action_int`` path at all, or the exit's
        # returned value is itself the check.
        return (bb in enforcing
                or sender_creator_guard_dominates(prog, pp, bb, action_int)
                or _block_excludes_action(prog, pp, bb, action_int)
                or (bb is exit_bb
                    and _preds_prove_sender_guard(prog, return_conds, action_int)))

    def _edge_closed(pred: BasicBlock, succ: BasicBlock) -> bool:
        """The EDGE ``pred → succ`` proves this is not an ``action_int`` path,
        or carries the sender check itself.

        HAZARD: this must stay per-EDGE. ``OC == Update; bz done`` leaves an entry
        block that is neither creator-checked nor action-excluded even though BOTH
        its out-edges are fine (one carries ``OC != Update``, the other leads into
        the guard) — reasoning per block reports that dispatch as unguarded. The
        same holds for the guard: ``OC == Update && Sender == Creator; bnz approve``
        proves the check on the TAKEN edge only, and a NoOp path rejoining at
        ``approve`` intersects it away from the block's entry set (finding 2.5)."""
        if (id(pred), id(succ)) in pin_arm_edges:
            return True
        try:
            conds = pp._edge_predicates(pred, succ)
        except Exception:
            return False
        return (predicates_exclude_action(prog, conds, action_int)
                or _preds_prove_sender_guard(prog, conds, action_int))

    # Backward over EDGES via the shared walk: an edge is closed when its
    # predecessor is guarded / action-excluded, or the edge itself excludes the
    # action. Entry detection is the walk's — a one-block always-approve
    # program (the exit IS the entry) and a self-loop entry are both UNGUARDED,
    # which the old predecessor-based spelling silently credited as covered.
    from ._program_shape import unguarded_entry_path_exists
    return not unguarded_entry_path_exists(
        prog, exit_bb,
        block_closed=_closed,
        edge_closed=_edge_closed,
    )




# ---------------------------------------------------------------------------
# OnCompletion guards
# ---------------------------------------------------------------------------


def _is_oncompletion_var(var, prog: Optional[SSAProgram] = None) -> bool:
    """``txn OnCompletion``, or ``gtxns OnCompletion`` indexed by ``txn
    GroupIndex`` — the dynamic-self spelling, the same field (the slot test
    `_signed_txn_field_reads` already applies to the drain fields)."""
    if _is_txn_field_var(var, "OnCompletion"):
        return True
    d = getattr(var, "defined_by", None)
    if (d is None or d.op != "gtxns" or d.immediates.strip() != "OnCompletion"
            or not d.inputs):
        return False
    from tealql.tealtools.cfg.group import relative_slot
    idx = _guard_operand(prog, d.inputs[0]) if prog is not None else d.inputs[0]
    return relative_slot(idx) == "this"




def _oncompletion_eq_const_value(
    cmp: Assignment, prog: Optional[SSAProgram] = None,
) -> Optional[int]:
    """``K`` if ``cmp`` is ``txn OnCompletion (==/!=) <const_K>`` (either operand
    order), for any ``K`` — not just the action under test. Else ``None``."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = (_guard_operand(prog, value) for value in cmp.inputs)
    if _is_oncompletion_var(a0, prog):
        return const_int(a1)
    if _is_oncompletion_var(a1, prog):
        return const_int(a0)
    return None




def _block_excludes_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    bb: BasicBlock,
    action_int: int,
) -> bool:
    """``bb``'s ENTRY state (plus, for a ``return V`` block, the approving
    return's own operand) proves ``OnCompletion != action_int`` — the per-BLOCK
    closure of the action walk.

    The exit's own ``return V`` counts as an ``assert V`` edge (finding 2.1):
    ``txn OnCompletion; !; txn ApplicationID; !; &&; return`` approves ONLY a
    NoOp-on-create call, so the returned conjunction excludes every action."""
    conds = pp.predicates_at(bb.file, bb.first_line)
    conds = conds | approving_return_conds(prog, pp, bb)
    return predicates_exclude_action(prog, conds, action_int)


def approval_exit_guarded_for_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    """Every path to ``exit_bb`` proves ``OnCompletion != action_int`` (guard
    shapes enumerated in :func:`predicates_exclude_action`) — a backward walk
    closing each path on a block whose entry state excludes the action or an
    EDGE that does.

    Deliberately tight: a contract that routes ``OC == K`` to ``err`` is treated as
    guarded, so this under-reports rather than emitting a wrong verdict.

    HAZARD: do NOT read the exit's entry predicates alone. At a join they are
    the INTERSECTION over incoming paths, so ``OC == NoOp; bnz approve; OC ==
    OptIn; bnz approve; err`` proves nothing at ``approve`` even though EVERY
    edge into it excludes Update/Delete — the hand-written shared-approve-label
    router read as updatable, deletable AND (at HIGH) deletable-without-a-funds-
    check. Same per-edge-vs-join class :func:`sender_creator_guard_covers_action`
    already walks; the walk's first probe is the exit block itself, so the old
    intersection answer is still the fast path when it suffices."""
    def _closed(bb: BasicBlock) -> bool:
        return _block_excludes_action(prog, pp, bb, action_int)

    def _edge_closed(pred: BasicBlock, succ: BasicBlock) -> bool:
        try:
            conds = pp._edge_predicates(pred, succ)
        except Exception:
            return False
        return predicates_exclude_action(prog, conds, action_int)

    from ._program_shape import unguarded_entry_path_exists
    return not unguarded_entry_path_exists(
        prog, exit_bb, block_closed=_closed, edge_closed=_edge_closed)


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
        is_oc = _is_oncompletion_var(v, prog)
        if is_oc:
            if cond.kind == "zero" and action_int != 0:
                return True
            if cond.kind == "nonzero" and action_int == 0:
                return True

        # switch / match edge predicates against an OnCompletion-typed key.
        if cond.kind == "eq" and is_oc and cond.args:
            k = const_int(cond.args[0])
            if k is not None and k != action_int:
                return True
        if cond.kind == "not_in_range" and is_oc:
            lo, hi = cond.args
            if isinstance(lo, int) and isinstance(hi, int) and lo <= action_int < hi:
                return True
        if cond.kind == "neq_all" and is_oc:
            for cand in cond.args:
                if const_int(cand) == action_int:
                    return True
        # An ORDERED bound: `OC <= OptIn; assert` admits only NoOp/OptIn.
        # The predicate layer canonicalises the field to the LEFT, so `K`
        # is `args[0]` whichever side it was written on.
        if cond.kind in ("lt", "le", "gt", "ge") and is_oc and cond.args:
            k = const_int(cond.args[0])
            if k is not None and (
                    (cond.kind == "lt" and action_int >= k)
                    or (cond.kind == "le" and action_int > k)
                    or (cond.kind == "gt" and action_int <= k)
                    or (cond.kind == "ge" and action_int < k)):
                return True

        # SSA-level ``V = OC ==/!= K`` whose truth is captured by the predicate.
        if isinstance(v, SSAVar) and v.defined_by is not None:
            a = v.defined_by
            # Truthy `||` of `OC == k_i` leaves is SET-MEMBERSHIP (PyTeal
            # `Or(OC == NoOp, OC == OptIn); bnz handler`): on the surviving
            # edge OC ∈ {k_i}, which excludes every action outside the set.
            # `_decompose_cond` rightly refuses to split a truthy `||`, so the
            # tree is read here; any non-`OC == const` leaf fails CLOSED.
            if a.op == "||" and cond.kind == "nonzero":
                leaves = _disjunction_leaves(prog, v)
                members = [
                    _oncompletion_eq_const_value(leaf, prog) if leaf.op == "==" else None
                    for leaf in leaves
                ]
                if members and all(k is not None for k in members) \
                        and action_int not in members:
                    return True
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
