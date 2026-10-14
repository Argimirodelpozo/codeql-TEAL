"""sec-guide/delete-funds-check: an approval exit reachable with ``OnCompletion ==
DeleteApplication`` whose paths carry no genuine balance-vs-min-balance check, the
canonical "are the funds out?" guard before a delete.

Two shapes are balance handling too, so the exit is out of scope:

* every path to the exit DRAINS the app first — an inner ``itxn_field
  CloseRemainderTo`` (a successful ALGO close-out also proves every asset
  holding was closed, or the close fails) — 67 mainnet FP cells, class
  ``delete-drains-first``;
* the app account can never move funds (no ``itxn_submit``; TEAL < 5 has none) AND
  the delete is gated to an authority: deletion strands nothing the app could
  have spent. An OPEN delete of such an app stays reported — it can still
  strand an lsig escrow that requires this app's call (54 cells, class
  ``app-cannot-move-funds``, every one gated; the open twins are labelled TP).
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import (BasicBlock, SSAProgram, SSAVar, const_int,
                                  operand_const)
from tealql.security._action_guards import (ONC_DELETE_APPLICATION,
                                           sender_creator_guard_covers_action)
from tealql.security._approval_action_guard import (
    _ApprovalActionGuardDetector,
    _ExitBBViolation,
)
from tealql.security._enforcement import _label_to_bb_first_line, scratch_forward_map
from tealql.security._field_protection import _collect_field_enforcement_bbs
from tealql.security._program_shape import file_match
from tealql.security._value_flow import (_operand_flows_from_field_var,
                                         resolve_through_copies)


_TIE_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "-",
    "b==", "b!=", "b<", "b>", "b<=", "b>=", "b-",
})


class DeleteFundsCheckViolation(_ExitBBViolation):
    headline = "Application handles DeleteApplication"
    joiner = " without checking balance == min_balance — "
    detail = "funds may be locked permanently on deletion."


def _same_account(prog: SSAProgram, a, b) -> bool:
    """``a`` and ``b`` provably name the same account: one SSA value (seen
    through copies), equal constants, or the same operand-free read of this
    transaction (``global CurrentApplicationAddress``, ``txn Sender``)."""
    a, b = resolve_through_copies(prog, a), resolve_through_copies(prog, b)
    if a is b:
        return True
    ka, kb = operand_const(a), operand_const(b)
    if ka is not None or kb is not None:
        return (ka is not None and kb is not None
                and (ka.kind, ka.value) == (kb.kind, kb.value))
    da, db = getattr(a, "defined_by", None), getattr(b, "defined_by", None)
    return (da is not None and db is not None and not da.inputs and not db.inputs
            and da.op == db.op and da.op in ("global", "txn")
            and da.immediates.strip() == db.immediates.strip())


def _funds_check_gates(
    prog: SSAProgram, file: Optional[str] = None,
) -> set:
    """Blocks ENFORCING a genuine funds check: ``balance`` and ``min_balance``
    OF THE SAME ACCOUNT flow into the same comparison or subtraction, one on
    each side, and that result reaches an enforcement sink. Empty when no such
    tie exists.

    HAZARD: opcode presence is not enough. Two unrelated uses — ``min_balance``
    of one account, ``balance`` of another — enforce nothing even when
    compared (``balance(app) >= min_balance(Sender)`` says nothing about the
    app's own funds), and a tie whose result is dropped (``pop``) is no check
    either."""
    def _reads(op_name):
        return [a for a in prog.assignments
                if a.op == op_name and a.inputs and file_match(a.location.file, file)
                and a.outputs and isinstance(a.outputs[0], SSAVar)]

    pairs = [({b.outputs[0]}, {m.outputs[0]})
             for b in _reads("balance") for m in _reads("min_balance")
             if _same_account(prog, b.inputs[0], m.inputs[0])]
    gates: set = set()
    if not pairs:
        return gates

    def _tied(op) -> bool:
        # balance on one side, min_balance of the SAME account on the other.
        if len(op.inputs) != 2:
            return False
        x, y = op.inputs
        return any(
            (_operand_flows_from_field_var(prog, x, bal)
                and _operand_flows_from_field_var(prog, y, mb))
            or (_operand_flows_from_field_var(prog, y, bal)
                and _operand_flows_from_field_var(prog, x, mb))
            for bal, mb in pairs)

    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for op in prog.assignments:
        if op.op not in _TIE_OPS or not file_match(op.location.file, file):
            continue
        if not op.outputs or not isinstance(op.outputs[0], SSAVar) or not _tied(op):
            continue
        _collect_field_enforcement_bbs(
            prog, op.outputs[0], label_lines, gates, set(), scratch_fwd)
    return gates


def _closeout_blocks(prog: SSAProgram, file: Optional[str] = None) -> set:
    """Blocks setting an inner ``CloseRemainderTo`` to a non-constant-zero
    target, in a program that submits inner transactions. A path crossing one
    closes the app's ALGO account before it can approve (an account still
    holding assets cannot close, so the close-out also proves the assets went)."""
    if not any(a.op == "itxn_submit" for a in prog.assignments):
        return set()
    out: set = set()
    for a in prog.assignments:
        if (a.op != "itxn_field" or a.immediates.strip() != "CloseRemainderTo"
                or a.basic_block is None or not file_match(a.location.file, file)):
            continue
        k = operand_const(resolve_through_copies(prog, a.inputs[0])) if a.inputs else None
        if k is not None and _is_zero_address(k):
            continue
        out.add(a.basic_block)
    return out


def _is_zero_address(k) -> bool:
    if k.kind != "bytes":
        return False
    try:
        raw = bytes.fromhex(k.value.removeprefix("0x"))
    except ValueError:
        return False
    return len(raw) == 32 and not any(raw)


def _is_app_balance(prog: SSAProgram, v) -> bool:
    d = getattr(resolve_through_copies(prog, v), "defined_by", None)
    if d is None or d.op != "balance" or not d.inputs:
        return False
    acct = getattr(resolve_through_copies(prog, d.inputs[0]), "defined_by", None)
    return (acct is not None and acct.op == "global"
            and acct.immediates.strip() == "CurrentApplicationAddress")


def _proves_app_balance_zero(prog: SSAProgram, conds) -> bool:
    """``conds`` (one CFG edge) proves ``balance(CurrentApplicationAddress) ==
    0`` — the skip edge of ``balance != 0; bz done`` around a close-out: an
    empty account has nothing to strand."""
    for cond in conds:
        v = resolve_through_copies(prog, cond.value)
        if _is_app_balance(prog, v):
            if cond.kind == "zero" or (cond.kind == "eq" and cond.args
                                       and const_int(cond.args[0]) == 0):
                return True
            continue
        d = getattr(v, "defined_by", None)
        if d is None or d.op not in ("==", "!=") or len(d.inputs) != 2:
            continue
        x, y = d.inputs
        if not ((_is_app_balance(prog, x) and const_int(y) == 0)
                or (_is_app_balance(prog, y) and const_int(x) == 0)):
            continue
        if (d.op == "!=" and cond.kind == "zero") or (d.op == "==" and cond.kind == "nonzero"):
            return True
    return False


def _app_cannot_move_funds(prog: SSAProgram) -> bool:
    """The app account can never send: no ``itxn_submit`` in the program
    (which covers TEAL < 5 — the parser drops opcodes the declared version
    lacks, so a pre-v5 program has none)."""
    return not any(a.op == "itxn_submit" for a in prog.assignments)


class DeleteFundsCheckDetector(_ApprovalActionGuardDetector):
    severity = "high"
    name = "sec-guide/delete-funds-check"
    action = ONC_DELETE_APPLICATION
    violation_cls = DeleteFundsCheckViolation

    def _delete_paths_cross(self, exit_bb: BasicBlock, gates: set) -> bool:
        """Every REALIZABLE entry path to ``exit_bb`` that can carry
        ``OnCompletion == DeleteApplication`` crosses a block of ``gates``. A
        NoOp arm sharing the exit (Puya's single ``itxn_submit; return`` tail)
        need not drain, and a Reach-style shared tail reached through helper
        ``retsub`` fan-out is walked with a return stack."""
        from tealql.security._action_guards import (_block_excludes_action,
                                                    predicates_exclude_action)
        from tealql.security._program_shape import unguarded_entry_path_exists
        prog, pp, act = self.prog, self.pp, self.action

        def _closed(bb):
            return bb in gates or _block_excludes_action(prog, pp, bb, act)

        def _edge_closed(pred, succ):
            try:
                conds = pp._edge_predicates(pred, succ)
            except Exception:
                return False
            return (predicates_exclude_action(prog, conds, act)
                    or _proves_app_balance_zero(prog, conds))

        return not unguarded_entry_path_exists(
            prog, exit_bb, block_closed=_closed, edge_closed=_edge_closed)

    def exit_protected(self, exit_bb: BasicBlock) -> bool:
        """Every entry path to THIS exit crosses an enforced balance/min_balance
        tie. Per-exit, not program-wide: a funds check in the NoOp arm proves
        nothing about a Delete arm that approves without one (finding 1.6, the
        delete-funds-check twin of timelock-upgrade)."""
        gates = getattr(self, "_gates_cache", None)
        if gates is None:
            gates = self._gates_cache = (_funds_check_gates(self.prog, self.file)
                                         | _closeout_blocks(self.prog, self.file))
        if gates and self._delete_paths_cross(exit_bb, gates):
            return True
        return (_app_cannot_move_funds(self.prog)
                and sender_creator_guard_covers_action(
                    self.prog, self.pp, exit_bb, self.action))
