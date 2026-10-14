"""sec-guide/abi-method-selector: an approval exit reachable without the ABI method
selector (``txna ApplicationArgs 0``) being checked, so a caller reaches logic the
method table was supposed to gate.

Scoped to programs that actually read the selector. An exit is protected when a
selector comparison (against a value the caller cannot choose) reaches
ENFORCEMENT on every path to it, or when every entry→exit path crosses a block
or edge that either pins the selector to a constant — the ``match m0 m1 …; err``
router shape, where reaching a handler already means the selector matched and
only the fall-through ``err`` rejects an unknown one — or proves ``NumAppArgs
== 0``: a BARE call carries no selector, so there is nothing for the method
table to gate and the exit is dispatched on OnCompletion instead.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import (BasicBlock, SSAProgram, SSAVar, const_int,
                                  is_field_var, operand_const)
from tealql.security._action_guards import (ONC_NOOP, _is_app_creation_path,
                                            approving_return_conds,
                                            predicates_exclude_action)
from tealql.security._approval_exit import _ApprovalExitViolation
from tealql.security._field_protection import approval_exit_protected_for_arg_reads
from tealql.security._program_shape import (_txna_reads, approving_exits,
                                            unguarded_entry_path_exists)
from tealql.security._value_flow import (cached_path_predicates,
                                         resolve_through_copies)

_SELECTOR = "ApplicationArgs 0"


class AbiMethodSelectorViolation(_ApprovalExitViolation):
    message = ('is reachable without validating the ABI method selector (txna ApplicationArgs 0) — unrecognised methods are not rejected.')


class AbiMethodSelectorDetector:
    name = "sec-guide/abi-method-selector"
    applies_to = frozenset({"app"})  # ABI dispatch is app-only

    def __init__(
        self,
        prog: SSAProgram,
        *,
        path_predicates: Optional[PathPredicateAnalysis] = None,
        file: Optional[str] = None,
    ):
        self.prog = prog
        self.file = file
        self._pp = path_predicates
        self._selector_vars = {
            out for a in _txna_reads(prog, _SELECTOR, file=file)
            for out in a.outputs if isinstance(out, SSAVar)
        }

    @property
    def pp(self) -> PathPredicateAnalysis:
        if self._pp is None:
            self._pp = cached_path_predicates(self.prog)
        return self._pp

    def _selector_pinned(self, conds) -> bool:
        """``conds`` pins the selector to a constant, so a path carrying them is
        reachable only with a matched selector, not an arbitrary one."""
        for cond in conds:
            # See through a scratch round-trip / value-preserving phi — a
            # predicate recorded on a `load` output hides every guard behind
            # one (the documented consumer contract in `_value_flow`).
            v = resolve_through_copies(self.prog, cond.value)
            # match / switch target edge: (selector, "eq", (K,))
            if (cond.kind == "eq" and v in self._selector_vars
                    and cond.args and operand_const(cond.args[0]) is not None):
                return True
            # `selector == K; bnz handler`: (cmp_result, "nonzero") where the cmp
            # is the selector against a constant.
            if cond.kind == "nonzero" and isinstance(v, SSAVar) \
                    and v.defined_by is not None and v.defined_by.op == "==" \
                    and len(v.defined_by.inputs) == 2:
                x, y = (resolve_through_copies(self.prog, i)
                        for i in v.defined_by.inputs)
                if (x in self._selector_vars and operand_const(y) is not None) or \
                   (y in self._selector_vars and operand_const(x) is not None):
                    return True
        return False

    def _no_app_args(self, conds) -> bool:
        """``conds`` proves ``txn NumAppArgs == 0`` — a BARE call, which has no
        ``ApplicationArgs 0`` to check. Every ARC4 compiler dispatches bare
        handlers under exactly this test (PuyaPy ``txn NumAppArgs; bz
        main_bare_routing``, PyTeal ``NumAppArgs == 0; bnz``); reading only
        selector-shaped evidence flagged every compiler-emitted bare create /
        creator-guarded update handler on mainnet."""
        for cond in conds:
            v = resolve_through_copies(self.prog, cond.value)
            if is_field_var(v, "txn", "NumAppArgs"):
                if cond.kind == "zero":
                    return True
                if cond.kind in ("eq", "le") and cond.args \
                        and const_int(cond.args[0]) == 0:
                    return True
                if cond.kind == "lt" and cond.args and const_int(cond.args[0]) == 1:
                    return True
                continue
            # SSA-level `V = NumAppArgs ==/!= 0` captured by truth.
            d = getattr(v, "defined_by", None)
            if d is None or d.op not in ("==", "!=") or len(d.inputs) != 2:
                continue
            a0, a1 = (resolve_through_copies(self.prog, i) for i in d.inputs)
            k = None
            if is_field_var(a0, "txn", "NumAppArgs"):
                k = const_int(a1)
            elif is_field_var(a1, "txn", "NumAppArgs"):
                k = const_int(a0)
            if k != 0:
                continue
            if (d.op == "==" and cond.kind == "nonzero") or (
                    d.op == "!=" and cond.kind == "zero"):
                return True
        return False

    def _lifecycle_path(self, conds) -> bool:
        """``conds`` proves the call is not a method call at all: the app is
        being CREATED (``txn ApplicationID == 0``), or ``OnCompletion != NoOp``
        (an OptIn / CloseOut / Update / Delete handler). Neither is reached
        through the method table — pre-ABI routers and ARC4 routers alike
        dispatch these on OnCompletion / creation before (or instead of)
        reading the selector, so an unpinned selector there gates nothing.

        HAZARD: per-EDGE like the other closures. An ABI router that accepts
        a METHOD under OptIn still pins the selector on that path, so this
        only ever widens what the selector/bare tests already close."""
        return (_is_app_creation_path(self.prog, conds)
                or predicates_exclude_action(self.prog, conds, ONC_NOOP))

    def _exit_out_of_scope(self, exit_bb: BasicBlock) -> bool:
        """Every entry→``exit_bb`` path crosses a block entry or an EDGE that
        pins the selector or proves the call bare.

        HAZARD: per-EDGE, not the exit's entry predicates. At a join those are
        the INTERSECTION over incoming paths — a shared epilogue reached from a
        matched method arm AND the bare create arm proves neither there."""
        pp = self.pp
        return_conds = approving_return_conds(self.prog, pp, exit_bb)

        def _conds_close(conds) -> bool:
            return (self._selector_pinned(conds) or self._no_app_args(conds)
                    or self._lifecycle_path(conds))

        def _closed(bb: BasicBlock) -> bool:
            conds = pp.predicates_at(bb.file, bb.first_line)
            if bb is exit_bb:
                conds = conds | return_conds
            return _conds_close(conds)

        def _edge_closed(pred: BasicBlock, succ: BasicBlock) -> bool:
            try:
                conds = pp._edge_predicates(pred, succ)
            except Exception:
                return False
            return _conds_close(conds)

        return not unguarded_entry_path_exists(
            self.prog, exit_bb, block_closed=_closed, edge_closed=_edge_closed)

    def _routes_on_selector(self) -> bool:
        """Some instruction compares ``ApplicationArgs 0`` ITSELF (seen through
        copies) — ``selector == X``/``!=`` or a ``match`` — so the program
        dispatches (or tries to validate) on it and a method table exists for
        an exit to bypass. The counterpart need not be a constant: a selector
        compared against another caller argument is a broken router, which is
        exactly what the detector must still judge.

        HAZARD: READING arg 0 is not routing on it. Pre-ABI apps carry a data
        payload there (a price, a name, ``len(arg0) == 6``); scoping on the
        read flagged every approving exit of such apps as an unchecked method
        selector (123 mainnet FP cells, class ``no-method-dispatch``)."""
        sel = set(self._selector_vars)
        # `btoi(arg0)` routing (Reach / hand-written integer method tags) is
        # dispatch on the selector too.
        for a in self.prog.assignments:
            if (a.op == "btoi" and a.inputs and a.outputs
                    and resolve_through_copies(self.prog, a.inputs[0]) in self._selector_vars):
                sel.update(o for o in a.outputs if isinstance(o, SSAVar))
        for a in self.prog.assignments:
            if self.file is not None and a.location.file != self.file:
                continue
            if a.op == "match":
                if any(resolve_through_copies(self.prog, i) in sel for i in a.inputs):
                    return True
            elif a.op in ("==", "!=", "switch") and a.inputs:
                if any(resolve_through_copies(self.prog, i) in sel for i in a.inputs):
                    return True
        return False

    def detect(self) -> list[AbiMethodSelectorViolation]:
        # A program that never routes on the selector isn't doing method dispatch.
        if not self._selector_vars or not self._routes_on_selector():
            return []
        out: list[AbiMethodSelectorViolation] = []
        for exit_bb in sorted(
            approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if approval_exit_protected_for_arg_reads(
                self.prog, exit_bb, _SELECTOR, file=self.file,
            ):
                continue
            if self._exit_out_of_scope(exit_bb):
                continue           # selector matched, or bare, on every path
            out.append(AbiMethodSelectorViolation(exit_bb))
        return out
