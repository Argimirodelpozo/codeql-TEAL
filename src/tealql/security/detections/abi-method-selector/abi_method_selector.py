"""sec-guide/abi-method-selector: an approval exit reachable without the ABI method
selector (``txna ApplicationArgs 0``) being checked, so a caller reaches logic the
method table was supposed to gate.

Scoped to programs that actually read the selector. An exit is protected when a
selector comparison reaches ENFORCEMENT on every path to it, or when the exit's
path predicate pins the selector to a constant — the ``match m0 m1 …; err`` router
shape, where reaching a handler already means the selector matched and only the
fall-through ``err`` rejects an unknown one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import BasicBlock, SSAProgram, SSAVar, operand_const
from tealql.security import common

_SELECTOR = "ApplicationArgs 0"


@dataclass
class AbiMethodSelectorViolation:
    exit_bb: BasicBlock

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Must mirror pretty(): the exit's LAST line.
        return self.exit_bb.last_line

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without validating the ABI method selector "
            "(txna ApplicationArgs 0) — unrecognised methods are not rejected."
        )

    def __repr__(self) -> str:
        return f"AbiMethodSelectorViolation({self.pretty()})"


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
            out for a in common._txna_reads(prog, _SELECTOR, file=file)
            for out in a.outputs if isinstance(out, SSAVar)
        }

    @property
    def pp(self) -> PathPredicateAnalysis:
        if self._pp is None:
            self._pp = common.cached_path_predicates(self.prog)
        return self._pp

    def _selector_matched_at_exit(self, exit_bb: BasicBlock) -> bool:
        """The path predicate at ``exit_bb`` pins the selector to a constant, so the
        exit is reachable only with a matched selector, not an arbitrary one."""
        for cond in self.pp.predicates_at(exit_bb.file, exit_bb.first_line):
            v = cond.value
            # match / switch target edge: (selector, "eq", (K,))
            if (cond.kind == "eq" and v in self._selector_vars
                    and cond.args and operand_const(cond.args[0]) is not None):
                return True
            # `selector == K; bnz handler`: (cmp_result, "nonzero") where the cmp
            # is the selector against a constant.
            if cond.kind == "nonzero" and isinstance(v, SSAVar) \
                    and v.defined_by is not None and v.defined_by.op == "==" \
                    and len(v.defined_by.inputs) == 2:
                x, y = v.defined_by.inputs
                if (x in self._selector_vars and operand_const(y) is not None) or \
                   (y in self._selector_vars and operand_const(x) is not None):
                    return True
        return False

    def detect(self) -> list[AbiMethodSelectorViolation]:
        # A program that never reads the selector isn't doing method dispatch.
        if not self._selector_vars:
            return []
        out: list[AbiMethodSelectorViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if common.approval_exit_protected_for_arg_reads(
                self.prog, exit_bb, _SELECTOR, file=self.file,
            ):
                continue
            if self._selector_matched_at_exit(exit_bb):
                continue                       # selector is constrained on every path
            out.append(AbiMethodSelectorViolation(exit_bb))
        return out
