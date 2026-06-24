"""sec-guide/abi-method-selector: unvalidated ABI method dispatch.

An ABI application routes on the method selector in ``txna ApplicationArgs 0`` —
comparing it to each method's 4-byte signature hash and rejecting anything
unrecognised. If an approval exit is reachable *without* the selector being
checked (e.g. a bare ``int 1; return`` fall-through past the dispatch, or a router
that routes but never rejects an unknown selector), a caller can reach application
logic the method table was supposed to gate.

Heuristic (scoped to ABI-shaped apps): only programs that actually read
``txna ApplicationArgs 0`` are considered. For such apps, an approval exit is
protected when EITHER:

  1. **Enforcement** — a selector comparison whose result reaches enforcement
     (assert / branch-to-err) on every path to the exit
     (:func:`common.approval_exit_protected_for_arg_reads`); or
  2. **Matched-selector edge** — the path predicate at the exit proves the
     selector equals a specific constant (the exit is reached only because the
     selector matched a known method). This is the ``txna ApplicationArgs 0;
     match m0 m1 …; err`` router shape (and the ``selector == M; bnz handler``
     shape): reaching a handler means the selector matched, so the handler exit
     is genuinely protected — only the final fall-through ``err`` rejects an
     unknown selector.

Case 2 (path-predicate reasoning, mirroring the OnCompletion match/switch guard
recognition in :func:`common.approval_exit_guarded_for_action`) removes the old
KNOWN IMPRECISION: a correct multi-method router used to have its *handlers*
flagged because reaching a handler via ``match`` didn't count as enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import BasicBlock, SSAProgram, SSAVar, operand_const
from security import common

_SELECTOR = "ApplicationArgs 0"


@dataclass
class AbiMethodSelectorViolation:
    exit_bb: BasicBlock

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
    applies_to = frozenset({"app"})  # ABI dispatch is an application concern

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
            self._pp = PathPredicateAnalysis(self.prog)
        return self._pp

    def _selector_matched_at_exit(self, exit_bb: BasicBlock) -> bool:
        """The path predicate at ``exit_bb`` pins the selector to a constant — the
        exit is reached only because the selector matched a known method (a
        ``match`` target edge, or the truthy edge of ``selector == K``). Such an
        exit is genuinely protected: an attacker cannot reach it with an arbitrary
        selector."""
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
        # Only ABI-shaped apps: if the program never reads the method selector,
        # it isn't doing method dispatch — nothing to validate.
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
                continue                       # reached only on a matched-selector edge
            out.append(AbiMethodSelectorViolation(exit_bb))
        return out
