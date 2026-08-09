"""Shared base for the OnCompletion-action lifecycle detector family (is-*,
unprotected-*, timelock-upgrade, delete-funds-check): flag every approving exit
reachable with a given ``OnCompletion`` action but not guarded against it.

A subclass sets ``action``, ``violation_cls``, and ``creator_guard`` — how a
covering ``sender == creator`` check affects the verdict: ``"ignore"``,
``"require_absent"`` (only an unguarded exit is a finding), or
``"require_present"`` (only a creator-guarded action is in scope) — and may
override :meth:`applies` for a program-level precondition.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class _ExitBBViolation:
    """Base carrying the unguarded approval-exit BB; renders
    ``{headline} at exit {file}:{line}{joiner}{detail}``."""

    exit_bb: BasicBlock

    headline: ClassVar[str]
    detail: ClassVar[str]
    joiner: ClassVar[str] = ": "

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Must mirror pretty(): the exit's LAST line.
        return self.exit_bb.last_line

    def pretty(self) -> str:
        return (
            f"{self.headline} at exit {self.exit_bb.file}:"
            f"{self.exit_bb.last_line}{self.joiner}{self.detail}"
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.pretty()})"


class _ApprovalActionGuardDetector:
    name: ClassVar[str]
    action: ClassVar[str]
    violation_cls: ClassVar[type]
    # "ignore" | "require_absent" | "require_present" — see module docstring.
    creator_guard: ClassVar[str] = "ignore"
    applies_to = frozenset({"app"})  # OnCompletion / app lifecycle

    def __init__(
        self,
        prog: SSAProgram,
        *,
        path_predicates: Optional[PathPredicateAnalysis] = None,
        file: Optional[str] = None,
    ):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def applies(self) -> bool:
        """Program-level precondition gate; default always-on."""
        return True

    def detect(self) -> list:
        if not self.applies():
            return []
        out = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_unguarded_for_action(
                self.prog, self.pp, exit_bb, self.action,
            ):
                continue
            if self.creator_guard != "ignore":
                # HAZARD: ask whether the creator check covers every
                # ACTION-CONSISTENT path, NOT whether it dominates the exit — a
                # guard on the Update branch that rejoins the common epilogue
                # dominates nothing, and reads as absent on real contracts.
                dominates = common.sender_creator_guard_covers_action(
                    self.prog, self.pp, exit_bb, self.action,
                )
                if self.creator_guard == "require_absent" and dominates:
                    continue
                if self.creator_guard == "require_present" and not dominates:
                    continue
            out.append(self.violation_cls(exit_bb))
        return out
