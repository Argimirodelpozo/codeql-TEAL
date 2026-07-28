"""Shared base for the OnCompletion-action lifecycle detector family —
is-updatable, is-deletable, unprotected-updatable, unprotected-deletable,
timelock-upgrade, delete-funds-check.

Each flags every approving exit reachable with a given ``OnCompletion``
action (``UpdateApplication`` / ``DeleteApplication``) that is not guarded
against that action (via :func:`common.approval_exit_unguarded_for_action`).
The constructor and the ``detect()`` loop are identical across the six; a
subclass sets:

  - ``action`` — the ``common.ONC_*`` constant the exit must be unguarded for,
  - ``violation_cls`` — the named per-detector :class:`_ExitBBViolation`,
  - ``creator_guard`` — how a dominating ``sender == creator`` check affects
    the verdict: ``"ignore"`` (is-*), ``"require_absent"`` (unprotected-*:
    only an *unguarded* exit is a finding), or ``"require_present"``
    (timelock-upgrade: only a *creator-guarded* upgrade is in scope), and
  - optionally overrides :meth:`applies` for a program-level precondition
    (timelock-upgrade / delete-funds-check gate on the absence of a genuine
    timelock / funds check).

Per-detector ``Violation`` classes stay in their own module — the registry
(:data:`tealql.security._DETECTION_ORDER`) resolves both detector and violation by
name — and subclass :class:`_ExitBBViolation` for the shared rendering.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import BasicBlock, SSAProgram
from . import common


@dataclass
class _ExitBBViolation:
    """Base for the action-guard exit violations: all carry the single
    unguarded approval-exit BB and render
    ``{headline} at exit {file}:{line}{joiner}{detail}``. Subclasses set
    ``headline`` + ``detail`` (and ``joiner`` when the sentence doesn't use
    the default ``": "`` separator)."""

    exit_bb: BasicBlock

    headline: ClassVar[str]
    detail: ClassVar[str]
    joiner: ClassVar[str] = ": "

    @property
    def file(self) -> str:
        return self.exit_bb.file

    @property
    def line(self) -> int:
        # Structured anchor for machine output (JSON/SARIF/suppressions);
        # mirrors pretty(): the exit's LAST line.
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
        """Program-level precondition gate — default always-on; override for a
        detector that only runs when some check is *absent* (timelock-upgrade,
        delete-funds-check)."""
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
                # Ask whether the creator check covers every ACTION-CONSISTENT
                # path, not merely whether it dominates the exit: a guard on the
                # Update branch that rejoins the common epilogue dominates
                # nothing, and reading it that way flagged most real contracts.
                dominates = common.sender_creator_guard_covers_action(
                    self.prog, self.pp, exit_bb, self.action,
                )
                if self.creator_guard == "require_absent" and dominates:
                    continue
                if self.creator_guard == "require_present" and not dominates:
                    continue
            out.append(self.violation_cls(exit_bb))
        return out
