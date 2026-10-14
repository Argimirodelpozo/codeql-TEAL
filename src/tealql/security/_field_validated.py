"""Shared base for the whole-program field-validation family (today:
asset-close-to), parameterised on field + message over
:func:`field_validated_on_all_paths`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.tealtools.ssa import SSAProgram
from ._field_protection import field_validated_on_all_paths
from ._program_shape import approving_exits, has_instructions


@dataclass
class _FieldValidatedViolation:
    prog: SSAProgram
    message: str = ""

    # The violation is the ABSENCE of a validation, so there is no anchor line.
    file = None
    line = None

    def pretty(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message})"


class _FieldValidatedDetector:
    """Subclasses set ``name``, ``field`` (a tuple — ANY of them being validated
    counts as fixed), ``message``, and optionally ``violation_cls``."""

    name: ClassVar[str]
    field: ClassVar[tuple[str, ...]]
    message: ClassVar[str]
    violation_cls: ClassVar[type] = _FieldValidatedViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def in_scope(self) -> bool:
        """The ABSENCE of a validation is a finding only for a program that
        parsed to instructions AND can approve.

        HAZARD: an empty / fully-unparsed program trivially "lacks" the
        validation — unanalyzable input, not a finding. And the claim is "a
        drain can be APPROVED without the check": a program with no approving
        exit (`int 0; return`, `err`) approves nothing, so the absent check
        protects nothing and is not a finding either."""
        return (has_instructions(self.prog, file=self.file)
                and bool(approving_exits(self.prog, file=self.file)))

    def detect(self) -> list[_FieldValidatedViolation]:
        if not self.in_scope():
            return []
        for f in self.field:
            if field_validated_on_all_paths(self.prog, f, file=self.file):
                return []
        return [self.violation_cls(self.prog, self.message)]
