"""Shared base for the strict-dominance ``txnFieldValidatedOnAllPaths``
family — asset-close-to, close-remainder-to, tx-type-check.

Each detector is a one-liner over :func:`common.field_validated_on_all_paths`
with a different field name and message. Rather than duplicating the
~40-LoC scaffold three times, the base class here parameterises the
field + message; the concrete detectors are 5-line subclasses.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.tealtools.ssa import SSAProgram
from . import common


@dataclass
class _FieldValidatedViolation:
    prog: SSAProgram
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message})"


class _FieldValidatedDetector:
    """Subclasses set ``name``, ``field`` (single string or tuple — any
    being validated counts as fixed), ``message``, and (optional)
    ``violation_cls`` for naming the dataclass."""

    name: ClassVar[str]
    field: ClassVar[tuple[str, ...]]
    message: ClassVar[str]
    violation_cls: ClassVar[type] = _FieldValidatedViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[_FieldValidatedViolation]:
        # Absence-style check: an empty / fully-unparsed program trivially
        # "lacks" the validation — that is unanalyzable input, not a finding.
        if not common.has_instructions(self.prog, file=self.file):
            return []
        for f in self.field:
            if common.field_validated_on_all_paths(self.prog, f, file=self.file):
                return []
        return [self.violation_cls(self.prog, self.message)]
