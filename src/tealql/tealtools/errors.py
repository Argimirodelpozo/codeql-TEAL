"""Typed exceptions + parse diagnostics for the TealQL pipeline.

One base class — :class:`TealQLError` — so a tool boundary catches every
*expected* pipeline failure in one clause while genuine bugs still surface as
tracebacks; the target errors also inherit the builtin they used to be
(``ValueError`` / ``FileNotFoundError``).

HAZARD: the parser DROPS spans it cannot parse, so a non-empty
:class:`ParseDiagnostic` list means the program is only PARTIALLY parsed and
every downstream result may be INCOMPLETE — never report such a contract as
clean. Diagnostics ride the graph (``g.graph["parse_diagnostics"]``) and
surface as :attr:`SSAProgram.parse_diagnostics`; strict callers raise
:class:`TealParseError` instead of proceeding.
"""
from __future__ import annotations

from dataclasses import dataclass


class TealQLError(Exception):
    """Base for every expected TealQL failure — catching it at a tool boundary
    separates user-facing errors from bugs."""


class TargetError(TealQLError, ValueError):
    """The target exists but is not analyzable TEAL (e.g. a non-``.teal`` file)."""


class TargetNotFoundError(TealQLError, FileNotFoundError):
    """The target does not exist, or a directory target holds no ``.teal`` files."""


@dataclass(frozen=True)
class ParseDiagnostic:
    """One span of source the TEAL grammar could not parse (a tree-sitter ``ERROR``
    node) and that was therefore DROPPED from analysis."""

    file: str
    start_line: int
    end_line: int
    snippet: str

    def __str__(self) -> str:
        where = (f"{self.file}:{self.start_line}"
                 if self.start_line == self.end_line
                 else f"{self.file}:{self.start_line}-{self.end_line}")
        return f"{where}: unparsed TEAL: {self.snippet!r}"


class TealParseError(TealQLError):
    """Strict-mode failure: the source has unparsed spans, so analysis would run on
    a partial program."""

    def __init__(self, diagnostics: tuple[ParseDiagnostic, ...]):
        self.diagnostics = tuple(diagnostics)
        n = len(self.diagnostics)
        first = f" (first: {self.diagnostics[0]})" if self.diagnostics else ""
        super().__init__(
            f"{n} unparsed TEAL span(s) — refusing to analyze a partial "
            f"program in strict mode{first}"
        )


class LiftError(TealQLError):
    """The Puya-IR lift failed; ``stage`` names where (``build`` = SSA→pre-IR,
    ``lower`` = pre-IR→puya.ir, ``optimize``, ``backend`` = destructure→MIR→TEAL)
    and the underlying puya exception is chained on ``__cause__``.

    HAZARD: this is the ONE type callers may treat as an expected coverage gap
    (~0.1% of mainnet contracts don't lift) and fall back on. A NON-``LiftError``
    escaping the lift is a genuine bug and must not be swallowed."""

    def __init__(self, message: str, *, stage: str = "lift"):
        self.stage = stage
        super().__init__(f"[{stage}] {message}")
