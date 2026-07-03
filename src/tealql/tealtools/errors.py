"""Typed exceptions + parse diagnostics for the TealQL pipeline.

One base class — :class:`TealQLError` — so a CLI (or any embedding tool)
can catch every *expected* failure of the pipeline in one clause and turn
it into a clean message + exit code, while genuine bugs still surface as
ordinary tracebacks.

The target-resolution errors multiply-inherit from the builtin they used
to be (``ValueError`` / ``FileNotFoundError``) so existing callers that
catch the builtins keep working.

:class:`ParseDiagnostic` records a span of TEAL source the grammar could
not parse. The parser DROPS such spans from analysis, so any non-empty
diagnostics list means downstream results may be INCOMPLETE — for a
security scan that is the difference between "clean" and "not actually
analyzed". Diagnostics ride the graph (``g.graph["parse_diagnostics"]``)
and surface as :attr:`SSAProgram.parse_diagnostics`; strict callers raise
:class:`TealParseError` instead of proceeding.
"""
from __future__ import annotations

from dataclasses import dataclass


class TealQLError(Exception):
    """Base for every expected TealQL failure (bad target, unparseable
    source, …). Catching this at a tool boundary separates user-facing
    errors from bugs."""


class TargetError(TealQLError, ValueError):
    """The user-supplied target exists but is not analyzable TEAL
    (e.g. a non-``.teal`` file)."""


class TargetNotFoundError(TealQLError, FileNotFoundError):
    """The user-supplied target does not exist, or a directory target
    contains no ``.teal`` files."""


@dataclass(frozen=True)
class ParseDiagnostic:
    """One span of source the TEAL grammar could not parse (a tree-sitter
    ``ERROR`` node). The span was dropped from analysis. ``snippet`` is the
    first line of the offending text, trimmed."""

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
    """Strict-mode failure: the source contains spans the grammar could not
    parse, so analysis would run on a partial program. Carries the
    :class:`ParseDiagnostic` list."""

    def __init__(self, diagnostics: tuple[ParseDiagnostic, ...]):
        self.diagnostics = tuple(diagnostics)
        n = len(self.diagnostics)
        first = f" (first: {self.diagnostics[0]})" if self.diagnostics else ""
        super().__init__(
            f"{n} unparsed TEAL span(s) — refusing to analyze a partial "
            f"program in strict mode{first}"
        )


class LiftError(TealQLError):
    """The Puya-IR lift failed on this program. ``stage`` names where
    (``"build"`` = SSA→pre-IR, ``"lower"`` = pre-IR→puya.ir, ``"optimize"``,
    ``"backend"`` = destructure→MIR→TEAL). The underlying cause is chained
    (``raise LiftError(...) from e``), so the original puya ``InternalError`` /
    ``TypeError`` / ``KeyError`` is preserved on ``__cause__``.

    This gives callers ONE type to catch — the lift has known reconstruction
    limits (~0.1% of real mainnet contracts don't lift), so a caller
    (``tealql.security.common.ir_lifter``) can treat a ``LiftError`` as an expected
    coverage gap and fall back, while a NON-``LiftError`` escaping the lift is
    a genuine bug that should not be swallowed."""

    def __init__(self, message: str, *, stage: str = "lift"):
        self.stage = stage
        super().__init__(f"[{stage}] {message}")
