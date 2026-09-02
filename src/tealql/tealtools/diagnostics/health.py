"""Standard completeness metadata for analysis APIs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Optional, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class AnalysisDegradation:
    code: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None


@dataclass(frozen=True)
class AnalysisHealth:
    degradations: tuple[AnalysisDegradation, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.degradations

    def messages(self) -> tuple[str, ...]:
        return tuple(item.message for item in self.degradations)


@dataclass(frozen=True)
class AnalysisResult(Generic[T]):
    """A value together with whether the model could answer completely."""

    value: T
    health: AnalysisHealth

    @property
    def complete(self) -> bool:
        return self.health.complete

    @property
    def degradations(self) -> tuple[AnalysisDegradation, ...]:
        return self.health.degradations


def health_for(prog, *, deep: bool = False) -> AnalysisHealth:
    items: list[AnalysisDegradation] = []
    for diagnostic in getattr(prog, "parse_diagnostics", ()) or ():
        items.append(AnalysisDegradation(
            "parse-diagnostic",
            f"TEAL span was excluded from analysis: {diagnostic}",
            getattr(diagnostic, "file", None),
            getattr(diagnostic, "start_line", None),
        ))
    unknown_ops = sorted(getattr(prog, "unknown_ops", ()) or ())
    if unknown_ops:
        items.append(AnalysisDegradation(
            "unknown-opcode",
            "unknown opcode stack effects: " + ", ".join(unknown_ops),
        ))
    # More than one `intcblock` / `bytecblock` in a file: the constant table
    # depends on WHICH one executed last, so `language.constants` resolves no
    # `intc_*`/`bytec_*` at all rather than guess (assembler-legal, compilers
    # emit one). Every such reference is then an unknown value; say so.
    cblocks: dict[tuple[str, str], list[int]] = {}
    for a in getattr(prog, "assignments", ()) or ():
        if a.op in ("intcblock", "bytecblock"):
            cblocks.setdefault((a.location.file, a.op), []).append(a.location.line)
    for (file, op), lines in sorted(cblocks.items()):
        if len(lines) > 1:
            items.append(AnalysisDegradation(
                "multiple-constant-blocks",
                f"{len(lines)} `{op}` ops (lines {', '.join(map(str, lines))}); "
                f"no `{op[:-5]}_*` reference in this file resolves to a constant",
                file,
                lines[0],
            ))
    if deep:
        try:
            prog._ensure_scratch_influence()
            facts = getattr(prog, "_scratch_facts", {}) or {}
            for (file, line), fact in sorted(facts.items()):
                if fact.unknown:
                    items.append(AnalysisDegradation(
                        "unknown-scratch-value",
                        "scratch load may read a value the SSA could not name",
                        file,
                        line,
                    ))
        except Exception as error:
            items.append(AnalysisDegradation(
                "scratch-analysis-failed",
                f"scratch influence could not be computed: {type(error).__name__}: {error}",
            ))
    return AnalysisHealth(tuple(items))


__all__ = [
    "AnalysisDegradation",
    "AnalysisHealth",
    "AnalysisResult",
    "health_for",
]
