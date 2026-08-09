"""Query-scoped value analysis.

The canonical :class:`SSAProgram` is never rewritten by this package.  Analyses
either query immutable :class:`ValueFacts` or request a private derived program
for legacy algorithms that still read annotations directly.
"""
from .context import (
    AnalysisContext,
    DerivedProfile,
    FactDomain,
    TypeFact,
    ValueFact,
    ValueFacts,
    derived_program,
)
from .render import functional_dump

__all__ = [
    "AnalysisContext",
    "DerivedProfile",
    "FactDomain",
    "TypeFact",
    "ValueFact",
    "ValueFacts",
    "derived_program",
    "functional_dump",
]
