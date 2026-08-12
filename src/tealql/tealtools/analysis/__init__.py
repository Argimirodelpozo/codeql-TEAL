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
from .resource_demand import (
    BoxAccess,
    DemandSite,
    ForeignStateRead,
    RESOURCE_DEMAND_SCHEMA_VERSION,
    ResourceDemand,
    ResourceReference,
    resource_demand,
)

__all__ = [
    "AnalysisContext",
    "DerivedProfile",
    "FactDomain",
    "TypeFact",
    "ValueFact",
    "ValueFacts",
    "derived_program",
    "functional_dump",
    "BoxAccess",
    "DemandSite",
    "ForeignStateRead",
    "RESOURCE_DEMAND_SCHEMA_VERSION",
    "ResourceDemand",
    "ResourceReference",
    "resource_demand",
]
