"""Conditional resource obligations; classification is never resource sufficiency."""
from __future__ import annotations

from dataclasses import dataclass

from .resource_demand import resource_demand


@dataclass(frozen=True)
class ResourceRequirement:
    dimension: str
    requirement: str
    status: str = 'REQUIRED'


def resource_requirements(program):
    demand = resource_demand(program)
    requirements = [ResourceRequirement('availability', str(ref.to_dict())) for ref in demand.references]
    requirements.extend(ResourceRequirement('box', f'available box {box.key!r}; include owner and I/O allocation')
                        for box in demand.box_accesses)
    requirements.extend((
        ResourceRequirement('opcode-budget', 'path/loop cost must fit available pooled credit'),
        ResourceRequirement('fees', 'outer fees and spendable inner fees cover every executed transaction'),
        ResourceRequirement('minimum-balance', 'each affected owner retains sufficient balance after every allocation'),
    ))
    if demand.uses_inner_transactions:
        requirements.append(ResourceRequirement('inner-transactions', 'declared callees, resources, and transaction count must be closed'))
    if not demand.complete:
        requirements.append(ResourceRequirement('unclassified', 'demand has unclassified accesses', 'UNKNOWN'))
    # Keep this explicit even for an empty demand: no supplied ledger/group
    # environment means there is no proof that execution will complete.
    requirements.append(ResourceRequirement('recoverability', 'failure handling and ledger/resource environment are unmodeled', 'UNKNOWN'))
    return tuple(requirements)
