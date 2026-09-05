"""Scalar views of inferred policies, numeric results and resource bounds."""
from dataclasses import asdict
import json

from ..analysis import FactDomain


def authority_text(context):
    from ..analysis.authority import authority_for
    analysis = authority_for(context.prog)
    rows = []
    for assignment in context.prog.assignments:
        if (assignment.op not in {'addr', 'app_global_get', 'app_global_get_ex', 'app_local_get', 'app_local_get_ex'}
                and not (assignment.op == 'global' and assignment.immediates.strip() in {'CreatorAddress', 'CurrentApplicationAddress'})):
            continue
        index = 1 if assignment.op.endswith('_ex') else 0
        if index >= len(assignment.outputs):
            continue
        value = assignment.outputs[index]
        result = analysis.address(value)
        status = 'PROVED' if result.proved else 'CONDITIONAL' if result.preserved else 'UNKNOWN'
        rows.append(f'{value}: {status}: {result.reason}; assumptions={json.dumps(result.assumptions)}')
    return '\n'.join(rows) or '(no explicit authority address or state-read candidates)'


def congruences_text(context):
    facts = context.facts(FactDomain.RANGES)
    rows = ['modulus 0 denotes an exact value; modulus 1 is unknown']
    for assignment in context.prog.assignments:
        for value in assignment.outputs:
            fact = facts.congruence(value)
            rows.append(f'{value}: modulus={fact.modulus}, residue={fact.residue}')
    return '\n'.join(rows)


def numeric_calls_text(context):
    facts = context.facts(FactDomain.RANGES)
    rows = []
    for call in context.prog.assignments:
        if call.op == 'callsub':
            for slot in range(max(1, len(call.outputs))):
                result = facts.call_result(call, slot)
                rows.append(f'{call.location} slot={slot}: {result!r}')
    return '\n'.join(rows) or '(no callsub sites)'


def resource_bounds_text(context):
    from ..analysis.resource_sufficiency import resource_sufficiency
    result = resource_sufficiency(context.prog, {})
    return json.dumps({'environment': 'not supplied; configure resource_sufficiency through its Python API',
                       'analysis': result.health.to_dict(),
                       'bounds': [asdict(row) for row in result.value]}, indent=2, sort_keys=True)
