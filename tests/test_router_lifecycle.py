"""All twelve lifecycle partitions and a deliberately different arithmetic key."""
import pytest

from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram, const_int


@pytest.mark.parametrize('factor', [6, 5])
def test_router_decomposition_matches_its_integer_encoding(factor):
    body = ['#pragma version 8', 'txn ApplicationID', '!', f'int {factor}', '*',
            'txn OnCompletion', '+', 'switch ' + ' '.join(f'case{i}' for i in range(12)), 'err']
    for index in range(12):
        body.extend((f'case{index}:', 'int 1', 'return'))
    p = SSAProgram.from_text('\n'.join(body), name='router.teal')
    paths = PathPredicateAnalysis(p)
    app_id = next(a.outputs[0] for a in p.assignments if a.op == 'txn' and a.immediates == 'ApplicationID')
    completion = next(a.outputs[0] for a in p.assignments if a.op == 'txn' and a.immediates == 'OnCompletion')
    for index, exit_ in enumerate(a for a in p.assignments if a.op == 'return'):
        facts = paths.predicates_at('router.teal', exit_.location.line)
        if factor == 6:
            assert any(f.value == completion and f.kind == 'eq' and const_int(f.args[0]) == index % 6 for f in facts)
            assert any(f.value == app_id and f.kind == ('zero' if index >= 6 else 'nonzero') for f in facts)
            # Independent enumeration of the twelve legal lifecycle cases.
            for create in (False, True):
                for oc in range(6):
                    if int(create) * 6 + oc == index:
                        assert oc == index % 6 and create == (index >= 6)
        else:
            assert not any(f.value in {completion, app_id} for f in facts)
