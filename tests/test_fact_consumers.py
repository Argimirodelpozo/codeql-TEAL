"""Read-only consumers share facts; call targets require actual stored data."""
import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.dataflow.taint_graph import TaintGraph
from tealql.tealtools.intercontract.analysis import find_appcall_sites
from tealql.tealtools.reporting.inner_transactions import InnerTxnReport
from tealql.tealtools.ssa import SSAProgram


def _caller(setup='', read='int 500\nint 55\n+'):
    return SSAProgram.from_text('#pragma version 13\n' + setup + '''
itxn_begin
int 2
int 3
*
itxn_field TypeEnum
''' + read + '\nitxn_field ApplicationID\nitxn_submit\nint 1\nreturn\n')


def _targets(prog):
    return [s.app_id for s in find_appcall_sites(prog, {555: '/unused/callee.teal'})]


def test_report_and_graph_share_constants_without_invalidating_existing_facts():
    prog = _caller()
    facts = prog.facts(FactDomain.CONSTANTS)
    assignments = [(a, tuple(a.inputs)) for a in prog.assignments]
    report = InnerTxnReport(prog)
    graph = TaintGraph.of(prog)
    node, = graph.find(op='+')
    assert graph.const_values_at(node) == (('int', '555'),)
    assert graph.is_const_at(node)
    assert _targets(prog) == [555]
    assert prog.revision == 0
    assert all(tuple(a.inputs) == inputs for a, inputs in assignments)
    added = next(a for a in prog.assignments if a.op == '+').outputs[0]
    assert facts.constant(added).value == '555'
    assert added.const_value is None
    # A report retained across a supported mutation refreshes its fact view.
    prog.propagate_constants()
    field, = report.groups[0].txns[0].fields_by_name()['ApplicationID']
    assert field.possible_values() == ['555']


@pytest.mark.parametrize('setup,read', [
    ('byte "target"\nint 555\napp_global_put\n', 'byte "target"\napp_global_get'),
    ('int 0\nbyte "target"\nint 555\napp_local_put\n',
     'int 0\nbyte "target"\napp_local_get'),
    ('byte "target"\nint 555\nitob\nbox_put\n', 'byte "target"\nbox_get\nassert\nbtoi'),
])
def test_state_target_requires_all_aliasing_writers(setup, read):
    assert _targets(_caller(setup, read)) == [555]
    if 'box_put' in setup:
        dynamic = 'txna ApplicationArgs 0\nint 777\nitob\nbox_put\n'
    elif 'app_local_put' in setup:
        dynamic = 'int 0\ntxna ApplicationArgs 0\nint 777\napp_local_put\n'
    else:
        dynamic = 'txna ApplicationArgs 0\nint 777\napp_global_put\n'
    assert _targets(_caller(setup + dynamic, read)) == []


@pytest.mark.parametrize('mutation', [
    'txna ApplicationArgs 0\nint 0\nbyte "unrelated"\nbox_replace\n',
    'byte "target"\nint 16\nbox_resize\n',
    'byte "target"\nbox_del\npop\n',
    'int 0\nbyte "target"\nbyte "different"\napp_box_put\n',
])
def test_partial_or_foreign_box_writes_prevent_a_constant_target(mutation):
    prog = _caller('byte "target"\nint 555\nitob\nbox_put\n' + mutation,
                   'byte "target"\nbox_get\nassert\nbtoi')
    assert _targets(prog) == []


def test_exist_flag_is_not_a_state_value():
    prog = _caller('byte "target"\nint 555\napp_global_put\n',
                   'int 0\nbyte "target"\napp_global_get_ex')
    assert _targets(prog) == []


def test_a_write_on_a_creation_path_does_not_prove_existing_ledger_contents():
    prog = _caller('txn ApplicationID\nbnz ready\nbyte "target"\nint 555\n'
                   'app_global_put\nready:\n', 'byte "target"\napp_global_get')
    assert _targets(prog) == []


def test_local_initialization_requires_the_same_account():
    prog = _caller('int 1\nbyte "target"\nint 555\napp_local_put\n',
                   'int 0\nbyte "target"\napp_local_get')
    assert _targets(prog) == []


def test_box_key_equal_to_value_still_uses_the_value_operand():
    prog = _caller('byte 0x022b\nbyte 0x022b\nbox_put\n',
                   'byte 0x022b\nbox_get\nassert\nbtoi')
    assert _targets(prog) == [555]


def test_join_of_equivalent_inputs_uses_the_shared_alias_relation():
    prog = SSAProgram.from_text('''#pragma version 8
txn Fee
txn NumAppArgs
bz second
dup
b joined
second:
txn Fee
joined:
==
return
''')
    comparison = next(a for a in prog.assignments if a.op == '==')
    facts = prog.facts(FactDomain.CONSTANTS)
    from tealql.security._value_flow import resolve_through_copies
    operands = [facts.resolve(v) for v in comparison.inputs]
    assert operands[0] is operands[1]
    assert all(resolve_through_copies(prog, v) is operands[0] for v in comparison.inputs)
    assert prog.revision == 0
