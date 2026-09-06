"""Recursive return alternatives checked against finite concrete executions."""
import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram


def helper(name='choose', callee='choose', value=42, flag='int 1',
           failure='int 0', after='retsub'):
    return (f'{name}:\ndup\nbz {name}_base\nint 1\n-\ncallsub {callee}\n{after}\n'
            f'{name}_base:\npop\ntxn Fee\nbz {name}_failure\nint {value}\n{flag}\nretsub\n'
            f'{name}_failure:\n{failure}\nretsub\n')


def program(body, guard='assert', suffix='store 0\nitob\nlog\nint 1\nreturn'):
    return SSAProgram.from_text(
        '#pragma version 10\nint 55\ntxn NumAppArgs\ncallsub choose\n'
        + guard + '\n' + suffix + '\n' + body, name='recursive-shapes.teal')


def input_constant(p, opcode):
    assignment = next(a for a in p.assignments if a.op == opcode)
    value = p.facts(FactDomain.CONSTANTS).constant(assignment.inputs[0]) if assignment.inputs else None
    return None if value is None else int(value.value)


@pytest.mark.parametrize('flag', ['int 1', 'int 7'])
def test_self_recursive_returns_keep_the_success_value_and_caller_residual(flag):
    p = program(helper(flag=flag))
    # A finite tail-recursive invocation changes only the remaining depth.
    # Its base case either leaves [42, flag] or [0], independently of depth.
    for depth in range(12):
        remaining = depth
        while remaining:
            remaining -= 1
        stack = [55, 42, int(flag.split()[1])]
        assert stack.pop()
        assert (stack.pop(), stack.pop()) == (42, 55)
    assert input_constant(p, 'store') == 42
    assert input_constant(p, 'itob') == 55


@pytest.mark.parametrize('reverse', [False, True])
def test_mutual_recursion_keeps_both_base_values_regardless_of_source_order(reverse):
    parts = [helper(callee='other'), helper('other', 'choose', value=77)]
    p = program(''.join(reversed(parts) if reverse else parts))
    assignment = next(a for a in p.assignments if a.op == 'store')
    assert assignment.inputs
    actual = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES).int_range(assignment.inputs[0])
    expected = {42 if depth % 2 == 0 else 77 for depth in range(12)}
    assert (actual.lo, actual.hi) == (min(expected), max(expected))
    assert input_constant(p, 'itob') == 55


@pytest.mark.parametrize('branch', ['bz', 'bnz'])
def test_recursive_return_flags_refine_both_branch_polarities(branch):
    success = 'store 0\nint 1\nreturn'
    failure = 'itob\nlog\nint 1\nreturn'
    suffix = (success + '\nfailure:\n' + failure if branch == 'bz'
              else failure + '\nsuccess:\n' + success)
    p = program(helper(), guard=branch + (' failure' if branch == 'bz' else ' success'),
                suffix=suffix)
    assert input_constant(p, 'store') == 42
    assert input_constant(p, 'itob') == 55


def test_recursive_unknown_flag_does_not_discard_the_shallow_return():
    p = program(helper(failure='txn FirstValid'), suffix='store 0\nint 1\nreturn')
    # A nonzero FirstValid on the failure arm makes the caller store its 55.
    assert input_constant(p, 'store') is None


def test_non_tail_recursion_retains_the_inductive_value():
    p = program(helper(after='assert\nint 1\n+\nint 1\nretsub'))
    add = next(a for a in p.assignments if a.op == '+')
    assert len(add.inputs) == 2
    pending, seen = [add.inputs[1]], set()
    while pending:
        value = pending.pop()
        if value in seen:
            continue
        seen.add(value)
        pending.extend(getattr(value, 'args', ()))
    assert add.outputs[0] in seen
    assert any(getattr(v, 'const_value', None) is not None
               and v.const_value.value == '42' for v in seen)
    assert input_constant(p, 'store') is None  # finite depths return 42 + depth
    assert input_constant(p, 'itob') == 55


def test_values_first_discovered_after_the_base_cases_are_included():
    p = program(helper(after='assert\npop\nint 99\nint 7\nretsub'))
    value = next(a.inputs[0] for a in p.assignments if a.op == 'store')
    actual = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES).int_range(value)
    # Depth zero returns 42. Every positive depth replaces it with 99.
    assert (actual.lo, actual.hi) == (42, 99)
    assert input_constant(p, 'itob') == 55


def test_recursive_parameter_returns_are_bound_to_each_actual_call():
    p = SSAProgram.from_text('''#pragma version 10
int 11
int 2
callsub choose
assert
store 0
int 77
int 3
callsub choose
assert
store 1
int 1
return
choose:
dup
bz base
int 1
-
callsub choose
retsub
base:
pop
txn Fee
bz fail
int 1
retsub
fail:
pop
int 0
retsub
''', name='recursive-payload.teal')
    facts = p.facts(FactDomain.CONSTANTS)
    actual = [int(facts.constant(a.inputs[0]).value) for a in p.assignments if a.op == 'store']
    assert actual == [11, 77]


def test_recursive_summary_includes_an_acyclic_dependency():
    body = helper().replace('int 42\nint 1', 'callsub leaf\nint 1')
    p = program(body + '\nleaf:\nint 42\nretsub')
    assert input_constant(p, 'store') == 42
    assert input_constant(p, 'itob') == 55


def test_a_constant_depth_local_loop_can_reach_a_fixed_point():
    loop = 'int 2\nloop:\ndup\nbz done\nint 1\n-\nb loop\ndone:\npop\nint 42'
    p = program(helper().replace('int 42', loop))
    assert input_constant(p, 'store') == 42
    assert input_constant(p, 'itob') == 55


@pytest.mark.parametrize('operation', ['+', '*', '^'])
def test_recursive_numeric_values_do_not_collapse_to_the_base_case(operation):
    p = program(helper(after=f'assert\nint 3\n{operation}\nint 1\nretsub'))
    value = next(a.inputs[0] for a in p.assignments if a.op == 'store')
    facts = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
    assert facts.constant(value) is None
    actual = facts.int_range(value)
    # No interval is an explicit absence of a bound. The new return-shape
    # proof must neither invent an interval nor fold the recurrence to 42.
    lo, hi = (actual.lo, actual.hi) if actual is not None else (0, 2 ** 64 - 1)
    result = 42
    for depth in range(9):
        if depth:
            result = {'+': lambda n: n + 3, '*': lambda n: n * 3,
                      '^': lambda n: n ^ 3}[operation](result)
        assert lo <= result <= hi


def test_a_direct_predecessor_cannot_borrow_a_recursive_call_guard():
    p = SSAProgram.from_text(
        '#pragma version 10\nint 55\ntxn Fee\nbnz direct\ntxn NumAppArgs\n'
        'callsub choose\njoin:\nassert\nstore 0\nint 1\nreturn\n'
        'direct:\nint 77\nint 1\nb join\n' + helper(), name='recursive-join.teal')
    assert input_constant(p, 'store') is None


def test_collapsed_recursive_guard_edges_retain_both_return_depths():
    p = program(helper(), guard='bnz next\nnext:', suffix='store 0\nint 1\nreturn')
    assert input_constant(p, 'store') is None


def test_an_unsupported_dependency_cannot_publish_the_recursive_base_case():
    body = helper().replace('int 42\nint 1', 'callsub leaf\nint 1')
    p = program(body + '\nleaf:\nproto 0 1\nint 42\nretsub')
    assert not p._pyssa._recursive_return_analysis.returns
    assert p._pyssa._recursive_return_analysis.refused
    assert input_constant(p, 'store') is None


def test_a_recursive_stack_that_grows_cannot_publish_only_its_base_cases():
    p = program(helper(after='int 9\nretsub'), suffix='store 0\nint 1\nreturn')
    assert input_constant(p, 'store') is None
    assert p._pyssa._recursive_return_analysis.refused


def test_a_recursive_path_that_consumes_the_callers_stack_refuses_the_proof():
    p = program(helper(after='assert\npop\nint 99\nretsub'),
                suffix='store 0\nint 1\nreturn')
    # A shallow return first appears at depth one. At depth two, the pop
    # reaches below the helper's arguments. The base cases alone look clean.
    proof = p._pyssa._recursive_return_analysis
    assert not proof.returns
    assert any('caller-owned' in reason for reason in proof.refused.values())
    assert input_constant(p, 'store') is None


def test_recursive_frame_operations_keep_the_existing_conservative_result():
    p = program(helper().replace('choose:\n', 'choose:\nframe_dig -1\npop\n', 1))
    proof = p._pyssa._recursive_return_analysis
    assert not proof.returns
    assert any('frame' in reason for reason in proof.refused.values())
    assert input_constant(p, 'store') is None


def test_zero_surviving_recursive_alternatives_do_not_invent_a_return_value():
    p = program(helper(flag='int 0'))
    assert input_constant(p, 'store') is None


def test_a_return_alternative_bound_cannot_publish_a_partial_cycle(monkeypatch):
    from tealql.tealtools.ssa import recursive_returns
    original = recursive_returns.analyze
    monkeypatch.setattr(recursive_returns, 'analyze',
                        lambda *args, **kwargs: original(*args, **kwargs, max_variants=2))
    p = program(helper(after='assert\nint 1\n+\nint 1\nretsub'))
    # Two base shapes fit the bound; the recursive value adds a third shape.
    assert not p._pyssa._recursive_return_analysis.returns
    assert p._pyssa._recursive_return_analysis.refused
    assert input_constant(p, 'store') is None


def test_the_retained_cell_bound_discards_unfinished_return_summaries(monkeypatch):
    from tealql.tealtools.ssa import recursive_returns
    original = recursive_returns.analyze
    monkeypatch.setattr(recursive_returns, 'analyze',
                        lambda *args, **kwargs: original(*args, **kwargs, max_cells=3))
    p = program(helper())
    assert not p._pyssa._recursive_return_analysis.returns
    assert p._pyssa._recursive_return_analysis.refused
    assert input_constant(p, 'store') is None


def test_an_exhausted_recursive_fixed_point_is_visible_and_keeps_unknowns(monkeypatch):
    from tealql.tealtools.ssa import recursive_returns
    original = recursive_returns.analyze
    monkeypatch.setattr(recursive_returns, 'analyze',
                        lambda *args, **kwargs: original(*args, **kwargs, max_steps=0))
    p = program(helper())
    assert input_constant(p, 'store') is None
    assert 'recursive-return-refinement' in {d.code for d in p.health().degradations}


@pytest.mark.parametrize('cyclic', [False, True])
def test_call_ordering_handles_graphs_deeper_than_pythons_recursion_limit(cyclic):
    from dataclasses import dataclass
    from types import SimpleNamespace
    from tealql.tealtools.ssa.stacksim import _callee_first

    @dataclass(eq=False)
    class Node:
        ops: list
        succs: list

    nodes = [Node([SimpleNamespace(op='callsub')], []) for _ in range(1500)]
    for left, right in zip(nodes, nodes[1:]):
        left.succs = [right]
    if cyclic:
        nodes[-1].succs = [nodes[0]]
    order = _callee_first({node: [node] for node in nodes}, {node: node for node in nodes})
    assert len(order) == len(set(order)) == len(nodes)
    if not cyclic:
        assert order == list(reversed(nodes))
