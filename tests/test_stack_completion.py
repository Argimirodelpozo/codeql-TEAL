"""Physical caller stacks checked against independently enumerated executions."""
import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram, stacksim


def program(body):
    return SSAProgram.from_text('#pragma version 10\n' + body, name='stack-completion.teal')


def constant(p, op):
    use = next(a for a in p.assignments if a.op == op)
    c = p.facts(FactDomain.CONSTANTS).constant(use.inputs[0]) if use.inputs else None
    return None if c is None else int(c.value)


@pytest.mark.parametrize('flag', ['int 1', 'int 7', 'intc_1'])
def test_assert_recovers_the_success_return_and_unshifted_residual(flag):
    p = program('intcblock 0 1\nint 55\ntxn NumAppArgs\ncallsub choose\nassert\n'
                'store 0\nitob\nlog\nint 1\nreturn\nchoose:\nbnz yes\n'
                'intc_0\nretsub\nyes:\nint 42\n' + flag + '\nretsub')
    # Concrete invocation oracle: the zero case fails assert; all five other
    # cases leave [55, 42], so store consumes 42 and the later log consumes 55.
    surviving = []
    for argument in range(6):
        stack = [55] + ([42, 1] if argument else [0])
        if stack.pop():
            surviving.append((stack.pop(), stack.pop()))
    assert set(surviving) == {(constant(p, 'store'), constant(p, 'itob'))} == {(42, 55)}


@pytest.mark.parametrize('branch', ['bz', 'bnz'])
def test_return_flag_refines_each_branch_with_its_own_stack(branch):
    after = ('bz failure\nstore 0\nint 1\nreturn\nfailure:\nitob\nlog\nint 1\nreturn'
             if branch == 'bz' else
             'bnz success\nitob\nlog\nint 1\nreturn\nsuccess:\nstore 0\nint 1\nreturn')
    p = program('int 55\ntxn NumAppArgs\ncallsub choose\n' + after +
                '\nchoose:\nbnz yes\nint 0\nretsub\nyes:\nint 42\nint 1\nretsub')
    assert constant(p, 'store') == 42
    assert constant(p, 'itob') == 55


def test_unknown_failure_flag_keeps_the_shallower_return():
    p = program('int 55\ntxn NumAppArgs\ncallsub choose\nassert\nstore 0\nint 1\nreturn\n'
                'choose:\nbnz yes\ntxn Fee\nretsub\nyes:\nint 42\nint 1\nretsub')
    assert constant(p, 'store') is None   # Fee != 0 makes the store consume 55.


def test_another_predecessor_cannot_borrow_the_return_flag_refinement():
    p = program('int 55\ntxn Fee\nbnz direct\ntxn NumAppArgs\ncallsub choose\n'
                'join:\nassert\nstore 0\nint 1\nreturn\ndirect:\nint 77\nint 1\nb join\n'
                'choose:\nbnz yes\nint 0\nretsub\nyes:\nint 42\nint 1\nretsub')
    assert constant(p, 'store') is None   # The direct branch stores 77.


def test_collapsed_branch_arms_do_not_filter_the_return_depth():
    p = program('int 55\ntxn NumAppArgs\ncallsub choose\nbnz next\nnext:\nstore 0\n'
                'int 1\nreturn\nchoose:\nbnz yes\nint 0\nretsub\nyes:\nint 42\nint 1\nretsub')
    assert constant(p, 'store') is None   # Both 55 and 42 reach the same block.


@pytest.mark.parametrize('extra', [1, 2, 4])
def test_minimum_depth_preserves_a_nested_callers_residual(extra):
    p = program('int 55\ncallsub outer\nitob\nlog\nint 1\nreturn\n'
                'outer:\nproto 0 0\ncallsub inner\nretsub\ninner:\nproto 0 0\n'
                'int 7\nloop:\ntxn NumAppArgs\nbz done\n' + 'int 8\n' * extra +
                'b loop\ndone:\npop\nretsub')
    assert p._pyssa._height_poisoned
    assert not p._pyssa._unsafe_callee_blocks
    assert constant(p, 'itob') == 55
    # Any finite lap count has >=1 local at the pop. A proto return discards
    # every remaining local and leaves the outer caller's 55 in place.
    for laps in range(12):
        stack = [55, 7] + [8] * (laps * extra)
        stack.pop()
        assert stack[:1] == [55]


def test_minimum_depth_does_not_preserve_a_residual_consumed_by_a_loop():
    p = program('int 55\ncallsub helper\nitob\nlog\nint 1\nreturn\n'
                'helper:\nproto 0 0\nint 7\nloop:\npop\ntxn NumAppArgs\n'
                'bnz loop\nint 8\nretsub')
    assert p._pyssa._unsafe_callee_blocks
    assert constant(p, 'itob') is None


def test_an_ambiguous_legacy_join_cannot_supply_a_fixed_nested_return_count():
    p = program('int 55\ncallsub outer\nitob\nlog\nint 1\nreturn\n'
                'outer:\nproto 0 0\ncallsub legacy\npop\npop\nint 99\nretsub\n'
                'legacy:\ntxn NumAppArgs\nbz one\nint 7\nint 8\nb done\n'
                'one:\nint 7\ndone:\nretsub')
    # The legacy helper has ONE retsub, reached at two heights. With one
    # returned local, the outer routine pops 55 and replaces it with 99; with
    # two locals, it preserves 55. Local non-interference alone is insufficient.
    assert p._pyssa._unsafe_callee_blocks
    assert constant(p, 'itob') is None


def test_exhausted_context_enumeration_is_visible_in_analysis_health(monkeypatch):
    from tealql.tealtools.ssa import execution_contexts
    original = execution_contexts.execution_bodies
    monkeypatch.setattr(execution_contexts, 'execution_bodies',
                        lambda *args: original(*args, max_visits=0))
    p = program('int 1\nreturn')
    assert not p.health().complete
    assert 'execution-context-budget' in {d.code for d in p.health().degradations}


def test_minimum_depth_budget_does_not_publish_a_partial_answer():
    py = program('int 1\nreturn')._pyssa
    assert stacksim.minimum_entry_heights(py.blocks, py._bb_to_sub,
        py._callsub_arities, py._return_point, max_steps=0) == {}


def test_shared_tail_operands_include_every_executing_routine():
    p = program('int 11\nint 22\nint 33\ncallsub first\n'
                'int 77\nint 88\nint 99\ncallsub second\nint 1\nreturn\n'
                'first:\npop\nb tail\nsecond:\npop\nb tail\n'
                'tail:\nitob\nlog\nitob\nlog\nretsub')
    facts = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
    values = [facts.int_range(a.inputs[0]) for a in p.assignments if a.op == 'itob']
    # Each routine removes its third argument; the shared tail logs the first
    # two in reverse order. Both actual caller inputs must be represented.
    assert [(v.lo, v.hi) for v in values] == [(22, 88), (11, 77)]
    py = p._pyssa
    assert py._stack_result.contexts_complete
    from tealql.tealtools.ssa.relations import shared_execution_blocks
    for block, entries in shared_execution_blocks(p).items():
        for entry in entries:
            context = py._stack_result.contexts[entry]
            assert block in context.exit
            for op in block.ops:
                assert len(context.args[id(op)]) >= op.n_in


def test_shared_return_stacks_remain_separate_for_each_routine():
    p = program('callsub first\nitob\nlog\ncallsub second\nitob\nlog\nint 1\nreturn\n'
                'first:\nint 11\nb tail\nsecond:\nint 77\nb tail\ntail:\nretsub')
    facts = p.facts(FactDomain.CONSTANTS)
    logs = [int(facts.constant(a.inputs[0]).value) for a in p.assignments if a.op == 'itob']
    assert logs == [11, 77]  # One physical retsub, two different physical stacks.


def test_unknown_shared_context_is_not_hidden_by_a_resolved_owner():
    p = program('int 11\ncallsub first\ntxn Fee\ncallsub second\nint 1\nreturn\n'
                'first:\nb tail\nsecond:\nb tail\ntail:\nitob\nlog\nretsub')
    assert constant(p, 'itob') is None


def test_context_walk_budget_reports_incompleteness():
    from tealql.tealtools.ssa.execution_contexts import execution_bodies
    py = program('int 1\nreturn')._pyssa
    _, complete = execution_bodies(py.blocks, py._bb_to_sub, lambda b: b.succs, max_visits=0)
    assert not complete
