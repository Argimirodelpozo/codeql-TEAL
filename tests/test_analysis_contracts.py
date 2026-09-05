"""Protect shared snapshots and work budgets directly, independent of timing."""
import subprocess
import sys

import pytest

from tealql.tealtools.lift import build_lifter, pre_ir
from tealql.tealtools.lift.summaries import compute_summaries
from tealql.tealtools.ssa import SSAProgram


def program():
    return SSAProgram.from_text('#pragma version 8\ntxn Fee\ncallsub f\nreturn\nf:\nproto 1 1\nframe_dig -1\nretsub', name='cache.teal')


def test_published_ir_is_sealed_and_summaries_are_cached():
    p = program()
    lifter = build_lifter(p)
    assert lifter is build_lifter(p)
    sub = lifter.subs[0]
    with pytest.raises(TypeError, match='read-only'):
        sub.body = []
    with pytest.raises((AttributeError, TypeError)):
        sub.body[0].ops.append(pre_ir.Assert(pre_ir.UInt64Constant(0)))
    with pytest.raises(TypeError, match='read-only'):
        lifter.subs = []
    summaries = compute_summaries(lifter)
    assert compute_summaries(lifter) is summaries
    with pytest.raises(TypeError):
        summaries['f'] = None
    assert summaries['f'].results[0].passthrough == {0}


def test_effect_summary_crosses_calls_positionally():
    p = SSAProgram.from_text(
        '#pragma version 8\nbyte "k"\nint 1\ncallsub outer\nint 1\nreturn\n'
        'outer:\nproto 2 0\nframe_dig -2\nframe_dig -1\ncallsub inner\nretsub\n'
        'inner:\nproto 2 0\nframe_dig -2\nframe_dig -1\napp_global_put\nretsub', name='effects.teal')
    summaries = compute_summaries(build_lifter(p))
    effect, = summaries['outer'].effects
    assert effect.op == 'app_global_put'
    assert [d.passthrough for d in effect.operands] == [{1}, {0}]


def test_core_analysis_imports_and_costs_without_optional_compiler():
    code = '''
import importlib.abc, sys
class BlockPuya(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, *args):
        if fullname == 'puya' or fullname.startswith('puya.'):
            raise ModuleNotFoundError('optional compiler disabled', name=fullname)
sys.meta_path.insert(0, BlockPuya())
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift import build_lifter
from tealql.tealtools.budget.costs import op_cost
from tealql.security.obligations import analyze_obligations
p = SSAProgram.from_text('#pragma version 8\\nint 1\\nreturn', name='core.teal')
assert build_lifter(p) is not None
assert op_cost('sha256').lower == 35
assert not analyze_obligations(p, {})['complete']
assert not any(name == 'puya' or name.startswith('puya.') for name in sys.modules)
'''
    subprocess.run([sys.executable, '-c', code], check=True, capture_output=True, text=True)


def test_fact_queries_reject_stale_program_revisions():
    from tealql.tealtools.analysis import FactDomain
    p = program()
    fee = next(a for a in p.assignments if a.op == 'txn').outputs[0]
    use = next(a for a in p.assignments if a.op == 'return')
    facts = p.facts(FactDomain.RANGES)
    facts.range_at(fee, use)
    p.propagate_constants()
    with pytest.raises(RuntimeError, match='stale facts'):
        facts.range_at(fee, use)
    assert p.facts(FactDomain.RANGES) is not facts


def test_mutable_ir_does_not_reuse_stale_taint_and_cached_results_are_readonly():
    from types import SimpleNamespace
    from tealql.tealtools.lift.taint import user_input_taint, unresolved_taint
    reg = pre_ir.Register('value', 0, 'bytes')
    assignment = pre_ir.Assignment([reg], pre_ir.BytesConstant('0x00'))
    block = pre_ir.BasicBlock(0, [], [assignment], pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))
    sub = pre_ir.Subroutine('main', [], [], [block], is_main=True)
    lifter = SimpleNamespace(subs=[sub], name2sub={})
    assert not user_input_taint(lifter) and not unresolved_taint(lifter)
    assignment.source = pre_ir.Undefined()
    assert unresolved_taint(lifter)
    assignment.source = pre_ir.Intrinsic('txna', ['ApplicationArgs', '0'], [])
    assert user_input_taint(lifter)[id(reg)] == {'ApplicationArgs'}
    frozen = build_lifter(program())
    result = user_input_taint(frozen)
    assert result is user_input_taint(frozen)
    with pytest.raises(TypeError):
        result[0] = frozenset()


def test_shared_semantic_modules_keep_one_dependency_direction():
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / 'src' / 'tealql' / 'tealtools'
    boundaries = {
        'language/spec.py': {'puya', 'analysis', 'lift', 'security'},
        'language/effects.py': {'puya', 'analysis', 'lift', 'security'},
        'lift/taint_flow.py': {'puya', 'summaries', 'taint'},
        'lift/summaries.py': {'puya', 'taint'},
    }
    for path, forbidden in boundaries.items():
        for node in ast.walk(ast.parse((root / path).read_text())):
            imports = ([node.module or ''] if isinstance(node, ast.ImportFrom) else
                       [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
            for imported in imports:
                assert not set(imported.split('.')) & forbidden, (path, imported)


def test_guard_queries_share_work_without_merging_different_subjects(monkeypatch):
    from tealql.tealtools.lift import fund_flow as flow
    p = SSAProgram.from_text('#pragma version 8\ntxn Fee\nint 10\n<=\nassert\nint 1\nreturn', name='guards.teal')
    lifter = build_lifter(p)
    defs = flow._def_map(lifter)
    comparison = next(op for b in pre_ir.blocks(lifter.subs) for op in b.ops
                      if isinstance(op, pre_ir.Assignment) and isinstance(op.source, pre_ir.Intrinsic)
                      and op.source.op == '<=')
    condition = comparison.targets[0]
    subject = {id(comparison.source.args[1])}
    visits = 0
    intrinsic = flow._intr
    def count_intrinsic(op):
        nonlocal visits
        visits += 1
        return intrinsic(op)
    monkeypatch.setattr(flow, '_intr', count_intrinsic)
    assert flow._classify('assert', None, condition, defs, subject, set()).checks_input
    first = visits
    again = flow._classify('assert-after', None, condition, defs, subject, set())
    assert again.kind == 'assert-after' and again.checks_input
    assert visits == first and defs.guard_hits == 1
    assert not flow._classify('assert', None, condition, defs, set(), set()).checks_input
    assert visits > first
    first = visits
    returns = {}
    flow._classify('assert', None, condition, defs, set(), set(), returns)
    assert visits > first and defs.guard_returns is returns
    # Many distinct source sets must not retain unbounded query keys.
    for n in range(1100):
        flow._classify('assert', None, condition, defs, set(range(n, n + 100)), set(), returns)
    assert len(defs.guard_cache) <= 1024
    assert sum(1 + len(k[2]) + len(k[3]) for k in defs.guard_cache) <= 65536
