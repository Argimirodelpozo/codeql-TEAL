"""Dynamic scratch slots are MAY value and selector dependencies."""
from __future__ import annotations

from tealql.tealtools.dataflow.engine import (
    ATTACKER_CONTROL_RULES,
    Sink,
    Source,
    TaintAnalysis,
)
from tealql.tealtools.ssa import SSAProgram


def _prog(body: str) -> SSAProgram:
    return SSAProgram.from_text(
        f"#pragma version 8\n{body}\nint 1\nreturn\n", name="p.teal"
    )


def _reaches_log(body: str) -> bool:
    prog = _prog(body)
    return bool(TaintAnalysis(
        prog,
        sources=[Source("arg", lambda a: a.op == "txna")],
        sinks=[Sink("log", lambda a: a.op == "log", lambda a: 1)],
        default_rules=ATTACKER_CONTROL_RULES,
    ).detect())


def test_dynamic_store_value_may_reach_static_load():
    assert _reaches_log(
        "txna ApplicationArgs 0\n"
        "global GroupSize\n"
        "stores\n"
        "load 0\nlog"
    )


def test_static_store_value_may_reach_dynamic_load():
    assert _reaches_log(
        "txna ApplicationArgs 0\n"
        "store 0\n"
        "global GroupSize\n"
        "loads\nlog"
    )


def test_dynamic_load_selector_is_a_control_dependency():
    assert _reaches_log(
        "byte 0x00\nstore 0\n"
        "byte 0x01\nstore 1\n"
        "txna ApplicationArgs 0\nbtoi\nloads\nlog"
    )


def test_dynamic_store_does_not_kill_previous_may_value_for_const_prop():
    prog = _prog(
        "int 7\nstore 0\n"
        "int 9\nglobal GroupSize\nstores\n"
        "load 0\npop"
    )
    prog.propagate_constants()
    prog.propagate_scratch_constants()
    load = next(a for a in prog.assignments if a.op == "load")
    assert load.outputs[0].const_value is None
    fact = prog._scratch_facts[("p.teal", load.location.line)]
    assert {(2, 1), (4, 1)} <= {(line, index) for _file, line, index in fact.values}
    assert fact.zero_initialized is False


def test_constant_dynamic_index_is_narrowed_to_one_slot():
    prog = _prog("int 5\nint 3\nstores\nload 3\npop")
    prog._ensure_scratch_influence()
    load = next(a for a in prog.assignments if a.op == "load")
    fact = prog._scratch_facts[("p.teal", load.location.line)]
    assert fact.values == frozenset({("p.teal", 2, 1)})
    assert not fact.zero_initialized and not fact.selectors
