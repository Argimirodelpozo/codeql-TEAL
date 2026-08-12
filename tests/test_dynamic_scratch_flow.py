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
    body = (
        "int 0\n"
        "txna ApplicationArgs 0\n"
        "stores\n"
        "load 0\nlog"
    )
    prog = _prog(body)
    prog._ensure_scratch_influence()
    load = next(a for a in prog.assignments if a.op == "load")
    fact = prog._scratch_facts[("p.teal", load.location.line)]
    assert fact.values == frozenset({("p.teal", 3, 1)})
    assert not fact.selectors
    assert _reaches_log(body)


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
        "global GroupSize\nint 9\nstores\n"
        "load 0\npop"
    )
    prog.propagate_constants()
    prog.propagate_scratch_constants()
    load = next(a for a in prog.assignments if a.op == "load")
    assert load.outputs[0].const_value is None
    fact = prog._scratch_facts[("p.teal", load.location.line)]
    assert {(2, 1), (5, 1)} <= {(line, index) for _file, line, index in fact.values}
    assert fact.zero_initialized is False


def test_constant_dynamic_index_is_narrowed_to_one_slot():
    prog = _prog("int 3\nint 5\nstores\nint 3\nloads\npop")
    prog.propagate_constants()
    prog.propagate_scratch_constants()
    prog._ensure_scratch_influence()
    load = next(a for a in prog.assignments if a.op == "loads")
    fact = prog._scratch_facts[("p.teal", load.location.line)]
    assert fact.values == frozenset({("p.teal", 3, 1)})
    assert not fact.zero_initialized and not fact.selectors
    assert load.outputs[0].const_value is not None
    assert int(load.outputs[0].const_value.value, 0) == 5

    untouched = _prog("int 3\nint 5\nstores\nint 4\nloads\npop")
    untouched._ensure_scratch_influence()
    other_load = next(a for a in untouched.assignments if a.op == "loads")
    other_fact = untouched._scratch_facts[("p.teal", other_load.location.line)]
    assert other_fact.zero_initialized and not other_fact.values


def test_lifted_and_dataflow_layers_agree_on_dynamic_scratch():
    """Lifted taint must classify store->``loads`` like coarse dataflow.

    It bridged scratch only for static ``load`` through the legacy
    ``_scratch_stores_for`` shape: ``loads`` got nothing, and unknown-store
    sentinels resolved through ``prog.var(...)`` to None and vanished. An
    attacker value stored to scratch and read back dynamically then reached
    the itxn sinks with the security layer — whose findings are the ONLY
    flows the downstream verifier examines — calling it clean while the
    dataflow layer called it tainted. The DIVERGENCE is the defect."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery

    # The slot selector is deliberately CLEAN (`global GroupSize`): a tainted
    # selector reaches the ``loads`` output through ordinary def-use and would
    # mask the missing VALUE channel this test pins.
    body = (
        "global GroupSize\n"
        "txna ApplicationArgs 0\n"
        "stores\n"
        "global GroupSize\n"
        "loads\nlog"
    )
    assert _reaches_log(body), "dataflow layer must taint the dynamic round-trip"
    prog = _prog(body)
    assert any(h.category == "log-emit"
               for h in TaintQuery(prog).tainted_sinks(precise=True))

    # Control: a constant stored and statically re-read stays clean.
    clean = _prog("int 7\nstore 0\nload 0\nlog")
    assert not TaintQuery(clean).tainted_sinks(precise=True)


def test_unresolvable_selector_marks_the_fact_unknown():
    """A dynamic ``stores`` whose slot operand the sim withdrew must not read
    as selector-INDEPENDENT: the write is already conservative (every slot),
    but ``selectors == {}`` with ``unknown`` unset hid that the CHOICE was
    unknowable — it may be attacker-derived. The sentinel policy of the value
    half now covers the selector half."""
    from tealql.tealtools.ssa.relations import scratch_unknown_loads

    # `perm` rewrites the caller's residual across its band (`cover 3`)
    # AND contains a nested call, so `callee_effects` cannot summarise it
    # exactly and the residual is withdrawn; after `pop`, the `stores`
    # slot operand is exactly such a withdrawn cell.
    body = (
        "int 1\nint 2\nint 3\ncallsub perm\npop\n"
        "txna ApplicationArgs 0\n"
        "stores\n"
        "int 0\nloads\nlog\n"
        "b end\n"
        "perm:\nproto 1 1\nint 7\nint 8\ncover 3\ncallsub pnop\nretsub\n"
        "pnop:\nretsub\n"
        "end:"
    )
    prog = _prog(body)
    loads = next(a for a in prog.assignments if a.op == "loads")
    stores = next(a for a in prog.assignments if a.op == "stores")
    assert stores.inputs and len(stores.inputs) < 2, (
        "fixture drift: the stores slot operand should be a withdrawn cell "
        "(the public rep drops None inputs, so it must be ABSENT here)")
    prog._ensure_scratch_influence()
    fact = prog._scratch_facts[("p.teal", loads.location.line)]
    assert fact.unknown, (
        "an unresolvable slot selector must set `unknown` — the fact "
        "recorded a fully selector-independent write with no marker")
    assert loads.outputs[0] in scratch_unknown_loads(prog)

    # Control: the same value through a static slot stays fully known.
    control = _prog(
        "int 1\nint 2\nint 3\ncallsub perm\npop\n"
        "txna ApplicationArgs 0\n"
        "store 0\n"
        "int 0\nloads\nlog\n"
        "b end\n"
        "perm:\nproto 1 1\nint 7\nint 8\ncover 3\ncallsub pnop\nretsub\n"
        "pnop:\nretsub\n"
        "end:"
    )
    cload = next(a for a in control.assignments if a.op == "loads")
    control._ensure_scratch_influence()
    assert not control._scratch_facts[("p.teal", cload.location.line)].unknown


def test_unknown_scratch_load_is_a_taint_graph_source():
    """A load whose MAY value the SSA could not name has no named source edge
    for the flow rows to draw, so it must surface as a SOURCE node — or every
    flow-row consumer (TaintQuery, group, xcontract) reads the unknown as
    clean while the engines call it tainted."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery

    prog = _prog(
        "int 1\nint 2\nint 3\ncallsub perm\npop\n"
        "txna ApplicationArgs 0\n"
        "stores\n"
        "int 0\nloads\nlog\n"
        "b end\n"
        "perm:\nproto 1 1\nint 7\nint 8\ncover 3\ncallsub pnop\nretsub\n"
        "pnop:\nretsub\n"
        "end:"
    )
    loads = next(a for a in prog.assignments if a.op == "loads")
    q = TaintQuery(prog)
    assert any(n.line == loads.location.line for n in q.all_sources()), (
        "the unknown-scratch load is missing from the source enumeration")
    log_line = next(a for a in prog.assignments if a.op == "log").location.line
    assert q.sources_of(line=log_line), (
        "the sink downstream of the unknown load shows no sources")
