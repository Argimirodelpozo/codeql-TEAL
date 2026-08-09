"""Coverage guards for generic AVM value dependencies."""
from __future__ import annotations

from tealql.tealtools.language.avm import (
    SIG,
    VALUE_FLOW_OPAQUE_READ_OPS,
    VALUE_FLOW_SPECIAL_OPS,
    _FRAME_OVERRIDES,
    _IMMEDIATE_ARITY_OPS,
    is_known_op,
    value_dependency_kind,
)
from tealql.tealtools.dataflow.engine import (
    ATTACKER_CONTROL_RULES,
    CONSERVATIVE_VALUE_PROPAGATION_RULE,
    DEFAULT_RULES,
    OPAQUE_READ_RULE,
    Sink,
    Source,
    TaintAnalysis,
)
from tealql.tealtools.ssa.presentation import _PURE_OPS
from tealql.tealtools.ssa import Assignment, Location, SSAProgram, SSAVar


def _assignment(op: str, n_in: int, n_out: int) -> Assignment:
    loc = Location("coverage.teal", 1)
    inputs = [SSAVar(loc.file, loc.line, i + 1) for i in range(n_in)]
    outputs = [SSAVar(loc.file, loc.line, i + 1 + n_in) for i in range(n_out)]
    return Assignment(
        outputs=outputs,
        op=op,
        immediates="",
        inputs=inputs,
        location=loc,
        ast_code=op,
    )


def test_every_fixed_value_opcode_has_a_dependency_category():
    value_ops = {op for op, (n_in, n_out) in SIG.items() if n_in and n_out}
    categories = {op: value_dependency_kind(op) for op in value_ops}
    assert set(categories.values()) <= {
        "special", "shuffle", "opaque-read", "derived"
    }
    assert "unknown" not in categories.values()
    assert "none" not in categories.values()


def test_every_known_opcode_is_classified_not_unknown():
    known = set(SIG) | set(_FRAME_OVERRIDES) | set(_IMMEDIATE_ARITY_OPS)
    assert {op for op in known if value_dependency_kind(op) == "unknown"} == set()


def test_special_and_opaque_categories_are_disjoint_known_ops():
    assert not (VALUE_FLOW_SPECIAL_OPS & VALUE_FLOW_OPAQUE_READ_OPS)
    assert all(is_known_op(op) for op in VALUE_FLOW_SPECIAL_OPS)
    assert all(is_known_op(op) for op in VALUE_FLOW_OPAQUE_READ_OPS)


def test_default_rules_end_in_explicit_opaque_and_conservative_policies():
    assert DEFAULT_RULES[-2:] == [
        OPAQUE_READ_RULE, CONSERVATIVE_VALUE_PROPAGATION_RULE
    ]


def test_new_unlisted_transform_propagates_to_every_output():
    # Crypto verification was intentionally absent from the old transform
    # allow-list and therefore silently killed taint. It now reaches the
    # validity result via the conservative derived-value category.
    assignment = _assignment("ed25519verify", 3, 1)
    assert value_dependency_kind(assignment.op) == "derived"
    assert CONSERVATIVE_VALUE_PROPAGATION_RULE.flows(assignment, [2]) == [1]


def _flows_to(src: str, sink_op: str) -> bool:
    prog = SSAProgram.from_text(src, name="flow.teal")
    return bool(TaintAnalysis(
        prog,
        sources=[Source("argument", lambda a: a.op == "txna")],
        sinks=[Sink("consumer", lambda a: a.op == sink_op, lambda a: 1)],
        default_rules=ATTACKER_CONTROL_RULES,
    ).detect())


def test_crypto_validity_result_no_longer_silently_kills_taint():
    assert _flows_to(
        "#pragma version 8\n"
        "txna ApplicationArgs 0\nbyte 0x00\nbyte 0x00\n"
        "ed25519verify\nreturn\n",
        "return",
    )


def test_dynamic_transaction_selector_flows_to_selected_value():
    assert _flows_to(
        "#pragma version 8\n"
        "txna ApplicationArgs 0\nbtoi\ntxnas ApplicationArgs\nlen\nreturn\n",
        "return",
    )


def test_dynamic_slice_selector_and_value_both_control_the_result():
    """Choosing a byte from a clean buffer is attacker influence just like
    choosing a scratch slot.  The value-tainted spelling is the control that
    the long-standing slice dependency must continue to preserve.
    """
    assert _flows_to(
        "#pragma version 8\n"
        "byte 0x0102030405060708090a0b0c0d0e0f10\n"
        "txna ApplicationArgs 0\nbtoi\ngetbyte\nitob\nlog\n"
        "int 1\nreturn\n",
        "log",
    )
    assert _flows_to(
        "#pragma version 8\n"
        "txna ApplicationArgs 0\nint 0\ngetbyte\nitob\nlog\n"
        "int 1\nreturn\n",
        "log",
    )


def test_opaque_state_read_is_an_explicit_no_flow_boundary():
    assert not _flows_to(
        "#pragma version 8\n"
        "txna ApplicationArgs 0\napp_global_get\npop\nint 1\nreturn\n",
        "pop",
    )


def test_cleanup_pure_table_contains_only_modelled_canonical_opcodes():
    assert {op for op in _PURE_OPS if not is_known_op(op)} == set()
