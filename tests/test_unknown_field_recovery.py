"""Grammar-rejected FIELD NAMES must be recovered, not dropped.

The tree-sitter-teal grammar hard-codes the set of field names each
field-taking opcode accepts. A field the grammar's list is missing — because a
newer AVM version added it, or simply by omission — parses as an ERROR and the
WHOLE instruction is dropped as an unparseable span.

That is not cosmetic. The push disappears, so the stack simulation every later
analysis is built on is short a value from that point; and `itxn_field` POPS,
so dropping it loses the inner-transaction field write AND leaves the stack one
too deep.

Found by the fuzzer on `txn GroupID`. The real scope was three txn fields
(`GroupID`, `AssetCloseAmount`, `RejectVersion`) plus the `itxn_field` and
`*_params_get` forms — two real AVM-12 corpus contracts went from a parse
diagnostic to none.
"""
from __future__ import annotations

import pytest

from tealql.tealtools.ssa import SSAProgram

_UNKNOWN_TXN_FIELDS = ["GroupID", "AssetCloseAmount", "RejectVersion"]


def _prog(tmp_path, body, version=12):
    p = tmp_path / "prog.teal"
    p.write_text(f"#pragma version {version}\n{body}int 1\nreturn\n")
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return prog


def _ops(prog):
    return [(a.op, a.immediates.strip()) for a in prog.assignments]


@pytest.mark.parametrize("field", _UNKNOWN_TXN_FIELDS)
def test_txn_field_the_grammar_rejects_is_recovered(tmp_path, field):
    prog = _prog(tmp_path, f"txn {field}\npop\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("txn", field) in _ops(prog)


@pytest.mark.parametrize("line,op,imm", [
    ("gtxn 0 GroupID", "gtxn", "0 GroupID"),
    ("itxn GroupID", "itxn", "GroupID"),
    ("gtxn 1 RejectVersion", "gtxn", "1 RejectVersion"),
])
def test_indexed_and_inner_forms_recover(tmp_path, line, op, imm):
    prog = _prog(tmp_path, f"{line}\npop\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert (op, imm) in _ops(prog)


def test_field_WRITE_is_recovered_with_its_pop(tmp_path):
    """`itxn_field` pops. Dropping it lost the write and desynced the stack."""
    prog = _prog(tmp_path, "itxn_begin\nint 0\nitxn_field RejectVersion\nitxn_submit\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("itxn_field", "RejectVersion") in _ops(prog)


def test_params_query_field_is_recovered(tmp_path):
    prog = _prog(tmp_path, "int 0\napp_params_get AppVersion\npop\npop\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("app_params_get", "AppVersion") in _ops(prog)


def test_greedy_error_recovery_keeps_every_instruction(tmp_path):
    """tree-sitter ERROR recovery is GREEDY: adjacent unknown-field reads
    collapse into ONE node. Recovering only the first silently swallowed the
    rest — the same trap the named-int recovery documents."""
    prog = _prog(tmp_path, "txn GroupID\ntxn RejectVersion\ntxn AssetCloseAmount\n"
                           "pop\npop\npop\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    ops = _ops(prog)
    for f in _UNKNOWN_TXN_FIELDS:
        assert ("txn", f) in ops


def test_known_fields_are_untouched(tmp_path):
    prog = _prog(tmp_path, "txn Sender\nitxn_begin\nitxn_field Receiver\nitxn_submit\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("txn", "Sender") in _ops(prog)
    assert ("itxn_field", "Receiver") in _ops(prog)


def test_recovered_field_reaches_the_lift_correctly_typed(tmp_path):
    """The original fuzzer report: `txn GroupID` vanished from the lifted IR,
    taking `log`'s operand with it. GroupID is 32 bytes, so it must type bytes."""
    puya = pytest.importorskip("puya")  # noqa: F841
    from tealql.security.common import ir_lifter
    from tealql.tealtools.lift import pre_ir

    prog = _prog(tmp_path, "txn GroupID\nlog\n")
    lifter = ir_lifter(prog)
    assert lifter is not None
    rendered = [op.render() if hasattr(op, "render") else str(op)
                for b in pre_ir.blocks(lifter.subs) for op in b.ops]
    assert any("(txn GroupID)" in r and "bytes" in r for r in rendered), rendered
    assert not any(r.strip() == "(log)" for r in rendered), "log lost its operand"


def test_real_avm12_contracts_parse_clean():
    """Two AVM-12 corpus contracts carried a parse diagnostic purely because of
    `txn RejectVersion`."""
    from pathlib import Path
    root = Path(__file__).resolve().parent / "experimental_IR_lift" / "puya"
    for name in ("avm_12_ContractV0/src/ContractV0.approval.teal",
                 "avm_12_ContractV1/src/ContractV1.approval.teal"):
        p = root / name
        if not p.exists():
            pytest.skip(f"corpus fixture missing: {name}")
        prog = SSAProgram(str(p))
        assert list(getattr(prog, "parse_diagnostics", ()) or []) == [], name
