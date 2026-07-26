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


# ---------------------------------------------------------------------------
# Byte-literal encodings the grammar rejects (the second half of the AVM-12 gap)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("literal,raw", [
    ("b64(SGVsbG8=)", b"Hello"),
    ("base64(SGVsbG8=)", b"Hello"),
    ("b64 SGVsbG8=", b"Hello"),
    ("base64 SGVsbG8=", b"Hello"),
    ("b32(NBSWY3DP)", b"hello"),
    ("base32(NBSWY3DP)", b"hello"),
    ("b32 NBSWY3DP", b"hello"),
    ("0x48656c6c6f", b"Hello"),
    ('"Hello"', b"Hello"),
])
def test_every_byte_literal_spelling_decodes(literal, raw):
    """`b64(..)` / `b32(..)` — the ABBREVIATED parenthesised spellings — fell
    through to the utf-8 fallback and decoded to the literal ASCII text
    `b64(SGVsbG8=)`. Worse than failing: a guard comparing against the constant
    silently mis-evaluates against a value the chain never produces."""
    from tealql.tealtools.ast.literals import decode_byte_literal
    assert decode_byte_literal(literal)[0] == raw


@pytest.mark.parametrize("line,op,imm", [
    ("pushbytes base64(SGVsbG8=)", "pushbytes", "0x48656c6c6f"),
    ("bytecblock base64(SGVsbG8=)", "bytecblock", "0x48656c6c6f"),
    ("bytecblock base64(SGVsbG8=) base64(d29ybGQ=)", "bytecblock",
     "0x48656c6c6f 0x776f726c64"),
    ("pushbytess base64(SGVsbG8=) base64(d29ybGQ=)", "pushbytess",
     "0x48656c6c6f 0x776f726c64"),
])
def test_encoded_byte_literal_operands_are_re_encoded(tmp_path, line, op, imm):
    """The grammar accepts `0x..` / `"str"` for these opcodes but not the
    base64/base32 encodings, so the line parsed as an ERROR and the opcode kept
    EMPTY immediates — the constant simply gone. For `bytecblock` that is
    severe: every `bytec_N` in the program then resolves to nothing."""
    body = f"{line}\npop\n" if op != "pushbytess" else f"{line}\npop\npop\n"
    prog = _prog(tmp_path, body, version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert (op, imm) in _ops(prog)


def test_plain_byte_literal_operands_are_left_alone(tmp_path):
    prog = _prog(tmp_path, 'bytecblock 0x48 "hi"\nbytec_0\npop\n', version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("bytecblock", '0x48 "hi"') in _ops(prog)


def test_bytecblock_constant_survives_to_its_bytec_reference(tmp_path):
    """The point of the fix: a `bytec_N` must resolve to the real constant."""
    prog = _prog(tmp_path, "bytecblock base64(SGVsbG8=)\nbytec_0\npop\n", version=10)
    bytec = [a for a in prog.assignments if a.op == "bytec_0"]
    assert bytec and bytec[0].outputs
    cv = getattr(bytec[0].outputs[0], "const_value", None)
    assert cv is not None and cv.value == "0x48656c6c6f", cv


def test_the_avm12_contract_parses_completely():
    """The contract this thread started from: 11 diagnostics -> 0."""
    from pathlib import Path
    p = (Path(__file__).resolve().parent / "experimental_IR_lift" / "puya"
         / "avm_12_Contract" / "src" / "Contract.approval.teal")
    if not p.exists():
        pytest.skip("corpus fixture missing")
    prog = SSAProgram(str(p))
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert any(a.op == "bytecblock" and a.immediates.strip().startswith("0x")
               for a in prog.assignments)


# ---------------------------------------------------------------------------
# `itxna FIELD INDEX` — the op survived with the INDEX silently missing
# ---------------------------------------------------------------------------


def test_itxna_keeps_its_array_index(tmp_path):
    """The grammar's `itxna` rule takes only a field, so the index parsed as a
    stray ERROR. The opcode SURVIVED with `.code == "itxna Logs"` — nastier
    than a drop, because `itxna Logs 0` and `itxna Logs 5` became identical to
    every analysis keyed on the array slot."""
    prog = _prog(tmp_path, "itxna Logs 0\nitxna Logs 5\npop\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    imms = [a.immediates.strip() for a in prog.assignments if a.op == "itxna"]
    assert imms == ["Logs 0", "Logs 5"], imms


@pytest.mark.parametrize("line,imm", [
    ("itxna ApplicationArgs 0", "ApplicationArgs 0"),
    ("itxna ApprovalProgramPages 1", "ApprovalProgramPages 1"),
])
def test_itxna_index_forms(tmp_path, line, imm):
    prog = _prog(tmp_path, f"{line}\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("itxna", imm) in _ops(prog)


def test_itxnas_and_txna_and_gitxna_unaffected(tmp_path):
    prog = _prog(tmp_path, "itxnas Logs\npop\ntxna ApplicationArgs 0\npop\n"
                           "gitxna 0 Logs 1\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    ops = _ops(prog)
    assert ("itxnas", "Logs") in ops
    assert ("txna", "ApplicationArgs 0") in ops
    assert ("gitxna", "0 Logs 1") in ops


# ---------------------------------------------------------------------------
# Labels named after an opcode
# ---------------------------------------------------------------------------


def _labels(prog):
    return sorted(c.rstrip(":").strip() for _, _, c in prog.labels)


def test_label_named_after_an_opcode_is_defined(tmp_path):
    """`pop:` tokenized as the `pop` OPCODE plus a stray `:`, so the label was
    never defined and every branch to it lost its CFG edge. Puya names router
    labels after ABI methods, and `get` / `set` / `pop` / `append` are ordinary
    method names."""
    prog = _prog(tmp_path, "int 0\nb pop\npop:\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert _labels(prog) == ["pop_label"]


def test_match_dispatch_to_opcode_named_labels(tmp_path):
    prog = _prog(tmp_path, "int 0\nmatch pop concat\npop:\nint 1\nreturn\nconcat:\n",
                 version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert _labels(prog) == ["concat_label", "pop_label"]


def test_rename_never_touches_the_opcode_token(tmp_path):
    """A label named `b`, branched to with `b b`: the operand must be renamed
    and the branch opcode left alone. A substring sweep would eat both."""
    prog = _prog(tmp_path, "int 0\nb b\nb:\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert _labels(prog) == ["b_label"]
    assert ("b", "b_label") in _ops(prog)


def test_the_real_pop_opcode_still_pops(tmp_path):
    prog = _prog(tmp_path, "int 0\nint 1\npop\nb store\nstore:\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("pop", "") in _ops(prog)
    assert _labels(prog) == ["store_label"]


def test_ordinary_labels_are_not_renamed(tmp_path):
    prog = _prog(tmp_path, "int 0\nb main\nmain:\n", version=10)
    assert _labels(prog) == ["main"]
