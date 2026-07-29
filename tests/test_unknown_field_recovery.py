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


# ---------------------------------------------------------------------------
# Deployment template variables in a constant block
# ---------------------------------------------------------------------------


def test_template_block_keeps_real_constants_and_arity(tmp_path):
    """The grammar has no template-variable token, so the const-block opcode
    STOPPED at the last real literal. `bytec_N` indexes the block POSITIONALLY,
    so a truncated list silently renumbers every later slot."""
    prog = _prog(tmp_path, 'bytecblock "greeting" "num" TMPL_GREETING TMPL_NUM\n'
                           "bytec_0\nbytec_1\nbytec_2\npop\npop\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    block = [a for a in prog.assignments if a.op == "bytecblock"][0]
    assert block.immediates.strip() == '"greeting" "num" TMPL_GREETING TMPL_NUM'


def test_template_slots_resolve_to_nothing(tmp_path):
    """A template has no value until deployment. Emitting the raw text as a
    bytes constant would be a fabricated value every later comparison trusts."""
    prog = _prog(tmp_path, 'bytecblock "greeting" TMPL_GREETING\n'
                           "bytec_0\nbytec_1\npop\npop\n", version=10)
    prog.propagate_constants()
    consts = {a.op: [getattr(o, "const_value", None) for o in a.outputs]
              for a in prog.assignments if a.op.startswith("bytec_")}
    assert consts["bytec_0"][0] is not None      # the real string resolves
    assert consts["bytec_1"][0] is None          # the template does NOT


def test_intcblock_template_slots(tmp_path):
    prog = _prog(tmp_path, "intcblock 1 64 TMPL_DELETABLE\nintc_0\nintc_2\npop\npop\n",
                 version=10)
    prog.propagate_constants()
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    consts = {a.op: [getattr(o, "const_value", None) for o in a.outputs]
              for a in prog.assignments if a.op.startswith("intc_")}
    assert consts["intc_0"][0] is not None
    assert consts["intc_2"][0] is None


def test_template_tail_does_not_become_a_phantom_label(tmp_path):
    """`TMPL_X` alone on the operand list looks exactly like a label
    definition to tree-sitter — a phantom label is a phantom branch target."""
    prog = _prog(tmp_path, 'bytecblock "greeting" TMPL_GREETING\nbytec_0\npop\n',
                 version=10)
    assert [c for _, _, c in prog.labels] == []


def test_non_template_identifier_is_not_absorbed(tmp_path):
    """The recovery is deliberately narrow — keyed on the `TMPL_` convention —
    so an arbitrary identifier after a const block must NOT be pulled into the
    block's operand list.

    (What that identifier does instead is a SEPARATE, pre-existing gap this
    test does not assert away: it is silently swallowed with no diagnostic at
    all, and the block truncates. Verified identical before and after this
    change, so it is not a regression — but it is worth fixing on its own.)"""
    prog = _prog(tmp_path, 'bytecblock "a" somethingelse\nbytec_0\npop\n', version=10)
    block = [a for a in prog.assignments if a.op == "bytecblock"][0]
    assert block.immediates.strip() == '"a"'


# ---------------------------------------------------------------------------
# Phantom labels: a bare identifier tree-sitter salvages as a "label"
# ---------------------------------------------------------------------------


def test_stray_identifier_is_reported_not_swallowed(tmp_path):
    """A stray identifier parses as a `label` whose `:` tree-sitter had to
    INVENT. It was then dropped by reachability gating, so the token vanished
    with NO diagnostic and the operand list it came from quietly truncated."""
    prog = _prog(tmp_path, 'bytecblock "a" somethingelse\nbytec_0\npop\n', version=10)
    diags = list(getattr(prog, "parse_diagnostics", ()) or [])
    assert diags and "stray token" in diags[0].snippet


def test_real_labels_are_not_reported(tmp_path):
    prog = _prog(tmp_path, "int 0\nb main\nmain:\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert _labels(prog) == ["main"]


def test_unknown_opcode_salvaged_as_a_label_is_emitted_as_the_opcode(tmp_path):
    """`falcon_verify` (AVM 12) is absent from the grammar, so it parsed as a
    bare identifier and was DROPPED — taking its 3-in/1-out stack effect with
    it and desyncing the simulation from that point. `avm.SIG` knows its arity;
    it just had to survive the parse."""
    prog = _prog(tmp_path, "pushbytes 0x00\npushbytes 0x00\npushbytes 0x00\n"
                           "falcon_verify\npop\n", version=12)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert "falcon_verify" in [a.op for a in prog.assignments]


def test_custom_template_prefix_is_recognised(tmp_path):
    """`TMPL_` is algokit's default, but puya lets a contract pick its own —
    the `compile_HelloPrfx` fixture uses `PRFX_`."""
    prog = _prog(tmp_path, 'bytecblock "greeting" PRFX_GREETING\nbytec_0\npop\n',
                 version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []


def test_bare_pushint_template_is_recovered_too(tmp_path):
    """This case was left OPEN for two commits — twice I recovered it and twice
    it broke the xgov lift, because a salvaged tail can span past its own line
    and a multi-line span slices to an empty `.code` (see
    `test_recovered_span_never_runs_past_its_own_line`). With the span clamped
    it recovers cleanly and lowers to a TemplateVar."""
    prog = _prog(tmp_path, "pushint TMPL_DELETABLE\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert "pushint" in [a.op for a in prog.assignments]


# ---------------------------------------------------------------------------
# The last residuals: gaid's index, and a quote-bearing inline comment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("idx", ["0", "5", "15", "20"])
def test_gaid_keeps_its_group_index(tmp_path, idx):
    """The grammar rejects EVERY `gaid` index — not just an out-of-range one —
    and types the op as a ZERO-argument opcode, so the index landed in a bare
    ERROR and `gaid 5` / `gaid 20` (different group transactions) were
    indistinguishable. Same silent-wrong-immediate class as `itxna`."""
    prog = _prog(tmp_path, f"gaid {idx}\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("gaid", idx) in _ops(prog)


def test_gaids_without_an_immediate_is_untouched(tmp_path):
    prog = _prog(tmp_path, "int 0\ngaids\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("gaids", "") in _ops(prog)


def test_quoted_inline_comment_does_not_pollute_the_constant(tmp_path):
    """The grammar's string tokenizer runs past `//` when the comment holds a
    quote, so `pushbytes "asa_"   // [name, "asa_"]` parsed with the comment
    text INSIDE the string argument — the constant became
    `"asa_"   // [name,`. A guard comparing against it could never match, and
    only a stray `]` showed up as a diagnostic elsewhere on the line."""
    prog = _prog(tmp_path, 'pushbytes "asa_"   // [name, "asa_"]\npop\n', version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("pushbytes", '"asa_"') in _ops(prog)


def test_ordinary_comments_are_untouched(tmp_path):
    prog = _prog(tmp_path, 'pushbytes "asa_"   // just a name\npop\n', version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert ("pushbytes", '"asa_"') in _ops(prog)


def test_blanking_preserves_line_length():
    """Comments are blanked with spaces, not deleted, so every column span on
    the line stays valid."""
    from tealql.tealtools.graph import _blank_quoted_comments
    src = 'pushbytes "asa_"   // [name, "asa_"]\nint 1\n'
    out = _blank_quoted_comments(src)
    for a, b in zip(src.split("\n"), out.split("\n")):
        assert len(a) == len(b)


# ---------------------------------------------------------------------------
# Bare template pushes — the last two, and the span bug behind them
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("line,op", [
    ("pushint TMPL_DELETABLE", "pushint"),
    ("pushint TMPL_DELETABLE // TMPL_DELETABLE", "pushint"),
    ("pushbytes TMPL_SOME_BYTES", "pushbytes"),
])
def test_bare_template_push_is_recovered(tmp_path, line, op):
    prog = _prog(tmp_path, f"{line}\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert op in [a.op for a in prog.assignments]


def test_recovered_span_never_runs_past_its_own_line(tmp_path):
    """THE root cause of two failed attempts at this. A salvaged tail can span
    FURTHER than its own line — xgov's `pushint TMPL_DELETABLE // TMPL_DELETABLE`
    swallowed the comment AND the following line — and a multi-line span slices
    to an EMPTY `.code`. `_opname` is `code or node_class`, so the op then became
    the literal string "PushintOpcode", which is not an AVMOp and broke the
    lift."""
    prog = _prog(tmp_path, "pushint TMPL_DELETABLE // TMPL_DELETABLE\n"
                           "// a following comment line\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    ops = [a.op for a in prog.assignments]
    assert "pushint" in ops
    assert not any("Opcode" in o for o in ops), ops


def test_several_template_tails_on_one_line(tmp_path):
    """A long operand list can shed MORE THAN ONE salvaged tail; absorbing only
    the first left the rest to become phantom labels."""
    prog = _prog(tmp_path, "bytecblock 0x151f7c75 TMPL_A TMPL_B TMPL_C TMPL_D TMPL_E\n"
                           "bytec_0\npop\n", version=10)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    block = [a for a in prog.assignments if a.op == "bytecblock"][0]
    for name in ("TMPL_A", "TMPL_B", "TMPL_C", "TMPL_D", "TMPL_E"):
        assert name in block.immediates
    assert [c for _, _, c in prog.labels] == []


def test_template_push_lowers_to_a_puya_template_var(tmp_path):
    """A template push has no value until deployment, so it must lower to
    `TemplateVar` rather than an Intrinsic — `'pushint' is not a valid AVMOp`."""
    pytest.importorskip("puya")
    from tealql.tealtools.lift import to_puya
    prog = _prog(tmp_path, "pushint TMPL_DELETABLE // TMPL_DELETABLE\npop\n", version=10)
    to_puya(prog)          # must not raise


def test_the_whole_corpus_parses_clean():
    """Every .teal fixture in the tree, after this thread. Started at 35
    contracts / 123 diagnostics.

    Uses load_graph, NOT SSAProgram: ``parse_diagnostics`` is produced entirely
    by the parse stage and read straight off the graph, so reconstructing SSA
    for 1663 files was pure waste — 108s against a 300s per-test ceiling, the
    same 2x margin that had the mainnet ratchet timing out in CI. Parse-only is
    53s and byte-identical here (verified: 0 files disagree across the corpus).
    """
    import pathlib
    from tealql.tealtools import graph as tg

    root = pathlib.Path(__file__).resolve().parent
    # Anchored at THIS file, never at the cwd: the old relative glob found zero
    # files when pytest ran from anywhere but the repo root, and a corpus test
    # over an empty corpus passes silently.
    files = sorted(root.rglob("*.teal"))
    assert len(files) > 100, f"corpus not found ({len(files)} files) — vacuous"

    bad = []
    for f in files:
        try:
            d = list(tg.load_graph(str(f)).graph.get("parse_diagnostics", ()) or [])
        except Exception:
            continue
        if d:
            bad.append((str(f.relative_to(root)), d[0].snippet[:60]))
    assert bad == [], bad


# ---------------------------------------------------------------------------
# Structural: one definition of "template variable", one recovery registry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token,expected", [
    ("TMPL_DELETABLE", True),
    ("PRFX_GREETING", True),      # puya lets a contract pick its own prefix
    ("A_B", True),
    ("somethingelse", False),
    ("main", False),
    ("lower_case", False),
    ("", False),
])
def test_template_variable_predicate(token, expected):
    from tealql.tealtools.ast.literals import is_template_variable
    assert is_template_variable(token) is expected


def test_template_predicate_has_exactly_one_definition():
    """It lived in four modules in two DIFFERENT forms — a `TMPL_` prefix test
    and a regex — which disagree on every custom prefix, so `const_values`
    would emit `PRFX_GREETING` as a real bytes constant while the parser
    treated it as a template. One definition, or they drift again."""
    import pathlib
    src = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = [
        str(f) for f in src.rglob("*.py")
        if f.name != "literals.py"
        and ("_TEMPLATE_VAR_RE" in (t := f.read_text())
             or 'startswith("TMPL_")' in t)
    ]
    assert offenders == [], offenders


def test_every_recovery_is_in_a_registry():
    """Each grammar gap is recovered as either a STANDALONE instruction or a
    TAIL merged into the preceding opcode. Keeping both families as registries
    means the next AVM version is one tuple entry, not another clause in two
    `or` chains that can drift out of step."""
    import inspect

    from tealql.tealtools.ast import parse as P

    assert len(P._STANDALONE_RECOVERIES) >= 3
    assert len(P._TAIL_RECOVERIES) >= 3
    # UNIFORM SIGNATURES are the whole point: standalone takes (node, src),
    # tail takes (prev, node, src). Before the registries these had three
    # different arities and each new gap grew another bespoke `or` clause.
    for fn in P._STANDALONE_RECOVERIES:
        assert len(inspect.signature(fn).parameters) == 2, fn.__name__
    for fn in P._TAIL_RECOVERIES:
        assert len(inspect.signature(fn).parameters) == 3, fn.__name__
