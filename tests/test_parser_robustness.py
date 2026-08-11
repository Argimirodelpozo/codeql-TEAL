"""Adversarial / hand-written TEAL must never produce a silently-wrong graph.

Every regression gate in this repo runs on Puya-COMPILED output, which is
strictly one instruction per line, never uses semicolons or named-int pseudo-op
runs, and never duplicates a label. These pin the hand-written forms that
previously parsed to a confidently wrong graph with no diagnostic at all.
"""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, src: str, name: str = "t.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text(src)
    # strict=False: these tests exercise the DIAGNOSTIC surface itself.
    return SSAProgram(str(p), strict=False)


def test_consecutive_named_ints_are_all_recovered(tmp_path):
    """Greedy ERROR recovery collapses consecutive `int <name>` pseudo-ops into
    one node; recovering only the first two children silently swallowed every
    instruction after the first, with an EMPTY diagnostics list."""
    prog = _prog(tmp_path, "#pragma version 8\nint pay\nint axfer\n+\nreturn\n")
    ops = [a.op for a in prog.assignments]
    assert ops.count("int") == 2, f"lost a named int: {ops}"
    # And the consumer still gets both operands.
    (plus,) = [a for a in prog.assignments if a.op == "+"]
    assert len(plus.inputs) == 2


def test_named_int_values_resolve(tmp_path):
    prog = _prog(tmp_path, "#pragma version 8\nint pay\nint axfer\n+\nreturn\n")
    prog.propagate_constants()
    vals = [str(o.const_value) for a in prog.assignments if a.op == "int"
            for o in a.outputs if o.const_value is not None]
    assert vals == ["1", "4"], f"pay=1, axfer=4 expected; got {vals}"


def test_multi_instruction_line_is_diagnosed(tmp_path):
    """`int 1; int 2` is legal TEAL but collapses to ONE node under the
    (file, line) identity the whole IR is keyed by. It must never pass
    silently — a security scan of a file we mis-parsed must not read clean."""
    prog = _prog(tmp_path, "#pragma version 8\nint 1; int 2\n+\nreturn\n")
    assert prog.parse_diagnostics, "multi-instruction line produced NO diagnostic"
    assert any("one line" in d.snippet for d in prog.parse_diagnostics)


def test_single_instruction_lines_have_no_diagnostics(tmp_path):
    """The normal form must stay diagnostic-free (no false alarms)."""
    prog = _prog(tmp_path, "#pragma version 8\nint 1\nint 2\n+\nreturn\n")
    assert not prog.parse_diagnostics


def test_duplicate_label_is_diagnosed_and_resolves_to_first(tmp_path):
    """The assembler rejects duplicate labels. Branch resolution can only pick
    one, so the other definition is pruned as unreachable — say so."""
    prog = _prog(tmp_path, """#pragma version 8
b x
x:
int 1
return
x:
int 0
return
""")
    assert any("duplicate label" in d.snippet for d in prog.parse_diagnostics), (
        f"no duplicate-label diagnostic: {prog.parse_diagnostics}")


def test_non_ascii_byte_literal_encodes_utf8(tmp_path):
    """`byte "café"` must normalise to the assembler's UTF-8 bytes. The old
    graph.py copy of the decoder emitted ord(c) per char (636166e9), so every
    guard comparing against the constant mis-evaluated."""
    from tealql.tealtools.frontend.graph import _byte_literal

    assert _byte_literal('"café"') == "café".encode("utf-8")
    assert _byte_literal('"café"').hex() == "636166c3a9"


def test_malformed_byte_escape_does_not_crash():
    """Untrusted source must not raise out of the literal decoder (a non-
    LiftError escaping the pipeline reads as a genuine bug)."""
    from tealql.tealtools.ast.literals import _teal_str_bytes

    assert _teal_str_bytes(r"a\xzz")            # bad hex digits -> literal
    assert _teal_str_bytes(r"a\x4")             # truncated -> literal, not 0x04
    assert _teal_str_bytes(r"a\x41") == b"aA"   # valid still decodes


def test_per_file_constant_blocks(tmp_path):
    """intcblock/bytecblock are PER FILE. Pooling them across the graph made
    two-file targets (the documented approval+clear form) resolve nothing, and
    a single block resolve the OTHER file's intc against the wrong table."""
    d = tmp_path / "pair"
    d.mkdir()
    (d / "a.teal").write_text("#pragma version 8\nintcblock 1 7\nintc_1\nreturn\n")
    (d / "b.teal").write_text("#pragma version 8\nintcblock 2 9\nintc_1\nreturn\n")
    prog = SSAProgram(str(d))
    prog.propagate_constants()
    got = {
        a.location.file.rsplit("/", 1)[-1]: str(a.outputs[0].const_value)
        for a in prog.assignments
        if a.op == "intc_1" and a.outputs and a.outputs[0].const_value is not None
    }
    assert got == {"a.teal": "7", "b.teal": "9"}, got


def test_bnot_is_a_logic_opcode(tmp_path):
    """`b~` had no mnemonic, so it parsed as a generic ZeroArgumentOpcode and
    every isinstance(n, LogicOpcode) family query missed it."""
    from tealql.tealtools.ast.ast import BnotOpcode, LogicOpcode, node_class_for_mnemonic

    cls = node_class_for_mnemonic("b~")
    assert cls is BnotOpcode
    assert issubclass(cls, LogicOpcode)


def test_comment_ending_in_backslash_does_not_swallow_next_line(tmp_path):
    r"""A TEAL comment runs to END OF LINE -- the AVM has no line-continuation, but
    the tree-sitter grammar lets a trailing backslash continue the `comment` node
    onto the next line, parsing that instruction as comment text.

    It vanished SILENTLY: `comment` is trivia, so no ERROR node and no diagnostic --
    the block just lost a stack push and every later stack reference in it shifted by
    one slot. Puya writes the contract's own Python source into comments and a Python
    line-continuation ends in exactly that backslash, so this fires on ordinary
    compiled output (found in Folks Finance's Wormhole NTT NttManager, where the
    swallowed `bytec_3` made a later `uncover 3` read a frame slot instead of the
    pushed box key).
    """
    src = ("#pragma version 10\n"
           "bytecblock 0x00 0x11 0x22 0x33\n"
           "// self.buckets[id].capacity = bucket.limit \\\n"
           "bytec_3\n"
           "bytec_2\n"
           "concat\n"
           "log\n"
           "int 1\n"
           "return\n")
    prog = _prog(tmp_path, src)
    ops = [a.op for a in prog.assignments]
    assert "bytec_3" in ops, f"the backslash comment swallowed the next line: {ops}"
    assert not prog.parse_diagnostics
    # and the swallowed push is really back on the stack, not just present
    (cat,) = [a for a in prog.assignments if a.op == "concat"]
    assert len(cat.inputs) == 2, f"stack shifted: {cat.inputs}"


def test_comment_backslash_parses_identically_to_no_backslash(tmp_path):
    """The neutralised backslash must change nothing else: same ops, same order."""
    body = ("#pragma version 10\n"
            "bytecblock 0x00 0x11 0x22 0x33\n"
            "// a comment{}\n"
            "bytec_3\n"
            "bytec_2\n"
            "concat\n"
            "log\n"
            "int 1\n"
            "return\n")
    with_bs = [a.op for a in _prog(tmp_path, body.format(" \\"), "a.teal").assignments]
    without = [a.op for a in _prog(tmp_path, body.format(""), "b.teal").assignments]
    assert with_bs == without, f"{with_bs} != {without}"


def test_double_slash_inside_a_byte_literal_is_not_a_comment(tmp_path):
    """The fix must find the comment start the way TEAL does: `//` inside a quoted
    byte literal is DATA (`pushbytes "http://x"`), not the start of a comment, so a
    backslash later on that line is still inside the real comment."""
    src = ('#pragma version 10\n'
           'bytecblock 0x00 0x11 0x22 0x33\n'
           'pushbytes "a//b" // a real comment \\\n'
           'bytec_3\n'
           'concat\n'
           'log\n'
           'int 1\n'
           'return\n')
    prog = _prog(tmp_path, src)
    ops = [a.op for a in prog.assignments]
    assert "pushbytes" in ops and "bytec_3" in ops, ops
    prog.propagate_constants()
    vals = [str(o.const_value) for a in prog.assignments if a.op == "pushbytes"
            for o in a.outputs if o.const_value is not None]
    # the literal may render quoted or as hex; either way it must still be `a//b`
    assert vals in (['"a//b"'], ["0x" + b"a//b".hex()]), \
        f"the literal's slashes were eaten: {vals}"

def test_scoped_subroutine_label_parses(tmp_path):
    """`a::b` is a legal label to a compiler and unparseable to the grammar.

    puya-ts names subroutines after the source that produced them, e.g.
    `callsub smart_contracts/main/contract.algo.ts::Main.cardAssetOptIn`. The grammar's label rule
    stops at the first `:` -- which is what TERMINATES a label definition -- so the `::` and
    everything after it became an unparsed span and the whole subroutine dropped out of the
    analysis. On auto-draw-card's Main that silently removed 5 spans.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "callsub smart_contracts/main/contract.algo.ts::Main.foo\n"
                           "int 1\n"
                           "return\n"
                           "\n"
                           "smart_contracts/main/contract.algo.ts::Main.foo:\n"
                           "proto 0 0\n"
                           "retsub\n")
    assert not prog.parse_diagnostics, f"scoped label unparsed: {prog.parse_diagnostics}"
    ops = [a.op for a in prog.assignments]
    assert "callsub" in ops and "retsub" in ops, f"subroutine dropped: {ops}"

def test_double_colon_inside_a_byte_literal_is_data(tmp_path):
    """The rename must not touch a quoted literal: `pushbytes "a::b"` is DATA, and rewriting it
    would corrupt the program rather than rename part of it."""
    prog = _prog(tmp_path, '#pragma version 11\npushbytes "a::b"\nlen\nreturn\n')
    prog.propagate_constants()
    vals = [str(o.const_value) for a in prog.assignments if a.op == "pushbytes"
            for o in a.outputs if o.const_value is not None]
    assert vals and "a::b" in vals[0].replace('"', '') or vals == ["0x" + b"a::b".hex()], vals


def test_underscore_separated_integer_parses(tmp_path):
    """`1_000_000` is a legal integer to the ASSEMBLER and unparseable to the grammar.

    Verified against go-algorand: `intcblock 1_000_000` assembles and runs. The grammar ends the
    integer at the underscore, so the rest of the constant block becomes an unparsed span and the
    program is refused at line 2 -- before any analysis begins. TEALScript passes the TypeScript
    numeric separator straight through, so this hits every TEALScript contract with a readable
    constant; both of Reti's do.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "intcblock 0 1 1_000_000 2_100_000\n"
                           "intc 2\nintc 3\n+\nreturn\n")
    assert not prog.parse_diagnostics, f"underscore int unparsed: {prog.parse_diagnostics}"
    prog.propagate_constants()
    vals = {int(str(o.const_value)) for a in prog.assignments if a.op.startswith("intc")
            for o in a.outputs if o.const_value is not None}
    assert 1000000 in vals and 2100000 in vals, f"separators not stripped: {vals}"


def test_asterisk_label_parses(tmp_path):
    """TEALScript names returns `*addStake*return` and router targets `*call_NoOp`.

    Verified against go-algorand: `b *foo*return` / `*foo*return:` assembles and runs.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "b *addStake*return\n"
                           "*addStake*return:\n"
                           "int 1\nreturn\n")
    assert not prog.parse_diagnostics, f"asterisk label unparsed: {prog.parse_diagnostics}"
    assert any(a.op == "b" for a in prog.assignments) or prog.labels, "branch/label dropped"


def test_asterisk_opcodes_survive_the_label_rewrite(tmp_path):
    """`*` is multiply and `b*` is byteslice-multiply — neither may be renamed.

    TEALScript's router uses the bare `*` two lines above `switch *call_NoOp ...`, so both readings
    of the character appear in one idiom. Keying the rewrite on the character BEFORE the asterisk
    turns `b*` into `b_`, replacing a real instruction with an undefined mnemonic.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "int 2\nint 3\n*\n"
                           "itob\npushbytes 0x02\nb*\n"
                           "pop\nint 1\nreturn\n")
    assert not prog.parse_diagnostics, f"asterisk opcode unparsed: {prog.parse_diagnostics}"
    ops = [a.op for a in prog.assignments]
    assert "*" in ops, f"multiply opcode lost: {ops}"
    assert "b*" in ops, f"byteslice-multiply lost: {ops}"


def test_immediateless_extract_parses(tmp_path):
    """`extract` with no immediates pops start/length from the stack — a synonym for `extract3`.

    Verified against go-algorand: `pushbytes 0x..; int 0; int 8; extract; btoi` assembles and runs.
    The grammar knows only the two-immediate form, so the bare one became an unparsed span, the
    block lost an instruction, and every later stack reference in it shifted -- which surfaced far
    downstream as a bogus `btoi` type error rather than as a parse problem.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "\tpushbytes 0x0102030405060708\n"
                           "\tint 0\n\tint 8\n"
                           "\textract\n"
                           "\tbtoi\n\treturn\n")
    assert not prog.parse_diagnostics, f"bare extract unparsed: {prog.parse_diagnostics}"
    ops = [a.op for a in prog.assignments]
    assert "extract3" in ops or "extract" in ops, f"extract dropped: {ops}"
    assert "btoi" in ops, f"instruction after extract lost: {ops}"


def test_immediateless_extract_at_column_zero_stays_a_diagnostic(tmp_path):
    """The documented limit of the rewrite, pinned so it cannot surprise anyone.

    Spelling `extract` as `extract3` costs a byte, and it is paid for by consuming the preceding
    whitespace so every offset downstream is unchanged. With no byte to spend the line is left
    alone and the span is REPORTED -- a diagnostic beats silently shifting every column after it.
    Every compiler indents its instructions, so this is unreachable in practice; it is here to say
    which way the tradeoff falls rather than to bless the shift.
    """
    prog = _prog(tmp_path, "#pragma version 11\n"
                           "pushbytes 0x01\nint 0\nint 1\n"
                           "extract\n"
                           "btoi\nreturn\n")
    assert prog.parse_diagnostics, "unindented bare extract should still be reported"


def test_numeric_separators_inside_byte_literals_are_data(tmp_path):
    """The underscore normaliser must not rewrite QUOTED string data.

    `pushbytes "1_000"` is DATA: packing it to `"1000 "` strips the underscore
    and injects a space INSIDE the program's bytes — silent value corruption,
    the exact class the label rewriter's in-string skip exists to prevent. The
    normaliser gets the same skip; unquoted integers on the same line still
    normalise."""
    prog = _prog(tmp_path, '#pragma version 8\n'
                           'pushbytes "1_000"\n'
                           'intcblock 1_000\n'
                           'intc 0\npop\nlog\nint 1\nreturn\n')
    assert not prog.parse_diagnostics, f"unparsed: {prog.parse_diagnostics}"
    vals = [o.const_value for a in prog.assignments if a.op == "pushbytes"
            for o in a.outputs if o.const_value is not None]
    assert vals and bytes.fromhex(str(vals[0]).removeprefix("0x")) == b"1_000", (
        f"quoted literal data was rewritten: {vals}")
    prog.propagate_constants()
    ints = {int(str(o.const_value)) for a in prog.assignments
            if a.op.startswith("intc")
            for o in a.outputs if o.const_value is not None}
    assert 1000 in ints, f"unquoted separator no longer normalised: {ints}"


def test_sha512_lifts_as_itself(tmp_path):
    """AVM v13 `sha512` must lift as its OWN op — never conflated with
    `sha512_256` (truncated form, DIFFERENT IV, unrelated digests) — and the
    puya lowering, which cannot represent it (upstream AVMOp enum gap), must
    refuse with a typed LiftError rather than crash."""
    from tealql.tealtools.diagnostics.errors import LiftError
    from tealql.tealtools.lift import lift
    from tealql.tealtools.lift.to_puya_ir import to_puya

    prog = _prog(tmp_path, "#pragma version 13\n"
                           "pushbytes 0x01\nsha512\nlen\nint 64\n==\nreturn\n")
    assert not prog.parse_diagnostics
    sha = next(a for a in prog.assignments if a.op == "sha512")
    assert sha.inputs, "sha512 must consume its bytes operand (arity 1,1)"
    rendered = lift(prog).render()
    assert "sha512" in rendered and "sha512_256" not in rendered, (
        f"sha512 lost its identity in the lift:\n{rendered}")
    try:
        to_puya(prog)
    except LiftError:
        pass                # honest typed refusal: puya has no sha512 AVMOp
