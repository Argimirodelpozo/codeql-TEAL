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
    return SSAProgram(str(p))


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
    from tealql.tealtools.graph import _byte_literal

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
