"""Pins for the 2026-09-02 audit's parse-floor defects (findings.md §5).

Every expected constant here was taken from `goal clerk compile` + `-D`
(the go-algorand assembler is the oracle for tokenizer / literal semantics).
One test per defect, with the control folded in."""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram


def _prog(src: str, version: int = 10) -> SSAProgram:
    prog = SSAProgram({"p.teal": f"#pragma version {version}\n{src}"}, strict=False)
    prog.propagate_constants()
    return prog


def _diags(prog) -> list:
    return list(getattr(prog, "parse_diagnostics", ()) or [])


def _consts(prog, *ops: str) -> list:
    """``[(op, [const_value or None per output]), …]`` in source order for
    the assignments whose op is one of ``ops``."""
    out = []
    for a in sorted(prog.assignments, key=lambda a: a.location.line):
        if a.op in ops:
            out.append((a.op, [str(o.const_value.value) if o.const_value else None
                               for o in a.outputs]))
    return out


# ---------------------------------------------------------------------------
# 5.3 — comment / tokenizer semantics == go-algorand `tokensFromLine`
# ---------------------------------------------------------------------------


def test_tokenizer_follows_go_algorand_tokens_from_line():
    """`//` is a comment anywhere outside a string or a base64 payload; a `b64`
    / `base64` keyword (or `b64(`) puts the tokenizer in base64 state so a
    payload's leading `//` is DATA. The old token-boundary rule read
    `b64 ////` as a comment (the whole constant block vanished) and kept a
    glued `//c` as data (`byte "a"//c` dropped, `method "x()void"//c` hashed
    to a WRONG selector with no diagnostic)."""
    from tealql.tealtools.ast.literals import (
        scan_line, strip_inline_comment, tokenize_operands,
    )

    # (a) keyword-form payloads beginning with `//` — goal: 0x000fff 0x000fff
    # 0xffffff 0xffffff, every bytec resolved, no parse warning.
    prog = _prog("bytecblock b64 AA// base64(AA//) b64 //// base64(////)\n"
                 "bytec_0\nlen\nbytec_1\nlen\n+\nbytec_2\nlen\n+\n"
                 "bytec_3\nlen\n+\nreturn\n")
    assert _diags(prog) == []
    assert _consts(prog, "bytec_0", "bytec_1", "bytec_2", "bytec_3") == [
        ("bytec_0", ["0x000fff"]), ("bytec_1", ["0x000fff"]),
        ("bytec_2", ["0xffffff"]), ("bytec_3", ["0xffffff"]),
    ]
    prog = _prog("pushbytess b64 AA// base64(AA//) b64 ////\n"
                 "len\ncover 2\nlen\ncover 1\nlen\n+\n+\nreturn\n")
    assert _diags(prog) == []
    (pbs,) = _consts(prog, "pushbytess")
    assert sorted(pbs[1]) == ["0x000fff", "0x000fff", "0xffffff"]
    prog = _prog("byte b64 //8=\nlen\nreturn\n")           # goal: 0xffff
    assert _diags(prog) == [] and _consts(prog, "pushbytes") == [("pushbytes", ["0xffff"])]

    # (b) a `//` glued to the last operand IS a comment (goal: pushes "a",
    # selector 0xb13faba1 = sha512_256("x()void")[:4]); controls: `//` inside a
    # string is data, a quote inside the comment stays in the comment.
    prog = _prog('byte "a"//c\nlen\nmethod "x()void"//c\nlen\n+\n'
                 'byte "a//b"\nlen\n+\nbyte "x" // byte "y"\nlen\n+\nreturn\n')
    assert _diags(prog) == []
    assert _consts(prog, "pushbytes") == [
        ("pushbytes", ["0x61"]), ("pushbytes", ["0xb13faba1"]),
        ("pushbytes", ["0x612f2f62"]), ("pushbytes", ["0x78"]),
    ]

    # (c) Go's string rule: a quote right after a backslash never closes the
    # string, so `pushbytess "a\\" "b"` is ONE constant (goal: 0x615c22202262),
    # not two — an odd-run escape rule fabricated a second stack slot.
    prog = _prog('pushbytess "a\\\\" "b"\npop\nint 1\nreturn\n')
    assert _consts(prog, "pushbytess") == [("pushbytess", ["0x615c22202262"])]

    # The shared primitive itself, on the shapes above.
    assert strip_inline_comment('method "x()void"//c') == 'method "x()void"'
    assert strip_inline_comment("bytecblock b64 //// base64(//)") == \
        "bytecblock b64 //// base64(//)"
    assert strip_inline_comment('byte "a//b" // c') == 'byte "a//b" '
    assert tokenize_operands("b64 //// 0x01 // c", fold_byte_keywords=True) == \
        ["b64 ////", "0x01"]
    assert scan_line("int 1; int 2")[0] == [(0, 3), (4, 5), (5, 6), (7, 10), (11, 12)]


def test_method_line_ranges_tokenize_like_the_assembler():
    """`abi._dispatch_methods` split the router line at the first `//`, so a
    string operand containing `//` cut the selector list short and the ARC-56
    table could not resolve the selectors after it. It now shares the
    assembler's tokenizer (a `//` inside a string is data)."""
    from tealql.tealtools.metadata.abi import method_line_ranges, parse_signature

    table = {"0xb13faba1": parse_signature("x()void")}
    src = ("#pragma version 10\n"
           "txna ApplicationArgs 0\n"
           'pushbytess "a//b" 0xb13faba1\n'
           "match m_x\n"
           "err\n"
           "m_x:\n"
           "int 1\nreturn\n")
    ranges = method_line_ranges(src, table)
    assert [(a, b, m.name) for a, b, m in ranges] == [(6, 8, "x")]
