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


# ---------------------------------------------------------------------------
# 5.1 — `int <Name>` / `txn <field>` split by a comment lost its immediate
# ---------------------------------------------------------------------------


def _ops(prog, op: str) -> list:
    return [a for a in sorted(prog.assignments, key=lambda a: a.location.line)
            if a.op == op]


def test_comment_split_named_int_and_txn_field_keep_their_immediate():
    """With a `// comment` on the same or the next line, tree-sitter emits a
    bare `int` (empty immediate) plus a phantom label holding the name, and the
    push lost its constant: `txn OnCompletion; int DeleteApplication; ==`
    became `== <unknown>`, so `detections --all` reported is-updatable /
    timelock-upgrade on a creator-guarded delete arm that the comment-free
    twin (identical bytecode per goal) did not. Controls: an unknown name stays
    refused, `pushint <Name>` stays refused (goal rejects it), and a bare
    `int TMPL_X` — previously swallowed with NO node and NO diagnostic — is
    now a const-free push."""
    from tealql.security import DETECTORS

    body = ("txn OnCompletion\nint DeleteApplication\n{c}==\nreturn\n")
    for comment in ("// only creator may delete\n", "    // indented\n"):
        prog = _prog(body.format(c=comment), version=8)
        assert _diags(prog) == []
        assert _consts(prog, "int") == [("int", ["5"])], comment
    prog = _prog("txn OnCompletion\nint DeleteApplication // c\n==\nreturn\n", version=8)
    assert _diags(prog) == [] and _consts(prog, "int") == [("int", ["5"])]
    # greedy ERROR: the next line's named int rides along and must be re-emitted
    prog = _prog("int DeleteApplication\n// c\nint NoOp\n+\nreturn\n", version=8)
    assert _diags(prog) == []
    assert _consts(prog, "int") == [("int", ["5"]), ("int", ["0"])]
    # txn-family twin: the grammar-unknown field is MISSING, the name a phantom
    prog = _prog("txn RejectVersion\n// c\nreturn\n", version=8)
    assert _diags(prog) == [] and [a.immediates for a in _ops(prog, "txn")] == ["RejectVersion"]
    prog = _prog("gtxn 0 RejectVersion\n// c\nreturn\n", version=8)
    assert _diags(prog) == [] and [a.immediates for a in _ops(prog, "gtxn")] == ["0 RejectVersion"]

    # controls: an unknown name never resolves, whichever shape tree-sitter
    # salvages it into (a bare ERROR, or `int` + phantom label)
    for src_ in ("int Foo\n// c\nreturn\n", "int Foo // c\nreturn\n",
                 "txn OnCompletion\nint Foo\n// c\n==\nreturn\n"):
        assert _consts(_prog(src_, version=8), "int") in ([], [("int", [None])]), src_
    prog = _prog("pushint DeleteApplication\nreturn\n", version=8)
    assert _ops(prog, "pushint") == [] and _diags(prog) != []
    prog = _prog("int TMPL_X\npop\nint 1\nreturn\n")
    assert _consts(prog, "int") == [("int", [None]), ("int", ["1"])]

    # the verdict: the two detectors that flipped, identical on both twins
    src = ("txn ApplicationID\nbz create\ntxn OnCompletion\nint DeleteApplication\n"
           "{c}==\nbnz delete\ntxn OnCompletion\nint UpdateApplication\n==\n"
           "bnz update\ntxn OnCompletion\nint NoOp\n==\nassert\nint 1\nreturn\n"
           "delete:\ntxn Sender\nglobal CreatorAddress\n==\nassert\nint 1\nreturn\n"
           "update:\ntxn Sender\nglobal CreatorAddress\n==\nassert\nint 1\nreturn\n"
           "create:\nint 1\nreturn\n")
    twins = [_prog(src.format(c=c), version=8) for c in ("", "// only the creator may delete\n")]
    for name in ("is-updatable", "timelock-upgrade"):
        counts = [len(DETECTORS[name](p).detect()) for p in twins]
        assert counts[0] == counts[1], (name, counts)


# ---------------------------------------------------------------------------
# 5.2 — `gtxn N <unknown field>` + next txn read → one mangled multi-line node
# ---------------------------------------------------------------------------


def test_mangled_multiline_txn_node_is_resegmented_per_line():
    """`gtxn 0 RejectVersion` followed by `gtxn 0 Sender` parsed as ONE
    `gtxn_opcode` spanning both lines (nested ERROR); the node's `.code` was
    empty, the op fell back to `GtxnOpcode` with arity (0, 0) in `unknown_ops`
    and both pushes were lost. Control: the `txn` twin, which the grammar
    splits into a top-level ERROR and was already recovered."""
    for mnem in ("gtxn", "gitxn"):
        prog = _prog(f"{mnem} 0 RejectVersion\n{mnem} 0 Sender\nlen\n+\nreturn\n", version=13)
        assert _diags(prog) == [], mnem
        assert not getattr(prog, "unknown_ops", set()), mnem
        assert [a.immediates for a in _ops(prog, mnem)] == ["0 RejectVersion", "0 Sender"], mnem
        (ln,) = _ops(prog, "len")
        assert len(ln.inputs) == 1 and ln.inputs[0].identifier.endswith("@L3"), mnem
    prog = _prog("txn RejectVersion\ntxn Sender\nlen\n+\nreturn\n", version=13)
    assert _diags(prog) == [] and [a.immediates for a in _ops(prog, "txn")] == ["RejectVersion", "Sender"]


# ---------------------------------------------------------------------------
# 5.4 — `_to_int` must be strconv.ParseUint(s, 0, 64)
# ---------------------------------------------------------------------------


def test_int_literals_parse_like_strconv_parseuint_base0():
    """A decimal-first `int()` read `int 010` as 10 where the assembler reads
    OCTAL 8, and accepted `08`, `-1`, 2**64 and `1__0` — literals goal
    rejects — as constants. Every value here is goal's (`intcblock 1 16 7 8
    1000` for `1 0x10 0o7 010 1000`; `pushints 1 16 8`)."""
    from tealql.tealtools.language.constants import _to_int

    table = {
        "010": 8, "017": 15, "00": 0, "0": 0, "0_7": 7, "0X1F": 31, "0O17": 15,
        "0B11": 3, "0x_10": 16, "0b_1": 1, "1_0": 10, "1_000_000": 1_000_000,
        "18446744073709551615": (1 << 64) - 1, "16": 16, "0xDEAD": 0xDEAD,
        # goal-rejected → None, never a fabricated value
        "08": None, "-1": None, "+1": None, "18446744073709551616": None,
        "1__0": None, "_1": None, "1_": None, "0x": None, "0x_": None,
        "0x0x10": None, "TMPL_X": None, "": None, "1.5": None,
    }
    got = {k: _to_int(k) for k in table}
    assert got == table, {k: (got[k], table[k]) for k in table if got[k] != table[k]}

    prog = _prog("intcblock 1 0x10 0o7 010 1_000\nintc_3\nintc 4\n+\nreturn\n")
    assert _consts(prog, "intc_3", "intc") == [("intc_3", ["8"]), ("intc", ["1000"])]
    prog = _prog("pushints 1 0x10 010\n+\n+\nreturn\n")
    (pi,) = _consts(prog, "pushints")
    assert pi[1] == ["8", "16", "1"]                 # outputs are TOP-FIRST
    prog = _prog("int 010\nint 08\n+\nreturn\n")
    assert _consts(prog, "int") == [("int", ["8"]), ("int", [None])]


# ---------------------------------------------------------------------------
# 5.5 — bare `extract` at column 0
# ---------------------------------------------------------------------------


def test_bare_extract_at_column_zero_is_extract3():
    """The `extract` -> `extract3` respelling needed a preceding whitespace
    byte to keep the line length, so unindented hand-written TEAL lost the
    instruction (2 pops, 1 push) with only a parse warning. Control: the
    indented form, and `extract 0 8` (immediates) untouched."""
    src = "byte 0x0102030405060708\nint 0\nint 8\n{ex}\nbtoi\nreturn\n"
    for ex in ("extract", "  extract", "extract // c", "\textract\t"):
        prog = _prog(src.format(ex=ex))
        assert _diags(prog) == [], ex
        (e3,) = _ops(prog, "extract3")
        assert len(e3.inputs) == 3 and len(e3.outputs) == 1, ex
        (btoi,) = _ops(prog, "btoi")
        assert btoi.inputs[0].identifier == e3.outputs[0].identifier, ex
    prog = _prog("byte 0x0102030405060708\nextract 0 8\nbtoi\nreturn\n")
    assert _ops(prog, "extract3") == [] and [a.immediates for a in _ops(prog, "extract")] == ["0 8"]


# ---------------------------------------------------------------------------
# 5.6 — `addr` checksum / canonical form, `method` quoted form
# ---------------------------------------------------------------------------


def test_addr_and_method_pseudo_ops_refuse_what_the_assembler_rejects():
    """`addr` took `raw[:32]` of anything that base32-decoded, fabricating a
    pubkey for a mistyped address (goal: "non-canonical" for a wrong last
    char, "checksum verification failed" for all-A); unquoted `method
    add(uint64,uint64)uint64` was hashed like the quoted form (goal: "unable
    to parse method signature"). Controls: the valid address (goal: 32×0xff)
    and the quoted signature (goal: 0xfe6bdf69)."""
    good = "7777777777777777777777777777777777777777777777777774MSJUVU"
    prog = _prog(f"addr {good}\nlen\nreturn\n")
    assert _diags(prog) == [] and _consts(prog, "pushbytes") == [("pushbytes", ["0x" + "ff" * 32])]
    for bad in (good[:-1] + "V",                           # non-canonical
                "A" * 58,                                  # checksum fails
                good[:-8]):                                # 50 chars: 31 bytes
        prog = _prog(f"addr {bad}\nlen\nreturn\n")
        assert _consts(prog, "pushbytes") == [] and _diags(prog) != [], bad

    prog = _prog('method "add(uint64,uint64)uint64"\nlen\nreturn\n')
    assert _diags(prog) == [] and _consts(prog, "pushbytes") == [("pushbytes", ["0xfe6bdf69"])]
    prog = _prog("method add(uint64,uint64)uint64\nlen\nreturn\n")
    assert _consts(prog, "pushbytes") == [] and _diags(prog) != []
