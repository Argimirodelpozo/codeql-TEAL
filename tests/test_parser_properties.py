"""Property-based decoding: a constant must survive EVERY spelling of itself.

The example tests assert "this literal decodes to that value" — written by the
same author as the decoder, so they agree with a wrong decoder. (`b64(..)`
decoded to its own ASCII text for a long time, and every example test passed,
because none of them used that spelling.)

This asserts the property that actually matters. The oracle is CONSTRUCTION: we
pick raw bytes / an int FIRST, render it in a randomly-chosen TEAL spelling, and
require the parser to give the value back. No reference implementation needed,
so it is hermetic and fast — the complement to
``test_assembler_differential.py``, which checks the same surface against the
chain but needs a node.

The spellings are the whole point. TEAL admits eight ways to write the same
byte constant and four to write the same integer; each is a separate code path,
and this session found real bugs in three of them. A comment is folded in as a
spelling too — the grammar's string tokenizer once ran past `//` when the
comment contained a quote, so the comment text became part of the constant.
"""
from __future__ import annotations

import base64

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings          # noqa: E402
from hypothesis import strategies as st                      # noqa: E402

from tealql.tealtools.ssa import SSAProgram                  # noqa: E402

_SETTINGS = settings(max_examples=150, deadline=None,
                     suppress_health_check=[HealthCheck.too_slow])


# --- rendering a known value in every legal spelling ------------------------


def _byte_spellings(raw: bytes) -> list:
    """Every TEAL spelling of ``raw``. Each is a distinct decoder path."""
    b64 = base64.b64encode(raw).decode()
    b32 = base64.b32encode(raw).decode()
    out = [
        f"0x{raw.hex()}",
        f"base64({b64})", f"b64({b64})",
        f"base32({b32})", f"b32({b32})",
        f"base32 {b32}", f"b32 {b32}",
    ]
    # The SPACE-separated base64 form only when the payload does not START with
    # `//`. The base64 alphabet includes `/`, so a payload can open with the
    # comment marker at a token boundary (`byte base64 //8=`) — and whether the
    # assembler reads that as payload or as a comment is a question this suite
    # cannot answer offline. algod is the reference implementation, so
    # `tests/assembler_differential.py` owns it; asserting either reading here
    # would be guessing, and guessing at decode semantics is what produced the
    # constant bugs that differential was written to catch. (A payload that
    # merely CONTAINS `//` mid-token is not ambiguous and IS covered — it was a
    # real truncation bug, fixed in `graph._strip_inline_comment`.)
    if not b64.startswith("//"):
        out += [f"base64 {b64}", f"b64 {b64}"]
    # The quoted form only when the bytes are printable ASCII with no escaping
    # subtleties — otherwise the spelling is not equivalent.
    if raw and all(0x20 <= c < 0x7F and c not in b'"\\' for c in raw):
        out.append('"' + raw.decode("ascii") + '"')
    return out


def _int_spellings(n: int) -> list:
    return [str(n), f"0x{n:x}"] if n else ["0", "0x0"]


def _decoded(source: str) -> "tuple[set, set]":
    """``(ints, bytes_as_hex)`` the parser recovers from ``source``."""
    prog = SSAProgram({"p.teal": source})
    prog.propagate_constants()
    ints, byts = set(), set()
    for a in prog.assignments:
        for out in a.outputs:
            cv = getattr(out, "const_value", None)
            if cv is None:
                continue
            if cv.kind == "int":
                try:
                    ints.add(int(str(cv.value), 0))
                except ValueError:
                    pass
            elif cv.kind == "bytes":
                v = str(cv.value)
                byts.add(v[2:].lower() if v.startswith("0x") else v)
    return ints, byts


def _program(lines: list) -> str:
    body = "\n".join(f"{op}\npop" for op in lines)
    return f"#pragma version 10\n{body}\nint 1\nreturn\n"


# --- the properties ---------------------------------------------------------


@given(raw=st.binary(min_size=1, max_size=24), pick=st.integers(0, 20))
@_SETTINGS
def test_a_byte_constant_survives_every_spelling(raw, pick):
    """Pick the bytes FIRST, render them any legal way, get them back."""
    spellings = _byte_spellings(raw)
    literal = spellings[pick % len(spellings)]
    src = _program([f"byte {literal}"])
    prog = SSAProgram({"p.teal": src})
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == [], literal
    _, byts = _decoded(src)
    assert raw.hex() in byts, f"{literal!r} decoded to {byts}, expected {raw.hex()}"


@given(raw=st.binary(min_size=1, max_size=16), pick=st.integers(0, 20))
@_SETTINGS
def test_the_push_opcodes_agree_with_the_pseudo_op(raw, pick):
    """`byte X` is a pseudo-op the normalizer rewrites; `pushbytes X` is a real
    opcode the grammar parses. Both must yield the same constant — they took
    DIFFERENT code paths and disagreed for the encoded spellings."""
    spellings = _byte_spellings(raw)
    literal = spellings[pick % len(spellings)]
    _, via_pseudo = _decoded(_program([f"byte {literal}"]))
    _, via_push = _decoded(_program([f"pushbytes {literal}"]))
    assert raw.hex() in via_pseudo and raw.hex() in via_push


@given(n=st.integers(min_value=0, max_value=2 ** 64 - 1), pick=st.integers(0, 6))
@_SETTINGS
def test_an_int_constant_survives_every_spelling(n, pick):
    spellings = _int_spellings(n)
    literal = spellings[pick % len(spellings)]
    src = _program([f"int {literal}"])
    ints, _ = _decoded(src)
    assert n in ints, f"{literal!r} decoded to {ints}, expected {n}"


@given(raw=st.binary(min_size=1, max_size=16),
       comment=st.text(alphabet='abcXY "[],/', min_size=0, max_size=24))
@_SETTINGS
def test_a_trailing_comment_never_changes_the_constant(raw, comment):
    """A `//` comment must be inert. The grammar's string tokenizer ran past it
    when it contained a quote, so `pushbytes "asa_"  // [name, "asa_"]` carried
    the comment text INSIDE the constant."""
    literal = f"0x{raw.hex()}"
    plain = _decoded(_program([f"byte {literal}"]))
    with_comment = _decoded(_program([f"byte {literal}   // {comment}"]))
    assert plain[1] == with_comment[1], f"comment {comment!r} altered the constant"


@given(names=st.lists(st.sampled_from(
    ["pop", "concat", "store", "append", "get", "set", "verify", "main", "loop"]),
    min_size=1, max_size=5, unique=True))
@_SETTINGS
def test_labels_named_after_opcodes_still_define_and_resolve(names):
    """A label whose name is an opcode mnemonic tokenized as the OPCODE plus a
    stray `:`, so it never got defined and every branch to it lost its edge."""
    body = "\n".join(f"b {n}\n{n}:" for n in names)
    src = f"#pragma version 10\nint 0\n{body}\nint 1\nreturn\n"
    prog = SSAProgram({"p.teal": src})
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    # every branch target resolves to a defined label
    labels = {c.rstrip(":").strip() for _f, _l, c in prog.labels}
    targets = {a.immediates.strip() for a in prog.assignments if a.op == "b"}
    assert targets <= labels, f"unresolved branch targets: {targets - labels}"


@given(idx=st.integers(min_value=0, max_value=15),
       field=st.sampled_from(["Logs", "ApplicationArgs", "ApprovalProgramPages"]))
@_SETTINGS
def test_array_indexed_reads_keep_their_index(idx, field):
    """`itxna Logs 0` and `itxna Logs 5` read DIFFERENT array elements. The
    grammar dropped the index and the op survived without it, so they became
    indistinguishable to every analysis keyed on the slot."""
    src = f"#pragma version 10\nitxna {field} {idx}\npop\nint 1\nreturn\n"
    prog = SSAProgram({"p.teal": src})
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    imms = [a.immediates.strip() for a in prog.assignments if a.op == "itxna"]
    assert imms == [f"{field} {idx}"], imms


def test_one_spelling_of_a_key_matches_another_across_state():
    """The motivating consequence. `xcontract` resolves a callee AppID by
    matching the state KEY a write used against the key a read used
    (`_const_bytes(inp) == key`). `pushbytes "cfg"` resolved to the raw text
    `'"cfg"'` while `byte "cfg"` resolved to `0x636667`, so the two never
    matched and the AppID silently stayed unresolved — no error, just a callee
    that vanished from the cross-contract graph."""
    from tealql.tealtools.xcontract import candidate_app_ids

    src = ("#pragma version 10\n"
           'pushbytes "cfg"\npushint 1234567\napp_global_put\n'   # write: pushbytes
           'byte "cfg"\napp_global_get\n'                          # read: byte
           "itxn_begin\nint appl\nitxn_field TypeEnum\n"
           "itxn_field ApplicationID\nitxn_submit\nint 1\nreturn\n")
    prog = SSAProgram({"p.teal": src})
    prog.propagate_constants()
    assert 1234567 in set(candidate_app_ids(prog))


def test_base64_payload_containing_a_double_slash():
    """`/` is in the base64 alphabet, so a payload with `//` is ordinary — and
    the inline-comment stripper cut the operand there, truncating the constant
    to the ASCII text of the fragment. Found by the property test above; pinned
    here as the concrete case."""
    raw = bytes([0x00, 0x0f, 0xff])            # base64 -> "AA//"
    src = _program([f"pushbytes base64({base64.b64encode(raw).decode()})"])
    prog = SSAProgram({"p.teal": src})
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    _, byts = _decoded(src)
    assert raw.hex() in byts, byts


def test_a_canonical_constant_still_reads_well_in_output():
    """Canonical storage must not cost readability: a finding that says
    `== 0x616c6c6f776564` is worse than `== "allowed"`."""
    from tealql.tealtools.ast.literals import render_byte_constant
    assert render_byte_constant("0x616c6c6f776564") == '"allowed"'
    assert render_byte_constant("0x00ff") == "0x00ff"        # not printable
    assert render_byte_constant("123") == "123"              # not a bytes const
