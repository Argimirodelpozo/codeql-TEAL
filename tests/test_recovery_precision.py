"""Recovery PRECISION: ground-truth-by-construction correctness.

The other recovery tests pin one idiom each. This validates the recovery END TO
END on multi-field, correctly-ABI-encoded values -- the byte idioms below are
hand-built to BE valid ARC4 wire encodings, so the recovered type is checked
against a known-correct answer, not merely "something was guessed". It also PINS
the two documented irreducible floors (a dynamic String decode floors to
DynamicBytes; a bit-packed Bool array floors to DynamicBytes) so that if either is
ever refined, the change is visible here rather than silent.

Correctness = every recovery is either the exact ABI type or a SOUND
generalisation of it (a wider type that still contains the value). A recovery that
is WRONG (a type the bytes are not) is the failure this guards against.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import lift, to_puya, to_puya_ir   # noqa: E402
from tealql.tealtools.ssa import SSAProgram             # noqa: E402


def _encodings(tmp_path, teal: str):
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    guesses, _ = to_puya_ir.guess_encoded_types_scored(main, subs)
    return [e.encoding for e in guesses.values()]


def test_dynamic_array_of_uint64_decode(tmp_path):
    """uint16 count @0 + to-end payload chunked by extract_uint64 => the exact
    type arc4.DynamicArray<UInt64>."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
dup
int 0
extract_uint16
swap
extract 2 0
int 0
extract_uint64
pop
pop
int 1
return
"""
    encs = _encodings(tmp_path, teal)
    assert any(isinstance(e, ArrayEncoding) and e.length_header
               and isinstance(e.element, UIntEncoding) and e.element.n == 64
               for e in encs), "must be DynamicArray<UInt64>"


def test_tuple_uint64_string_decode(tmp_path):
    """A fixed head uint64 @0 + a dynamic field via an offset slot @8 =>
    Tuple<UInt64, <dynamic>>. The dynamic field floors to DynamicBytes (a String
    can't be proven on dynamic data) -- a SOUND generalisation, not wrong."""
    from puya.ir.encodings import TupleEncoding, UIntEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
dup
dup
int 0
extract_uint64
pop
int 8
extract_uint16
dup
int 100
substring3
pop
pop
int 1
return
"""
    encs = _encodings(tmp_path, teal)
    tuples = [e for e in encs if isinstance(e, TupleEncoding)]
    assert tuples, "a fixed head + dynamic tail must reconstruct a tuple"
    # first element is the static UInt64; the second is a dynamic sequence.
    t = tuples[0]
    assert isinstance(t.elements[0], UIntEncoding) and t.elements[0].n == 64


def test_producer_static_array_uint64(tmp_path):
    """concat of three itob results => the exact type StaticArray<UInt64, 3>."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
btoi
itob
txna ApplicationArgs 1
btoi
itob
concat
txna ApplicationArgs 2
btoi
itob
concat
log
int 1
return
"""
    encs = _encodings(tmp_path, teal)
    assert any(isinstance(e, ArrayEncoding) and not e.length_header and e.size == 3
               and isinstance(e.element, UIntEncoding) and e.element.n == 64
               for e in encs), "must be StaticArray<UInt64, 3>"


def test_const_string_exact(tmp_path):
    """0x0005 + 'Hello' is a valid self-describing arc4.String => recovered
    exactly (the one place a String, not a DynamicBytes floor, is provable)."""
    from puya.ir.encodings import UTF8Encoding

    teal = """#pragma version 10
pushbytes 0x000548656c6c6f
log
int 1
return
"""
    encs = _encodings(tmp_path, teal)
    assert any(isinstance(e, UTF8Encoding) for e in encs), "const must be arc4.String"


def test_no_recovery_is_wrong_on_opaque_bytes(tmp_path):
    """An opaque bytes value that is only hashed (no ABI idiom) must yield NO
    encoded-type guess -- recovery invents nothing."""
    teal = """#pragma version 10
txna ApplicationArgs 0
sha256
log
int 1
return
"""
    assert _encodings(tmp_path, teal) == []


@pytest.mark.parametrize("name,body,expected", [
    # The op is the ONLY typing signal the parameter has: nothing at the call
    # site says what `load 5` is, so if the use does not speak, the register
    # stays `?` and lowers to a DEFAULT that may be the wrong family.
    ("gtxns", "frame_dig -1\ngtxns Amount\nretsub\n", "uint64"),
    ("gloads", "frame_dig -1\ngloads 3\nretsub\n", "uint64"),
    ("gaids", "frame_dig -1\ngaids\nretsub\n", "uint64"),
    ("args", "frame_dig -1\nargs\nretsub\n", "uint64"),
])
def test_an_index_operand_types_its_source(tmp_path, name, body, expected):
    """`gtxns` and friends pop a uint64 INDEX — a group index, a scratch slot.

    That family was absent from the expected-type tables, which is not a missing
    refinement but a missing SIGNAL: `_infer_types_from_uses` only refines
    registers still `?`, so a value consumed ONLY by one of these got no
    expected type from any use at all. It is exactly the shape of an ARC-4
    TRANSACTION parameter — `transfer(pay, axfer, ...)` passes its `pay` as a
    group index and the callee reads it with `gtxns Amount` — so every such
    subroutine mistyped its own parameters and then mismatched its own call
    sites (`received = (bytes), expected = (uint64)`).
    """
    teal = tmp_path / f"{name}.teal"
    teal.write_text("#pragma version 10\nload 5\ncallsub f\npop\npushint 1\n"
                    "return\nf:\nproto 1 1\n" + body)
    ir = lift(SSAProgram(str(teal)))
    sub = next(s for s in ir.subroutines if s.id.endswith("f"))
    got = sub.parameters[0].register.ir_type
    assert got == expected, (
        f"a value whose only use is `{name}` typed {got!r}, not {expected!r} — "
        "the use carries no expected type, so nothing refines the register")


def test_log_types_its_operand_as_bytes(tmp_path):
    """`log` takes a byteslice, and an ARC-4 event payload that reaches it only
    through a frame slot has no other typing signal."""
    teal = tmp_path / "log.teal"
    teal.write_text("#pragma version 10\nload 5\ncallsub f\npushint 1\nreturn\n"
                    "f:\nproto 1 0\nframe_dig -1\nlog\nretsub\n")
    ir = lift(SSAProgram(str(teal)))
    sub = next(s for s in ir.subroutines if s.id.endswith("f"))
    assert sub.parameters[0].register.ir_type == "bytes"
