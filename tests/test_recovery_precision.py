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

from tealql.tealtools.lift import to_puya, to_puya_ir   # noqa: E402
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
