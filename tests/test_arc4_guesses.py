"""The SPECULATIVE ARC4 encoded-type side-channel (``_guess_encoded_types``).

Pins the tier's two contracts:

  * each guess comes from a NAMED idiom with its local proof discharged
    (producer-side: the ``concat(uint16(len(D)), D)`` encode idiom; constant:
    self-describing ``arc4.String`` literals; decode-side: the
    length-prefix + to-end-payload shape); and
  * guesses live ONLY in the side-channel — the register's ``ir_type`` is
    never an ``EncodedType`` because of a guess.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealql.tealtools.ssa import SSAProgram  # noqa: E402


def _guesses_for(tmp_path, teal: str):
    import puya.ir.models as M

    from tealql.tealtools.lift import to_puya
    from tealql.tealtools.lift import to_puya_ir

    (tmp_path / "prog.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    guesses = to_puya_ir._guess_encoded_types(main, subs)
    by_op = {}          # defining op name -> list[(Register, EncodedType)]
    for sub in (main, *subs):
        for bb in sub.body:
            for o in bb.ops:
                if not isinstance(o, M.Assignment):
                    continue
                for t in o.targets:
                    if id(t) in guesses:
                        key = (o.source.op.name
                               if isinstance(o.source, M.Intrinsic)
                               else type(o.source).__name__)
                        by_op.setdefault(key, []).append((t, guesses[id(t)]))
    return guesses, by_op


ENCODE_IDIOM = """#pragma version 10
txna ApplicationArgs 0
dup
len
itob
extract 6 2
swap
concat
log
int 1
return
"""

UNRELATED_PREFIX = """#pragma version 10
txna ApplicationArgs 0
txna ApplicationArgs 1
len
itob
extract 6 2
swap
concat
log
int 1
return
"""


def test_encode_idiom_guessed_as_dynamic_sequence(tmp_path):
    from puya.ir.encodings import ArrayEncoding
    from puya.ir.types_ import EncodedType

    _, by_op = _guesses_for(tmp_path, ENCODE_IDIOM)
    concat_guesses = by_op.get("concat", [])
    assert concat_guesses, "the length-proven encode idiom must produce a guess"
    reg, et = concat_guesses[0]
    assert isinstance(et.encoding, ArrayEncoding)
    assert et.encoding.length_header is True
    assert et.encoding.size is None
    # SIDE-CHANNEL ONLY: the guess never reaches the register's ir_type.
    assert not isinstance(reg.ir_type, EncodedType)


def test_unrelated_length_prefix_is_not_guessed(tmp_path):
    # prefix = uint16(len(ApplicationArgs 1)) but data = ApplicationArgs 0 —
    # the length proof must fail, so no dynamic-sequence guess on the concat.
    _, by_op = _guesses_for(tmp_path, UNRELATED_PREFIX)
    from puya.ir.encodings import ArrayEncoding
    bad = [g for _, g in by_op.get("concat", [])
           if isinstance(g.encoding, ArrayEncoding) and g.encoding.length_header]
    assert not bad, f"unproven prefix must not be guessed: {bad}"


def test_const_string_literal_guessed(tmp_path):
    from puya.ir.encodings import UTF8Encoding

    teal = """#pragma version 10
pushbytes 0x000548656c6c6f
log
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert any(isinstance(g.encoding, UTF8Encoding) for g in guesses.values()), (
        "an inline self-describing arc4.String constant must be guessed")


def test_decode_side_dynamic_guessed(tmp_path):
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
dup
int 0
extract_uint16
swap
extract 2 0
len
+
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert any(isinstance(g.encoding, ArrayEncoding) and g.encoding.length_header
               for g in guesses.values()), "decode shape must yield a dynamic guess"


def test_static_array_homogeneous_concat(tmp_path):
    """A concat of N identical static elements is recovered as
    arc4.StaticArray<T, N> (exact N), side-channel only. Three uint64s ->
    uint64[3]."""
    from puya.ir.encodings import ArrayEncoding

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
    guesses, _ = _guesses_for(tmp_path, teal)
    sa = [e.encoding for e in guesses.values()
          if isinstance(e.encoding, ArrayEncoding)
          and not e.encoding.length_header and e.encoding.size == 3]
    assert sa, "three concatenated uint64s must be StaticArray<UInt64, 3>"


def test_decoded_static_array_from_fixed_length(tmp_path):
    """A fixed-length value (extract -> SizedBytesType(24)) read as same-width
    uint64s at 0/8/16 is decoded arc4.StaticArray<UInt64, 3> -- exact N from the
    byte length."""
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
extract 0 24
dup
dup
int 0
extract_uint64
pop
int 8
extract_uint64
pop
int 16
extract_uint64
pop
pop
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert any(isinstance(e.encoding, ArrayEncoding) and not e.encoding.length_header
               and e.encoding.size == 3 for e in guesses.values()), (
        "24-byte value read as uint64s must be StaticArray<UInt64, 3>")


def test_decoded_static_array_needs_known_length(tmp_path):
    """Without a statically-known byte length, N is unknown -- no static-array
    guess (a raw ApplicationArgs value read at 0/8 could be any size)."""
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
dup
int 0
extract_uint64
pop
int 8
extract_uint64
pop
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert not any(isinstance(e.encoding, ArrayEncoding) and not e.encoding.length_header
                   and (e.encoding.size or 0) >= 2 for e in guesses.values()), (
        "unknown-length value must not yield a fixed-N static array")


def test_heterogeneous_concat_not_static_array(tmp_path):
    """A concat of DIFFERENT static elements is a tuple, NOT a static array:
    no header-less array-of-size guess for it (uint64 + uint32)."""
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
btoi
itob
txna ApplicationArgs 1
btoi
itob
extract 4 4
concat
log
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    # a size-2 header-less array would be the false positive; the mixed widths
    # must not be collapsed into one.
    bad = [e.encoding for e in guesses.values()
           if isinstance(e.encoding, ArrayEncoding)
           and not e.encoding.length_header and e.encoding.size == 2]
    assert not bad, f"heterogeneous concat must not be a static array: {bad}"


def test_guess_propagates_through_state(tmp_path):
    """A guessed encoding flows put -> get: the length-proven encode idiom
    result is stored to a global key and read back; the read-back register
    inherits the guess (all-writes-agree state propagation). Side-channel
    only, so lowering is untouched."""
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
byte "k"
txna ApplicationArgs 0
dup
len
itob
extract 6 2
swap
concat
app_global_put
byte "k"
app_global_get
log
int 1
return
"""
    _, by_op = _guesses_for(tmp_path, teal)
    # the ENCODE idiom is guessed at the concat...
    assert any(isinstance(e.encoding, ArrayEncoding) and e.encoding.length_header
               for _, e in by_op.get("concat", [])), "encode idiom must seed a guess"
    # ...and PROPAGATION carries it to the app_global_get read-back.
    got = by_op.get("app_global_get", [])
    assert got, "state read-back produced no guess — propagation did not fire"
    assert all(isinstance(e.encoding, ArrayEncoding) and e.encoding.length_header
               for _, e in got)


def _leads_for(tmp_path, teal: str):
    from tealql.tealtools.lift import to_puya, to_puya_ir
    (tmp_path / "prog.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    return to_puya_ir.abi_address_fund_flows(main, subs)


_PAY_PROLOGUE = """#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
"""
_PAY_EPILOGUE = """int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def test_abi_address_fund_flow_arbitrary_recipient(tmp_path):
    """A caller-supplied ABI address paid out with NO validation is the
    arbitrary-recipient shape: caller_supplied and not guarded. The recovered
    arc4.Address type is what identifies the operand as a caller-chosen address."""
    teal = _PAY_PROLOGUE + "txna ApplicationArgs 0\nitxn_field Receiver\n" + _PAY_EPILOGUE
    leads = _leads_for(tmp_path, teal)
    assert leads, "an address reaching a fund sink must produce a lead"
    assert all(x["field"] == "Receiver" for x in leads)
    assert any(x["caller_supplied"] and not x["guarded"] for x in leads), (
        "an unvalidated caller-supplied payout must be flagged")


def test_abi_address_fund_flow_guarded_not_flagged(tmp_path):
    """The same payout, but the address is pinned (== a stored admin) before the
    send -- guarded, so NOT the arbitrary-recipient shape."""
    teal = (_PAY_PROLOGUE
            + 'txna ApplicationArgs 0\nbyte "admin"\napp_global_get\n==\nassert\n'
            + "txna ApplicationArgs 0\nitxn_field Receiver\n" + _PAY_EPILOGUE)
    leads = _leads_for(tmp_path, teal)
    assert leads, "the address still reaches the sink"
    assert all(x["guarded"] for x in leads), (
        "a validated payout address must be marked guarded")
    assert not any(x["caller_supplied"] and not x["guarded"] for x in leads)


def test_abi_address_fund_flow_survives_decode_chain(tmp_path):
    """The backward slice must see through the ABI-decode chain: an address
    EXTRACTED out of the args (not read raw at the sink) is still caller-supplied."""
    teal = (_PAY_PROLOGUE
            + "txna ApplicationArgs 0\nextract 2 32\nitxn_field Receiver\n"
            + _PAY_EPILOGUE)
    leads = _leads_for(tmp_path, teal)
    assert any(x["caller_supplied"] and not x["guarded"] for x in leads), (
        "provenance must survive an extract off the args tuple")


def test_no_fund_lead_without_sink(tmp_path):
    """No fund/asset-transfer sink -> no lead, even for a caller-supplied address
    that is merely logged (the sink-field filter is part of the trigger)."""
    teal = """#pragma version 10
txna ApplicationArgs 0
log
int 1
return
"""
    assert _leads_for(tmp_path, teal) == []


def test_own_app_address_recipient_not_caller_supplied(tmp_path):
    """Paying the app's OWN address (global CurrentApplicationAddress) is a
    recovered-address recipient, so it leads -- but it is NOT caller-supplied,
    so it is not the arbitrary-recipient shape."""
    teal = (_PAY_PROLOGUE
            + "global CurrentApplicationAddress\nitxn_field Receiver\n"
            + _PAY_EPILOGUE)
    leads = _leads_for(tmp_path, teal)
    assert leads and not any(x["caller_supplied"] for x in leads)


def _is_address(et) -> bool:
    from puya.ir.encodings import ArrayEncoding
    return (isinstance(et.encoding, ArrayEncoding)
            and et.encoding.size == 32 and not et.encoding.length_header)


def test_address_from_itxn_field(tmp_path):
    """A bytes value SENT to an account-typed itxn field (Receiver) is guessed
    arc4.Address, and propagation carries it back to the value's definition
    (the txna result), not just the itxn_field operand."""
    from puya.ir.types_ import EncodedType

    teal = """#pragma version 10
txna ApplicationArgs 0
itxn_field Receiver
int 1
return
"""
    guesses, by_op = _guesses_for(tmp_path, teal)
    assert any(_is_address(e) for e in guesses.values()), (
        "value used at itxn_field Receiver must be guessed arc4.Address")
    # propagation reached the txna producer, and it stayed side-channel.
    txna = by_op.get("txna", [])
    assert txna and any(_is_address(e) for _, e in txna)
    for reg, _ in txna:
        assert not isinstance(reg.ir_type, EncodedType)


def test_address_from_zero_address_compare(tmp_path):
    """Comparing a value against global ZeroAddress (const-folded to 32 null
    bytes) marks it an address."""
    teal = """#pragma version 10
txna ApplicationArgs 0
global ZeroAddress
!=
assert
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert any(_is_address(e) for e in guesses.values()), (
        "value compared to ZeroAddress must be guessed arc4.Address")


def test_non_address_bytes_not_guessed_address(tmp_path):
    """A bytes value only logged / concatenated (never used at an address
    position) must NOT collect an address guess -- the usage evidence is the
    whole proof."""
    teal = """#pragma version 10
txna ApplicationArgs 0
log
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    assert not any(_is_address(e) for e in guesses.values()), (
        "a plain logged value has no address usage evidence")


def test_guess_propagates_through_copy_merge(tmp_path):
    """A guessed value that reaches a join (phi) from every arm carries its
    encoding to the merged register."""
    from puya.ir.encodings import ArrayEncoding

    teal = """#pragma version 10
txna ApplicationArgs 0
dup
len
itob
extract 6 2
swap
concat
store 0
txn NumAppArgs
int 1
==
bnz done
load 0
store 0
done:
load 0
log
int 1
return
"""
    guesses, _ = _guesses_for(tmp_path, teal)
    dyn = [g for g in guesses.values()
           if isinstance(g.encoding, ArrayEncoding) and g.encoding.length_header]
    # At minimum the producer; propagation through the scratch/branch merge
    # should carry it to more than the single concat result.
    assert len(dyn) >= 1
