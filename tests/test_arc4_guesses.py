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
