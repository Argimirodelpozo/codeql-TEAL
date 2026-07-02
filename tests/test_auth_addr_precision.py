"""The sender-equality auth matcher requires a 32-BYTE address constant.

An Algorand address is exactly 32 bytes, so ``txn Sender == <shorter bytes>``
can never hold — it's a vacuous check, not a real admin guard. The detector must
therefore still FLAG a sensitive sink "guarded" by such a comparison, while a
genuine 32-byte address guard suppresses it.
"""
from tealtools.ssa import SSAProgram
from tealtools.auth_domination import AuthDominationDetector

# A 32-byte (64 hex) bytes literal — address-shaped.
_ADDR32 = "0x" + "11" * 32
# A 2-byte literal — cannot be an address.
_SHORT = "0x" + "11" * 2

_PROG = """#pragma version 8
txn Sender
byte {const}
==
assert
byte "k"
byte "v"
app_global_put
int 1
return
"""


def _flagged(tmp_path, const_literal):
    p = tmp_path / "t.teal"
    p.write_text(_PROG.format(const=const_literal))
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    violations = AuthDominationDetector(prog).detect()
    return any(v.sink.op == "app_global_put" for v in violations)


def test_32_byte_sender_guard_suppresses(tmp_path):
    # A real 32-byte address guard dominates the sink -> not flagged.
    assert _flagged(tmp_path, _ADDR32) is False


def test_short_sender_compare_is_not_a_guard(tmp_path):
    # `txn Sender == <2 bytes>` is vacuous (sender is always 32 bytes), so the
    # sink is effectively unguarded -> flagged.
    assert _flagged(tmp_path, _SHORT) is True
