"""Operand typing for ops the lift's local tables do not enumerate.

``_expected_type`` typed operands from two hand-maintained tables while the
AVM-wide ``_BYTES_CONSUME`` / ``_U64_CONSUME`` sets — already imported into the
same module for phi-web reconciliation — knew about more ops than either table
listed. A register whose ONLY use was such an op therefore had no typed use at
all, stayed ``?``, and to-puya's default demoted it to uint64: a Bytes/uint64
mixed-type lowering error that makes the contract uncompilable.

The signature-verify family is the case that bit: a withdrawal pubkey read out
of global state and passed straight to ``ed25519verify_bare``.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

import puya.ir.models as M                               # noqa: E402
from puya.ir.types_ import PrimitiveIRType as PT         # noqa: E402

from tealql.tealtools.lift import to_puya                # noqa: E402
from tealql.tealtools.lift.type_recovery import _expected_type   # noqa: E402
from tealql.tealtools.ssa import SSAProgram              # noqa: E402


def _verify_operand_types(tmp_path, teal: str, opname: str):
    """ir_types of every operand of the first `opname` intrinsic in the program."""
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = getattr(o, "source", o)
                if isinstance(src, M.Intrinsic) and opname in str(src.op):
                    return [getattr(a, "ir_type", None) for a in src.args]
    return None


_ED25519 = """#pragma version 10
txna ApplicationArgs 0
txna ApplicationArgs 1
int 0
byte "pwpk"
app_global_get_ex
assert
ed25519verify_bare
return
"""


def test_pubkey_from_global_state_is_bytes(tmp_path):
    """The pubkey's only use is ed25519verify_bare. Nothing else can type it, so
    if that op does not, the register defaults to uint64 and the program will not
    lower — which is exactly what happened to the auto-draw-card Main contract."""
    types = _verify_operand_types(tmp_path, _ED25519, "ed25519verify_bare")
    assert types is not None, "ed25519verify_bare intrinsic not found in lifted IR"
    assert all(t is PT.bytes for t in types), types


@pytest.mark.parametrize("op", [
    "ed25519verify", "ed25519verify_bare", "ecdsa_verify", "ecdsa_pk_decompress",
    "vrf_verify", "falcon_verify", "mimc", "sumhash512", "base64_decode",
])
def test_all_bytes_verify_ops_type_their_operands(op):
    """Every operand of these is a byteslice, so any position must answer bytes.
    A table that knows the op only for phi reconciliation but not for use-driven
    inference leaves single-use registers untyped."""
    assert _expected_type(op, 0, [None]) == "bytes", op


def test_ecdsa_pk_recover_is_positional_not_all_bytes():
    """The family's one exception: `ecdsa_pk_recover A B C D` takes a uint64
    recovery id at B. Sweeping it into the all-bytes set would mis-type that
    operand, so it is pinned positionally — top-first, so args are [D, C, B, A]."""
    args = [None] * 4
    assert [_expected_type("ecdsa_pk_recover", i, args) for i in range(4)] == [
        "bytes", "bytes", "uint64", "bytes"]


def test_a_deliberately_unknown_position_stays_unknown():
    """The position table wins over the family fallback. `getbit`'s value operand
    is POLYMORPHIC (uint64 bitmap or byteslice) and is deliberately left None;
    letting the fallback answer for it would re-introduce the mis-typing of a
    uint64 bitmap that the None was added to prevent."""
    assert _expected_type("getbit", 1, [None, None]) is None
    assert _expected_type("getbit", 0, [None, None]) == "uint64"   # index still pinned
