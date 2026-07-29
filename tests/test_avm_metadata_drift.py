"""Guard avm.py's hand-maintained op-result-type tables against puya's langspec.

``avm.py`` carries ``_U64_OPS`` / ``_BYTES_OPS`` — the set of opcodes
whose single result is uint64- vs bytes-backed. It is a SECOND source of truth
beside puya's own ``AVMOpData`` signatures (which ``to_puya_ir._langspec_returns``
already reads), and it has drifted before: crypto producers like ``mimc`` were
missing from ``_BYTES_OPS`` and defaulted to uint64, crossing the AVM divide and
corrupting the lift (the "residual recovery bug").

This test derives the expected coarse AVM type for every op that puya models
under the same mnemonic, and fails if the table disagrees — so a new AVM version
(a retyped op, a new bytes-returning crypto op added to _U64_OPS by mistake)
fails CI here instead of silently mistyping a register. It also pins a coverage
floor: if puya renames a member so an op drops out of the comparison, the count
regresses and this notices.

Puya-gated: without puya installed there is no langspec to compare against.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from puya.avm import AVMType
from puya.ir.avm_ops import AVMOp
from puya.ir.avm_ops_models import Variant

from tealql.tealtools import avm

# Ops in avm.py's result tables that puya does NOT model under the same
# mnemonic: TEAL uses symbols (`+`) where puya uses identifiers (`add`), and
# the const-push pseudo-ops (`intc*` / `pushint*` / …) are typed from their
# folded const value, not a langspec return. These are deliberately outside
# this test's reach — it checks the name-identical ops (where drift actually
# bit). Kept as an explicit skip-set so an accidental new symbol-named entry
# is not silently uncovered.
_SYMBOL_OR_PUSH = (
    set("+ - * / %".split())
    | {f"b{s}" for s in "+ - * / % | & ^ ~".split()}
    | avm._U64_PUSH | avm._BYTES_PUSH
    | {"len"}  # puya models len via a differently-named member
)

# Coverage floor: the number of optypes result-table ops that map to a puya
# static signature today. If puya renames a member (dropping an op out of the
# comparison) this regresses and the test fails — surfacing the drift rather
# than silently shrinking coverage. Bump deliberately when adding covered ops.
_MIN_COVERED = 45


def _puya_return_avm_kinds(op_name: str):
    """Coarse kinds ('u'/'b'/'?') of an op's return slots from puya's STATIC
    Variant signature, or None if the op isn't a puya member / isn't statically
    signed (dynamic field-keyed ops like txn/global are typed elsewhere)."""
    member = getattr(AVMOp, op_name, None)
    if member is None:
        return None
    variants = getattr(member, "_variants", None)
    if not isinstance(variants, Variant):
        return None  # DynamicVariants or none — not a single static signature
    kinds = []
    for rt in variants.signature.returns:
        at = getattr(rt, "avm_type", None)
        kinds.append("u" if at == AVMType.uint64
                     else "b" if at == AVMType.bytes else "?")
    return kinds


def _covered_ops():
    for op in sorted(avm._U64_OPS | avm._BYTES_OPS):
        if op in _SYMBOL_OR_PUSH:
            continue
        kinds = _puya_return_avm_kinds(op)
        if kinds:
            yield op, kinds


def test_optypes_result_tables_match_puya_langspec():
    want = {op: "u" for op in avm._U64_OPS}
    want.update({op: "b" for op in avm._BYTES_OPS})
    mismatches = []
    for op, kinds in _covered_ops():
        # Every return slot of a single-result-typed op must share avm.py's
        # coarse classification (multi-return byte ops like ecdsa_pk_recover
        # return all-bytes, so every slot must be 'b').
        if any(k != want[op] for k in kinds):
            mismatches.append((op, want[op], kinds))
    assert not mismatches, (
        "optypes result tables disagree with puya's langspec "
        f"(op, optypes_says, puya_returns): {mismatches}")


def test_drift_coverage_floor():
    covered = list(_covered_ops())
    assert len(covered) >= _MIN_COVERED, (
        f"only {len(covered)} ops compared against puya (floor {_MIN_COVERED}) "
        "— did puya rename an AVMOp member, dropping coverage?")


def test_address_fields_single_source_consistency():
    # The address-field universe is defined ONCE (ADDRESS_*_FIELDS in avm) and
    # drives BOTH the "account" type table and the 32-byte length table. This
    # locks the two derived views against that single source so they can't
    # drift: every address field is account-typed AND 32 bytes, and nothing else
    # claims to be an account.
    from tealql.tealtools.avm import ADDRESS_TXN_FIELDS, ADDRESS_GLOBAL_FIELDS
    from tealql.tealtools import avm as O
    M = O

    for f in ADDRESS_TXN_FIELDS:
        assert O._TXN_FIELD_TYPE.get(f) == "account", f
        assert M._TXN_FIELD_BYTELEN.get(f) == 32, f
    for f in ADDRESS_GLOBAL_FIELDS:
        assert O._GLOBAL_FIELD_TYPE.get(f) == "account", f
        assert M._GLOBAL_FIELD_BYTELEN.get(f) == 32, f
    # No account-typed field is missing from the address source (the derivation
    # is the ONLY producer of "account" entries).
    assert {f for f, t in O._TXN_FIELD_TYPE.items() if t == "account"} == set(ADDRESS_TXN_FIELDS)
    assert {f for f, t in O._GLOBAL_FIELD_TYPE.items() if t == "account"} == set(ADDRESS_GLOBAL_FIELDS)
    # Every global 32-byte field is an address; txn 32-byte fields are addresses
    # plus exactly the enumerated non-address fixed-width fields.
    assert {f for f, n in M._GLOBAL_FIELD_BYTELEN.items() if n == 32} == set(ADDRESS_GLOBAL_FIELDS)
    assert set(ADDRESS_TXN_FIELDS) <= {f for f, n in M._TXN_FIELD_BYTELEN.items() if n == 32}


def test_known_crypto_producers_are_bytes_typed():
    # The exact regression that motivated this: crypto / hashing / EC ops that
    # return byteslices must be in _BYTES_OPS (not defaulting to uint64).
    for op in ("mimc", "sha256", "sha512_256", "keccak256", "sha3_256",
               "ec_add", "ec_scalar_mul", "ecdsa_pk_recover",
               "ecdsa_pk_decompress"):
        assert op in avm._BYTES_OPS, op
        kinds = _puya_return_avm_kinds(op)
        if kinds:  # puya confirms all-bytes returns
            assert all(k == "b" for k in kinds), (op, kinds)
