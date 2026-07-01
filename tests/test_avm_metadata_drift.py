"""Guard optypes' hand-maintained op-result-type tables against puya's langspec.

``lift/optypes.py`` carries ``_U64_OPS`` / ``_BYTES_OPS`` — the set of opcodes
whose single result is uint64- vs bytes-backed. It is a SECOND source of truth
beside puya's own ``AVMOpData`` signatures (which ``to_puya_ir._langspec_returns``
already reads), and it has drifted before: crypto producers like ``mimc`` were
missing from ``_BYTES_OPS`` and defaulted to uint64, crossing the AVM divide and
corrupting the lift (the "residual recovery bug").

This test derives the expected coarse AVM type for every op that puya models
under the same mnemonic, and fails if optypes disagrees — so a new AVM version
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
from puya.ir.avm_ops_models import DynamicVariants, Variant

from tealtools.lift import optypes

# Ops in optypes' result tables that puya does NOT model under the same
# mnemonic: TEAL uses symbols (`+`) where puya uses identifiers (`add`), and
# the const-push pseudo-ops (`intc*` / `pushint*` / …) are typed from their
# folded const value, not a langspec return. These are deliberately outside
# this test's reach — it checks the name-identical ops (where drift actually
# bit). Kept as an explicit skip-set so an accidental new symbol-named entry
# is not silently uncovered.
_SYMBOL_OR_PUSH = (
    set("+ - * / %".split())
    | {f"b{s}" for s in "+ - * / % | & ^ ~".split()}
    | optypes._U64_PUSH | optypes._BYTES_PUSH
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
    for op in sorted(optypes._U64_OPS | optypes._BYTES_OPS):
        if op in _SYMBOL_OR_PUSH:
            continue
        kinds = _puya_return_avm_kinds(op)
        if kinds:
            yield op, kinds


def test_optypes_result_tables_match_puya_langspec():
    want = {op: "u" for op in optypes._U64_OPS}
    want.update({op: "b" for op in optypes._BYTES_OPS})
    mismatches = []
    for op, kinds in _covered_ops():
        # Every return slot of a single-result-typed op must share optypes'
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


def test_known_crypto_producers_are_bytes_typed():
    # The exact regression that motivated this: crypto / hashing / EC ops that
    # return byteslices must be in _BYTES_OPS (not defaulting to uint64).
    for op in ("mimc", "sha256", "sha512_256", "keccak256", "sha3_256",
               "ec_add", "ec_scalar_mul", "ecdsa_pk_recover",
               "ecdsa_pk_decompress"):
        assert op in optypes._BYTES_OPS, op
        kinds = _puya_return_avm_kinds(op)
        if kinds:  # puya confirms all-bytes returns
            assert all(k == "b" for k in kinds), (op, kinds)
