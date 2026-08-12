"""Guard avm.py's hand-maintained op tables against puya's langspec.

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


from tealql.tealtools.language import avm

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
    from tealql.tealtools.language.avm import ADDRESS_TXN_FIELDS, ADDRESS_GLOBAL_FIELDS
    from tealql.tealtools.language import avm as O
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
    # 32-byte fields are the addresses PLUS the enumerated non-address
    # fixed-width ones. Kept as equality on the global side (an exhaustive list,
    # so a new 32-byte global has to be declared here deliberately rather than
    # inherited): `GroupID` and `GenesisHash` are 32 bytes and are NOT accounts.
    assert ({f for f, n in M._GLOBAL_FIELD_BYTELEN.items() if n == 32}
            == set(ADDRESS_GLOBAL_FIELDS) | {"GroupID", "GenesisHash"})
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


# ---------------------------------------------------------------------------
# SIG arity coverage
#
# Relocated here when cost_analysis was removed: this guards avm.SIG, not the
# cost table, and only shared a file with the cost-drift tests by accident.
# ---------------------------------------------------------------------------

# Puya models these under an identifier where TEAL uses a symbol (`add` for `+`),
# or as pseudo-ops this project resolves from the const block. They are outside
# this test's reach by construction; kept explicit so a genuinely NEW opcode
# cannot hide in the gap.
_PUYA_ONLY_NAMES = frozenset({
    "add", "sub", "mul", "div_floor", "mod",
    "add_bytes", "sub_bytes", "mul_bytes", "div_floor_bytes", "mod_bytes",
    "lt", "gt", "lte", "gte", "eq", "neq", "not_", "and_", "or_",
    "lt_bytes", "gt_bytes", "lte_bytes", "gte_bytes", "eq_bytes", "neq_bytes",
    "bitwise_and", "bitwise_or", "bitwise_xor", "bitwise_not",
    "bitwise_and_bytes", "bitwise_or_bytes", "bitwise_xor_bytes",
    "bitwise_not_bytes",
    "len_", "global_",
})

# Height-dependent / dynamic-arity opcodes ``op_arity`` computes from the
# immediates rather than from :data:`avm.SIG`.
_DYNAMIC_ARITY = frozenset({
    "dig", "bury", "cover", "uncover", "popn", "dupn",
    "pushints", "pushbytess", "match", "switch",
    "frame_dig", "frame_bury", "callsub", "retsub", "proto",
})


def _teal_ops():
    """Puya ops that share a mnemonic with the TEAL source token."""
    return [op for op in AVMOp if op.code not in _PUYA_ONLY_NAMES]


def test_every_puya_opcode_has_a_sig_entry():
    """An opcode absent from :data:`avm.SIG` is modelled as ``(0, 0)`` — no
    stack effect at all — which corrupts the SSA reconstruction for every
    program using it. That must never happen silently."""
    missing = sorted(
        op.code for op in _teal_ops()
        if op.code not in avm.SIG and op.code not in _DYNAMIC_ARITY
    )
    assert not missing, (
        f"opcodes puya models but avm.SIG does not: {missing} — each is "
        "modelled with NO stack effect. Add them to SIG."
    )


# Arity VALUES floor: how many SIG entries have a puya static signature to
# compare against today. A puya rename that silently drops ops out of the
# comparison regresses this count instead of shrinking coverage unnoticed.
_MIN_ARITY_COVERED = 120


def test_sig_arities_match_puya_signatures():
    """The (n_in, n_out) VALUES — not just presence. A wrong arity shifts every
    later stack slot, corrupting the whole SSA reconstruction with no local
    symptom, so each entry with a static puya signature is pinned to it.
    ``return`` is the ONE deliberate divergence (see the HAZARD in avm.SIG:
    modelling its pop would shrink the exit stack the lift reads)."""
    mismatches = []
    checked = 0
    for member in AVMOp:
        code = member.code
        sig = avm.SIG.get(code)
        if sig is None or code == "return":
            continue
        variants = getattr(member, "_variants", None)
        if not isinstance(variants, Variant):
            continue  # dynamic-signature ops are field-keyed, typed elsewhere
        checked += 1
        want = (len(variants.signature.args), len(variants.signature.returns))
        if sig != want:
            mismatches.append((code, sig, want))
    assert not mismatches, (
        "SIG arities disagree with puya's langspec "
        f"(op, SIG_says, puya_says): {mismatches}")
    assert checked >= _MIN_ARITY_COVERED, (
        f"only {checked} SIG arities compared against puya "
        f"(floor {_MIN_ARITY_COVERED}) — did puya restructure AVMOp?")


def test_return_pop_matches_avm_and_is_an_explicit_live_out():
    """``return`` consumes its approval value in SSA just as it does on AVM.

    Puya does not model it as an intrinsic, so the generic metadata comparison
    cannot pin this. An explicit input is load-bearing: DCE must see the
    approval producer as live and every consumer must agree on the returned
    value rather than recovering it from a neighbouring instruction/stack.
    """
    assert avm.SIG["return"] == (1, 0)
    assert not any(m.code == "return" for m in AVMOp)


def test_immediate_keyed_result_tables_match_puya():
    """block / json_ref result types are keyed on the immediate (DynamicVariants
    in puya). Pin the tables COMPLETE in both directions and coarse-type-equal,
    so a new AVM version's block field fails here instead of going untyped —
    the exact 'v11 tail' rot this file exists to prevent."""
    from puya.ir.avm_ops_models import DynamicVariants

    for op_name, table in (("block", avm._BLOCK_FIELD_TYPE),
                           ("json_ref", avm._JSON_REF_RESULT_TYPE)):
        variants = getattr(AVMOp, op_name)._variants
        assert isinstance(variants, DynamicVariants)
        assert set(table) == set(variants.variant_map), (
            op_name, set(table) ^ set(variants.variant_map))
        for key, var in variants.variant_map.items():
            (ret,) = var.signature.returns  # both ops: single result per kind
            want = ("u" if ret.avm_type == AVMType.uint64
                    else "b" if ret.avm_type == AVMType.bytes else "?")
            assert avm.avm(table[key]) == want, (op_name, key, table[key], want)

    # Every params/holding getter routes through the same multi-output typing
    # machinery: value followed by did_exist in puya source order (the SSA
    # representation reverses that to TOP-FIRST). Pin field completeness in
    # both directions, not merely the fields TealQL happened to know already;
    # this is what caught AppVersion when AVM v12 added it.
    for op_name, fields in avm.PARAMS_FIELDS_BY_OP.items():
        assert op_name in avm._EX_FLAG_OPS
        variants = getattr(AVMOp, op_name)._variants
        assert set(fields) == set(variants.variant_map), (
            op_name, set(fields) ^ set(variants.variant_map))
        for key, var in variants.variant_map.items():
            value_ret = var.signature.returns[0]
            want = "u" if value_ret.avm_type == AVMType.uint64 else "b"
            assert avm.avm(avm.PARAMS_FIELD_TYPE[key]) == want, (op_name, key)


def test_every_operand_position_has_an_expected_type():
    """Each ARGUMENT POSITION of every statically-signed op must resolve to the
    AVM family puya declares — the tables are the lift's only typing signal.

    A missing position is not a missing refinement but a missing SIGNAL: a value
    consumed ONLY there gets no expected type, stays ``?``, and lowering defaults
    it to uint64. That is how a pubkey used only by ``ed25519verify_bare``
    lowered to uint64 and made a contract uncompilable, and how the whole
    elliptic-curve family sat untyped while its results were typed. Positions
    puya itself declares polymorphic (``any``) are exempt — for those, unknown
    is the correct answer and the value flow decides.

    HAZARD: this must walk BOTH signature kinds. Checking only the statically
    signed ops reads as complete while leaving every immediate-keyed op
    unverified — that gap hid 47 untyped positions (the ``*_params_get`` /
    ``asset_holding_get`` id operands, ``block``'s round, ``json_ref``'s
    operands), including the one that left a value feeding
    ``asset_holding_get`` with no signal at all.
    """
    from puya.avm import AVMType as _AVMType
    from puya.ir.avm_ops_models import DynamicVariants

    from tealql.tealtools.lift import type_recovery as TR

    class _Unknown:
        ir_type = "?"

    missing, wrong, covered = [], [], 0

    def check(sig_args, code, imm=None):
        nonlocal covered
        # puya lists args deepest-first; _expected_type indexes TOP-FIRST.
        top_first = list(reversed(sig_args))
        args = [_Unknown() for _ in top_first]
        for idx, arg in enumerate(top_first):
            at = getattr(arg, "avm_type", None)
            if at not in (_AVMType.uint64, _AVMType.bytes):
                continue                      # polymorphic: deliberately open
            want = "uint64" if at == _AVMType.uint64 else "bytes"
            got = TR._expected_type(code, idx, args, imm=[imm] if imm else None)
            if got is None:
                missing.append((code, imm, idx, want))
                continue
            family = ("bytes" if got in TR._BYTES_FAMILY
                      else "uint64" if got in TR._U64_FAMILY else got)
            if family != want:
                wrong.append((code, imm, idx, want, got))
            else:
                covered += 1

    for member in AVMOp:
        variants = getattr(member, "_variants", None)
        if isinstance(variants, Variant):
            if variants.signature.args:
                check(variants.signature.args, member.code)
        elif isinstance(variants, DynamicVariants):
            for key, var in variants.variant_map.items():
                if var.signature.args:
                    check(var.signature.args, member.code, key)

    assert not wrong, f"operand types contradict puya (op, imm, idx, puya, ours): {wrong}"
    assert not missing, (
        "operand positions with NO expected type (op, imm, top-first idx, puya "
        f"says): {missing} — a value used only there stays `?` and lowers to uint64")
    assert covered >= 400, f"only {covered} positions compared — did puya restructure?"


def test_every_single_result_op_is_typed():
    """A single-result op absent from every result table produces an UNTYPED
    value: consumed only at a polymorphic position it stays ``?`` and lowering
    guesses. That is how the bitwise ops (``&`` ``|`` ``^`` ``~``) and the whole
    verify-flag family sat untyped — invisible to the family-comparison test,
    which only checks ops it already finds IN a table.

    Refining beyond puya is allowed (we type ``txna Assets`` ``asset`` where
    puya says ``uint64``, and ``bytes`` covers its sized ``bytes[N]``); crossing
    the uint64/bytes divide is not."""
    from puya.ir.avm_ops_models import DynamicVariants

    from tealql.tealtools.language.avm import _BOOL_OPS, _BYTES_OPS, _U64_OPS

    def ours(code, imm):
        if code in _BOOL_OPS:
            return "bool"
        ft = avm._field_type(code, imm or "")
        if ft:
            return ft
        if code in _U64_OPS:
            return "uint64"
        if code in _BYTES_OPS:
            return "bytes"
        return None

    untyped, crossed = [], []
    for member in AVMOp:
        variants = getattr(member, "_variants", None)
        if isinstance(variants, Variant):
            cases = [(None, variants.signature.returns)]
        elif isinstance(variants, DynamicVariants):
            cases = [(k, v.signature.returns) for k, v in variants.variant_map.items()]
        else:
            continue
        for imm, returns in cases:
            if len(returns) != 1 or str(returns[0]) == "any":
                continue
            got = ours(member.code, imm)
            if got is None:
                untyped.append((member.code, imm, str(returns[0])))
                continue
            want_fam = "u" if getattr(returns[0], "avm_type", None) == AVMType.uint64 else "b"
            if avm.avm(got) != want_fam:
                crossed.append((member.code, imm, str(returns[0]), got))

    assert not crossed, f"result type crosses the AVM divide: {crossed}"
    assert not untyped, (
        f"single-result ops with NO type: {untyped} — values they produce stay "
        "`?` and lowering guesses")


def test_multi_output_slot_types_match_puya_exactly():
    """Per-slot types of multi-result ops, compared EXACTLY — not by AVM family.

    HAZARD: the family comparison the result-table test uses cannot see this.
    ``bool`` and ``uint64`` are both ``u``, so typing every ``did_exist`` /
    ``verified`` flag as a plain uint64 read as agreeing with puya while being
    strictly coarser than the langspec we already have — and coarser than the
    lift's own treatment of comparison results, which it types ``bool``.

    Slots puya declares polymorphic (``any``, i.e. a state value whose type
    depends on the contract's schema) are exempt: unknown is correct there."""
    from puya.ir.avm_ops_models import DynamicVariants

    mismatches = []
    for member in AVMOp:
        variants = getattr(member, "_variants", None)
        if isinstance(variants, Variant):
            cases = [(None, variants.signature.returns)]
        elif isinstance(variants, DynamicVariants):
            cases = [(k, v.signature.returns)
                     for k, v in variants.variant_map.items()]
        else:
            continue
        for imm, returns in cases:
            if len(returns) < 2:
                continue                       # single-result ops typed elsewhere
            # puya lists returns deepest-first; our slots are TOP-FIRST.
            for idx, ret in enumerate(reversed(returns)):
                want = str(ret)
                if want == "any":
                    continue                   # schema-dependent: correctly unknown
                got = avm._multi_out_type(member.code, imm or "", idx)
                if got is None:
                    continue                   # deliberately unknowable slot
                if got != want:
                    mismatches.append((member.code, imm, idx, want, got))

    # bytes[N] / sized types are a finer distinction than this table models;
    # only flag a genuine name disagreement, not a width refinement.
    real = [m for m in mismatches if not m[3].startswith(m[4])]
    assert not real, (
        "multi-output slot types disagree with puya "
        f"(op, immediate, top-first slot, puya, ours): {real}")


def test_block_address_fields_single_source_consistency():
    """Same single-source lock as the txn/global address universes, for the
    ``block`` fields added with them: every ADDRESS_BLOCK_FIELDS entry is
    account-typed AND 32 bytes, and nothing else in the block table claims
    to be an account."""
    for f in avm.ADDRESS_BLOCK_FIELDS:
        assert avm._BLOCK_FIELD_TYPE.get(f) == "account", f
        assert avm._BLOCK_FIELD_BYTELEN.get(f) == 32, f
    assert {f for f, t in avm._BLOCK_FIELD_TYPE.items() if t == "account"} \
        == set(avm.ADDRESS_BLOCK_FIELDS)
