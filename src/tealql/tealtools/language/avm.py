"""AVM / TEAL language metadata — THE single home (one place per AVM bump).

Pure spec data plus tiny lookups, with no imports from the rest of
``tealtools`` (leaf module, so ssa / dataflow / lift / cfg / security all
consume it without cycles) — ONE deliberate exception: :func:`op_arity`
lazily borrows ``const_values._split_byte_literals`` to count ``pushbytess``
literals, because quoted byte literals contain spaces and real parsing stays
in ``const_values``. The tables cover opcode arities (:data:`SIG` / :func:`op_arity`),
opcode groups and txn-field families, op result types and field types, uint64
range and byte-length seeds, and op classification (shuffles, terminators,
constblock refs).

HAZARD: this is SPEC data with a real source of truth. Derive narrower views by
filtering these tables — never hand-roll a fresh literal, which is how they
drifted apart across four modules before consolidation. The result-type and
byte-length tables are pinned against puya's langspec by
``tests/test_avm_metadata_drift.py``; bump :data:`AVM_LANGSPEC_VERSION` and
re-run it when adding a new AVM version's opcodes.
"""
from __future__ import annotations

from typing import Optional

#: AVM/TEAL langspec version these tables target (v12 = ``falcon_verify`` /
#: ``sumhash512``). Informational — the drift test pins result types and
#: arities to the installed puya, so a mismatch surfaces there.
AVM_LANGSPEC_VERSION = 12


# ===========================================================================
# Opcode stack arities
# ===========================================================================


# Constant-arity opcodes: mnemonic -> (n_in, n_out). Mnemonics are source
# tokens, so symbolic ops are "+", "&&", "b==", etc.
SIG: dict[str, tuple[int, int]] = {
    # Arithmetic
    "+": (2, 1), "-": (2, 1), "*": (2, 1), "/": (2, 1), "%": (2, 1),
    "addw": (2, 2), "mulw": (2, 2), "divmodw": (4, 4), "exp": (2, 1),
    "expw": (2, 2), "divw": (3, 1), "sqrt": (1, 1), "shl": (2, 1), "shr": (2, 1),
    # Byte arithmetic
    "b+": (2, 1), "b-": (2, 1), "b/": (2, 1), "b*": (2, 1), "b%": (2, 1),
    "bsqrt": (1, 1),
    # Byte comparison
    "b<": (2, 1), "b>": (2, 1), "b<=": (2, 1), "b>=": (2, 1),
    "b==": (2, 1), "b!=": (2, 1),
    # Comparison
    "<": (2, 1), "<=": (2, 1), ">": (2, 1), ">=": (2, 1),
    "==": (2, 1), "!=": (2, 1), "!": (1, 1),
    # Logic / bitwise
    "&&": (2, 1), "||": (2, 1), "&": (2, 1), "|": (2, 1), "^": (2, 1), "~": (1, 1),
    "b|": (2, 1), "b&": (2, 1), "b^": (2, 1), "b~": (1, 1),
    # Hashing
    "sha256": (1, 1), "sha512_256": (1, 1), "keccak256": (1, 1),
    "sha3_256": (1, 1), "mimc": (1, 1), "sumhash512": (1, 1),
    "sha512": (1, 1),                    # AVM v13: the FULL 64-byte digest

    # Crypto
    "ed25519verify": (3, 1), "ed25519verify_bare": (3, 1), "ecdsa_verify": (5, 1),
    "ecdsa_pk_decompress": (1, 2), "ecdsa_pk_recover": (4, 2), "vrf_verify": (3, 2),
    "falcon_verify": (3, 1),          # AVM v12: (message, signature, pubkey) -> bool
    # Elliptic curve
    "ec_add": (2, 1), "ec_scalar_mul": (2, 1), "ec_pairing_check": (2, 1),
    "ec_multi_scalar_mul": (2, 1),
    "ec_subgroup_check": (1, 1), "ec_map_to": (1, 1),
    # Byte ops
    "concat": (2, 1), "substring": (1, 1), "substring3": (3, 1),
    "extract": (1, 1), "extract3": (3, 1), "extract_uint16": (2, 1),
    "extract_uint32": (2, 1), "extract_uint64": (2, 1), "replace2": (2, 1),
    "replace3": (3, 1), "len": (1, 1), "bitlen": (1, 1), "getbit": (2, 1),
    "setbit": (3, 1), "getbyte": (2, 1), "setbyte": (3, 1), "itob": (1, 1),
    "btoi": (1, 1), "base64_decode": (1, 1), "json_ref": (2, 1),
    # Constants (fixed-arity members; pushints/pushbytess are dynamic — see op_arity)
    "int": (0, 1), "intc": (0, 1), "intc_0": (0, 1), "intc_1": (0, 1),
    "intc_2": (0, 1), "intc_3": (0, 1), "pushint": (0, 1), "intcblock": (0, 0),
    "bytec": (0, 1), "bytec_0": (0, 1), "bytec_1": (0, 1), "bytec_2": (0, 1),
    "bytec_3": (0, 1), "pushbytes": (0, 1), "bytecblock": (0, 0), "bzero": (1, 1),
    # Control flow (callsub/retsub handled by op_arity overrides; match dynamic).
    # ``return`` consumes the approval value exactly like the AVM. Keeping that
    # operand explicit makes it a real SSA live-out: DCE, taint, exit
    # classification and the lifter all read one semantic authority.
    "return": (1, 0), "err": (0, 0), "assert": (1, 0), "b": (0, 0),
    "bnz": (1, 0), "bz": (1, 0), "switch": (1, 0),
    # Stack manipulation (dig/popn/dupn/bury/cover/uncover/frame_* dynamic)
    "pop": (1, 0), "dup": (1, 2), "dup2": (2, 4), "swap": (2, 2),
    "select": (3, 1), "proto": (0, 0),
    # Scratch space
    "load": (0, 1), "store": (1, 0), "loads": (1, 1), "stores": (2, 0),
    "gload": (0, 1), "gloads": (1, 1), "gloadss": (2, 1), "gaid": (0, 1),
    "gaids": (1, 1),
    # Transaction
    "txn": (0, 1), "txna": (0, 1), "txnas": (1, 1), "gtxn": (0, 1),
    "gtxna": (0, 1), "gtxnas": (1, 1), "gtxns": (1, 1), "gtxnsa": (1, 1),
    "gtxnsas": (2, 1), "gitxn": (0, 1), "gitxna": (0, 1), "gitxnas": (1, 1),
    # Global / app state
    "global": (0, 1), "app_opted_in": (2, 1), "app_local_get": (2, 1),
    "app_local_get_ex": (3, 2), "app_global_get": (1, 1), "app_global_get_ex": (2, 2),
    "app_local_put": (3, 0), "app_global_put": (2, 0), "app_local_del": (2, 0),
    "app_global_del": (1, 0), "app_params_get": (1, 2), "asset_holding_get": (2, 2),
    "asset_params_get": (1, 2), "acct_params_get": (1, 2), "balance": (1, 1),
    "min_balance": (1, 1), "online_stake": (0, 1), "voter_params_get": (1, 2),
    # Inner transactions
    "itxn_begin": (0, 0), "itxn_next": (0, 0), "itxn_submit": (0, 0),
    "itxn_field": (1, 0), "itxn": (0, 1), "itxna": (0, 1), "itxnas": (1, 1),
    # Logging
    "log": (1, 0),
    # Misc
    "arg": (0, 1), "arg_0": (0, 1), "arg_1": (0, 1), "arg_2": (0, 1),
    "arg_3": (0, 1), "args": (1, 1), "block": (1, 1),
    # Box storage
    "box_create": (2, 1), "box_extract": (3, 1), "box_replace": (3, 0),
    "box_del": (1, 1), "box_len": (1, 2), "box_get": (1, 2), "box_put": (2, 0),
    "box_splice": (4, 0), "box_resize": (2, 0),
}

# Height-dependent ops PySSA phase 1 instantiates with simple counts; the
# proto-aware forms are rebuilt by later PySSA phases.
_FRAME_OVERRIDES: dict[str, tuple[int, int]] = {
    "frame_dig": (0, 1),
    "frame_bury": (1, 0),
    "callsub": (0, 0),
    "retsub": (0, 0),
}


def _imm_int(immediates: str) -> int:
    try:
        return int(immediates.split()[0])
    except (ValueError, IndexError):
        return 0


#: Opcodes :func:`op_arity` was asked about but does not know. Module-level
#: because ``op_arity`` is a pure function called from every layer.
_UNKNOWN_OPS: set[str] = set()

#: Every opcode :func:`op_arity` special-cases AHEAD of the :data:`SIG` lookup
#: (immediate-dependent arities). :func:`is_known_op`'s contract is that this
#: set + :data:`_FRAME_OVERRIDES` + :data:`SIG` is the complete modelled
#: universe — a new special-case branch in ``op_arity`` must be added here too,
#: and forgetting fails LOUD (a spurious refusal on corpus contracts), never
#: wrong.
_IMMEDIATE_ARITY_OPS: frozenset[str] = frozenset({
    "dig", "bury", "cover", "uncover", "popn", "dupn",
    "pushints", "pushbytess", "match",
})


def is_known_op(op: str) -> bool:
    """Whether this build can model ``op``'s stack effect. :func:`op_arity`
    answers ``(0, 0)`` for an unknown opcode — which silently corrupts the
    whole downstream stack simulation — so boundary callers consult this and
    refuse instead (:class:`..errors.UnknownOpcodeError`)."""
    return (op in SIG or op in _FRAME_OVERRIDES
            or op in _IMMEDIATE_ARITY_OPS)


def unknown_opcodes() -> frozenset[str]:
    """Opcodes seen so far with no :data:`SIG` entry.

    HAZARD: their stack effect was modelled as ``(0, 0)``, which makes the whole
    downstream stack simulation wrong with no other signal. Non-empty means this
    build predates the contract's AVM version — treat every result as unreliable.

    This is a PROCESS-WIDE union across every program built so far (op_arity is
    a pure function with no program context), so in a long-lived process it
    over-reports for any single contract. Per-program callers should read
    ``SSAProgram.unknown_ops`` instead — the builder records exactly the ops
    THAT program uses."""
    return frozenset(_UNKNOWN_OPS)


def op_arity(op: str, immediates: str) -> tuple[int, int]:
    """``(n_in, n_out)`` for an opcode + its immediate text; an opcode absent
    from :data:`SIG` yields ``(0, 0)`` and is recorded in :func:`unknown_opcodes`."""
    o = _FRAME_OVERRIDES.get(op)
    if o is not None:
        return o
    if op == "dig":
        n = _imm_int(immediates)
        return (n + 1, n + 2)
    if op == "bury":
        n = _imm_int(immediates)
        return (n + 1, n)
    if op == "cover" or op == "uncover":
        n = _imm_int(immediates)
        return (n + 1, n + 1)
    if op == "popn":
        return (_imm_int(immediates), 0)
    if op == "dupn":
        return (1, _imm_int(immediates) + 1)
    if op == "pushints":
        return (0, len(immediates.split()))
    if op == "pushbytess":
        from .constants import _split_byte_literals
        return (0, len(_split_byte_literals(immediates)))
    if op == "match":
        return (len(immediates.split()) + 1, 0)
    sig = SIG.get(op)
    if sig is None:
        _UNKNOWN_OPS.add(op)
        return (0, 0)
    return sig


# ===========================================================================
# Opcode groups and transaction-field families
# ===========================================================================

# --- address (32-byte account) fields -------------------------------------

#: Txn-family fields reading a 32-byte account address. SINGLE SOURCE: being an
#: address determines BOTH the AVM type (``"account"``, ``_TXN_FIELD_TYPE``) and
#: the byte length (32, ``_TXN_FIELD_BYTELEN``); both derive from this set, so a
#: new address field is added in ONE place.
ADDRESS_TXN_FIELDS: frozenset[str] = frozenset({
    "Sender", "Receiver", "CloseRemainderTo", "RekeyTo",
    "AssetSender", "AssetReceiver", "AssetCloseTo", "FreezeAssetAccount",
    "ConfigAssetManager", "ConfigAssetReserve", "ConfigAssetFreeze",
    "ConfigAssetClawback",
    "Accounts",                         # array element (txna Accounts i)
})

#: ``global`` fields reading a 32-byte address (same single-source role).
#: ``global`` fields that are NOT execution-stable — they change as the program
#: runs, so two reads can differ and a predicate on one does not survive a call.
#:
#: HAZARD: this is the STABILITY question, NOT the trust question. A field can be
#: perfectly stable and still attacker-chosen (``GroupSize`` — the attacker
#: assembles the group but it does not change mid-execution); that set lives in
#: ``dataflow.byte_taint._CLEAN_GLOBALS``. Conflating them either loses proofs or
#: credits guards on values the caller controls.
UNSTABLE_GLOBAL_FIELDS = frozenset({"OpcodeBudget"})


ADDRESS_GLOBAL_FIELDS: frozenset[str] = frozenset({
    "ZeroAddress", "CreatorAddress",
    "CurrentApplicationAddress", "CallerApplicationAddress",
})

#: ``block`` fields reading a 32-byte address (same single-source role): the
#: round's proposer and the protocol fee sink.
ADDRESS_BLOCK_FIELDS: frozenset[str] = frozenset({
    "BlkProposer", "BlkFeeSink",
})


# --- inner-transaction fields ---------------------------------------------

#: Inner-txn fields whose operand governs value movement or control transfer —
#: attacker control over any of these is the thing worth reporting.
SENSITIVE_ITXN_FIELDS: frozenset[str] = frozenset({
    "Receiver", "Amount", "AssetReceiver", "AssetAmount",
    "ApplicationID", "RekeyTo", "CloseRemainderTo", "AssetCloseTo",
    "ApprovalProgram", "ClearStateProgram",
})

#: Payment fields where attacker control = redirected / oversized fund movement,
#: tagged by severity (account-draining close fields rank CRITICAL).
#:
#: HAZARD: ``RekeyTo`` is deliberately NOT here — rekey is an LSIG-only check. An
#: app-call's ``txn RekeyTo`` rekeys the USER's own account and an ``itxn_field
#: RekeyTo`` rekeys the app's own, so neither is an app fund-flow sink; adding it
#: here fires on every app. See :data:`CLOSE_REKEY_FIELDS`.
FUND_FIELDS: dict[str, str] = {
    "CloseRemainderTo": "CRITICAL",
    "AssetCloseTo": "CRITICAL",
    "Receiver": "HIGH",
    "AssetReceiver": "HIGH",
    "Amount": "MEDIUM",
    "AssetAmount": "MEDIUM",
}

#: The "pure payment" (no close/rekey) subset of :data:`FUND_FIELDS`.
PAYMENT_FUND_FIELDS: dict[str, str] = {
    k: v for k, v in FUND_FIELDS.items()
    if k in ("Receiver", "AssetReceiver", "Amount", "AssetAmount")
}

#: Account-draining / control-handover fields (each has its own dedicated
#: validator detector).
CLOSE_REKEY_FIELDS: frozenset[str] = frozenset({
    "CloseRemainderTo", "RekeyTo", "AssetCloseTo",
})

#: Asset-transfer value / destination / source fields.
ASSET_TRANSFER_FIELDS: frozenset[str] = frozenset({
    "AssetAmount", "AssetReceiver", "AssetSender",
})

# --- state-mutating / sink opcodes ----------------------------------------

#: Opcodes mutating persistent state or emitting a transaction — the sensitive
#: sink family, which should run only on a guard-dominated path.
STATE_MUTATING_OPS: frozenset[str] = frozenset({
    "box_create", "box_put", "box_replace", "box_del", "box_splice",
    "box_resize",
    "app_global_put", "app_global_del",
    "app_local_put", "app_local_del",
    "itxn_submit",
})

#: Just the persistent-state WRITE ops (the box / app put/del family, without
#: ``itxn_submit``).
STATE_WRITE_OPS: frozenset[str] = STATE_MUTATING_OPS - {"itxn_submit"}

# --- user-input / transaction source opcode families ----------------------

#: Current/group transaction field reads, including the ``*as`` stack-index
#: variants.
TXN_SOURCE_OPS: frozenset[str] = frozenset({
    "txn", "txna", "txnas",
    "gtxn", "gtxna", "gtxnas", "gtxns", "gtxnsa", "gtxnsas",
})

#: Inner-transaction result reads (log / created-id / field read-back).
ITXN_SOURCE_OPS: frozenset[str] = frozenset({
    "itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas",
})

#: Logic-signature argument reads.
LSIG_ARG_OPS: frozenset[str] = frozenset({
    "arg", "args", "arg_0", "arg_1", "arg_2", "arg_3",
})

#: Transaction ARRAY fields the SENDER composes, so attacker-controlled input in
#: exactly the way ``ApplicationArgs`` is: ``txn Accounts 1`` is a caller-named
#: address, ``txn Assets 0`` a caller-named asset. HAZARD: index 0 of
#: ``Accounts`` is the SENDER — an authorisation value, not a free choice — so
#: check the index against :data:`FOREIGN_ARRAY_SELF_INDEX`.
FOREIGN_ARRAY_FIELDS: frozenset[str] = frozenset({
    "Accounts", "Assets", "Applications",
})

#: ``Accounts 0`` is ``Sender`` — implicit, not caller-chosen.
FOREIGN_ARRAY_SELF_INDEX: dict[str, int] = {"Accounts": 0}


def attacker_input_label(op: str, immediates: str) -> Optional[str]:
    """The attacker-controlled input family ``op`` reads, or ``None`` — THE
    single source for "is this read attacker-steerable", shared by the SSA-level
    and IR-level taint seeds. An absent or non-constant index in ``immediates``
    still labels the read: a computed index is no less attacker-chosen.

    HAZARD: the field is matched as an EXACT token via :func:`txn_field_name`,
    never by substring — ``txn NumAccounts`` (the uint64 array-length read)
    contains ``"Accounts"`` and used to be mislabelled ``ForeignAccounts``,
    seeding phantom taint on every count-guarded contract."""
    if op in LSIG_ARG_OPS:
        return "LogicSigArgs"
    field = txn_field_name(op, immediates)
    if op in TXN_SOURCE_OPS and field is not None:
        if field == "ApplicationArgs":
            return "ApplicationArgs"
        if field in FOREIGN_ARRAY_FIELDS:
            # `Accounts 0` is the sender, which is not a free choice.
            toks = immediates.split()
            self_idx = FOREIGN_ARRAY_SELF_INDEX.get(field)
            if self_idx is not None and toks and toks[-1].isdigit() \
                    and int(toks[-1]) == self_idx:
                return None
            return f"Foreign{field}"
    if op in ITXN_SOURCE_OPS and field == "LastLog":
        return "ItxnLastLog"
    return None

#: Opcodes the AVM accepts ONLY in Application mode, so their presence PROVES a
#: program is an application (consumed by ``classify_program``).
#:
#: HAZARD: keyed strictly on OPCODES, never on txn fields. A logic signature can
#: be attached to an ApplicationCall txn and so may read ``OnCompletion`` /
#: ``ApplicationArgs`` / ``ApplicationID``; keying on those misclassifies that
#: whole lsig class. An app missing from this set is classified LOGICSIG and
#: gets the lsig-only detectors run against it — a false-positive swarm.
APP_ONLY_OPS: frozenset[str] = frozenset({
    # state
    "app_global_get", "app_global_put", "app_global_del", "app_global_get_ex",
    "app_local_get", "app_local_put", "app_local_del", "app_local_get_ex",
    "app_opted_in",
    # parameter / holding queries
    "app_params_get", "asset_params_get", "asset_holding_get",
    "acct_params_get", "voter_params_get", "online_stake",
    "balance", "min_balance",
    # inner transactions
    "itxn_begin", "itxn_field", "itxn_submit", "itxn_next",
    "itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas",
    # boxes
    "box_create", "box_put", "box_get", "box_del", "box_replace",
    "box_extract", "box_len", "box_resize", "box_splice",
    # logging + cross-group scratch / created-id reads
    "log", "gload", "gloads", "gloadss", "gaid", "gaids",
})

# --- comparison / boolean-combinator opcodes ------------------------------

#: uint64 comparison ops.
U64_CMP_OPS: frozenset[str] = frozenset({"==", "!=", "<", ">", "<=", ">="})

#: byteslice (``b``-prefixed) comparison ops.
BYTE_CMP_OPS: frozenset[str] = frozenset({"b==", "b!=", "b<", "b>", "b<=", "b>="})

#: All comparison ops (uint64 + byteslice).
CMP_OPS: frozenset[str] = U64_CMP_OPS | BYTE_CMP_OPS

#: Pure boolean combinators; union with :data:`CMP_OPS` for the combined view.
LOGICAL_OPS: frozenset[str] = frozenset({"&&", "||", "!"})

# --- branch opcode families ------------------------------------------------

#: Two-way conditional branches: pop one uint64, branch on non-zero (``bnz``)
#: or zero (``bz``). THE definition — three modules once hand-rolled
#: same-named sets with different contents; derive wider views by union
#: (``| MULTIWAY_BRANCH_OPS``, ``| {"b"}``), never a fresh literal.
COND_BRANCH_OPS: frozenset[str] = frozenset({"bnz", "bz"})

#: N-way value-keyed branches: ``switch`` (index into a target list) and
#: ``match`` (equality against a popped value list).
MULTIWAY_BRANCH_OPS: frozenset[str] = frozenset({"switch", "match"})


# ===========================================================================
# Op result types and field types
# ===========================================================================


#: Single-result ops whose value is a 0/1 FLAG rather than a full-width uint64.
#: Same refinement the did_exist flags get in :func:`_multi_out_type` and that
#: puya's langspec declares. They stay in :data:`_U64_OPS` too — that set is
#: consulted for the coarse AVM FAMILY, where bool and uint64 agree.
BOOL_RESULT_OPS: frozenset[str] = frozenset({
    "app_opted_in", "box_create", "box_del", "getbit",
    "falcon_verify", "ecdsa_verify", "ed25519verify", "ed25519verify_bare",
    "ec_pairing_check", "ec_subgroup_check",
})

_BOOL_OPS = CMP_OPS | LOGICAL_OPS | BOOL_RESULT_OPS
# Const-push / const-load ops are normally typed from their folded const value;
# these sets are the fallback when the parser dropped the operand
# (`pushbytes base64(..)`, `bytec N`) and there is no value to type them from.
_U64_PUSH = frozenset({"pushint", "pushints", "intc",
                       "intc_0", "intc_1", "intc_2", "intc_3"})
_BYTES_PUSH = frozenset({"pushbytes", "pushbytess", "bytec",
                         "bytec_0", "bytec_1", "bytec_2", "bytec_3"})
_U64_OPS = frozenset({"+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr",
                      "divw",                       # uint128 / uint64 -> uint64
                      "bitlen", "len", "btoi", "getbyte", "getbit",
                      "extract_uint16", "extract_uint32", "extract_uint64",
                      "box_create", "box_del",     # both return a uint64 flag
                      "gaid", "gaids",             # created asset/app id (uint64)
                      "&", "|", "^", "~",          # full-width uint64 bitwise
                      # Verification flags. Their RESULTS were in no table at
                      # all, so a value produced here and consumed only at a
                      # polymorphic position stayed `?`.
                      "falcon_verify", "ecdsa_verify",
                      "ed25519verify", "ed25519verify_bare",
                      "ec_pairing_check", "ec_subgroup_check",
                      "online_stake",              # total online stake, microalgos
                      "balance", "min_balance", "app_opted_in"}) | _U64_PUSH
_BYTES_OPS = frozenset({"itob", "concat", "substring", "substring3", "extract",
                        "extract3", "replace2", "replace3", "sha256",
                        "sha512_256", "sha512", "keccak256", "sha3_256", "bzero",
                        "setbyte", "b+", "b-", "b*", "b/", "b%",
                        "b|", "b&", "b^", "b~", "bsqrt", "box_extract",
                        "mimc", "sumhash512", "base64_decode",
                        "ec_add", "ec_map_to", "ec_scalar_mul",
                        "ec_multi_scalar_mul",
                        # ecdsa pubkey ops return TWO byteslices (X, Y of the
                        # recovered / decompressed point); `ecdsa_verify` returns
                        # a uint64 flag and so is NOT here.
                        "ecdsa_pk_recover", "ecdsa_pk_decompress",
                        "arg", "arg_0", "arg_1", "arg_2", "arg_3", "args",
                        }) | _BYTES_PUSH
# HAZARD: `setbit` is POLYMORPHIC — its result type equals its VALUE operand
# (`setbit A B C` -> type of A, uint64 or bytes), so it must stay out of
# _BYTES_OPS and be typed from that operand. (`getbit` always returns uint64;
# `setbyte` is byte-array only.)
_POLY_FIRST_OPERAND_OPS = frozenset({"setbit"})
_NAME_PREFIX = {"len": "len", "==": "eq", "!=": "ne", "<": "lt", ">": "gt",
                "<=": "le", ">=": "ge", "!": "not", "&&": "and", "||": "or",
                "btoi": "val", "concat": "concat", "itob": "enc"}

# Transaction-field accessors. The field name is one of the immediate tokens and
# its POSITION varies (gtxn puts a group index first), so _field_type scans all
# tokens against the table.
_TXN_OPS = TXN_SOURCE_OPS | ITXN_SOURCE_OPS
_TXN_FIELD_TYPE = {
    # uint64
    "Fee": "uint64", "FirstValid": "uint64", "FirstValidTime": "uint64",
    "LastValid": "uint64", "TypeEnum": "uint64", "GroupIndex": "uint64",
    "Amount": "uint64", "AssetAmount": "uint64", "OnCompletion": "uint64",
    "NumAppArgs": "uint64", "NumAccounts": "uint64", "NumAssets": "uint64",
    "NumApplications": "uint64", "NumLogs": "uint64", "AssetCloseAmount": "uint64",
    "GlobalNumUint": "uint64", "GlobalNumByteSlice": "uint64",
    "LocalNumUint": "uint64", "LocalNumByteSlice": "uint64",
    "ExtraProgramPages": "uint64", "ConfigAssetTotal": "uint64",
    "ConfigAssetDecimals": "uint64", "VoteFirst": "uint64", "VoteLast": "uint64",
    "VoteKeyDilution": "uint64", "NumApprovalProgramPages": "uint64",
    "NumClearStateProgramPages": "uint64", "RejectVersion": "uint64",
    # bool
    "ConfigAssetDefaultFrozen": "bool", "FreezeAssetFrozen": "bool",
    "Nonparticipation": "bool",
    # account (addresses) — merged in below from ADDRESS_TXN_FIELDS.
    # asset / application ids
    "XferAsset": "asset", "ConfigAsset": "asset", "FreezeAsset": "asset",
    "CreatedAssetID": "asset", "Assets": "asset",
    "ApplicationID": "application", "Applications": "application",
    "CreatedApplicationID": "application",
    # bytes
    "Note": "bytes", "Lease": "bytes", "Type": "bytes", "GroupID": "bytes",
    "TxID": "bytes",                  # 32-byte transaction hash
    "ApplicationArgs": "bytes", "Logs": "bytes", "LastLog": "bytes",
    "ApprovalProgram": "bytes", "ClearStateProgram": "bytes",
    "ApprovalProgramPages": "bytes", "ClearStateProgramPages": "bytes",
    "VotePK": "bytes", "SelectionPK": "bytes", "StateProofPK": "bytes",
    "ConfigAssetName": "bytes", "ConfigAssetUnitName": "bytes",
    "ConfigAssetURL": "bytes", "ConfigAssetMetadataHash": "bytes",
}
# Merged from the single source so the address universe isn't listed twice.
_TXN_FIELD_TYPE.update({f: "account" for f in ADDRESS_TXN_FIELDS})

_GLOBAL_FIELD_TYPE = {
    "MinTxnFee": "uint64", "MinBalance": "uint64", "MaxTxnLife": "uint64",
    "GroupSize": "uint64", "LogicSigVersion": "uint64", "Round": "uint64",
    "LatestTimestamp": "uint64", "OpcodeBudget": "uint64",
    "AssetCreateMinBalance": "uint64", "AssetOptInMinBalance": "uint64",
    "PayoutsGoOnlineFee": "uint64", "PayoutsPercent": "uint64",
    "PayoutsMinBalance": "uint64", "PayoutsMaxBalance": "uint64",
    "PayoutsEnabled": "bool",
    "CurrentApplicationID": "application", "CallerApplicationID": "application",
    "GenesisHash": "bytes",
    "GroupID": "bytes",                 # 32-byte group id (also a txn field)
}
_GLOBAL_FIELD_TYPE.update({f: "account" for f in ADDRESS_GLOBAL_FIELDS})

# ``block`` field types, immediate-keyed like the txn/global tables. Address
# fields derive from the single source above; the rest are enumerated.
_BLOCK_FIELD_TYPE = {
    "BlkSeed": "bytes", "BlkBranch": "bytes", "BlkProtocol": "bytes",
    "BlkTimestamp": "uint64", "BlkFeesCollected": "uint64", "BlkBonus": "uint64",
    "BlkTxnCounter": "uint64", "BlkProposerPayout": "uint64",
}
_BLOCK_FIELD_TYPE.update({f: "account" for f in ADDRESS_BLOCK_FIELDS})

# ``json_ref``'s single result is keyed by its KIND immediate, not a field —
# same lookup shape, so _field_type serves it too.
_JSON_REF_RESULT_TYPE = {
    "JSONString": "bytes", "JSONObject": "bytes", "JSONUint64": "uint64",
}


def _field_type(op, immediates):
    """Type of an immediate-keyed read — a ``txn``-family / ``global`` /
    ``block`` field or a ``json_ref`` kind (immediates scanned for a known
    name) — or ``None`` if ``op`` isn't one or the name is unknown."""
    toks = immediates.split() if immediates else []
    if op in _TXN_OPS:
        table = _TXN_FIELD_TYPE
    elif op == "global":
        table = _GLOBAL_FIELD_TYPE
    elif op == "block":
        table = _BLOCK_FIELD_TYPE
    elif op == "json_ref":
        table = _JSON_REF_RESULT_TYPE
    else:
        return None
    for tk in toks:
        if tk in table:
            return table[tk]
    return None


#: Single-result ops producing a BIGUINT — a big-endian arbitrary-precision
#: number in a byte slice. Distinct from opaque ``bytes`` because it is
#: NUMERIC: an address or a hash is never byte-math output, so the two being
#: indistinguishable hid a real type confusion. Only the b-ARITHMETIC ops
#: qualify — ``b|`` / ``b&`` / ``b^`` / ``b~`` are bitwise over raw byte slices
#: and stay ``bytes``, exactly as puya declares them.
#:
#: HAZARD: results ONLY. Typing the OPERANDS biguint (puya declares `b==`'s
#: operands biguint) would retype two addresses compared with `b==`, destroying
#: their `account` typing to say something the comparison does not require.
BIGUINT_RESULT_OPS: frozenset[str] = frozenset({
    "b+", "b-", "b*", "b/", "b%", "bsqrt",
})

#: AVM types that live in a byte-slice stack value vs a uint64.
_AVM_BYTES_TYPES = frozenset({"bytes", "account", "string", "biguint"})
_AVM_UINT64_TYPES = frozenset({"uint64", "bool", "asset", "application"})


def txn_field_avm_type(field: str) -> "str | None":
    """The canonical AVM stack type of a txn field's value: ``'b'`` (byte slice —
    addresses, notes, programs), ``'u'`` (uint64 — ids, amounts, flags), or
    ``None`` for an unknown field."""
    t = _TXN_FIELD_TYPE.get(field)
    if t in _AVM_BYTES_TYPES:
        return "b"
    if t in _AVM_UINT64_TYPES:
        return "u"
    return None


# Per-output-slot types for multi-result intrinsics. HAZARD: outputs are
# TOP-FIRST — the `*_get_ex` / `*_params_get` / `*_holding_get` / `box_get` ops
# leave `did_exist` on TOP (output 0) and the value below (output 1).
# `box_len` puts `did_exist` over a uint64 length; the `w` arithmetic ops give
# all-uint64 word pairs / quads.
#
# Every did_exist / verified flag is a `bool`, not a plain uint64 — the same
# refinement the lift already applies to comparison results (`_BOOL_OPS`), and
# what puya's own langspec declares for all ten. Coarse-typing them uint64 was
# invisible to the result-table drift test, which compares only AVM FAMILIES
# (bool and uint64 are both `u`), so it read as agreeing.
_MULTI_ALL_U64 = frozenset({"addw", "mulw", "expw", "divmodw"})
_EX_FLAG_OPS = frozenset({
    "app_global_get_ex", "app_local_get_ex", "asset_holding_get",
    "asset_params_get", "app_params_get", "acct_params_get",
    "voter_params_get",
})
_PARAMS_FIELD_TYPE = {
    # acct_params_get
    "AcctBalance": "uint64", "AcctMinBalance": "uint64", "AcctAuthAddr": "account",
    "AcctTotalNumUint": "uint64", "AcctTotalNumByteSlice": "uint64",
    "AcctTotalExtraAppPages": "uint64", "AcctTotalAppsCreated": "uint64",
    "AcctTotalAppsOptedIn": "uint64", "AcctTotalAssetsCreated": "uint64",
    "AcctTotalAssets": "uint64", "AcctTotalBoxes": "uint64",
    "AcctTotalBoxBytes": "uint64", "AcctIncentiveEligible": "bool",
    "AcctLastProposed": "uint64", "AcctLastHeartbeat": "uint64",
    # app_params_get
    "AppApprovalProgram": "bytes", "AppClearStateProgram": "bytes",
    "AppGlobalNumUint": "uint64", "AppGlobalNumByteSlice": "uint64",
    "AppLocalNumUint": "uint64", "AppLocalNumByteSlice": "uint64",
    "AppExtraProgramPages": "uint64", "AppCreator": "account",
    "AppAddress": "account",
    # voter_params_get
    "VoterBalance": "uint64", "VoterIncentiveEligible": "bool",
    # asset_holding_get
    "AssetBalance": "uint64", "AssetFrozen": "bool",
    # asset_params_get
    "AssetTotal": "uint64", "AssetDecimals": "uint64",
    "AssetDefaultFrozen": "bool", "AssetUnitName": "bytes", "AssetName": "bytes",
    "AssetURL": "bytes", "AssetMetadataHash": "bytes", "AssetManager": "account",
    "AssetReserve": "account", "AssetFreeze": "account",
    "AssetClawback": "account", "AssetCreator": "account",
}


def _multi_out_type(op, immediates, idx):
    """Type of output slot ``idx`` (0 = TOP of stack) of a multi-result op, or
    ``None`` when the op isn't a typed multi-result or the slot's type is
    unknowable here (an ``*_get_ex`` value depends on the contract's state
    schema, not the op)."""
    if op in _MULTI_ALL_U64:
        return "uint64"
    if op == "box_len":
        return "bool" if idx == 0 else "uint64"    # did_exist, length
    if op == "box_get":
        return "bool" if idx == 0 else "bytes"     # did_exist, value
    if op == "vrf_verify":
        return "bool" if idx == 0 else "bytes"     # verified flag, 64-byte output
        # _OP_OUTPUT_BYTELEN pins the 64 only once the slot is typed bytes.
    if op in _EX_FLAG_OPS:
        if idx == 0:
            return "bool"                           # did_exist flag
        toks = immediates.split() if immediates else []
        for tk in toks:
            if tk in _PARAMS_FIELD_TYPE:
                return _PARAMS_FIELD_TYPE[tk]       # params/holding value field
        return None                                 # state-schema-dependent value
    return None


# Ops whose operand AVM type is unambiguous, used to decide a phi-web's type in
# the lift's mixed-type reconciliation. `==`/`!=` are excluded because they
# accept BOTH; `itxn_field` is field-dependent.
_U64_CONSUME = frozenset({
    "+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr", "<", ">", "<=", ">=",
    "itob", "bitlen", "!", "&&", "||", "assert", "&", "|", "^", "~"})
_BYTES_CONSUME = frozenset({
    "concat", "len", "btoi", "log", "sha256", "sha512_256", "sha512", "keccak256",
    "sha3_256", "extract", "extract3", "substring", "substring3", "replace2",
    "replace3", "b+", "b-", "b*", "b/", "b%", "b<", "b>",
    "extract_uint16", "extract_uint32", "extract_uint64",
    # `b==` / `b!=` are NOT the polymorphic `==`/`!=`: they take byteslices
    # only, so they type their operands just as hard as `b<`.
    "b<=", "b>=", "b==", "b!=", "b|", "b&", "b^", "b~", "bsqrt",
    "setbyte", "getbyte", "base64_decode", "mimc", "sumhash512",
    # The signature-verify family: every operand is a byteslice (message,
    # signature, public key). `ecdsa_pk_recover` is the one exception — its
    # recovery id is a uint64 — so it is typed positionally by the lift instead.
    "ed25519verify", "ed25519verify_bare", "falcon_verify",
    "ecdsa_verify", "ecdsa_pk_decompress", "vrf_verify",
    # The elliptic-curve family: every operand is a byteslice (curve points,
    # scalars). Their RESULTS were typed while their operands were not, which is
    # the exact shape that made a contract uncompilable for `ed25519verify_bare`
    # above — a value consumed ONLY here had no typing signal, so it lowered to
    # the uint64 default where the AVM wants bytes.
    "ec_add", "ec_scalar_mul", "ec_multi_scalar_mul", "ec_pairing_check",
    "ec_map_to", "ec_subgroup_check"})


def avm(t) -> str:
    """Coarse AVM type of a type name: 'b' (bytes), 'u' (uint64), '?' (unknown)."""
    return ("b" if t in ("bytes", "account", "string", "biguint")
            else "u" if t in ("uint64", "bool", "asset", "application")
            else "?")


# ===========================================================================
# Range / byte-length seeds and op classification
# ===========================================================================


_CONST_BLOCK_REF_NAMES = frozenset({
    # constblock references
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
    # inline-literal pushers (literal in immediates; the resolved-constant
    # table already emits values, so propagation reads through).
    "IntOpcode", "PushintOpcode", "PushbytesOpcode",
})


# Control-flow terminators. HAZARD: these affect the flow graph independently of
# their SSA outputs, so dead-code elimination must NOT drop them even when every
# output is a dead constant — a `retsub` whose return value was const-propagated
# still transfers control to the caller.
_TERMINATOR_OPS = frozenset({
    "callsub", "retsub",
    "b", "bnz", "bz",
    "return", "err",
    "switch", "match",
})


# Per-op uint64 output ranges for ops whose bound follows from the op semantics
# alone (no operand or immediate dependency); source for `propagate_ranges`. AVM
# bytes-stack values cap at 4096 bytes, which bounds `len` / `bitlen`.
_OP_RANGE_SEEDS: dict = None  # filled in below

def _build_op_range_seeds():
    bool_ops = (
        "<", ">", "<=", ">=", "==", "!=",
        "b<", "b>", "b<=", "b>=", "b==", "b!=",
        "&&", "||", "!",
    )
    return {
        **{op: ("uint64", 0, 1) for op in bool_ops},
        # bit/byte extraction with hard-coded output width
        "getbit":         ("uint64", 0, 1),
        "getbyte":        ("uint64", 0, 0xFF),
        "extract_uint16": ("uint64", 0, 0xFFFF),
        "extract_uint32": ("uint64", 0, 0xFFFFFFFF),
        # Full-width, so not a tightening — but a non-None range lets downstream
        # arithmetic bound it (`btoi(x) % 8 -> [0,7]`; range_arith needs BOTH
        # operand ranges and these are the usual dividend).
        "extract_uint64": ("uint64", 0, 0xFFFFFFFFFFFFFFFF),
        "btoi":           ("uint64", 0, 0xFFFFFFFFFFFFFFFF),
        # isqrt of any uint64 never exceeds 2^32 - 1, regardless of input.
        "sqrt":   ("uint64", 0, 0xFFFFFFFF),
        # length ops bounded by AVM stack-bytes cap (4096 bytes)
        "len":    ("uint64", 0, 4096),
        "bitlen": ("uint64", 0, 4096 * 8),
    }

_OP_RANGE_SEEDS = _build_op_range_seeds()

# Bounded enum / count fields, tracking the AVM consensus spec: OnCompletion
# {0..5}, TypeEnum {0..6} (unknown..appl), GroupIndex 0-based under a max group
# size of 16, GroupSize >= 1; Num* are array lengths at the per-txn reference
# limits (MaxAppArgs 16, accounts 4, foreign assets/apps 8, logs 32); schema
# counts at MaxGlobal/LocalSchemaEntries 64 / 16; decimals 19; program pages 3.
#
# HAZARD: each bound must be the SOUND upper limit for the field read in
# isolation — a too-tight cap silently proves things that are false.
_TXN_FIELD_RANGES: dict = {
    "OnCompletion":        (0, 5),
    "TypeEnum":            (0, 6),
    "GroupIndex":          (0, 15),
    # Reference-array lengths.
    "NumAppArgs":          (0, 16),
    "NumAccounts":         (0, 4),
    "NumAssets":           (0, 8),
    "NumApplications":     (0, 8),
    "NumLogs":             (0, 32),
    # State-schema entry counts.
    "GlobalNumUint":       (0, 64),
    "GlobalNumByteSlice":  (0, 64),
    "LocalNumUint":        (0, 16),
    "LocalNumByteSlice":   (0, 16),
    # Other spec-capped scalars.
    "ExtraProgramPages":   (0, 3),
    "ConfigAssetDecimals": (0, 19),
}
_GLOBAL_FIELD_RANGES: dict = {
    "GroupSize": (1, 16),
}

# Reverse of the parser's `int pay` / `int NoOp` pseudo-op resolution, so a
# recovered `TypeEnum == 1` renders as `TypeEnum == pay`. Field -> {int: name}.
_TXN_TYPE_ENUM_NAMES: dict[int, str] = {
    0: "unknown", 1: "pay", 2: "keyreg", 3: "acfg", 4: "axfer", 5: "afrz",
    6: "appl",
}
_ONCOMPLETION_NAMES: dict[int, str] = {
    0: "NoOp", 1: "OptIn", 2: "CloseOut", 3: "ClearState",
    4: "UpdateApplication", 5: "DeleteApplication",
}
#: Enum-valued txn field -> its {int: symbolic-name} table.
TXN_ENUM_FIELD_NAMES: dict[str, dict] = {
    "TypeEnum": _TXN_TYPE_ENUM_NAMES,
    "OnCompletion": _ONCOMPLETION_NAMES,
}


def enum_field_name(field: str, value: int) -> "str | None":
    """Symbolic name of an enum field's value (``("TypeEnum", 1) -> "pay"``), or ``None``."""
    return TXN_ENUM_FIELD_NAMES.get(field, {}).get(value)

# Positional output range seeds, ``op -> [(output_index, lo, hi), …]``.
#
# HAZARD: indices are TOP-FIRST. The ``*_get`` / ``*_ex`` family pushes its 0/1
# "exists" flag as ``outputs[0]`` (the value fed to ``assert`` / ``bz``);
# ``box_len`` bounds its length at ``outputs[1]`` by the 32768-byte max box;
# ``addw`` pushes ``(high, low)`` with LOW on top, so the 0/1 carry is
# ``outputs[1]``; ``vrf_verify`` pushes ``(output, verified)`` with the flag on
# top. Reading any of these positionally the other way inverts flag and value.
_OP_OUTPUT_SEEDS: dict = {
    "asset_params_get":  [(0, 0, 1)],
    "app_params_get":    [(0, 0, 1)],
    "acct_params_get":   [(0, 0, 1)],
    "voter_params_get":  [(0, 0, 1)],
    "app_global_get_ex": [(0, 0, 1)],
    "app_local_get_ex":  [(0, 0, 1)],
    "box_get":           [(0, 0, 1)],
    "box_len":           [(0, 0, 1), (1, 0, 32768)],
    "addw":              [(1, 0, 1)],
    "vrf_verify":        [(0, 0, 1)],
}

# Static byte_length seeds for ``analysis._byte_lengths``: fixed-width txn /
# global field reads, plus ``_OP_OUTPUT_BYTELEN`` positional (TOP-FIRST) lengths
# on multi-output crypto ops. Address fields are DERIVED from the single source
# above, never re-listed; only the non-address fixed widths are enumerated here.
_ADDR_TXN, _ADDR_GLOBAL = ADDRESS_TXN_FIELDS, ADDRESS_GLOBAL_FIELDS

_TXN_FIELD_BYTELEN: dict = {
    **{f: 32 for f in _ADDR_TXN},
    # Fixed-width participation keys / lease / hashes (NOT addresses).
    "Lease":        32,
    "TxID":                    32,   # transaction hash
    "ConfigAssetMetadataHash": 32,
    "VotePK":       32,
    "SelectionPK":  32,
    "StateProofPK": 64,
}
_GLOBAL_FIELD_BYTELEN: dict = {
    **{f: 32 for f in _ADDR_GLOBAL},
    # Fixed-width, but NOT addresses.
    "GroupID":     32,
    "GenesisHash": 32,
}
_BLOCK_FIELD_BYTELEN: dict = {
    **{f: 32 for f in ADDRESS_BLOCK_FIELDS},
    # 32-byte VRF seed / block-hash fields (NOT addresses); BlkProtocol is a
    # variable-length string, so deliberately absent.
    "BlkSeed":   32,
    "BlkBranch": 32,
}
_OP_OUTPUT_BYTELEN: dict = {
    # ecdsa pubkey ops push two 32-byte words (X, Y).
    "ecdsa_pk_decompress": [(0, 32), (1, 32)],
    "ecdsa_pk_recover":    [(0, 32), (1, 32)],
    # vrf_verify's non-flag output (outputs[1]) is the 64-byte VRF output.
    "vrf_verify":          [(1, 64)],
}

#: Single-output ops with a FIXED-WIDTH bytes result: the hash / digest family,
#: plus ``itob`` — always exactly 8 bytes, and the head of nearly every ARC-4
#: integer encoding chain, so its width feeds the offset/width reasoning.
FIXED_BYTES_OUTPUT_LEN: dict[str, int] = {
    "itob":       8,
    "sha256":     32,
    "sha512_256": 32,
    "keccak256":  32,
    "sha3_256":   32,
    "mimc":       32,
    "sumhash512": 64,
}

# The ``*_params_get`` family pushes ``(value, exists)``: the 0/1 exists flag is
# ``outputs[0]`` (seeded by ``_OP_OUTPUT_SEEDS``), the VALUE is ``outputs[1]``
# and is keyed by field immediate here. Field names are globally unique
# (Asset*/App*/Acct*), so one flat table per kind is unambiguous.
_PARAMS_OPS: frozenset = frozenset({
    "asset_params_get", "app_params_get", "acct_params_get",
    "voter_params_get",
})
_PARAMS_VALUE_RANGES: dict = {
    "VoterIncentiveEligible": (0, 1),
    "AssetDecimals":        (0, 19),
    "AssetDefaultFrozen":   (0, 1),
    "AppExtraProgramPages": (0, 3),
    "AppGlobalNumUint":      (0, 64),
    "AppGlobalNumByteSlice": (0, 64),
    "AppLocalNumUint":       (0, 16),
    "AppLocalNumByteSlice":  (0, 16),
    "AcctIncentiveEligible": (0, 1),
}
_PARAMS_VALUE_BYTELEN: dict = {
    "AssetManager":      32,
    "AssetReserve":      32,
    "AssetFreeze":       32,
    "AssetClawback":     32,
    "AssetCreator":      32,
    "AssetMetadataHash": 32,
    "AppCreator":        32,
    "AppAddress":        32,
    "AcctAuthAddr":      32,
}

# HAZARD: the field-name immediate POSITION varies. It is immediate 0 for the
# current-txn and stack-group forms, but immediate 1 for the ``gtxn``/``gitxn``
# group-indexed forms (the group index comes first). Getting this wrong returns
# no field name, which silently zeroes taint and byte lengths on those reads.
_FIELD_OPS_POS0: frozenset = frozenset({
    "txn", "txna", "gtxns", "gtxnsa", "gtxnsas", "itxn", "itxna",
    # The stack-index forms belong here: they pop the ARRAY INDEX off the
    # stack, so the field name is still immediate 0.
    "txnas", "itxnas",
})
_FIELD_OPS_POS1: frozenset = frozenset({
    "gtxn", "gtxna", "gtxnas", "gitxn", "gitxna", "gitxnas",
})


#: Every op that reads a named txn-family field, in either immediate position.
#: Public so callers stop hand-rolling their own op tuples: two such lists in
#: `group_taint_graph` had already drifted, covering only `("gtxn", "gtxna")`
#: and `("txna", "txn", "gtxn", "gtxna")` and so missing the dynamic-index
#: `gtxns*` forms entirely.
TXN_FIELD_OPS: frozenset = _FIELD_OPS_POS0 | _FIELD_OPS_POS1


def txn_field_name(op: str, immediates) -> Optional[str]:
    """The field-name immediate of a txn-family field read, or ``None``.

    ``immediates`` may be the raw string or an already-split token list — call
    sites have both, and making each one split first is how they ended up
    re-deriving the position rule instead of calling this."""
    toks = immediates.split() if isinstance(immediates, str) else list(immediates or ())
    if op in _FIELD_OPS_POS0 and toks:
        return toks[0]
    if op in _FIELD_OPS_POS1 and len(toks) >= 2:
        return toks[1]
    return None


#: Pre-rename alias. Kept only because this module is imported widely; prefer
#: the public name.
_txn_field_name = txn_field_name


# Pure stack-shuffle opcodes: they permute / duplicate / drop existing values
# (frame variants move between stack top and visible frame slots) rather than
# compute. The per-output input index is fixed by opcode + immediate, so every
# output SSAVar can be rewritten to its source value at every consumer.
_STACK_SHUFFLE_OPS: frozenset = frozenset({
    "swap", "dup", "dup2", "dupn", "cover", "uncover", "dig", "bury",
    "frame_dig", "frame_bury",
})


# ===========================================================================
# Generic value-dependency policy
# ===========================================================================

# These sets classify DATA dependency only. They deliberately do not try to
# encode detector-specific trust: a source may independently seed an output,
# and a sink may independently inspect an input.
VALUE_FLOW_HASH_OPS: frozenset[str] = frozenset({
    "sha256", "keccak256", "sha512_256", "sha3_256",
})

VALUE_FLOW_SLICE_OPS: frozenset[str] = frozenset({
    "extract", "extract3", "extract_uint16", "extract_uint32",
    "extract_uint64", "substring", "substring3", "getbyte",
})

VALUE_FLOW_TRANSCODE_OPS: frozenset[str] = frozenset({"itob", "btoi"})

VALUE_FLOW_TRANSFORM_OPS: frozenset[str] = frozenset({
    # uint64 arithmetic, wide forms, bitwise and comparisons
    "+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr",
    "addw", "mulw", "expw", "divw", "divmodw",
    "&", "|", "^", "~", "len", "bitlen",
    "==", "!=", "<", "<=", ">", ">=",
    "b==", "b!=", "b<", "b<=", "b>", "b>=", "!", "&&", "||",
    "getbit",
    # value transforms / derivations
    "bzero", "base64_decode", "mimc", "sumhash512", "json_ref", "bsqrt",
    "ecdsa_pk_decompress", "ecdsa_pk_recover",
})

VALUE_FLOW_SPLICE_OPS: frozenset[str] = frozenset({
    "setbyte", "setbit", "replace2", "replace3",
})

VALUE_FLOW_BYTE_MATH_OPS: frozenset[str] = frozenset({
    "b+", "b-", "b*", "b/", "b%", "bsqrt", "b|", "b&", "b^", "b~",
})

# Reads whose result is external storage/context selected by the inputs, rather
# than a function of the input bits. Generic taint does not infer that a tainted
# key makes the stored value attacker-authored. Analyses that care about those
# values seed them as sources or use the explicit state/scratch bridges.
VALUE_FLOW_OPAQUE_READ_OPS: frozenset[str] = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
    "app_opted_in", "app_params_get", "asset_holding_get", "asset_params_get",
    "acct_params_get", "voter_params_get", "balance", "min_balance",
    "box_get", "box_len", "box_extract", "block",
})

VALUE_FLOW_SPECIAL_OPS: frozenset[str] = (
    VALUE_FLOW_HASH_OPS
    | VALUE_FLOW_SLICE_OPS
    | VALUE_FLOW_TRANSCODE_OPS
    | VALUE_FLOW_TRANSFORM_OPS
    | VALUE_FLOW_SPLICE_OPS
    | VALUE_FLOW_BYTE_MATH_OPS
    | {"concat", "select", "loads"}
)


def value_dependency_kind(op: str) -> str:
    """Classify a known opcode's generic input-to-output value dependency.

    The result is one of ``special`` (a precise engine rule), ``shuffle``,
    ``opaque-read`` (explicitly blocked), ``derived`` (conservatively every
    tainted input may influence every output), ``none`` (no input or output),
    or ``unknown``. The conservative category is intentional: adding a new AVM
    transform cannot silently create a taint false negative merely because a
    hand-maintained allow-list was not updated at the same time.
    """
    if op in VALUE_FLOW_SPECIAL_OPS:
        return "special"
    if op in _STACK_SHUFFLE_OPS:
        return "shuffle"
    if op in VALUE_FLOW_OPAQUE_READ_OPS:
        return "opaque-read"
    arity = SIG.get(op) or _FRAME_OVERRIDES.get(op)
    if arity is not None:
        return "derived" if arity[0] > 0 and arity[1] > 0 else "none"
    if op in _IMMEDIATE_ARITY_OPS:
        # Every immediate-dependent value producer is a stack shuffle; the
        # remaining dynamic ops are constants, pops, or control flow.
        return "none"
    return "unknown"
