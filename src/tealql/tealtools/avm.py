"""AVM / TEAL language metadata — THE single home (one place per AVM bump).

Everything the toolkit knows about the AVM spec lives here, as pure data plus
tiny lookup helpers, with NO imports from the rest of ``tealtools`` (leaf
module; every layer — ssa, dataflow, lift, cfg, security detectors — consumes
it without cycles):

  * opcode stack ARITIES ``(n_in, n_out)`` .... :data:`SIG` / :func:`op_arity`
  * opcode GROUPS (cmp / logical / txn-source / state-write / …) and
    txn-field FAMILIES (address / fund / close-rekey / …)
  * op RESULT TYPES + txn/global/params field TYPES
    (``_U64_OPS`` / ``_BYTES_OPS`` / :func:`_field_type` / :func:`_multi_out_type`)
  * uint64 RANGE and BYTE-LENGTH seeds per op / field
  * op classification: shuffles, terminators, constblock references

Consumers that need a narrower or wider view should derive it from these
(filter / union) with a comment, rather than hand-rolling a fresh literal —
before consolidation these tables had drifted apart across four modules.

Correctness of the op-result-type and byte-length tables is pinned against
puya's langspec by ``tests/test_avm_metadata_drift.py``; bump
:data:`AVM_LANGSPEC_VERSION` (and re-run the drift test) when adding a new
AVM version's opcodes.
"""
from __future__ import annotations

from typing import Optional

#: The AVM/TEAL langspec version these tables are written against.
#: Informational: the drift test pins the result-type tables to whatever puya
#: (``puyapy``) is installed, so a mismatch surfaces there; keep this in sync
#: when widening the tables for a new version.
AVM_LANGSPEC_VERSION = 11


# ===========================================================================
# Opcode stack arities
# ===========================================================================


# Constant-arity opcodes: mnemonic -> (n_in, n_out). Mnemonics are the
# source tokens (so symbolic ops are "+", "&&", "b==", etc.).
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
    # Control flow (callsub/retsub handled by op_arity overrides; match dynamic)
    # NOTE `return` is DELIBERATELY (0, 0) though the AVM pops 1 (the approval
    # value): it terminates the program, so modelling the pop would shrink the
    # exit stack the lift reads its ProgramExit operand off, and
    # `path_predicates` documents not classifying that value. Any NEW consumer
    # of op_arity must account for this one divergence from the spec.
    "return": (0, 0), "err": (0, 0), "assert": (1, 0), "b": (0, 0),
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
# fat / proto-aware forms are rebuilt by later PySSA phases.
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


#: Opcodes ``op_arity`` was asked about but does not know. A future AVM version
#: adds opcodes this table has never seen; they silently default to ``(0, 0)``,
#: which makes the whole downstream stack simulation wrong with no signal at
#: all. Recording them lets a caller (and :func:`unknown_opcodes`) surface the
#: gap instead of trusting a bad model. Module-level because ``op_arity`` is a
#: pure function called from every layer.
_UNKNOWN_OPS: set[str] = set()


def unknown_opcodes() -> frozenset[str]:
    """Opcodes seen so far that have no entry in :data:`SIG` — their stack
    effect was modelled as ``(0, 0)``, so any analysis of a program using them
    is unreliable. Non-empty means this build predates the contract's AVM
    version (or the table is missing an op)."""
    return frozenset(_UNKNOWN_OPS)


def op_arity(op: str, immediates: str) -> tuple[int, int]:
    """Return ``(n_in, n_out)`` for an opcode + its immediate text.

    An opcode absent from :data:`SIG` yields ``(0, 0)`` and is recorded in
    :func:`unknown_opcodes` — see the note there."""
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
        from .const_values import _split_byte_literals
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

#: Txn-family fields that read a 32-byte account address. SINGLE SOURCE of the
#: address-field universe: a field being an address determines BOTH its AVM type
#: (``"account"``, in ``_TXN_FIELD_TYPE`` below) AND its byte length (32, in
#: ``_TXN_FIELD_BYTELEN`` below). Both derive from this set instead of each
#: re-listing the fields, so a new address field is added in ONE place.
ADDRESS_TXN_FIELDS: frozenset[str] = frozenset({
    "Sender", "Receiver", "CloseRemainderTo", "RekeyTo",
    "AssetSender", "AssetReceiver", "AssetCloseTo", "FreezeAssetAccount",
    "ConfigAssetManager", "ConfigAssetReserve", "ConfigAssetFreeze",
    "ConfigAssetClawback",
    "Accounts",                         # array element (txna Accounts i)
})

#: ``global`` fields that read a 32-byte account address (same single-source
#: role as :data:`ADDRESS_TXN_FIELDS`).
ADDRESS_GLOBAL_FIELDS: frozenset[str] = frozenset({
    "ZeroAddress", "CreatorAddress",
    "CurrentApplicationAddress", "CallerApplicationAddress",
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
#: tagged by severity (the account-draining close fields rank CRITICAL).
#:
#: ``RekeyTo`` is deliberately NOT here. A rekey check is a LOGICSIG concern: an
#: lsig that authorises a spend must validate the outer txn's ``RekeyTo`` or an
#: attacker rekeys the lsig account away. For an APP there is nothing to validate
#: — an app-call's ``txn RekeyTo`` rekeys the *user's own* account (their
#: business, not the app's), and an ``itxn_field RekeyTo`` rekeys the *app's own*
#: account, a self-inflicted, vanishingly-rare operation rather than a tainted-
#: field vuln. So rekey lives in the lsig-scoped detectors, not the app fund-flow
#: sink set. See :data:`CLOSE_REKEY_FIELDS` for the field-name catalog.
FUND_FIELDS: dict[str, str] = {
    "CloseRemainderTo": "CRITICAL",
    "AssetCloseTo": "CRITICAL",
    "Receiver": "HIGH",
    "AssetReceiver": "HIGH",
    "Amount": "MEDIUM",
    "AssetAmount": "MEDIUM",
}

#: The "pure payment" subset of :data:`FUND_FIELDS` (no close/rekey) — the
#: Receiver/Amount destination+amount fields.
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

#: Opcodes that mutate persistent state or emit a transaction — the "sensitive
#: sink" family that should typically run only on a guard-dominated path.
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

#: Opcodes the AVM accepts ONLY in Application mode (it rejects them in
#: Signature mode), so their presence PROVES a program is an application.
#: Keyed strictly on opcodes, never on txn fields: a logic signature can be
#: attached to an ApplicationCall txn and therefore may read ``OnCompletion`` /
#: ``ApplicationArgs`` / ``ApplicationID`` (every AlgoPlonk-style proof
#: verifier does), so those fields prove nothing and keying on them would
#: misclassify that whole lsig class.
#:
#: Lives here rather than in the detection layer because it is AVM spec data
#: (this module is the single home, per the module docstring); the classifier
#: :func:`tealql.security.common.classify_program` consumes it. The account-
#: query family (``balance`` / ``min_balance`` / ``gaid`` / ``gaids`` /
#: ``online_stake`` / ``voter_params_get``) was missing, so a program whose only
#: app-mode opcodes were those classified as a LOGICSIG and then had the
#: lsig-only detectors (rekey / close-remainder / fee / lsig-args) run against
#: it — a false-positive swarm on an app.
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

#: Pure boolean combinators (logical and / or / not). Union with
#: :data:`CMP_OPS` for the "pure boolean/comparison combinator" view.
LOGICAL_OPS: frozenset[str] = frozenset({"&&", "||", "!"})


# ===========================================================================
# Op result types and field types (formerly lift/optypes.py)
# ===========================================================================


_BOOL_OPS = CMP_OPS | LOGICAL_OPS
# Const-push / const-load ops are normally typed by their folded const value;
# they fall back to these sets only when the parser dropped the operand
# (`pushbytes base64(..)`, `bytec N`) so there is no value to type them from.
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
                      "falcon_verify",             # verified flag (uint64/bool)
                      "balance", "min_balance", "app_opted_in"}) | _U64_PUSH
_BYTES_OPS = frozenset({"itob", "concat", "substring", "substring3", "extract",
                        "extract3", "replace2", "replace3", "sha256",
                        "sha512_256", "keccak256", "sha3_256", "bzero",
                        "setbyte", "b+", "b-", "b*", "b/", "b%",
                        "b|", "b&", "b^", "b~", "bsqrt", "box_extract",
                        # further single-`bytes`-return ops (per Puya's langspec)
                        # the table previously missed -- so e.g. `mimc` and the
                        # crypto / lsig-arg producers no longer default to uint64
                        # and cross the AVM divide (the residual recovery bug).
                        "mimc", "sumhash512", "base64_decode",
                        "ec_add", "ec_map_to", "ec_scalar_mul",
                        "ec_multi_scalar_mul",
                        # ecdsa pubkey ops return TWO byteslices (the X, Y coords
                        # of the recovered / decompressed point) -- both bytes, so
                        # type_of (called per output) types each correctly. Without
                        # this the outputs default to uint64 and Puya rejects the
                        # bytes assignment downstream (`source=(uint64) target=
                        # (bytes)`). `ecdsa_verify` returns a uint64 flag -> NOT here.
                        "ecdsa_pk_recover", "ecdsa_pk_decompress",
                        "arg", "arg_0", "arg_1", "arg_2", "arg_3", "args",
                        }) | _BYTES_PUSH
# `setbit` is polymorphic: its result type equals its VALUE operand (`setbit A B
# C` -> type of A, uint64 or bytes), so it is NOT in _BYTES_OPS; lift.type_of /
# _ssa_type type it from that operand. (`getbit` always returns uint64, so it
# stays in _U64_OPS; `setbyte` is byte-array only, so it stays in _BYTES_OPS.)
_POLY_FIRST_OPERAND_OPS = frozenset({"setbit"})
_NAME_PREFIX = {"len": "len", "==": "eq", "!=": "ne", "<": "lt", ">": "gt",
                "<=": "le", ">=": "ge", "!": "not", "&&": "and", "||": "or",
                "btoi": "val", "concat": "concat", "itob": "enc"}
_COND_BRANCH = frozenset({"bnz", "bz"})

# Transaction-field accessors (txn/txna/gtxn/itxn families). The field name is
# one of the immediate tokens (position varies: gtxn has a group index first),
# so _field_type scans all tokens against the table. Canonical families in
# the groups section above.
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
    # account (addresses) — derived from ADDRESS_TXN_FIELDS above (single source
    # shared with the 32-byte length table below); see the merge below.
    # asset / application ids
    "XferAsset": "asset", "ConfigAsset": "asset", "FreezeAsset": "asset",
    "CreatedAssetID": "asset", "Assets": "asset",
    "ApplicationID": "application", "Applications": "application",
    "CreatedApplicationID": "application",
    # bytes
    "Note": "bytes", "Lease": "bytes", "Type": "bytes", "GroupID": "bytes",
    "TxID": "bytes",                  # 32-byte transaction hash (was defaulting u64)
    "ApplicationArgs": "bytes", "Logs": "bytes", "LastLog": "bytes",
    "ApprovalProgram": "bytes", "ClearStateProgram": "bytes",
    "ApprovalProgramPages": "bytes", "ClearStateProgramPages": "bytes",
    "VotePK": "bytes", "SelectionPK": "bytes", "StateProofPK": "bytes",
    "ConfigAssetName": "bytes", "ConfigAssetUnitName": "bytes",
    "ConfigAssetURL": "bytes", "ConfigAssetMetadataHash": "bytes",
}
# Merge in the account (address) fields from the single source above, so the
# address-field universe isn't hand-listed both here and in the length table.
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
}
_GLOBAL_FIELD_TYPE.update({f: "account" for f in ADDRESS_GLOBAL_FIELDS})


def _field_type(op, immediates):
    """Type of a ``txn``-family / ``global`` field read, by scanning the
    immediate tokens for a known field name. ``None`` if not a field read or
    the field is unknown."""
    toks = immediates.split() if immediates else []
    if op in _TXN_OPS:
        table = _TXN_FIELD_TYPE
    elif op == "global":
        table = _GLOBAL_FIELD_TYPE
    else:
        return None
    for tk in toks:
        if tk in table:
            return table[tk]
    return None


#: AVM types that live in a byte-slice stack value vs a uint64.
_AVM_BYTES_TYPES = frozenset({"bytes", "account", "string"})
_AVM_UINT64_TYPES = frozenset({"uint64", "bool", "asset", "application"})


def txn_field_avm_type(field: str) -> "str | None":
    """The AVM stack type of a transaction field's value — ``'b'`` (byte slice)
    or ``'u'`` (uint64), or ``None`` for an unknown field. The canonical
    field -> ``'b'``/``'u'`` decision (addresses / notes / programs are bytes;
    ids / amounts / flags are uint64), so the lift's itxn-field typing single-
    sources it here instead of re-deriving from puya's registry."""
    t = _TXN_FIELD_TYPE.get(field)
    if t in _AVM_BYTES_TYPES:
        return "b"
    if t in _AVM_UINT64_TYPES:
        return "u"
    return None


# Per-output-slot types for multi-result intrinsics. The `*_get_ex` /
# `*_params_get` / `*_holding_get` / `box_get` ops leave `did_exist` on top
# (output 0, uint64) and the value below (output 1); `box_len` leaves
# `did_exist` over a uint64 length; the `w` arithmetic ops produce all-uint64
# word pairs / quads. (Output order per dataflow/state.py + dataflow/box.py.)
_MULTI_ALL_U64 = frozenset({"addw", "mulw", "expw", "divmodw", "box_len"})
_EX_FLAG_OPS = frozenset({
    "app_global_get_ex", "app_local_get_ex", "asset_holding_get",
    "asset_params_get", "app_params_get", "acct_params_get",
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
    """Type of output slot ``idx`` (0 = top of stack) of a multi-result op, or
    ``None`` when the op isn't a typed multi-result here, or the slot's type
    is unknown — e.g. an ``app_global_get_ex`` / ``app_local_get_ex`` *value*,
    whose type depends on the contract's state schema, not the op."""
    if op in _MULTI_ALL_U64:
        return "uint64"
    if op == "box_get":
        return "uint64" if idx == 0 else "bytes"   # did_exist, value
    if op == "vrf_verify":
        return "uint64" if idx == 0 else "bytes"   # verified flag, 64-byte output
        # (the bytes length is pinned to 64 by _OP_OUTPUT_BYTELEN, which only
        # fires once the slot is already typed bytes — hence typing it here.)
    if op in _EX_FLAG_OPS:
        if idx == 0:
            return "uint64"                         # did_exist flag
        toks = immediates.split() if immediates else []
        for tk in toks:
            if tk in _PARAMS_FIELD_TYPE:
                return _PARAMS_FIELD_TYPE[tk]       # params/holding value field
        return None                                 # state-schema-dependent value
    return None


# Ops whose operand AVM type is unambiguous (used to decide a phi-web's type in
# the lift's mixed-type reconciliation). `==`/`!=` are excluded (they accept
# both); `itxn_field`/`setbyte` are field/position dependent.
_U64_CONSUME = frozenset({
    "+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr", "<", ">", "<=", ">=",
    "itob", "bitlen", "!", "&&", "||", "assert", "&", "|", "^", "~"})
_BYTES_CONSUME = frozenset({
    "concat", "len", "btoi", "log", "sha256", "sha512_256", "keccak256",
    "sha3_256", "extract", "extract3", "substring", "substring3", "replace2",
    "replace3", "b+", "b-", "b*", "b/", "b%", "b<", "b>",
    "extract_uint16", "extract_uint32", "extract_uint64",
    # The rest of the unambiguously-bytes consumers the set had missed. The
    # `b`-prefixed comparisons are NOT the polymorphic `==`/`!=`: `b==` / `b!=`
    # take byteslices only, so they type their operands just as hard as `b<`.
    "b<=", "b>=", "b==", "b!=", "b|", "b&", "b^", "b~", "bsqrt",
    "setbyte", "getbyte", "base64_decode", "mimc", "sumhash512",
    "ed25519verify_bare", "falcon_verify"})


def avm(t) -> str:
    """Coarse AVM type lattice of a type name: 'b' (bytes-backed), 'u'
    (uint64-backed), or '?' (unknown)."""
    return ("b" if t in ("bytes", "account", "string")
            else "u" if t in ("uint64", "bool", "asset", "application")
            else "?")


def _imm0(a) -> int | None:
    """First immediate of an SSA assignment as an int (slot / frame index / ...),
    or None when it has none or it isn't an integer."""
    toks = (a.immediates or "").split()
    if not toks:
        return None
    try:
        return int(toks[0])
    except ValueError:
        return None


# ===========================================================================
# Range / byte-length seeds and op classification (formerly ssa/models.py)
# ===========================================================================



# -------------------------------------------------------------------------


_CONST_BLOCK_REF_NAMES = frozenset({
    # constblock references
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
    # inline-literal pushers (carry their literal in immediates; the
    # resolved-constant table already emits values for them, so
    # propagation reads through naturally).
    "IntOpcode", "PushintOpcode", "PushbytesOpcode",
})


# Control-flow terminators. These ops have side effects on the flow graph
# independent of their SSA outputs, so dead-code elimination must NOT drop
# them even if every output is a "dead constant" (e.g. a ``retsub`` whose
# return-value output is constant-propagated and has no remaining consumers
# in the SSA — the op still transfers control to the caller).
_TERMINATOR_OPS = frozenset({
    "callsub", "retsub",
    "b", "bnz", "bz",
    "return", "err",
    "switch", "match",
})


# Op-level constant folding (concat / itob / extract / arithmetic /
# comparisons / ...) is layered above the SSA substrate in
# :mod:`tealql.tealtools.const_fold`; lazily imported inside
# :meth:`SSAProgram.propagate_constants` so the substrate itself
# carries no TEAL-semantics knowledge.



# Per-op uint64 output ranges for ops whose bound is determined by the
# op semantics alone (no operand or immediate dependency). Source for
# `propagate_ranges`. AVM bytes-stack values are capped at 4096 bytes,
# which gives `len`/`bitlen` their upper bounds.
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
        # bytes -> full-width uint64: not a tightening in itself, but a non-None
        # range so downstream arithmetic can bound it (e.g. `btoi(x) % 8 -> [0,7]`;
        # range_arith needs BOTH operand ranges, and these are the usual dividend).
        "extract_uint64": ("uint64", 0, 0xFFFFFFFFFFFFFFFF),
        "btoi":           ("uint64", 0, 0xFFFFFFFFFFFFFFFF),
        # isqrt of any uint64 never exceeds 2^32 - 1, regardless of input.
        "sqrt":   ("uint64", 0, 0xFFFFFFFF),
        # length ops bounded by AVM stack-bytes cap (4096 bytes)
        "len":    ("uint64", 0, 4096),
        "bitlen": ("uint64", 0, 4096 * 8),
    }

_OP_RANGE_SEEDS = _build_op_range_seeds()

# Bounded enum / count fields for txn-family / global field reads. Values
# track the AVM consensus spec: OnCompletion in {0..5}, TypeEnum in {0..6}
# (unknown..appl), GroupIndex 0-based with max group size 16, GroupSize ≥ 1.
# The Num* fields are array lengths capped by the per-txn reference limits
# (MaxAppArgs 16, accounts 4, foreign assets/apps 8, logs 32); the schema
# counts by MaxGlobalSchemaEntries 64 / MaxLocalSchemaEntries 16; asset
# decimals at 19; extra program pages at 3. Each bound is the *sound* upper
# limit for the field read in isolation (a too-tight cap would be unsound).
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

# Symbolic names for the enum-valued txn fields, so a recovered `TypeEnum == 1`
# renders as `TypeEnum == pay` (the parser resolves the `int pay` / `int NoOp`
# pseudo-ops to these ints; this is the reverse map). Field -> {int: name}.
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
    """The symbolic name of an enum-valued txn field's integer value
    (``("TypeEnum", 1) -> "pay"``, ``("OnCompletion", 5) -> "DeleteApplication"``),
    or ``None`` if ``field`` isn't enum-valued or ``value`` is out of range."""
    return TXN_ENUM_FIELD_NAMES.get(field, {}).get(value)

# Positional output range seeds for multi-output ops, top-first:
# ``op -> [(output_index, lo, hi), …]``. The ``*_get`` / ``*_ex`` family
# pushes a 0/1 "exists / found" flag as its top output (``outputs[0]``) —
# the value most often fed to ``assert`` / ``bz`` / ``bnz`` — which the
# single-output ``_OP_RANGE_SEEDS`` path can't reach. ``box_len`` also
# bounds its length output (``outputs[1]``) by the 32768-byte max box size.
# ``addw`` pushes ``(high, low)`` with low on top, so its high word
# (``outputs[1]``) is the carry of a 64+64-bit add — always 0 or 1.
# ``vrf_verify`` pushes ``(output, verified)`` with the 0/1 verified flag
# on top (its 64-byte output length is seeded in ``_OP_OUTPUT_BYTELEN``).
_OP_OUTPUT_SEEDS: dict = {
    "asset_params_get":  [(0, 0, 1)],
    "app_params_get":    [(0, 0, 1)],
    "acct_params_get":   [(0, 0, 1)],
    "app_global_get_ex": [(0, 0, 1)],
    "app_local_get_ex":  [(0, 0, 1)],
    "box_get":           [(0, 0, 1)],
    "box_len":           [(0, 0, 1), (1, 0, 32768)],
    "addw":              [(1, 0, 1)],
    "vrf_verify":        [(0, 0, 1)],
}

# Static byte_length seeds, consumed by ``passes/byte_length_prop``.
#
# ``_TXN_FIELD_BYTELEN`` / ``_GLOBAL_FIELD_BYTELEN`` — txn-family / global
# field reads whose output is a fixed-width bytes value: 32-byte addresses
# and the participation keys (StateProofPK is 64). ``_OP_OUTPUT_BYTELEN``
# — positional fixed lengths on multi-output crypto ops, top-first
# (``op -> [(output_index, byte_length), …]``).
# 32-byte address fields come from the single source above (shared with the
# ``"account"`` type table) — derived, not re-listed — plus the
# non-address fixed-width fields (participation keys, lease) enumerated here.
_ADDR_TXN, _ADDR_GLOBAL = ADDRESS_TXN_FIELDS, ADDRESS_GLOBAL_FIELDS

_TXN_FIELD_BYTELEN: dict = {
    **{f: 32 for f in _ADDR_TXN},
    # Fixed-width participation keys / lease (NOT addresses).
    "Lease":        32,
    "VotePK":       32,
    "SelectionPK":  32,
    "StateProofPK": 64,
}
_GLOBAL_FIELD_BYTELEN: dict = {f: 32 for f in _ADDR_GLOBAL}
_OP_OUTPUT_BYTELEN: dict = {
    # ecdsa pubkey ops push two 32-byte words (X, Y).
    "ecdsa_pk_decompress": [(0, 32), (1, 32)],
    "ecdsa_pk_recover":    [(0, 32), (1, 32)],
    # vrf_verify's non-flag output (outputs[1]) is the 64-byte VRF output.
    "vrf_verify":          [(1, 64)],
}

#: Single-output ops with a FIXED-WIDTH bytes result — the hash / digest family.
#: ``passes/byte_length_prop`` used to carry the four SHA/Keccak lengths inline
#: as a literal, which left ``mimc`` (32) and ``sumhash512`` (64) — both of
#: which puya types as sized-bytes returns — with no length at all. Keeping the
#: table here is the module's stated contract: one AVM-metadata home, derived
#: rather than re-listed per consumer.
FIXED_BYTES_OUTPUT_LEN: dict[str, int] = {
    "sha256":     32,
    "sha512_256": 32,
    "keccak256":  32,
    "sha3_256":   32,
    "mimc":       32,
    "sumhash512": 64,
}

# ``asset_params_get`` / ``app_params_get`` / ``acct_params_get`` push
# ``(value, exists)`` — the 0/1 exists flag (``outputs[0]``) is seeded by
# ``_OP_OUTPUT_SEEDS``; the *value* (``outputs[1]``) is keyed by the field
# immediate here. Field names are globally unique (Asset*/App*/Acct*), so a
# single flat table per kind is unambiguous. Range fields are bounded scalars
# / booleans; byte-length fields are 32-byte addresses + the metadata hash.
_PARAMS_OPS: frozenset = frozenset({
    "asset_params_get", "app_params_get", "acct_params_get",
})
_PARAMS_VALUE_RANGES: dict = {
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

# Field-immediate position for every txn-family field-reading op. The field
# name is the *first* immediate for current-txn / stack-group forms, and the
# *second* (after the immediate group index) for the ``gtxn``/``gitxn``
# group-indexed forms. One helper unifies field extraction across the range,
# byte-length and any future field-keyed seeding (so the inner-txn ``itxna`` /
# ``gitxn*`` and stack-group ``gtxnsa`` / ``gtxnsas`` forms are covered too).
_FIELD_OPS_POS0: frozenset = frozenset({
    "txn", "txna", "gtxns", "gtxnsa", "gtxnsas", "itxn", "itxna",
})
_FIELD_OPS_POS1: frozenset = frozenset({
    "gtxn", "gtxna", "gtxnas", "gitxn", "gitxna", "gitxnas",
})


def _txn_field_name(op: str, toks: list) -> Optional[str]:
    """The field-name immediate of a txn-family field read, or ``None``
    when ``op`` doesn't read a named field (or its immediates are absent).
    ``toks`` is ``immediates.split()``."""
    if op in _FIELD_OPS_POS0 and toks:
        return toks[0]
    if op in _FIELD_OPS_POS1 and len(toks) >= 2:
        return toks[1]
    return None


# Pure stack-shuffle opcodes — they don't compute, they only permute /
# duplicate / drop existing stack values (or, for the frame variants,
# move values between the stack top and the visible frame slots). For
# each, the per-output input index is fixed by the opcode plus its
# immediate, so every output SSAVar can be rewritten to its source
# value at every consumer (see :meth:`SSAProgram.propagate_stack_shuffles`).
_STACK_SHUFFLE_OPS: frozenset = frozenset({
    "swap", "dup", "dup2", "dupn", "cover", "uncover", "dig", "bury",
    "frame_dig", "frame_bury",
})
