"""AVM opcode / type metadata — pure data + functions, no IR dependency (so both
`lift` and `to_puya_ir` import it without a cycle).

Op result types (`_U64_OPS`/`_BYTES_OPS`, `txn`/`global` fields via `_field_type`,
multi-result slots via `_multi_out_type`), operand types (`_*_CONSUME`), the
coarse `avm()` lattice ('b'/'u'/'?'), and `_imm0`.
"""
from __future__ import annotations

from ..opsets import TXN_SOURCE_OPS, ITXN_SOURCE_OPS

_BOOL_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "!", "&&", "||",
                       "b==", "b!=", "b<", "b>", "b<=", "b>="})
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
                      "balance", "min_balance", "app_opted_in"}) | _U64_PUSH
_BYTES_OPS = frozenset({"itob", "concat", "substring", "substring3", "extract",
                        "extract3", "replace2", "replace3", "sha256",
                        "sha512_256", "keccak256", "sha3_256", "bzero",
                        "setbyte", "b+", "b-", "b*", "b/", "b%",
                        "b|", "b&", "b^", "b~", "bsqrt", "box_extract"}) | _BYTES_PUSH
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
# tealtools.opsets.
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
    "NumClearStateProgramPages": "uint64",
    # bool
    "ConfigAssetDefaultFrozen": "bool", "FreezeAssetFrozen": "bool",
    "Nonparticipation": "bool",
    # account (addresses)
    "Sender": "account", "Receiver": "account", "CloseRemainderTo": "account",
    "AssetSender": "account", "AssetReceiver": "account", "Accounts": "account",
    "AssetCloseTo": "account", "RekeyTo": "account", "FreezeAssetAccount": "account",
    "ConfigAssetManager": "account", "ConfigAssetReserve": "account",
    "ConfigAssetFreeze": "account", "ConfigAssetClawback": "account",
    # asset / application ids
    "XferAsset": "asset", "ConfigAsset": "asset", "FreezeAsset": "asset",
    "CreatedAssetID": "asset", "Assets": "asset",
    "ApplicationID": "application", "Applications": "application",
    "CreatedApplicationID": "application",
    # bytes
    "Note": "bytes", "Lease": "bytes", "Type": "bytes", "GroupID": "bytes",
    "ApplicationArgs": "bytes", "Logs": "bytes", "LastLog": "bytes",
    "ApprovalProgram": "bytes", "ClearStateProgram": "bytes",
    "ApprovalProgramPages": "bytes", "ClearStateProgramPages": "bytes",
    "VotePK": "bytes", "SelectionPK": "bytes", "StateProofPK": "bytes",
    "ConfigAssetName": "bytes", "ConfigAssetUnitName": "bytes",
    "ConfigAssetURL": "bytes", "ConfigAssetMetadataHash": "bytes",
}
_GLOBAL_FIELD_TYPE = {
    "MinTxnFee": "uint64", "MinBalance": "uint64", "MaxTxnLife": "uint64",
    "GroupSize": "uint64", "LogicSigVersion": "uint64", "Round": "uint64",
    "LatestTimestamp": "uint64", "OpcodeBudget": "uint64",
    "AssetCreateMinBalance": "uint64", "AssetOptInMinBalance": "uint64",
    "PayoutsGoOnlineFee": "uint64", "PayoutsPercent": "uint64",
    "PayoutsMinBalance": "uint64", "PayoutsMaxBalance": "uint64",
    "PayoutsEnabled": "bool",
    "ZeroAddress": "account", "CreatorAddress": "account",
    "CurrentApplicationAddress": "account", "CallerApplicationAddress": "account",
    "CurrentApplicationID": "application", "CallerApplicationID": "application",
    "GenesisHash": "bytes",
}


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
    "extract_uint16", "extract_uint32", "extract_uint64"})


def avm(t) -> str:
    """Coarse AVM type lattice of a type name: 'b' (bytes-backed), 'u'
    (uint64-backed), or '?' (unknown)."""
    return ("b" if t in ("bytes", "account")
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
