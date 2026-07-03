"""Canonical opcode and transaction-field sets shared across the analysis,
the lift, and the security detectors.

A **pure leaf** module — it imports nothing from ``tealtools`` — so every layer
(``dataflow/``, ``lift/``, ``cfg/``, and the importlib-loaded security
detectors) can consume one source of truth instead of re-listing these sets.
Before this module they had drifted: e.g. ``cfg/super_auth`` silently dropped
``box_replace``/``box_splice``/``box_resize`` that ``auth_domination`` flagged,
and the txn-source families disagreed on the ``*as`` (stack-index) variants.

Consumers that genuinely need a narrower or wider view should derive it from
these (filter / union) with a comment, rather than hand-rolling a fresh literal.

AVM metadata map — where each kind of opcode/field table lives (they are NOT
yet physically consolidated; this is the "start here" index for an AVM version
bump). Correctness of the op-result-type tables is guarded by
``tests/test_avm_metadata_drift.py`` against puya's langspec:

  * opcode ARITIES (n_in, n_out) .......... :mod:`tealql.tealtools.opcode_sigs`
  * opcode GROUPS (cmp/logical/txn-source/…) this module
  * op RESULT TYPES + field types ......... :mod:`tealql.tealtools.lift.optypes`
  * field RANGES / byte-lengths / shuffles  :mod:`tealql.tealtools.ssa.models`

:data:`AVM_LANGSPEC_VERSION` records the TEAL/AVM version these tables target;
bump it (and re-run the drift test) when adding a new AVM version's opcodes.
"""
from __future__ import annotations

#: The AVM/TEAL langspec version the metadata across the modules listed in the
#: module docstring is written against. Informational: the drift test pins the
#: result-type tables to whatever puya (``puyapy``) is installed, so a mismatch
#: surfaces there; keep this in sync when widening the tables for a new version.
AVM_LANGSPEC_VERSION = 11

# --- address (32-byte account) fields -------------------------------------

#: Txn-family fields that read a 32-byte account address. SINGLE SOURCE of the
#: address-field universe: a field being an address determines BOTH its AVM type
#: (``"account"``, in :mod:`tealql.tealtools.lift.optypes`) AND its byte length (32, in
#: :mod:`tealql.tealtools.ssa.models`). Both derive from this set instead of each
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
