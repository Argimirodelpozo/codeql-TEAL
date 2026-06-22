"""Canonical opcode and transaction-field sets shared across the analysis,
the lift, and the security detectors.

A **pure leaf** module — it imports nothing from ``tealtools`` — so every layer
(``dataflow/``, ``WIP_lift2puyaIR/``, ``cfg/``, and the importlib-loaded security
detectors) can consume one source of truth instead of re-listing these sets.
Before this module they had drifted: e.g. ``cfg/super_auth`` silently dropped
``box_replace``/``box_splice``/``box_resize`` that ``auth_domination`` flagged,
and the txn-source families disagreed on the ``*as`` (stack-index) variants.

Consumers that genuinely need a narrower or wider view should derive it from
these (filter / union) with a comment, rather than hand-rolling a fresh literal.
"""
from __future__ import annotations

# --- inner-transaction fields ---------------------------------------------

#: Inner-txn fields whose operand governs value movement or control transfer —
#: attacker control over any of these is the thing worth reporting.
SENSITIVE_ITXN_FIELDS: frozenset[str] = frozenset({
    "Receiver", "Amount", "AssetReceiver", "AssetAmount",
    "ApplicationID", "RekeyTo", "CloseRemainderTo", "AssetCloseTo",
    "ApprovalProgram", "ClearStateProgram",
})

#: Payment fields where attacker control = redirected / oversized fund movement,
#: tagged by severity (the account-draining close/rekey fields rank CRITICAL).
FUND_FIELDS: dict[str, str] = {
    "RekeyTo": "CRITICAL",
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
