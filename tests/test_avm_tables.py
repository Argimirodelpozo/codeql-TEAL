"""Behavior pins for avm.py's lookup layer (spec-vs-puya drift lives in
test_avm_metadata_drift.py).

The regression that motivated this: ``attacker_input_label`` matched fields by
SUBSTRING, so ``txn NumAccounts`` — a uint64 array-LENGTH read — was labelled
``ForeignAccounts`` because ``"Accounts" in "NumAccounts"``, seeding phantom
taint in every consumer of the single-source table.
"""
from __future__ import annotations

import pytest

from tealql.tealtools import avm
from tealql.tealtools.avm import _field_type, _multi_out_type, attacker_input_label


@pytest.mark.parametrize("op,imm,want", [
    # The regression: Num* counts must NOT match their array namesakes.
    ("txn", "NumAccounts", None),
    ("txn", "NumAssets", None),
    ("txn", "NumApplications", None),
    # Foreign-array reads still label, in either immediate position.
    ("txna", "Accounts 1", "ForeignAccounts"),
    ("gtxna", "0 Accounts 1", "ForeignAccounts"),
    ("txna", "Assets 0", "ForeignAssets"),
    # `Accounts 0` is the sender — an authorisation value, not a free choice.
    ("txna", "Accounts 0", None),
    ("gtxna", "0 Accounts 0", None),
    # A stack-supplied index is still attacker-chosen: over-approximate.
    ("txnas", "Accounts", "ForeignAccounts"),
    # The other families.
    ("txna", "ApplicationArgs 0", "ApplicationArgs"),
    ("itxn", "LastLog", "ItxnLastLog"),
    ("itxn", "Logs", None),
    ("arg", "0", "LogicSigArgs"),
    ("global", "GroupSize", None),
])
def test_attacker_input_label_matches_exact_tokens(op, imm, want):
    assert attacker_input_label(op, imm) == want


def test_v12_opcode_tail_is_typed():
    """``online_stake`` / ``voter_params_get`` / ``json_ref`` / ``block`` got
    arities when they were added and nothing else — their results went untyped,
    which the drift test cannot catch for an op in NEITHER result table."""
    assert "online_stake" in avm._U64_OPS

    # voter_params_get routes through the *_params_get machinery: exists flag
    # on TOP (output 0), field-typed value below.
    assert {"voter_params_get"} <= avm._EX_FLAG_OPS & avm._PARAMS_OPS
    assert _multi_out_type("voter_params_get", "VoterBalance", 0) == "uint64"
    assert _multi_out_type("voter_params_get", "VoterIncentiveEligible", 1) == "bool"
    assert avm._OP_OUTPUT_SEEDS["voter_params_get"] == [(0, 0, 1)]

    assert _field_type("json_ref", "JSONUint64") == "uint64"
    assert _field_type("json_ref", "JSONObject") == "bytes"

    assert _field_type("block", "BlkProposer") == "account"
    assert _field_type("block", "BlkTimestamp") == "uint64"
    assert avm._BLOCK_FIELD_BYTELEN["BlkProposer"] == 32
    # BlkProtocol is a variable-length string: typed, deliberately unmeasured.
    assert "BlkProtocol" not in avm._BLOCK_FIELD_BYTELEN


def test_shared_op_families_have_one_definition():
    """Three modules once carried same-named branch sets with DIFFERENT
    contents, and ``imm0`` was re-rolled per module. Consumers derive now."""
    from tealql.tealtools import abi, structure
    from tealql.tealtools.lift import type_recovery
    from tealql.tealtools.passes import frame_resolution
    from tealql.tealtools.ssa.operands import imm0

    assert avm.COND_BRANCH_OPS == frozenset({"bnz", "bz"})
    assert avm.MULTIWAY_BRANCH_OPS == frozenset({"switch", "match"})
    assert (avm.COND_BRANCH_OPS | avm.MULTIWAY_BRANCH_OPS) <= avm._TERMINATOR_OPS
    assert structure._VALUE_BRANCH_OPS == avm.COND_BRANCH_OPS | avm.MULTIWAY_BRANCH_OPS
    assert abi._SELECTOR_BRANCH_OPS == avm.COND_BRANCH_OPS | {"b"}

    assert frame_resolution._imm0 is imm0 and type_recovery._imm0 is imm0
    assert not hasattr(avm, "_imm0")     # left the spec-data leaf entirely
