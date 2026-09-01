"""Conservative SSA resource-demand certificate."""
from __future__ import annotations

import json

from tealql.tealtools import (
    RESOURCE_DEMAND_SCHEMA_VERSION,
    SSAProgram,
    resource_demand,
)
from tealql.tealtools.analysis.resource_demand import CLASSIFIED_RESOURCE_OPS
from tealql.tealtools.language.avm import (
    PARAMS_FIELDS_BY_OP,
    PARAMS_FIELD_TYPE,
    RESOURCE_ACCESS_OPS,
    SIG,
)


def _program(body: str, *, name: str = "contract.teal", strict: bool = True) -> SSAProgram:
    return SSAProgram.from_text(
        f"#pragma version 10\n{body.strip()}\nint 1\nreturn\n",
        name=name,
        strict=strict,
    )


def test_asset_parameter_fields_and_existence_are_demanded():
    demand = resource_demand(_program("""
        int 1
        asset_params_get AssetName
        pop
        pop
        int 2
        asset_params_get AssetManager
        pop
        pop
    """))

    assert demand.asset_fields == frozenset({"AssetName", "AssetManager"})
    assert "asset" in demand.existence_checks
    assert demand.complete


def test_asset_holding_fields_preserve_both_resource_identities():
    demand = resource_demand(_program("""
        txn Sender
        int 1
        asset_holding_get AssetBalance
        pop
        pop
        txna Accounts 1
        txna Assets 0
        asset_holding_get AssetFrozen
        pop
        pop
    """))

    assert demand.holding_fields == frozenset({"AssetBalance", "AssetFrozen"})
    assert {"account", "asset", "holding"} <= demand.existence_checks
    assert {ref.family for ref in demand.references} >= {"Accounts", "Assets"}


def test_account_parameter_balance_and_min_balance_fields():
    demand = resource_demand(_program("""
        int 1
        acct_params_get AcctAuthAddr
        pop
        pop
        int 2
        balance
        pop
        txn Sender
        min_balance
        pop
    """))

    assert demand.account_fields == frozenset({
        "AcctAuthAddr", "AcctBalance", "AcctMinBalance",
    })
    assert "account" in demand.existence_checks
    assert any(ref.kind == "position" and ref.value == "txn.Accounts[1]"
               for ref in demand.references)
    assert any(ref.kind == "address" and ref.value == "txn.Sender"
               for ref in demand.references)


def test_voter_parameter_access_cannot_bypass_account_demand():
    demand = resource_demand(_program("""
        txn Sender
        voter_params_get VoterBalance
        pop
        pop
    """))

    assert "VoterBalance" in demand.account_fields
    assert "account" in demand.existence_checks
    assert any(ref.family == "Accounts" and ref.kind == "address"
               for ref in demand.references)


def test_application_parameter_fields_and_existence():
    demand = resource_demand(_program("""
        int 0
        app_params_get AppCreator
        pop
        pop
        int 7
        app_params_get AppAddress
        pop
        pop
    """))

    assert demand.application_fields == frozenset({"AppCreator", "AppAddress"})
    assert "application" in demand.existence_checks


def test_foreign_global_local_and_optin_state_are_distinct():
    demand = resource_demand(_program("""
        int 0
        byte "global-key"
        app_global_get_ex
        pop
        pop
        txn Sender
        int 4
        byte "local-key"
        app_local_get_ex
        pop
        pop
        txna Accounts 1
        int 0
        app_opted_in
        pop
    """))

    by_scope = {read.scope: read for read in demand.foreign_app_state}
    assert set(by_scope) == {"global", "local", "optin"}
    assert by_scope["global"].key == "0x676c6f62616c2d6b6579"
    assert by_scope["global"].self_only is True
    assert by_scope["local"].key == "0x6c6f63616c2d6b6579"
    assert by_scope["local"].self_only is False
    assert by_scope["optin"].key is None
    assert by_scope["optin"].self_only is True


def test_current_foreign_and_dynamic_application_references_are_not_guessed():
    demand = resource_demand(_program("""
        int 0
        byte "self"
        app_global_get_ex
        pop
        pop
        int 2
        byte "foreign"
        app_global_get_ex
        pop
        pop
        txn GroupIndex
        byte "dynamic"
        app_global_get_ex
        pop
        pop
        int 300
        byte "raw-id"
        app_global_get_ex
        pop
        pop
        txna Applications 0
        byte "array-value"
        app_global_get_ex
        pop
        pop
    """))

    by_key = {read.key: read.self_only for read in demand.foreign_app_state}
    assert by_key["0x73656c66"] is True
    assert by_key["0x666f726569676e"] is False
    assert by_key["0x64796e616d6963"] is None
    assert by_key["0x7261772d6964"] is None
    assert by_key["0x61727261792d76616c7565"] is None


def test_current_transaction_immediate_and_stack_array_accessors():
    demand = resource_demand(_program("""
        txna Accounts 1
        pop
        txn GroupIndex
        txnas Assets
        pop
        txna Applications 1
        pop
    """))

    assert demand.resource_arrays == frozenset({"Accounts", "Assets", "Applications"})
    assert "Assets" in demand.dynamic_refs
    assert any(ref.family == "Accounts" and ref.kind == "position"
               for ref in demand.references)
    assert any(ref.family == "Assets" and ref.kind == "dynamic"
               for ref in demand.references)


def test_scalar_array_counts_and_raw_resource_identities_are_classified():
    demand = resource_demand(_program("""
        txn NumAccounts
        pop
        gtxn 0 NumAssets
        pop
        txn GroupIndex
        gtxns NumApplications
        pop
        txn Sender
        pop
        txn XferAsset
        pop
        txn ApplicationID
        pop
    """))

    assert demand.resource_arrays == frozenset({"Accounts", "Assets", "Applications"})
    assert "Applications" in demand.dynamic_refs
    assert any(ref.family == "Accounts" and ref.kind == "address"
               and ref.value == "txn.Sender" for ref in demand.references)
    assert any(ref.family == "Assets" and ref.kind == "identity"
               and ref.value == "txn.XferAsset" for ref in demand.references)
    assert any(ref.family == "Applications" and ref.kind == "implicit"
               and ref.value == "current" for ref in demand.references)


def test_all_group_transaction_array_accessor_shapes():
    demand = resource_demand(_program("""
        gtxna 0 Accounts 1
        pop
        txn GroupIndex
        gtxnas 1 Assets
        pop
        txn GroupIndex
        gtxnsa Applications 1
        pop
        txn GroupIndex
        txn GroupIndex
        gtxnsas Accounts
        pop
    """))

    assert demand.resource_arrays == frozenset({"Accounts", "Assets", "Applications"})
    assert {"Accounts", "Assets", "Applications"} <= demand.dynamic_refs
    assert any(ref.value == "gtxn[0].Accounts[1]" and ref.kind == "position"
               for ref in demand.references)


def test_inner_transaction_result_array_accessor_shapes_are_classified():
    demand = resource_demand(_program("""
        itxna Accounts 0
        pop
        txn GroupIndex
        itxnas Assets
        pop
        gitxna 0 Applications 1
        pop
        txn GroupIndex
        gitxnas 0 Accounts
        pop
    """))

    assert demand.resource_arrays == frozenset({"Accounts", "Assets", "Applications"})
    assert {"Accounts", "Assets"} <= demand.dynamic_refs


def test_called_subroutine_resource_access_is_included():
    program = SSAProgram.from_text("""#pragma version 10
        b main
        resource_sub:
        int 1
        asset_params_get AssetName
        pop
        pop
        retsub
        main:
        callsub resource_sub
        int 1
        return
    """, name="called.teal")

    assert resource_demand(program).asset_fields == frozenset({"AssetName"})


def test_all_supplied_subprograms_are_scanned_independent_of_order():
    main = _program("txn Fee\npop", name="main.teal")
    asset_sub = _program("""
        int 1
        asset_params_get AssetManager
        pop
        pop
    """, name="asset-sub.teal")
    app_sub = _program("""
        int 1
        app_params_get AppAddress
        pop
        pop
    """, name="app-sub.teal")

    left = resource_demand(main, (asset_sub, app_sub))
    right = resource_demand(main, (app_sub, asset_sub))
    assert left == right
    assert left.asset_fields == frozenset({"AssetManager"})
    assert left.application_fields == frozenset({"AppAddress"})


def test_unused_resource_read_result_is_still_included():
    # Both getter outputs are immediately discarded. Demand is syntactic, not
    # liveness-based, so this access must survive.
    demand = resource_demand(_program("""
        int 1
        asset_params_get AssetCreator
        pop
        pop
    """))
    assert demand.asset_fields == frozenset({"AssetCreator"})


def test_inner_transaction_fields_accumulate_across_next_and_submit():
    demand = resource_demand(_program("""
        itxn_begin
        int pay
        itxn_field TypeEnum
        txn Sender
        itxn_field Receiver
        itxn_next
        int axfer
        itxn_field TypeEnum
        int 7
        itxn_field XferAsset
        itxn_submit
    """))

    assert demand.uses_inner_transactions
    assert demand.inner_txn_fields == frozenset({"TypeEnum", "Receiver", "XferAsset"})
    assert sum(site.category == "inner-transaction-field" for site in demand.sites) == 4


def test_unknown_parameter_field_is_incomplete_and_widens_family():
    demand = resource_demand(_program("""
        int 1
        asset_params_get FutureAssetField
        pop
        pop
    """))

    assert not demand.complete
    assert demand.unknowns
    assert demand.asset_fields == PARAMS_FIELDS_BY_OP["asset_params_get"]
    assert "Assets" in demand.dynamic_refs
    assert "Assets" in demand.resource_arrays


def test_parse_gap_is_incomplete_and_widens_every_family():
    program = SSAProgram.from_text(
        "#pragma version 10\nthis is not teal $$$\nint 1\nreturn\n",
        strict=False,
    )
    demand = resource_demand(program)

    assert not demand.complete
    assert demand.resource_arrays == frozenset({"Accounts", "Assets", "Applications"})
    assert demand.dynamic_refs == frozenset({"Accounts", "Assets", "Applications", "Boxes"})
    assert demand.uses_inner_transactions


def test_program_without_resource_operations_is_empty_and_complete():
    demand = resource_demand(_program("int 2\nint 3\n+\npop"))

    assert demand.complete
    assert not demand.account_fields
    assert not demand.asset_fields
    assert not demand.application_fields
    assert not demand.holding_fields
    assert not demand.foreign_app_state
    assert not demand.resource_arrays
    assert not demand.dynamic_refs
    assert not demand.inner_txn_fields
    assert not demand.uses_inner_transactions
    assert not demand.unknowns
    assert not demand.sites
    assert not demand.references
    assert not demand.box_accesses


def test_to_dict_is_versioned_json_stable_and_deterministically_ordered():
    demand = resource_demand(_program("""
        int 2
        asset_params_get AssetName
        pop
        pop
        int 1
        asset_params_get AssetManager
        pop
        pop
        txna Accounts 2
        pop
        txna Accounts 1
        pop
    """))

    first = demand.to_dict()
    second = resource_demand(_program("""
        int 2
        asset_params_get AssetName
        pop
        pop
        int 1
        asset_params_get AssetManager
        pop
        pop
        txna Accounts 2
        pop
        txna Accounts 1
        pop
    """)).to_dict()
    assert first == second
    assert first["schema_version"] == RESOURCE_DEMAND_SCHEMA_VERSION == 1
    assert first["asset_fields"] == ["AssetManager", "AssetName"]
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert first["sites"] == sorted(
        first["sites"],
        key=lambda site: (
            site["file"], site["line"], site["op"], site["category"], site["field"] or ""
        ),
    )


def test_box_names_and_dynamic_box_accesses_are_reported():
    demand = resource_demand(_program("""
        byte "fixed-box"
        box_get
        pop
        pop
        txn Note
        int 4
        box_create
        pop
    """))

    assert any(access.key == "0x66697865642d626f78" and not access.dynamic_key
               for access in demand.box_accesses)
    assert any(access.key is None and access.dynamic_key for access in demand.box_accesses)
    assert "Boxes" in demand.dynamic_refs
    assert "box" in demand.existence_checks


def test_resource_classifier_and_parameter_partition_cannot_drift_silently():
    assert CLASSIFIED_RESOURCE_OPS == RESOURCE_ACCESS_OPS
    assert RESOURCE_ACCESS_OPS <= set(SIG)
    owned = [field for fields in PARAMS_FIELDS_BY_OP.values() for field in fields]
    assert len(owned) == len(set(owned))
    assert set(owned) == set(PARAMS_FIELD_TYPE)


def test_scalar_and_array_application_references_share_one_index_space():
    """A scalar small int resolves exactly like the txna accessor — `int 3;
    app_params_get` and `txna Applications 3` denote the SAME app — so both
    must emit the same label. The old `- 1` shift put scalars in
    ForeignApps-relative space: same label = different apps, and a consumer
    populating access arrays from references picked wrong slots."""
    demand = resource_demand(_program("""
        int 3
        app_params_get AppCreator
        pop
        pop
        txna Applications 3
        app_params_get AppCreator
        pop
        pop
        int 1
        return
    """))
    labels = {ref.value for ref in demand.references
              if ref.family == "Applications"}
    assert labels == {"txn.Applications[3]"}, (
        f"the two spellings of the same app must share one label: {labels}")
