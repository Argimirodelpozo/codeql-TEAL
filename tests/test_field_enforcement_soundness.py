"""Regression: `field_validated_on_all_paths` must be a MUST-reach on the
enforcement site, not a may-reach on the comparison.

The old formulation ("a single field comparison dominates all approving exits
AND its result reaches *some* assert/branch-to-reject") was unsound: a field
compared in a dominating block but enforced on only one branch — while an
approving branch drops the check — read as validated-on-all-paths, a false
negative that let an attacker set the field (e.g. AssetCloseTo → drain the app
account) on the unenforced approving path. Covers both the `dup` and scratch
spellings of "enforced on one branch only", plus a genuinely-safe control.
"""
from __future__ import annotations

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.security._enforcement import def_forward_reaches_enforcement
from tealql.security._field_protection import (
    approval_exit_protected_for_field,
    field_validated_on_all_paths,
)
from tealql.security._program_shape import approving_exits


def _validated(tmp_path, teal: str) -> bool:
    (tmp_path / "p.teal").write_text(teal)
    return field_validated_on_all_paths(SSAProgram(str(tmp_path)), "AssetCloseTo")


# AssetCloseTo==Zero computed in the entry (dominates both exits), then enforced
# only on the DeleteApplication branch; the NoOp branch approves without it.
_FN_DUP = """#pragma version 10
txn AssetCloseTo
global ZeroAddress
==
dup
txn OnCompletion
int 5
==
bnz do_delete
pop
int 1
return
do_delete:
assert
int 1
return
"""

_FN_SCRATCH = """#pragma version 10
txn AssetCloseTo
global ZeroAddress
==
store 0
txn OnCompletion
int 5
==
bnz do_delete
int 1
return
do_delete:
load 0
assert
int 1
return
"""

# Enforced on EVERY path: the assert dominates both exits.
_SAFE = """#pragma version 10
txn AssetCloseTo
global ZeroAddress
==
assert
txn OnCompletion
int 5
==
bnz do_delete
int 1
return
do_delete:
int 1
return
"""


def test_branch_enforced_dup_is_not_validated(tmp_path):
    assert _validated(tmp_path, _FN_DUP) is False


def test_branch_enforced_scratch_is_not_validated(tmp_path):
    assert _validated(tmp_path, _FN_SCRATCH) is False


def test_assert_on_all_paths_is_validated(tmp_path):
    assert _validated(tmp_path, _SAFE) is True


def test_field_never_compared_is_not_validated(tmp_path):
    teal = "#pragma version 10\nint 1\nreturn\n"
    assert _validated(tmp_path, teal) is False


def test_approval_guard_follows_a_dup_without_mutating_shared_ssa():
    prog = SSAProgram.from_text(
        "#pragma version 10\n"
        "txn RekeyTo\n"
        "dup\n"
        "global ZeroAddress\n"
        "==\n"
        "assert\n"
        "pop\n"
        "int 1\n"
        "return\n"
    )
    exit_bb = approving_exits(prog)[0]
    before = tuple(tuple(a.inputs) for a in prog.assignments)

    assert approval_exit_protected_for_field(
        prog, exit_bb, "RekeyTo"
    )
    assert tuple(tuple(a.inputs) for a in prog.assignments) == before


def test_asset_close_to_detector_flags_branch_enforced(tmp_path):
    """End-to-end: the asset-close-to detector must emit on the dup FN."""
    from tealql.security import DETECTORS
    if "asset-close-to" not in DETECTORS:
        pytest.skip("asset-close-to detector not registered")
    (tmp_path / "p.teal").write_text(_FN_DUP)
    prog = SSAProgram(str(tmp_path))
    findings = DETECTORS["asset-close-to"](prog).detect()
    assert findings, "branch-enforced AssetCloseTo must be flagged"


# --- the SAME must-reach fix now unifies the approval_exit family
#     (rekey-to / is-deletable / tx-type-check via approval_exit_protected_for_field) ---

def _detector(tmp_path, name, teal):
    from tealql.security import DETECTORS
    (tmp_path / "p.teal").write_text(teal)
    return DETECTORS[name](SSAProgram(str(tmp_path))).detect()


_REKEY_BRANCH_ENFORCED = """#pragma version 10
txn RekeyTo
global ZeroAddress
==
store 0
txn OnCompletion
int 5
==
bnz do_delete
int 1
return
do_delete:
load 0
assert
int 1
return
"""

_REKEY_SAFE = """#pragma version 10
txn RekeyTo
global ZeroAddress
==
assert
txn OnCompletion
int 5
==
bnz do_delete
int 1
return
do_delete:
int 1
return
"""


def test_rekey_branch_enforced_is_flagged(tmp_path):
    """RekeyTo compared in a dominator but asserted on only the Delete branch,
    while the NoOp branch approves without it — must flag (was a may-reach FN)."""
    assert _detector(tmp_path, "rekey-to", _REKEY_BRANCH_ENFORCED)


def test_rekey_asserted_on_all_paths_is_clean(tmp_path):
    """RekeyTo asserted unconditionally (dominates both exits) — no finding."""
    assert _detector(tmp_path, "rekey-to", _REKEY_SAFE) == []


# --- scratch-aware enforcement (the pre-existing store/load round-trip gap) ---

def _reaches_enforcement(tmp_path, teal: str, cmp_op: str) -> bool:
    (tmp_path / "p.teal").write_text(teal)
    prog = SSAProgram(str(tmp_path))
    cmp = next(a for a in prog.assignments if a.op == cmp_op)
    return def_forward_reaches_enforcement(prog, cmp.outputs[0])


# `==; store 0; load 0; assert` — the comparison is enforced, just laundered
# through scratch. The walk must follow the provable round-trip.
_SCRATCH_ENFORCED = """#pragma version 10
gtxn 0 Receiver
global CurrentApplicationAddress
==
store 0
load 0
assert
int 1
return
"""


def test_scratch_roundtrip_reaches_enforcement(tmp_path):
    assert _reaches_enforcement(tmp_path, _SCRATCH_ENFORCED, "==")


# The slot is CLOBBERED by a constant before the load, so the assert enforces the
# constant, not the comparison — must-semantics must NOT claim enforcement.
_SCRATCH_CLOBBERED = """#pragma version 10
gtxn 0 Receiver
global CurrentApplicationAddress
==
store 0
int 1
store 0
load 0
assert
int 1
return
"""


def test_clobbered_scratch_does_not_reach_enforcement(tmp_path):
    assert not _reaches_enforcement(tmp_path, _SCRATCH_CLOBBERED, "==")


# --- signed-txn-scope for delegated-lsig drain fields (asset-close-to) ---
# A `gtxn N AssetCloseTo` check protects the SIGNER only when it reads the SIGNED
# txn's own field: `txn`, `gtxns` indexed by GroupIndex, or `gtxn N` with
# `GroupIndex == N` pinned. A bare `gtxn N` on an unpinned index does not.

def _acto(tmp_path, teal):
    return _detector(tmp_path, "asset-close-to", teal)


_H = "#pragma version 8\n"


def test_asset_close_to_txn_self_clean(tmp_path):
    assert _acto(tmp_path, _H + "txn AssetCloseTo\nglobal ZeroAddress\n==\n"
                 "assert\nint 1\nreturn\n") == []


def test_asset_close_to_dynamic_self_gtxns_clean(tmp_path):
    # gtxns AssetCloseTo indexed by txn GroupIndex = the signed txn's own field
    assert _acto(tmp_path, _H + "txn GroupIndex\ngtxns AssetCloseTo\n"
                 "global ZeroAddress\n==\nassert\nint 1\nreturn\n") == []


def test_asset_close_to_gtxn_with_groupindex_pin_clean(tmp_path):
    # gtxn 0 checked AND GroupIndex==0 pinned -> gtxn 0 IS the signed txn
    assert _acto(tmp_path, _H + "txn GroupIndex\nint 0\n==\nassert\n"
                 "gtxn 0 AssetCloseTo\nglobal ZeroAddress\n==\nassert\n"
                 "int 1\nreturn\n") == []


def test_asset_close_to_unpinned_sibling_flagged(tmp_path):
    # gtxn 0 checked but GroupIndex NOT pinned -> signed txn still exposed
    vs = _acto(tmp_path, _H + "gtxn 0 AssetCloseTo\nglobal ZeroAddress\n==\n"
               "assert\nint 1\nreturn\n")
    assert len(vs) == 1
    assert "GroupIndex" in vs[0].pretty()          # the specific unpinned-index warning


def test_asset_close_to_wrong_index_pin_flagged(tmp_path):
    # pins GroupIndex==1 but checks gtxn 0 (a genuine sibling) -> flagged
    vs = _acto(tmp_path, _H + "txn GroupIndex\nint 1\n==\nassert\n"
               "gtxn 0 AssetCloseTo\nglobal ZeroAddress\n==\nassert\n"
               "int 1\nreturn\n")
    assert len(vs) == 1


def test_asset_close_to_no_check_generic_message(tmp_path):
    vs = _acto(tmp_path, _H + "int 1\nreturn\n")
    assert len(vs) == 1
    assert "does not validate txn AssetCloseTo" in vs[0].pretty()


# --- signed-txn scope for close-remainder-to / rekey-to (same rule as
#     asset-close-to, via the _ApprovalExitProtected path) ---

def test_close_remainder_to_dynamic_self_clean(tmp_path):
    assert _detector(tmp_path, "close-remainder-to",
                     _H + "txn GroupIndex\ngtxns CloseRemainderTo\n"
                     "global ZeroAddress\n==\nassert\nint 1\nreturn\n") == []


def test_close_remainder_to_pinned_absolute_clean(tmp_path):
    assert _detector(tmp_path, "close-remainder-to",
                     _H + "txn GroupIndex\nint 0\n==\nassert\n"
                     "gtxn 0 CloseRemainderTo\nglobal ZeroAddress\n==\nassert\n"
                     "int 1\nreturn\n") == []


def test_close_remainder_to_unpinned_sibling_flagged(tmp_path):
    assert _detector(tmp_path, "close-remainder-to",
                     _H + "gtxn 0 CloseRemainderTo\nglobal ZeroAddress\n==\n"
                     "assert\nint 1\nreturn\n")


def test_rekey_to_dynamic_self_clean(tmp_path):
    assert _detector(tmp_path, "rekey-to",
                     _H + "txn GroupIndex\ngtxns RekeyTo\n"
                     "global ZeroAddress\n==\nassert\nint 1\nreturn\n") == []


def test_rekey_to_pinned_absolute_clean(tmp_path):
    assert _detector(tmp_path, "rekey-to",
                     _H + "txn GroupIndex\nint 0\n==\nassert\n"
                     "gtxn 0 RekeyTo\nglobal ZeroAddress\n==\nassert\n"
                     "int 1\nreturn\n") == []


def test_rekey_to_unpinned_sibling_flagged(tmp_path):
    assert _detector(tmp_path, "rekey-to",
                     _H + "gtxn 0 RekeyTo\nglobal ZeroAddress\n==\n"
                     "assert\nint 1\nreturn\n")


# --- the COMPILED spellings of a guard ---------------------------------------
# A hand-written lsig says `txn RekeyTo`. A compiler says `txn GroupIndex` once, then `dup`s that
# index before each field read of the same transaction, and spells `field === 0` as `!`. Both were
# invisible to the field-protection resolver, so a logicsig that pinned TypeEnum, RekeyTo,
# AssetCloseTo and Fee was reported as protecting NONE of them -- six drain findings on a contract
# that had explicitly guarded against every one (algorandfoundation/auto-draw-card's AutoDraw, built with puya-ts).

_DUP_CARRIED = """#pragma version 11
txn GroupIndex
dup
gtxns TypeEnum
pushint 4
==
assert
dup
gtxns RekeyTo
global ZeroAddress
==
assert
pop
int 1
return
"""

_FEE_VIA_NOT = """#pragma version 11
txn GroupIndex
dup
gtxns Fee
!
assert
pop
int 1
return
"""


def _findings(tmp_path, teal: str, detector: str) -> list:
    from tealql.security import DETECTORS
    p = tmp_path / "p.teal"
    p.write_text(teal)
    return DETECTORS[detector](SSAProgram(str(p)), file="p.teal").detect()


def test_abi_selector_accepts_an_enforced_dynamic_expected_value(tmp_path):
    """A selector need not be compared with an inline constant: application
    state can hold the accepted selector.  What matters is that the selector
    comparison is enforced on every approving path.  Merely computing and
    dropping that same comparison is the negative control.
    """
    checked = """#pragma version 11
txna ApplicationArgs 0
byte "key"
app_global_get
==
assert
int 1
return
"""
    dropped = checked.replace("assert\n", "pop\n")

    assert not _findings(tmp_path, checked, "abi-method-selector")
    assert _findings(tmp_path, dropped, "abi-method-selector")


@pytest.mark.parametrize("detector", ["rekey-to", "tx-type-check"])
def test_dup_carried_group_index_counts_as_a_guard(tmp_path, detector):
    """`gtxns FIELD` on a dup'd `txn GroupIndex` reads THIS transaction, so it is a guard.

    Resolving it needs the stack shuffles propagated first; without that the index operand traces
    to the `dup` rather than to `txn GroupIndex` and the read is not credited to the signer.
    """
    assert not _findings(tmp_path, _DUP_CARRIED, detector), \
        f"{detector}: a dup-carried guard was not credited"


def test_logical_not_is_a_zero_test(tmp_path):
    """`txn Fee; !` pins the fee to zero exactly as `== 0` does, and is what a compiler emits."""
    assert not _findings(tmp_path, _FEE_VIA_NOT, "fee-validation"), \
        "fee-validation: `!` was not recognised as a zero-test"


def test_unpinned_sibling_read_is_still_refused(tmp_path):
    """The soundness half: `gtxn 1 RekeyTo` checks a SIBLING, never the signer, so it must NOT
    count -- crediting it would let a delegated logicsig be drained through a check that never
    touched the signed transaction."""
    sibling = """#pragma version 11
gtxn 1 RekeyTo
global ZeroAddress
==
assert
int 1
return
"""
    assert _findings(tmp_path, sibling, "rekey-to"), \
        "a sibling-only check must not count as protecting the signer"
