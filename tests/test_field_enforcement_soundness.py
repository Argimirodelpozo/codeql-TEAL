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
from tealql.security import common


def _validated(tmp_path, teal: str) -> bool:
    (tmp_path / "p.teal").write_text(teal)
    return common.field_validated_on_all_paths(SSAProgram(str(tmp_path)), "AssetCloseTo")


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
