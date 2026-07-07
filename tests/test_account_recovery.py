"""Usage-backward account recovery (the CONFIDENT tier).

``_recover_ir_types`` types addresses FORWARD from producer ops (txn Sender,
global ZeroAddress). This pins the complementary USAGE-backward rule: a value
fed to an operand the AVM REQUIRES to be a 32-byte address (an account-typed
``itxn_field``, or the account operand of a local-state / account-param op) has
its plain-``bytes`` intrinsic definition refined to ``account``. Same avm_type,
so still a free annotation (the corpus neutrality gate proves TEAL is unchanged).
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

import puya.ir.models as M                               # noqa: E402
from puya.ir.types_ import PrimitiveIRType as PT         # noqa: E402

from tealql.tealtools.lift import to_puya                # noqa: E402
from tealql.tealtools.ssa import SSAProgram              # noqa: E402


def _account_defs(tmp_path, teal: str) -> int:
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    return sum(1 for s in (main, *subs) for bb in s.body for o in bb.ops
               if isinstance(o, M.Assignment)
               for t in o.targets if t.ir_type is PT.account)


def test_arg_to_receiver_recovers_account(tmp_path):
    """An ApplicationArgs value (plain bytes) sent to itxn Receiver has its txna
    definition recovered as account."""
    teal = """#pragma version 10
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""
    assert _account_defs(tmp_path, teal) >= 1


def test_account_operand_recovers_account(tmp_path):
    """The account operand of app_opted_in (a decoded address) is recovered."""
    teal = """#pragma version 10
txna ApplicationArgs 0
int 0
app_opted_in
return
"""
    assert _account_defs(tmp_path, teal) >= 1


def test_plain_bytes_not_at_address_operand_stays_bytes(tmp_path):
    """A bytes value only logged (never at an address operand) is NOT retyped
    account -- usage evidence is the whole trigger."""
    teal = """#pragma version 10
txna ApplicationArgs 0
log
int 1
return
"""
    assert _account_defs(tmp_path, teal) == 0


def test_uint64_account_index_not_retyped(tmp_path):
    """app_opted_in accepts a uint64 account INDEX (0 = sender); that is not an
    address, so nothing is retyped account (the avm_type=bytes filter holds)."""
    teal = """#pragma version 10
int 0
int 0
app_opted_in
return
"""
    assert _account_defs(tmp_path, teal) == 0
