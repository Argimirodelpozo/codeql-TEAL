"""Reads of one constant state key carry ONE recovered type
(``type_recovery._infer_state_types``).

Found by the historical-replay gate (``tests/behavioral_lift/timetravel.py``):
mainnet app 3192677198 did not lift. Its owner key was put from an
account-typed register and from a constant, and read in several places; the
reads only witnessed "bytes", which was counted as a rival claim, so the key
stayed unresolved and each read kept its own use-inferred type. Puya's CSE then
merged an ``(account, bool)`` read into an untyped ``(uint64, bool)`` one and
rejected the assignment.
"""
from __future__ import annotations

import logging

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import build_lifter  # noqa: E402
from tealql.tealtools.lift.backend import lift_to_teal  # noqa: E402
from tealql.tealtools.ssa import SSAProgram  # noqa: E402

logging.getLogger("puya").setLevel(logging.CRITICAL)

_OWNER_KEY = """#pragma version 10
txn ApplicationID
bnz run
byte "owner"
txn Sender
app_global_put
int 1
return
run:
txn OnCompletion
int 5
==
bz call
byte "owner"
byte 0x00
app_global_put
int 1
return
call:
int 0
byte "owner"
app_global_get_ex
assert
acct_params_get AcctBalance
assert
itob
log
txn Sender
int 0
byte "owner"
app_global_get_ex
assert
==
return
"""


def _read_types(tmp_path, source: str, op: str = "app_global_get_ex") -> list:
    path = tmp_path / "prog.teal"
    path.write_text(source)
    prog = SSAProgram(str(path))
    lifter = build_lifter(prog, None)
    out = 1 if op.endswith("_ex") else 0
    return sorted(lifter.reg(a.outputs[out]).ir_type
                  for a in prog.stack_assignments if a.op == op)


def test_reads_of_one_key_share_the_put_claim_and_the_program_lifts(tmp_path):
    # One account claim (txn Sender) + a constant put + reads that only witness
    # bytes: every read is account, and the recompile no longer trips Puya's CSE.
    assert _read_types(tmp_path, _OWNER_KEY) == ["account", "account"]
    path = tmp_path / "owner.teal"
    path.write_text(_OWNER_KEY)
    assert "acct_params_get AcctBalance" in lift_to_teal(str(path))

    # Control, uint64 family: a bool claim beside a constant 5 does not make the
    # key bool (5 is not a bool) — the base type, which every write satisfies.
    counter = ("#pragma version 10\ntxn ApplicationID\nbnz run\nbyte \"k\"\nint 5\napp_global_put\n"
               "int 1\nreturn\nrun:\nbyte \"k\"\ntxn Fee\nint 1000\n>\napp_global_put\n"
               "byte \"k\"\napp_global_get\nitob\nlog\nint 1\nreturn\n")
    assert _read_types(tmp_path, counter, "app_global_get") == ["uint64"]

