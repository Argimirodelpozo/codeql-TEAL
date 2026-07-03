"""xcontract dynamic ApplicationID resolution from BOX and LOCAL state.

Extends :mod:`test_xcontract_dynamic_appid` (which covers global state) to the
other two persistent stores. A callee whose AppID is stashed in a box or in an
account's local state and read back to drive the inner appcall is resolved by the
same discipline: trace the read to the writes of that key, and resolve only when
EVERY write agrees on one int constant (sound — no invented target).

Box values are bytes, so an AppID lands in a box either as ``itob(N)`` or as a raw
<=8-byte constant, and is read back with ``btoi(box_get KEY)``.
"""

from tealql.tealtools.xcontract import find_appcall_sites
from helpers import make_xcontract

_CALLEE = "#pragma version 10\n    int 1\n    return\n"


def _sites(caller_teal, tmp_path):
    prog, registry = make_xcontract(tmp_path, caller_teal, {555: _CALLEE, 777: _CALLEE})
    return find_appcall_sites(prog, registry)


# --- local state ------------------------------------------------------------

# `app_local_put 0 "target" 555` then `app_local_get 0 "target"` (account 0 =
# Txn.Accounts[0], the sender). The value 555 is the top-of-stack operand.
_LOCAL = """#pragma version 10
    int 0
    byte "target"
    int 555
    app_local_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 0
    byte "target"
    app_local_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# The local slot is written from attacker input -> not a constant -> unresolvable.
_LOCAL_DYNAMIC = """#pragma version 10
    int 0
    byte "target"
    txn ApplicationArgs 0
    btoi
    app_local_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 0
    byte "target"
    app_local_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_local_state_appid_resolves(tmp_path):
    assert [s.app_id for s in _sites(_LOCAL, tmp_path)] == [555]


def test_local_attacker_written_slot_unresolved(tmp_path):
    assert _sites(_LOCAL_DYNAMIC, tmp_path) == []


# --- box state --------------------------------------------------------------

# `box_put "target", itob(555)` then `btoi(box_get "target")`.
_BOX_ITOB = """#pragma version 10
    byte "target"
    int 555
    itob
    box_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    box_get
    assert
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# Same, but the box holds a raw 8-byte big-endian constant (0x...22b == 555).
_BOX_RAW = """#pragma version 10
    byte "target"
    byte 0x000000000000022b
    box_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    box_get
    assert
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# The box is written from attacker input -> unresolvable.
_BOX_DYNAMIC = """#pragma version 10
    byte "target"
    txn ApplicationArgs 0
    box_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    box_get
    assert
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# Two writes to the box disagree on the constant -> unprovable -> unresolved.
_BOX_DISAGREE = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    bz set_b
    byte "target"
    int 555
    itob
    box_put
    b call
set_b:
    byte "target"
    int 777
    itob
    box_put
call:
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    box_get
    assert
    btoi
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_box_itob_appid_resolves(tmp_path):
    assert [s.app_id for s in _sites(_BOX_ITOB, tmp_path)] == [555]


def test_box_raw_bytes_appid_resolves(tmp_path):
    assert [s.app_id for s in _sites(_BOX_RAW, tmp_path)] == [555]


def test_box_attacker_written_slot_unresolved(tmp_path):
    assert _sites(_BOX_DYNAMIC, tmp_path) == []


def test_box_disagreeing_writes_unresolved(tmp_path):
    assert _sites(_BOX_DISAGREE, tmp_path) == []
