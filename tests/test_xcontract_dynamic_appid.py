"""xcontract dynamic ApplicationID resolution.

A cross-contract callee whose AppID is not an inline literal but read from this
app's GLOBAL state (the common router/factory pattern) is resolved by tracing
``app_global_get KEY`` to the constant ``app_global_put KEY, <v>`` writes -- but
only when every write to the slot agrees on one constant (sound: no invented
target).
"""

from tealtools.xcontract import find_appcall_sites
from helpers import make_xcontract

_CALLEE = "#pragma version 10\n    int 1\n    return\n"


def _sites(caller_teal, tmp_path):
    prog, registry = make_xcontract(tmp_path, caller_teal, {555: _CALLEE, 777: _CALLEE})
    return find_appcall_sites(prog, registry)


_LITERAL = """#pragma version 10
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

_STATE = """#pragma version 10
    byte "target"
    int 555
    app_global_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    app_global_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# The slot is written from attacker input -- not a constant, so unresolvable.
_DYNAMIC_INPUT = """#pragma version 10
    byte "target"
    txn ApplicationArgs 0
    btoi
    app_global_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    app_global_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""

# Two writes to the slot disagree on the constant -> unprovable -> unresolved.
_DISAGREE = """#pragma version 10
    txn ApplicationArgs 0
    btoi
    bz set_b
    byte "target"
    int 555
    app_global_put
    b call
set_b:
    byte "target"
    int 777
    app_global_put
call:
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    app_global_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def test_inline_literal_still_resolves(tmp_path):
    assert [s.app_id for s in _sites(_LITERAL, tmp_path)] == [555]


def test_state_backed_appid_resolves(tmp_path):
    assert [s.app_id for s in _sites(_STATE, tmp_path)] == [555]


def test_attacker_written_slot_unresolved(tmp_path):
    assert _sites(_DYNAMIC_INPUT, tmp_path) == []


def test_disagreeing_writes_unresolved(tmp_path):
    # Both 555 and 777 are registered, but the slot provably holds neither
    # single value -> no site (sound: we don't pick one arbitrarily).
    assert _sites(_DISAGREE, tmp_path) == []
