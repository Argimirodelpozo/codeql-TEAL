"""Storage-schema recovery (``recover_storage_schema``), mirroring Puya's
``ContractState`` model across GLOBAL / LOCAL / BOX storage.

A CONSTANT key is a single stored value (``is_map=False``); a computed key is a
map (``is_map=True``), prefixed if ``concat(const, encode(k))`` else unprefixed.
Prefix and key TYPE are orthogonal, so a composite ``concat(Sender, itob(id))`` is
an unprefixed map with a ``(address,uint64)`` tuple key.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import to_puya                # noqa: E402
from tealql.tealtools.lift.box_recovery import recover_storage_schema  # noqa: E402
from tealql.tealtools.ssa import SSAProgram              # noqa: E402


def _schema(tmp_path, teal: str):
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    return recover_storage_schema(main, subs)


def test_static_box_named_by_const_key(tmp_path):
    schema = _schema(tmp_path,
                     '#pragma version 10\nbyte "counter"\nbox_get\npop\npop\nint 1\nreturn\n')
    assert any(s.kind == "box" and not s.is_map and s.key_or_prefix == b"counter"
               for s in schema)


def test_boxmap_uint64_key(tmp_path):
    """concat("m", itob(k)) => a prefixed box map with a recovered key type."""
    teal = """#pragma version 10
byte "m"
txna ApplicationArgs 0
btoi
itob
concat
box_get
pop
pop
int 1
return
"""
    maps = [s for s in _schema(tmp_path, teal) if s.kind == "box" and s.is_map]
    assert maps and maps[0].key_or_prefix == b"m"
    assert maps[0].arc56_key_type == "uint64"


def test_composite_tuple_key_recovered_not_dynamic(tmp_path):
    """ACCEPTANCE: a per-holder balance box `box[Sender ++ itob(assetId)]` is an
    unprefixed map with a recovered (address, uint64) tuple key (width 40) — NOT
    dropped as an unclassified/dynamic key."""
    teal = """#pragma version 10
txn Sender
txna ApplicationArgs 0
btoi
itob
concat
dup
box_get
pop
pop
txna ApplicationArgs 1
box_put
int 1
return
"""
    schema = _schema(tmp_path, teal)
    comp = [s for s in schema if s.kind == "box" and s.is_map
            and s.key_or_prefix == b"" and s.arc56_key_type == "(address,uint64)"]
    assert comp, [s.render() for s in schema]


def test_global_map_recovered(tmp_path):
    """app_global_put(concat("bal", itob(id)), v) => a GLOBAL map keyed by uint64."""
    teal = """#pragma version 10
byte "bal"
txna ApplicationArgs 0
btoi
itob
concat
int 100
app_global_put
int 1
return
"""
    g = [s for s in _schema(tmp_path, teal) if s.kind == "global" and s.is_map]
    assert g and g[0].key_or_prefix == b"bal" and g[0].arc56_key_type == "uint64"


def test_local_map_recovered(tmp_path):
    """app_local_put(Sender, concat("pos", itob(id)), v) => a LOCAL map (the
    account is the implicit per-account axis; the map key is arg1)."""
    teal = """#pragma version 10
txn Sender
byte "pos"
txna ApplicationArgs 0
btoi
itob
concat
int 5
app_local_put
int 1
return
"""
    lo = [s for s in _schema(tmp_path, teal) if s.kind == "local" and s.is_map]
    assert lo and lo[0].key_or_prefix == b"pos" and lo[0].arc56_key_type == "uint64"


def test_global_single_key(tmp_path):
    """A constant global key is a single value, not a map."""
    teal = ('#pragma version 10\nbyte "admin"\napp_global_get\npop\nint 1\nreturn\n')
    g = [s for s in _schema(tmp_path, teal) if s.kind == "global"]
    assert g and not g[0].is_map and g[0].key_or_prefix == b"admin"


def test_box_value_type_recovered(tmp_path):
    """A fixed-length value written to a box recovers as its sized type."""
    teal = """#pragma version 10
byte "data"
txna ApplicationArgs 0
extract 0 8
box_put
int 1
return
"""
    data = [s for s in _schema(tmp_path, teal) if s.key_or_prefix == b"data"]
    assert data and data[0].arc56_value_type == "byte[8]" and data[0].value_confident


def test_interprocedural_key_from_caller(tmp_path):
    """A box op in a HELPER whose key arrives as a subroutine parameter is named
    by resolving the parameter back to the caller's argument."""
    teal = """#pragma version 10
byte "counter"
callsub helper
int 1
return

helper:
proto 1 0
frame_dig -1
box_get
pop
pop
retsub
"""
    schema = _schema(tmp_path, teal)
    assert any(s.kind == "box" and not s.is_map and s.key_or_prefix == b"counter"
               for s in schema)


def test_no_storage_is_empty(tmp_path):
    assert _schema(tmp_path, "#pragma version 10\nint 1\nreturn\n") == []


# --- box access-control detector (cross-user address-keyed BoxMap) ---

from tealql.tealtools.lift.box_recovery import box_access_control  # noqa: E402


def _acl(tmp_path, teal: str):
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    return box_access_control(main, subs)


def test_acl_flags_caller_address_write(tmp_path):
    """A per-account box keyed by a caller-supplied 32-byte address (not Sender),
    written -> flagged as a WRITE cross-user access lead."""
    teal = """#pragma version 10
byte "bal"
txna ApplicationArgs 0
extract 0 32
concat
txna ApplicationArgs 1
box_put
int 1
return
"""
    f = _acl(tmp_path, teal)
    assert len(f) == 1 and f[0].prefix == b"bal" and f[0].written


def test_acl_sender_key_is_safe(tmp_path):
    teal = """#pragma version 10
byte "bal"
txn Sender
concat
txna ApplicationArgs 0
box_put
int 1
return
"""
    assert _acl(tmp_path, teal) == []


def test_acl_sender_guarded_is_safe(tmp_path):
    """Caller address validated == txn Sender before use -> suppressed."""
    teal = """#pragma version 10
txna ApplicationArgs 0
extract 0 32
txn Sender
==
assert
byte "bal"
txna ApplicationArgs 0
extract 0 32
concat
box_get
pop
pop
int 1
return
"""
    assert _acl(tmp_path, teal) == []


def test_acl_numeric_id_map_not_flagged(tmp_path):
    """A caller-supplied uint64 id key (a legit listing/auction map) is NOT an
    address, so not a cross-user impersonation lead."""
    teal = """#pragma version 10
byte "lst"
txna ApplicationArgs 0
btoi
itob
concat
box_get
pop
pop
int 1
return
"""
    assert _acl(tmp_path, teal) == []
