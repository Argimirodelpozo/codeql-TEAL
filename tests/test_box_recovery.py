"""Box storage-schema recovery (``recover_box_schema``).

A box op keyed by a CONSTANT is a single ``Box`` named by it; one keyed by
``concat(prefix, encode(k))`` is a ``BoxMap`` whose prefix names it and whose tail
is one encoded key. Key and value types are recovered by the shared ABI type
recovery, so a BoxMap over an address key / a struct key comes back typed.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import to_puya                # noqa: E402
from tealql.tealtools.lift.box_recovery import recover_box_schema  # noqa: E402
from tealql.tealtools.ssa import SSAProgram              # noqa: E402


def _schema(tmp_path, teal: str):
    (tmp_path / "p.teal").write_text(teal)
    main, subs = to_puya(SSAProgram(str(tmp_path)))
    return recover_box_schema(main, subs)


def test_static_box_named_by_const_key(tmp_path):
    teal = """#pragma version 10
byte "counter"
box_get
pop
pop
int 1
return
"""
    schema = _schema(tmp_path, teal)
    boxes = [s for s in schema if s.kind == "Box"]
    assert any(s.name == b"counter" for s in boxes)


def test_boxmap_uint64_key(tmp_path):
    """concat("m", itob(k)) => BoxMap prefix 'm' with a recovered key type."""
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
    schema = _schema(tmp_path, teal)
    maps = [s for s in schema if s.kind == "BoxMap"]
    assert maps and maps[0].name == b"m"
    assert maps[0].key_type is not None


def test_boxmap_address_key(tmp_path):
    """concat("u", txn Sender) => a per-account BoxMap; the key recovers as an
    account/address (Sender is a 32-byte address)."""
    teal = """#pragma version 10
byte "u"
txn Sender
concat
box_get
pop
pop
int 1
return
"""
    schema = _schema(tmp_path, teal)
    maps = [s for s in schema if s.kind == "BoxMap" and s.name == b"u"]
    assert maps and "account" in (maps[0].key_type or "")


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
    schema = _schema(tmp_path, teal)
    data = [s for s in schema if s.name == b"data"]
    assert data and data[0].value_type == "bytes[8]" and data[0].value_confident


def test_interprocedural_key_from_caller(tmp_path):
    """A box op in a HELPER whose key arrives as a subroutine parameter is named
    by resolving the parameter back to the caller's argument (the whole program
    is in the IR). main passes const 'counter' into a helper that box_gets it =>
    a Box named 'counter', NOT a dynamic group."""
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
    assert any(s.kind == "Box" and s.name == b"counter" for s in schema)
    assert not any(s.kind == "dynamic" for s in schema), (
        "the passed-in key must resolve, not fall to a dynamic group")


def test_no_box_storage_is_empty(tmp_path):
    teal = "#pragma version 10\nint 1\nreturn\n"
    assert _schema(tmp_path, teal) == []


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
