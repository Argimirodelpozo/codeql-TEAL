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


def test_no_box_storage_is_empty(tmp_path):
    teal = "#pragma version 10\nint 1\nreturn\n"
    assert _schema(tmp_path, teal) == []
