"""ARC-56 app-spec ingestion (``tealtools.metadata.arc56``).

The spec is the authoritative HIGH-LEVEL source: methods with struct-resolved
arg/return types (+ names), and global/local/box state schema. Selectors are
computed FORWARD from the resolved signature (never reversed), so an ARC-56 method
table is a drop-in, richer replacement for the source-text one. VERY OPTIONAL: a
partial/absent/bad spec degrades cleanly.
"""
from __future__ import annotations

import json

from tealql.tealtools.metadata import arc56
from tealql.tealtools.metadata.abi import method_selector


_SPEC = {
    "name": "Vault",
    "structs": {
        "UserRecord": [
            {"name": "balance", "type": "uint64"},
            {"name": "owner", "type": "address"},
        ],
    },
    "methods": [
        {"name": "deposit",
         "args": [{"type": "pay", "name": "payment"},
                  {"type": "uint64", "name": "amount"}],
         "returns": {"type": "void"}},
        {"name": "get_record",
         "args": [{"type": "address", "name": "who"}],
         "returns": {"type": "UserRecord", "struct": "UserRecord"}},
        {"name": "set_record",
         "args": [{"type": "UserRecord", "name": "rec", "struct": "UserRecord"}],
         "returns": {"type": "void"}},
    ],
    "state": {
        "keys": {
            "global": {"total": {"keyType": "AVMString", "valueType": "uint64",
                                 "key": "dG90YWw="}},
            "local": {"rec": {"keyType": "AVMString", "valueType": "UserRecord",
                              "key": "cmVj"}},
        },
        "maps": {
            "box": {"records": {"keyType": "address", "valueType": "UserRecord",
                                "prefix": "Yg=="}},
        },
    },
}


def _spec():
    return arc56.from_dict(_SPEC)


class TestStructResolution:
    def test_struct_resolves_to_tuple(self):
        assert _spec().structs["UserRecord"] == "(uint64,address)"

    def test_struct_return_type_in_signature(self):
        m = {x.name: x for x in _spec().methods}["get_record"]
        assert m.signature == "get_record(address)(uint64,address)"
        assert m.return_type == "(uint64,address)"

    def test_struct_arg_type_in_signature(self):
        m = {x.name: x for x in _spec().methods}["set_record"]
        assert m.arg_types == ("(uint64,address)",)
        assert m.signature == "set_record((uint64,address))void"

    def test_self_referential_struct_is_cycle_safe(self):
        s = arc56.from_dict({"structs": {"Node": [{"name": "next", "type": "Node"}]},
                             "methods": [{"name": "f", "args": [{"type": "Node"}],
                                          "returns": {"type": "void"}}]})
        # resolves to `(Node)` rather than recursing forever
        assert s.structs["Node"] == "(Node)"


class TestMethods:
    def test_selector_is_forward_hash(self):
        m = {x.name: x for x in _spec().methods}["get_record"]
        assert m.selector == method_selector("get_record(address)(uint64,address)")

    def test_arg_names_carried(self):
        m = {x.name: x for x in _spec().methods}["deposit"]
        assert m.arg_names == ("payment", "amount")
        assert m.arg_types == ("pay", "uint64")

    def test_app_arg_byte_length_uses_resolved_struct(self):
        m = {x.name: x for x in _spec().methods}["set_record"]
        assert m.app_arg_byte_length(1) == 40           # (uint64,address) = 8 + 32

    def test_transaction_arg_shifts_index(self):
        m = {x.name: x for x in _spec().methods}["deposit"]
        # `pay` rides as a group txn -> ApplicationArgs[1] is the uint64
        assert m.app_arg_types == ("uint64",)
        assert m.app_arg_byte_length(1) == 8

    def test_method_table_keyed_by_selector(self):
        tbl = _spec().method_table()
        assert set(tbl) == {m.selector_hex for m in _spec().methods}
        sel = "0x" + method_selector("get_record(address)(uint64,address)").hex()
        assert tbl[sel].name == "get_record"


class TestState:
    def test_global_key(self):
        g = {e.name: e for e in _spec().global_state}
        assert g["total"].value_type == "uint64"
        assert g["total"].key_type == "AVMString" and not g["total"].is_map

    def test_local_key_resolves_struct_value(self):
        loc = {e.name: e for e in _spec().local_state}
        assert loc["rec"].value_type == "(uint64,address)"

    def test_box_map_with_prefix(self):
        b = {e.name: e for e in _spec().box_state}
        assert b["records"].is_map and b["records"].key_type == "address"
        assert b["records"].value_type == "(uint64,address)"
        assert b["records"].prefix_b64 == "Yg=="


class TestTolerance:
    def test_empty_spec(self):
        s = arc56.from_dict({})
        assert s.methods == () and s.global_state == () and s.name == ""

    def test_malformed_methods_dropped(self):
        s = arc56.from_dict({"methods": [{"no": "name"}, "notadict",
                                         {"name": "ok", "args": [],
                                          "returns": {"type": "void"}}]})
        assert [m.name for m in s.methods] == ["ok"]

    def test_load_optional_none_on_missing(self, tmp_path):
        assert arc56.load_optional(tmp_path / "nope.json") is None
        assert arc56.load_optional("") is None

    def test_load_optional_none_on_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        assert arc56.load_optional(p) is None

    def test_load_from_file(self, tmp_path):
        p = tmp_path / "spec.json"
        p.write_text(json.dumps(_SPEC))
        assert arc56.load(p).name == "Vault"


class TestStorageAnnotation:
    """`box_recovery.annotate_with_arc56` matches recovered storage entries to the
    spec's state by kind + key/prefix bytes and fills in name + authoritative type.
    Imported here (not puya) — the annotate path only needs base64 + the spec."""

    def _entries(self):
        from tealql.tealtools.lift.box_recovery import StorageEntry
        return [
            StorageEntry(kind="global", is_map=False, key_or_prefix=b"total",
                         arc56_value_type="bytes", value_confident=False),
            StorageEntry(kind="box", is_map=True, key_or_prefix=b"r",
                         arc56_key_type="address", arc56_value_type=None),
            StorageEntry(kind="global", is_map=False, key_or_prefix=b"nomatch"),
        ]

    def _spec(self):
        import base64
        b = lambda s: base64.b64encode(s).decode()
        return arc56.from_dict({"state": {
            "keys": {"global": {"total": {"keyType": "AVMString",
                                          "valueType": "uint64", "key": b(b"total")}}},
            "maps": {"box": {"records": {"keyType": "address",
                                         "valueType": "(uint64,address)",
                                         "prefix": b(b"r")}}},
        }})

    def test_matched_entries_get_name_and_authoritative_type(self):
        from tealql.tealtools.lift.box_recovery import annotate_with_arc56
        out = {(e.kind, e.key_or_prefix): e
               for e in annotate_with_arc56(self._entries(), self._spec())}
        total = out[("global", b"total")]
        assert total.name == "total" and total.arc56_value_type == "uint64"
        assert total.value_confident                  # spec type is authoritative
        rec = out[("box", b"r")]
        assert rec.name == "records" and rec.arc56_value_type == "(uint64,address)"

    def test_unmatched_entry_untouched(self):
        from tealql.tealtools.lift.box_recovery import annotate_with_arc56
        out = {e.key_or_prefix: e
               for e in annotate_with_arc56(self._entries(), self._spec())}
        assert out[b"nomatch"].name is None

    def test_none_spec_is_noop(self):
        from tealql.tealtools.lift.box_recovery import annotate_with_arc56
        ents = self._entries()
        assert annotate_with_arc56(ents, None) is ents
        assert all(e.name is None for e in ents)
