"""The normalized Finding schema + location extraction (B-core / C3)."""
from __future__ import annotations

from tealql.security.findings import Finding, SCHEMA_VERSION, normalize


class _MsgOnly:
    """A violation exposing only pretty() — satisfies NO structured-location
    contract, so it normalizes as whole-program (prose is never parsed)."""
    def pretty(self):
        return "Approval exit at prog.teal:11 is reachable without a RekeyTo check."


class _Structured:
    """A violation with an explicit .location string (IR taint-sink style)."""
    severity = "critical"
    sources = ("arg 0", "frame_dig 2")

    def __init__(self):
        self.location = "prog.teal:23"

    def pretty(self):
        return "itxn CloseRemainderTo <- attacker  via: arg0 -> ... -> sink"

    def to_dict(self):
        return {"field": "CloseRemainderTo", "severity": "critical",
                "sources": list(self.sources), "location": self.location,
                "message": self.pretty()}


def test_prose_is_not_parsed():
    f = normalize(_MsgOnly(), rule_id="rekey-to", rel_path="prog.teal",
                  severity="high", confidence="high")
    assert f.file == "prog.teal"
    assert f.line is None          # whole-program: prose is never parsed
    assert f.rule_id == "rekey-to"
    assert f.severity == "high"


def test_line_from_structured_location():
    f = normalize(_Structured(), rule_id="ir-tainted-fund-flow",
                  rel_path="prog.teal", severity="critical")
    assert f.line == 23
    # witness carries the taint-road sources.
    assert f.witness == {"sources": ["arg 0", "frame_dig 2"]}
    # extra to_dict keys (field) preserved under details, minus the modelled ones.
    assert f._extra.get("field") == "CloseRemainderTo"
    assert "location" not in f._extra and "sources" not in f._extra


def test_whole_program_finding_has_no_line():
    class _NoLoc:
        def pretty(self):
            return "Contract does not validate txn AssetCloseTo anywhere."
    f = normalize(_NoLoc(), rule_id="asset-close-to", rel_path="prog.teal")
    assert f.line is None
    assert f.file == "prog.teal"


def test_to_dict_is_stable_schema():
    f = Finding(rule_id="x", message="m", severity="high", confidence="low",
                file="p.teal", line=5, witness={"sources": ["a"]})
    d = f.to_dict()
    assert d == {
        "rule_id": "x", "severity": "high", "confidence": "low",
        "message": "m", "file": "p.teal", "line": 5,
        "witness": {"sources": ["a"]},
    }
    assert isinstance(SCHEMA_VERSION, int)
