"""Open taint-reachability query layer (`tealtools.dataflow.taint_query`) and the
source map (`tealtools.source_map`)."""
from __future__ import annotations

from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.dataflow.taint_query import (
    TaintQuery, classify_sink, is_source)
from tealql.tealtools.source_map import build_source_map, reverse_source_map


# tainted amount, tainted receiver, tainted state-write value/key, plus a
# non-sink read — a compact attack surface.
_TEAL = """#pragma version 8
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
btoi
itxn_field Amount
txna ApplicationArgs 1
itxn_field Receiver
itxn_submit
txna ApplicationArgs 2
txna ApplicationArgs 3
app_global_put
int 1
return
"""


def _q(tmp_path):
    (tmp_path / "p.teal").write_text(_TEAL)
    return TaintQuery(SSAProgram(str(tmp_path / "p.teal")))


class TestTaxonomy:
    def test_itxn_field_sinks(self):
        assert classify_sink("itxn_field", "CloseRemainderTo") == \
            ("inner-close-remainder", "critical")
        assert classify_sink("itxn_field", "Receiver")[1] == "high"
        assert classify_sink("itxn_field", "Amount")[1] == "medium"

    def test_opcode_sinks(self):
        assert classify_sink("app_global_put", "")[0] == "global-state-write"
        assert classify_sink("box_put", "")[0] == "box-write"
        assert classify_sink("log", "")[0] == "log-emit"

    def test_non_sinks_are_none(self):
        assert classify_sink("btoi", "") is None
        assert classify_sink("itxn_field", "TypeEnum") is None    # not dangerous
        assert classify_sink(None, None) is None

    def test_sources(self):
        assert is_source("txna", "ApplicationArgs 0")
        assert is_source("arg", "0")
        assert not is_source("txn", "Sender")
        assert not is_source("txna", "Accounts 0")


class TestQuery:
    def test_all_sinks(self, tmp_path):
        cats = {h.category for h in _q(tmp_path).all_sinks()}
        assert {"inner-payment-amount", "inner-payment-receiver",
                "global-state-write"} <= cats

    def test_sinks_from_source_is_scoped(self, tmp_path):
        # ApplicationArgs 1 flows only to the Receiver sink, not the Amount one.
        hits = _q(tmp_path).sinks_from(op="txna", immediates="ApplicationArgs 1")
        cats = {h.category for h in hits}
        assert "inner-payment-receiver" in cats
        assert "inner-payment-amount" not in cats

    def test_sources_of_sink(self, tmp_path):
        # the Receiver sink (line 9) is reached by ApplicationArgs 1 (line 8).
        srcs = _q(tmp_path).sources_of(line=9)
        assert any(n.line == 8 for n in srcs)

    def test_whole_attack_surface(self, tmp_path):
        hits = _q(tmp_path).tainted_sinks()
        assert len(hits) >= 3
        assert hits[0].severity in ("critical", "high")   # sorted most-severe first

    def test_severity_ordering(self, tmp_path):
        sevs = [h.severity for h in _q(tmp_path).all_sinks()]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert sevs == sorted(sevs, key=lambda s: order[s])


class TestSourceMap:
    def test_build_and_reverse(self):
        teal = ("#pragma version 8\n"
                "// c.py:10\nint 1\nint 2\n+\n"
                "// c.py:11\nint 3\npop\nreturn\n")
        fwd = build_source_map(teal)
        assert fwd[3] == ("c.py", 10)      # `int 1` under c.py:10
        assert fwd[4] == ("c.py", 10)      # carries down until next comment
        assert fwd[7] == ("c.py", 11)      # `int 3` under c.py:11
        rev = reverse_source_map(fwd)
        # lines 2 (the comment itself) .. 5, before the next ref
        assert rev[("c.py", 10)] == [2, 3, 4, 5]

    def test_empty_on_raw_bytecode(self):
        assert build_source_map("#pragma version 8\nint 1\nreturn\n") == {}


def test_high_level_query_end_to_end():
    # a real Puya contract with `// contract.py:N` comments: a high-level line
    # resolves to the TEAL it compiled to, and sinks report their source line.
    import glob, os
    src = None
    for d in sorted(glob.glob("tests/experimental_IR_lift/puya/*/src")):
        tl = glob.glob(d + "/*.teal")
        if tl and "itxn_field" in open(tl[0]).read() and ".py:" in open(tl[0]).read():
            src = (d, os.path.basename(tl[0]))
            break
    if src is None:
        import pytest
        pytest.skip("no puya fixture with itxn sinks + source comments")
    q = TaintQuery(SSAProgram(src[0]), file=src[1])
    sinks = q.all_sinks()
    assert sinks and any(h.source and ".py:" in h.source for h in sinks)


_GUARDED = """#pragma version 8
txn Sender
global CreatorAddress
==
assert
itxn_begin
int pay
itxn_field TypeEnum
txna ApplicationArgs 0
btoi
itxn_field Amount
txna ApplicationArgs 1
itxn_field Receiver
itxn_submit
int 1
return
"""


class TestVerify:
    """`verify_sinks` chains reachability -> guard-aware detector verdict."""

    def test_unguarded_is_confirmed(self, tmp_path):
        from tealql.security.sink_verdict import verify_sinks
        (tmp_path / "p.teal").write_text(_TEAL)
        vs = verify_sinks(SSAProgram(str(tmp_path / "p.teal")))
        fund = [v for v in vs if v.sink.category.startswith("inner-payment")]
        assert fund and all(v.verdict == "CONFIRMED" for v in fund)
        assert all("ir-tainted-fund-flow" in v.confirmed_by for v in fund)

    def test_sender_gate_is_guarded(self, tmp_path):
        # reachable but the fund-flow detector's sender-auth reasoning clears it.
        from tealql.security.sink_verdict import verify_sinks
        (tmp_path / "p.teal").write_text(_GUARDED)
        vs = verify_sinks(SSAProgram(str(tmp_path / "p.teal")))
        fund = [v for v in vs if v.sink.category.startswith("inner-payment")]
        assert fund and all(v.verdict == "GUARDED" for v in fund)
        assert all(not v.confirmed_by and v.covered_by for v in fund)

    def test_confirmed_ranks_before_guarded(self, tmp_path):
        from tealql.security.sink_verdict import verify_sinks
        (tmp_path / "p.teal").write_text(_TEAL)
        vs = verify_sinks(SSAProgram(str(tmp_path / "p.teal")))
        ranks = ["CONFIRMED", "GUARDED", "UNVERIFIED"]
        idx = [ranks.index(v.verdict) for v in vs]
        assert idx == sorted(idx)
