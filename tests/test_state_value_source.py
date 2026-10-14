"""The ``StateValue`` taint source (2026-10-10, engine task A): a read of the
app's OWN state at a constant key is attacker input when some writer of that
slot stores an attacker-dependent value without authority (`lift/taint.py`
``_StateCandidates``). The verdict shapes are benchmark fixtures
(`tests/benchmark/tainted-fund-flow/*/state_value_*`); these pin the rule,
the severity step, the writer line in the message and the query inventory."""
from __future__ import annotations

from pathlib import Path

from tealql.cli.main import main
from tealql.security import DETECTORS
from tealql.tealtools.dataflow.taint_query import TaintQuery
from tealql.tealtools.lift import build_lifter
from tealql.tealtools.lift.fund_flow import state_value_severity, tainted_fund_flows
from tealql.tealtools.lift.taint import state_value_sources, state_value_writers
from tealql.tealtools.ssa import SSAProgram

_BENCH = Path(__file__).resolve().parent / "benchmark" / "tainted-fund-flow"
_VULN = _BENCH / "vuln" / "state_value_unguarded_writer.teal"

# Dispatcher: arg0 == "set" -> SETTER; else pay app_global_get "payee".
_PAY_STATE = ("#pragma version 10\ntxna ApplicationArgs 0\nbyte \"set\"\n==\nbnz set\n"
              "itxn_begin\nint pay\nitxn_field TypeEnum\nbyte \"payee\"\napp_global_get\n"
              "itxn_field Receiver\nint 1000\nitxn_field Amount\nitxn_submit\nint 1\n"
              "return\nset:\n")


def _lifter(path: Path):
    prog = SSAProgram(str(path))
    prog.propagate_constants()
    return build_lifter(prog)


def _seeded(teal: str, tmp_path: Path) -> dict:
    p = tmp_path / "p.teal"
    p.write_text(teal)
    return dict(state_value_sources(_lifter(p)))


def test_seeding_rule(tmp_path):
    """Seed iff an untrusted writer stores an attacker-dependent value into
    the read's constant slot (or may alias it); controls fold in every way
    the rule must NOT fire."""
    put = "byte \"payee\"\n{}\napp_global_put\nint 1\nreturn\n"
    # Unguarded writer of caller input -> the read at L10 is a source.
    assert _seeded(_PAY_STATE + put.format("txna Accounts 1"), tmp_path) == {
        ("p.teal", 10): "StateValue:payee"}
    # A possibly-aliasing DYNAMIC-key global writer seeds too.
    dyn = "txna ApplicationArgs 1\ntxna ApplicationArgs 2\napp_global_put\nint 1\nreturn\n"
    assert _seeded(_PAY_STATE + dyn, tmp_path) == {("p.teal", 10): "StateValue:payee"}
    # ... but not one whose key is pinned to a constant set ("w1"/"w2"):
    # the attacker cannot steer it onto "payee".
    pinned = ('txna ApplicationArgs 1\nbyte "w1"\n==\ntxna ApplicationArgs 1\n'
              'byte "w2"\n==\n||\nassert\n' + dyn)
    assert _seeded(_PAY_STATE + pinned, tmp_path) == {}
    # Creator-guarded writer: authority-preserving -> no seed.
    guarded = "txn Sender\nglobal CreatorAddress\n==\nassert\n" + put.format("txna Accounts 1")
    assert _seeded(_PAY_STATE + guarded, tmp_path) == {}
    # Unguarded writer of a CLEAN value (constant, sender-free counter):
    # timing, not content -> no seed (the tightening).
    assert _seeded(_PAY_STATE + put.format("global ZeroAddress"), tmp_path) == {}
    # A writer of a DIFFERENT constant key does not alias "payee".
    other = "byte \"note\"\ntxna ApplicationArgs 1\napp_global_put\nint 1\nreturn\n"
    assert _seeded(_PAY_STATE + other, tmp_path) == {}
    # Chained: "b" written from the seeded "a" read is a source in turn.
    chain = ("#pragma version 10\ntxna ApplicationArgs 0\nbtoi\nswitch a b\n"
             "itxn_begin\nint pay\nitxn_field TypeEnum\nbyte \"b\"\napp_global_get\n"
             "itxn_field Receiver\nitxn_submit\nint 1\nreturn\n"
             "a:\nbyte \"a\"\ntxna Accounts 1\napp_global_put\nint 1\nreturn\n"
             "b:\nbyte \"b\"\nbyte \"a\"\napp_global_get\napp_global_put\nint 1\nreturn\n")
    assert _seeded(chain, tmp_path).get(("p.teal", 9)) == "StateValue:b"
    # A DYNAMIC box key read is never seeded: its slot cannot be named, so the
    # writers that matter cannot be either.
    box = ("#pragma version 10\ntxna ApplicationArgs 0\ntxna ApplicationArgs 1\nbox_put\n"
           "itxn_begin\nint pay\nitxn_field TypeEnum\ntxn Sender\nbox_get\nassert\n"
           "itxn_field Receiver\nitxn_submit\nint 1\nreturn\n")
    assert _seeded(box, tmp_path) == {}
    # ... while a CONSTANT box key with an attacker-keyed dynamic writer is.
    cbox = box.replace("txn Sender\nbox_get", "byte \"payee\"\nbox_get")
    assert _seeded(cbox, tmp_path) == {("p.teal", 9): "StateValue:payee"}


def test_state_value_sink_is_one_severity_step_down(tmp_path):
    """Set-then-drain needs a prior call, so a sink fed ONLY by StateValue
    sources reports one step below its direct-input twin; any direct input
    keeps the full severity."""
    (finding,) = [f for f in tainted_fund_flows(_lifter(_VULN)) if not f.guarded]
    assert (finding.field, finding.sources) == ("Receiver", frozenset({"StateValue:payee"}))
    direct = tmp_path / "direct.teal"
    direct.write_text(_VULN.read_text().replace(
        'byte "payee"\napp_global_get\nitxn_field Receiver',
        'txna Accounts 1\nitxn_field Receiver'))
    (twin,) = [f for f in tainted_fund_flows(_lifter(direct)) if not f.guarded]
    assert (twin.severity, finding.severity) == ("HIGH", "MEDIUM")
    assert state_value_severity("CRITICAL", {"StateValue:a"}) == "HIGH"
    assert state_value_severity("LOW", {"StateValue:a"}) == "LOW"
    assert state_value_severity("HIGH", {"StateValue:a", "ApplicationArgs"}) == "HIGH"


def test_message_names_the_untrusted_writer_line():
    assert state_value_writers(_lifter(_VULN)) == {"StateValue:payee": (23,)}
    prog = SSAProgram(str(_VULN))
    prog.propagate_constants()
    (violation,) = DETECTORS["tainted-fund-flow"](prog).detect()
    assert violation.severity == "MEDIUM"
    assert "<- StateValue:payee (writer unguarded at L23)" in violation.message


def test_taint_query_sources_lists_the_state_read(capsys):
    lines = [n.line for n in TaintQuery(SSAProgram(str(_VULN))).all_sources()]
    assert 13 in lines                         # the app_global_get "payee"
    safe = _BENCH / "safe" / "state_value_creator_guarded_writer.teal"
    assert 13 not in [n.line for n in TaintQuery(SSAProgram(str(safe))).all_sources()]
    assert main(["taint-query", str(_VULN), "--sources"]) == 0
    assert "state_value_unguarded_writer.teal:13" in capsys.readouterr().out
