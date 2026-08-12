"""A scan that could not do its job must never read as a clean bill.

"No findings" has two meanings — analyzed and clean, or never analyzed — and
until these gates existed the output could not tell them apart. Every policy
that requires lifted evidence now has exactly one implementation; if that
representation cannot be built, the policy does not silently switch semantics.

Every test here forces the failure on a contract that otherwise lifts fine, so
the ONLY difference from the passing baseline is the degradation itself.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tealql.security.scan import (
    ScanNotification, ScanResults, render_json, render_sarif, render_text, scan,
)
from tealql.tealtools.diagnostics.errors import TealQLError

TESTS = Path(__file__).resolve().parent

#: Canonical lifted policies: on lift failure they do not run at all.
LIFTED_POLICIES = {
    "arbitrary-inner-appcall", "arbitrary-inner-asset",
    "tainted-asset-admin", "tainted-state-write", "tainted-log",
    "tainted-freeze", "tainted-fee",
    "tainted-fund-flow", "partial-tainted-fund-flow",
}


@pytest.fixture
def contract(tmp_path) -> Path:
    """A real mainnet contract, copied into a scan root of its own."""
    probes = sorted((TESTS / "mainnet-random-probes").glob("*.teal"))
    if not probes:
        pytest.skip("mainnet probe corpus not present")
    shutil.copy(probes[5], tmp_path / "prog.teal")
    return tmp_path


@pytest.fixture
def lift_fails(monkeypatch):
    """Force the canonical representation builder to fail."""
    import tealql.tealtools.lift as lift_layer
    monkeypatch.setattr(lift_layer, "build_lifter", lambda prog, file=None: None)


# ---------------------------------------------------------------------------
# Non-vacuity: the baseline must be clean, or every assertion below is hollow
# ---------------------------------------------------------------------------


def test_working_lift_reports_no_degradation(contract):
    res = scan(contract)
    assert not res.notifications, (
        "a contract that lifts fine must produce no degradation notices")
    assert json.loads(render_sarif(res))["runs"][0]["invocations"][0][
        "executionSuccessful"] is True


# ---------------------------------------------------------------------------
# The detectors self-report
# ---------------------------------------------------------------------------


def test_every_lifted_policy_reports_when_the_lift_fails(contract, lift_fails):
    res = scan(contract)
    reported = {n.detector for n in res.notifications
                if n.kind == "detector-degraded"}
    assert LIFTED_POLICIES <= reported, f"silent: {LIFTED_POLICIES - reported}"


def test_lifted_policies_say_they_did_not_run(contract, lift_fails):
    by_det = {n.detector: n.message for n in scan(contract).notifications}
    for name in LIFTED_POLICIES:
        assert "did NOT run" in by_det[name], by_det[name]


# ---------------------------------------------------------------------------
# ...and every renderer carries it
# ---------------------------------------------------------------------------


def test_text_never_prints_a_bare_clean_bill(contract, lift_fails):
    out = render_text(scan(contract))
    assert "[DEGRADED]" in out
    assert "results are INCOMPLETE" in out


def test_text_degradation_survives_an_empty_finding_list():
    """The dangerous case: no findings AND a failed analysis. "(no findings)"
    alone is a clean bill and must not be the whole message."""
    res = ScanResults([], [ScanNotification(
        kind="ssa-failed", message="boom", rel_path="a.teal")])
    out = render_text(res)
    assert out != "(no findings)"
    assert "[DEGRADED]" in out and "INCOMPLETE" in out


def test_json_always_carries_the_key(contract, lift_fails):
    doc = json.loads(render_json(scan(contract)))
    assert doc["notifications"], "degradation missing from JSON"
    assert {"kind", "message", "file", "detector"} == set(doc["notifications"][0])
    # present even when empty, so a consumer never has to guess whether this
    # version emits the key at all
    assert "notifications" in json.loads(render_json(ScanResults([], [])))


def test_sarif_uses_invocations_not_results(contract, lift_fails):
    """SARIF's home for this is invocations[].toolExecutionNotifications.

    Emitting them as results would inflate the dashboard's finding count and
    make a broken analysis look like a vulnerable contract."""
    run = json.loads(render_sarif(scan(contract)))["runs"][0]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    notes = inv["toolExecutionNotifications"]
    assert len(notes) >= len(LIFTED_POLICIES)
    assert all(n["descriptor"]["id"] == "detector-degraded" for n in notes)
    ids = {r["ruleId"] for r in run["results"]}
    assert not any("degraded" in r for r in ids), "degradation leaked into results"


# ---------------------------------------------------------------------------
# strict mode
# ---------------------------------------------------------------------------


def test_strict_refuses_a_degraded_scan(contract, lift_fails):
    """``strict=True`` already refuses unparsed input and failed SSA; a
    detector that could not run belongs in the same bucket, so CI can insist
    the whole analysis actually happened."""
    with pytest.raises(TealQLError, match="degraded"):
        scan(contract, strict=True)


# ---------------------------------------------------------------------------
# Suppressions must not delete the notice
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# The `all` / `audit` path, which does not go through scan() at all
# ---------------------------------------------------------------------------


def _prog(contract: Path):
    from tealql.tealtools.ssa import SSAProgram
    return SSAProgram(str(contract / "prog.teal"))


def test_run_all_dict_reports_degradation(contract, lift_fails):
    """``tealql all --json`` and ``tealql audit`` use run.py, not scan()."""
    from tealql.security.run import run_all_dict

    assert run_all_dict(_prog(contract))["notifications"], (
        "the all/audit path silently dropped the degradation")


def test_run_all_text_reports_degradation_without_inflating_the_count(
        contract, monkeypatch):
    """The count drives the exit code, so a detector that could NOT run must
    not add to it — that would read as a vulnerability rather than a gap.

    Measures BOTH sides rather than taking the fixture: the claim is about the
    count staying equal, which needs the undegraded number to compare against."""
    import tealql.tealtools.lift as lift_layer
    from tealql.security.run import run_all_findings

    clean_text, clean_n = run_all_findings(_prog(contract))
    assert "[DEGRADED]" not in clean_text

    monkeypatch.setattr(lift_layer, "build_lifter", lambda prog, file=None: None)
    degraded_text, degraded_n = run_all_findings(_prog(contract))

    assert "[DEGRADED]" in degraded_text and "INCOMPLETE" in degraded_text
    assert degraded_n == clean_n, (
        f"degradation changed the finding count {clean_n} -> {degraded_n}, "
        "which would move the CLI exit code")


def test_run_all_notes_do_not_accumulate_across_calls(contract, lift_fails):
    """The adapters are rebuilt per call; binding them to a module-level list
    would grow the notice list on every invocation of a long-lived process."""
    from tealql.security.run import run_all_dict

    first = len(run_all_dict(_prog(contract))["notifications"])
    second = len(run_all_dict(_prog(contract))["notifications"])
    assert first == second > 0


def test_suppressions_do_not_swallow_degradation(contract, lift_fails, capsys):
    """`partition` returns plain lists, so the CLI has to re-attach the
    notifications. A baseline file quietly deleting "this detector never ran"
    would defeat the entire mechanism."""
    from tealql.cli.main import main

    rc = main(["detections-scan", str(contract)])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "[DEGRADED]" in out, "CLI dropped the degradation notices"
