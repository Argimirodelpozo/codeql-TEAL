"""Verdict logic of the historical-replay differential
(``tests/replay_harness/timetravel.py``). The replay itself needs the network and
a built ``ttreplay``; what decides FAITHFUL vs DIVERGES is pure and pinned here.
"""
from __future__ import annotations

from tests.replay_harness.timetravel import _entry_mutant, classify, first_diff, instruction_count


def _group(gi, *, match=True, error="", txns=None, boxes=None):
    return {"group": gi, "match_chain": match, "error": error, "box_writes": boxes or {},
            "txns": txns or [{"index": 0, "match_chain": match}]}


def test_classify_verdicts_and_which_divergences_poison_the_rest_of_the_block():
    orig = {"groups": [_group(0), _group(1), _group(2, match=False, error="eval drift")]}
    # Group 0 commits a different log; the chain's state after it is no longer
    # the lifted run's, so group 1 is not comparable. Group 2 is the ORACLE's miss.
    bad_log = {"index": 0, "match_chain": False,
               "apply_json": '{"dt": {"lg": ["a", "b"]}}', "chain_json": '{"dt": {"lg": ["a"]}}'}
    lifted = {"groups": [_group(0, match=False, txns=[bad_log]), _group(1), _group(2)]}
    rows = {r["group"]: r for r in classify(orig, lifted)}
    assert rows[0]["status"] == "DIVERGES" and rows[0]["detail"] == "txn 0: $.dt.lg: length 2 != 1"
    assert rows[1]["status"] == "AFTER_DIVERGENCE"
    assert rows[2]["status"] == "REPLAY_MISS" and rows[2]["detail"] == "eval drift"
    # A FAILED lifted group poisons too: it commits nothing, but the chain
    # committed it (the bug that read a budget failure's knock-on as DIVERGES).
    for error, status in (("transaction rejected by ApprovalProgram", "DIVERGES"),
                          ("pc=12 dynamic cost budget exceeded", "BUDGET")):
        failed = classify({"groups": [_group(0), _group(1)]},
                          {"groups": [_group(0, match=False, error=error), _group(1)]})
        assert [r["status"] for r in failed] == [status, "AFTER_DIVERGENCE"], error

    # Controls: an equal run is FAITHFUL only when the box writes agree too.
    assert [r["status"] for r in classify({"groups": [_group(0)]}, {"groups": [_group(0)]})] == ["FAITHFUL"]
    boxes = classify({"groups": [_group(0, boxes={"k": "AQ=="})]}, {"groups": [_group(0, boxes={"k": "Ag=="})]})
    assert boxes[0]["status"] == "DIVERGES" and boxes[0]["detail"].startswith("box writes: $.k")
    # An update to an older-AVM program is refused only because the lift raised
    # the version: an oracle artifact, not a divergence.
    downgrade = classify({"groups": [_group(0)]}, {"groups": [_group(
        0, match=False, error="approval program version downgrade: 9 < 10")]})
    assert downgrade[0]["status"] == "VERSION_ARTIFACT"
    assert first_diff({"a": [1, {"b": 2}]}, {"a": [1, {"b": 2}]}) is None


def test_entry_mutant_lands_on_the_first_executed_instruction():
    lifted = ("#pragma version 10\n#pragma typetrack false\n\n// f() -> void:\nmain:\n"
              "    intcblock 1 0\n    bytecblock 0x00\n    txn ApplicationID\n    bz create\n"
              "create:\n    intc_0\n    return\n")
    mutant = _entry_mutant(lifted).splitlines()
    i = mutant.index("pushbytes 0x7465616c716c")
    assert mutant[i + 1] == "log" and mutant[i + 2].strip() == "txn ApplicationID"
    assert mutant[i - 1].strip().startswith("bytecblock")      # constant blocks stay first
    # Labels, pragmas, comments and blanks are not instructions.
    assert instruction_count(lifted) == 6 and instruction_count(_entry_mutant(lifted)) == 8


def test_an_update_refused_as_a_downgrade_is_rerun_installing_the_lifted_program(monkeypatch):
    """The lift raises the AVM version, so an update installing the chain's
    older-version program is refused; the block is re-run with the installed
    programs replaced — on the lifted variants only, the deployed run untouched."""
    import base64

    import tests.replay_harness.timetravel as tt
    assert tt.program_version(base64.b64encode(bytes([9, 0x20])).decode()) == 9
    assert tt.program_version(base64.b64encode(bytes([0x81, 0x01])).decode()) == 129
    assert tt.at_version("#pragma version 9\nint 1\n", 11) == "#pragma version 11\nint 1\n"

    refused = {"error": "approval program version downgrade: 9 < 10"}
    reqs = []

    def fake_run(req):
        reqs.append(req)
        installs = any(v.get("installs") for v in req["variants"])
        return {"variants": [{"name": v["name"], "groups": [{} if installs or v["name"] == "orig" else refused]}
                             for v in req["variants"]]}
    monkeypatch.setattr(tt, "_run_replay", fake_run)
    monkeypatch.setattr(tt, "install_map", lambda *a: ({"aa": "Cg=="}, None))
    resp = tt.replay_block(1, 2, {"status": "OK", "lifted": "Cg=="}, None, lifts=object())
    assert resp["installs_lifted"] and len(reqs) == 2
    assert [v.get("installs") for v in reqs[1]["variants"]] == [None, {"aa": "Cg=="}]
    # No lift of the new program: the refusal stands, with the reason recorded.
    monkeypatch.setattr(tt, "install_map", lambda *a: ({}, "installed program x: LIFT_FAIL"))
    reqs.clear()
    resp = tt.replay_block(1, 2, {"status": "OK", "lifted": "Cg=="}, None, lifts=object())
    assert len(reqs) == 1 and resp["install_error"].endswith("LIFT_FAIL") and "installs_lifted" not in resp


def test_stream_window_grows_backwards_and_unlifted_programs_are_pending_not_judged():
    """``stream.chunks`` anchors at the end round, so a longer window only adds
    older chunks; a group whose target app ran a program with no lift is
    LIFT_PENDING, never a verdict on a program that was not swapped."""
    import base64

    from tests.replay_harness import stream
    short, long = stream.chunks(1000, 10 * stream.BLOCK_SECONDS / 86400, 4), \
        stream.chunks(1000, 20 * stream.BLOCK_SECONDS / 86400, 4)
    assert short == [(997, 1000), (993, 996), (991, 992)]
    assert long[:2] == short[:2] and long[-1] == (981, 984) and len(long) == 5

    class NoLifts:
        def status(self, prog):
            return None
    prog = base64.b64encode(b"\x0a\x81\x01\x43").decode()
    blk = {"round": 7, "targets": {"0": [11, 12]}, "unlifted": {"12": prog},
           "variants": [{"name": "orig", "groups": [_group(0)]}, {"name": "lifted", "groups": [_group(0)]}]}
    rows = {r["app"]: r for r in stream.block_rows(blk, NoLifts())}
    assert rows[11]["status"] == "FAITHFUL" and rows[11]["group"] == 0
    assert rows[12]["status"] == "LIFT_PENDING"
    # A divergence is judged per app on the same group.
    blk["unlifted"] = {}
    blk["variants"][1]["groups"] = [_group(0, match=False, error="rejected")]
    assert {r["status"] for r in stream.block_rows(blk, NoLifts())} == {"DIVERGES"}


def test_extra_budget_goes_only_to_the_groups_the_lift_ran_out_of_budget_in(monkeypatch):
    """Extra budget is itself an artifact for an OpUp caller (it reads
    `global OpcodeBudget` and skips its padding calls), so the extra-budget
    re-run grants it only to groups whose plain lifted run hit the budget —
    and runs beside the deployed run, whose budget trace it is equalized to."""
    import tests.replay_harness.timetravel as tt
    reqs = []

    def fake_run(req):
        reqs.append(req)
        out = []
        for v in req["variants"]:
            groups = [_group(g) for g in (2, 3)]
            if v["name"] == "lifted":
                groups[1] = _group(3, match=False, error="pc=9 dynamic cost budget exceeded")
            out.append({"name": v["name"], "groups": groups})
        return {"variants": out}
    monkeypatch.setattr(tt, "_run_replay", fake_run)
    resp = tt.replay_block(1, 2, {"status": "OK", "lifted": "Cg=="}, None)
    assert [v["name"] for v in reqs[0]["variants"]] == ["orig", "lifted"]
    assert [(v["name"], v.get("extra_groups")) for v in reqs[1]["variants"]] == [("orig", None), ("lifted_xb", [3])]
    assert [v["name"] for v in resp["variants"]] == ["orig", "lifted", "lifted_xb"]
    # No budget failure: no extra-budget run at all.
    reqs.clear()
    monkeypatch.setattr(tt, "_run_replay", lambda req: reqs.append(req) or {
        "variants": [{"name": v["name"], "groups": [_group(2)]} for v in req["variants"]]})
    tt.replay_block(1, 2, {"status": "OK", "lifted": "Cg=="}, None)
    assert len(reqs) == 1
