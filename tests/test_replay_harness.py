"""Verdict logic of the historical-replay differential
(``tests/replay_harness/timetravel.py``). The replay itself needs the network and
a built ``ttreplay``; what decides FAITHFUL vs DIVERGES is pure and pinned here.
"""
from __future__ import annotations

import pytest

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


def test_a_divergence_naming_its_app_is_not_charged_to_the_other_targets_of_the_group():
    from tests.replay_harness.stream import attribute
    err = "logic eval error: - would result negative. Details: app=7, pc=421"
    rows = [{"round": 1, "group": 0, "app": a, "status": "DIVERGES", "detail": err} for a in (5, 7)]
    rows.append({"round": 1, "group": 1, "app": 5, "status": "DIVERGES", "detail": err})   # 7 not in group 1
    rows.append({"round": 1, "group": 2, "app": 5, "status": "DIVERGES", "detail": "txn 0: $.dt: x"})
    got = [(r["group"], r["app"], r["status"]) for r in attribute(rows)]
    assert got == [(0, 5, "CO_DIVERGED"), (0, 7, "DIVERGES"), (1, 5, "DIVERGES"), (2, 5, "DIVERGES")]


def test_a_divergence_the_deployed_program_reproduces_when_made_as_costly_is_a_cost_artifact(monkeypatch):
    """App 3715247030 (an OpUp router) sizes its budget calls from `global
    OpcodeBudget` and pays their fees from the ALGO balance its final
    `balance >= before + min_out` assert reads: the lift's +17/+44 opcodes moved
    an OpUp call / failed that assert. The control pads the DEPLOYED program with
    at most that many no-ops; only the SAME divergence signature counts."""
    import tests.replay_harness.timetravel as tt
    from tests.replay_harness.stream import apply_controls
    teal = ("#pragma version 10\nint 0\nstore 1\nloop:\nload 1\nint 1\n+\nstore 1\nload 1\nint 3\n<\n"
            "bnz loop\ncallsub sub\nint 1\nreturn\nsub:\nproto 0 0\nretsub")
    assert tt.loop_heads(teal) == ["loop"]
    assert tt.loop_heads("sub:\nretsub\ncallsub sub\nloop:\nb loop") == ["loop"]   # a call back is no loop
    assert tt.pad_program(teal, None, 4).split("\n")[1:5] == ["pushint 1", "pop"] * 2
    assert tt.pad_program(teal, "sub", 2).split("\n")[-5:-1] == ["proto 0 0", "pushint 1", "pop", "retsub"]
    want = "transaction T: logic eval error: assert failed pc=50. Details: app=9, pc=50"

    def fake_replay(app, rnd, lift, cache, lifts=None):
        prog = lift["lifted"]
        if prog == "REAL":
            lifted = _group(0, match=False, error=want)
            orig, lifted = {**_group(0), "app_cost": {"9": 100}}, {**lifted, "app_cost": {"9": 100 + extra}}
        else:
            lines = prog.split("\n")
            at_loop = lines[lines.index("loop:") + 1] == "pushint 1"
            pad = prog.count("pushint 1") * 2
            orig = _group(0)
            if at_loop and pad >= 6:
                lifted = _group(0, match=False, error=want.replace("pc=50", "pc=68"))
            elif not at_loop:            # diverges, but differently: not the lift's divergence
                lifted = _group(0, match=False, error="assert failed pc=3. Details: app=9, pc=3")
            else:
                lifted = _group(0)
        return {"variants": [{"name": "orig", "groups": [orig]}, {"name": "lifted", "groups": [lifted]}]}
    monkeypatch.setattr(tt, "programs_at", lambda app, rnd: ("b64", "clear"))
    monkeypatch.setattr(tt, "lift_program", lambda prog, cache: {"status": "OK", "lifted": "REAL"})
    monkeypatch.setattr(tt, "disassemble", lambda prog: teal)
    monkeypatch.setattr(tt, "assemble", lambda src: (src, None))
    monkeypatch.setattr(tt, "replay_block", fake_replay)
    extra = 6
    got = tt.cost_control(9, 100, 0, want, tt.Path("/nonexistent"))
    assert got == {"reproduced": True, "padded": "deployed", "site": "loop", "pad": 6, "extra": 6, "tried": 4,
                   "v": tt.CONTROL_VERSION}
    extra = 1                      # the lift is not costlier here: nothing to control for
    assert tt.cost_control(9, 100, 0, want, tt.Path("/nonexistent")) == {
        "reproduced": False, "why": "lift costs +1 here", "extra": 1, "v": tt.CONTROL_VERSION}

    rows = [{"round": 1, "group": 0, "app": a, "status": "DIVERGES", "detail": "txn 0: $.dt.itx[7]"} for a in (5, 9)]
    rows.append({"round": 2, "group": 0, "app": 5, "status": "DIVERGES", "detail": "x"})
    controls = {(1, 0, 9): {**got}, (2, 0, 5): {"reproduced": False}}
    out = [(r["round"], r["app"], r["status"], r.get("culprit")) for r in apply_controls(rows, controls)]
    assert out == [(1, 5, "CO_DIVERGED", 9), (1, 9, "COST_ARTIFACT", None), (2, 5, "DIVERGES", None)]


def test_a_cheaper_lift_that_skips_an_opup_call_is_padded_before_the_budget_read(monkeypatch, tmp_path):
    """Router 2714516089 tops its budget up (`global OpcodeBudget; pushint 500; <;
    bz`) after an inner call; its lift, 182 opcodes cheaper, stayed above 500 and
    sent 2 inner txns where the chain has 3. The control only padded a COSTLIER
    lift's deployed side, and at entry an earlier ensure-budget loop refills the
    padding. Now the cheaper side is padded, also right before each budget read,
    and a padded lift must replay faithfully; unexplained v1 controls rerun (v2 ones do not)."""
    import json
    import tests.replay_harness.timetravel as tt
    from tests.replay_harness.stream import Run, run_controls
    lifted = ("#pragma version 10\nensure:\nglobal OpcodeBudget\npushint 300\n<\nbnz ensure\n"
              "itxn_submit\nglobal OpcodeBudget // after the call\npushint 500\n<\nbz done\nitxn_submit\n"
              "done:\nint 1\nreturn")
    assert tt.budget_reads(lifted) == [tt._BUDGET_SITE + "0", tt._BUDGET_SITE + "1"]
    assert tt.pad_program(lifted, tt._BUDGET_SITE + "1", 2).split("\n")[7:10] == [
        "pushint 1", "pop", "global OpcodeBudget // after the call"]
    want = "txn 3: $.dt.itx: length 2 != 3"

    def fake_replay(app, rnd, lift, cache, lifts=None):
        prog, orig = lift["lifted"], {**_group(0), "app_cost": {"9": 300}}
        if prog == "REAL":
            return {"variants": [{"name": "orig", "groups": [orig]}, {"name": "lifted", "groups": [
                {**_group(0, match=False, error=want), "app_cost": {"9": 280}}]}]}
        lines = prog.split("\n")
        before = lines[lines.index("global OpcodeBudget // after the call") - 1] == "pop"
        ok = before and prog.count("pushint 1") * 2 >= 16
        got = _group(0) if ok else _group(0, match=False, error=want)
        return {"variants": [{"name": "orig", "groups": [orig]}, {"name": "lifted", "groups": [got]}]}
    monkeypatch.setattr(tt, "programs_at", lambda app, rnd: ("b64", "clear"))
    monkeypatch.setattr(tt, "lift_program", lambda prog, cache: {"status": "OK", "lifted": "REAL", "sha": "s"})
    monkeypatch.setattr(tt, "disassemble", lambda prog: pytest.fail("the deployed side is the costlier one"))
    monkeypatch.setattr(tt, "lifted_teal", lambda lift, lifts: lifted)
    monkeypatch.setattr(tt, "assemble", lambda src: (src, None))
    monkeypatch.setattr(tt, "replay_block", fake_replay)

    run = Run(tmp_path)
    run.append_rows([{"round": r, "group": 0, "app": 9, "status": "DIVERGES", "detail": want} for r in (7, 8)])
    (tmp_path / "controls.jsonl").write_text("".join(json.dumps(c) + "\n" for c in (
        {"round": 7, "group": 0, "app": 9, "reproduced": False, "why": "lift costs -20 here", "extra": -20},
        {"round": 8, "group": 0, "app": 9, "reproduced": False, "extra": -20, "v": tt.CONTROL_VERSION})))
    assert run_controls(run) == {"reproduced": 1}
    got = [json.loads(line) for line in (tmp_path / "controls.jsonl").open()][-1]
    assert got == {"round": 7, "group": 0, "app": 9, "reproduced": True, "padded": "lifted",
                   "site": tt._BUDGET_SITE + "1", "pad": 16, "extra": -20, "tried": 11, "v": tt.CONTROL_VERSION}
    assert run_controls(run) == {}                       # explained: never rerun


def test_rows_store_each_app_pc_once_and_are_read_streamed(tmp_path):
    """A 30-day run's rows.jsonl reached 1 GB (86% per-row coverage lists) and
    every summary loaded it whole: 3.5 GB RSS. Rows now carry only the pcs new
    for their app (the union is unchanged, a fresh process re-seeds from disk),
    and the readers stream, attribution and cost controls included."""
    import json
    from tests.replay_harness.stream import Run, iter_rows, summarize
    run = Run(tmp_path)
    err = "assert failed pc=9. Details: app=7, pc=9"
    batch = [{"round": 1, "group": 0, "app": 5, "status": "FAITHFUL", "orig_pcs": [1, 2, 3]},
             {"round": 2, "group": 0, "app": 5, "status": "DIVERGES", "detail": err, "orig_pcs": [2, 3]},
             {"round": 2, "group": 0, "app": 7, "status": "DIVERGES", "detail": err, "orig_pcs": [4]},
             {"round": 3, "group": 1, "app": 5, "status": "DIVERGES", "detail": "x", "orig_pcs": [3, 8]}]
    run.thin_coverage(batch[:2])
    run.append_rows(batch[:2])
    fresh = Run(tmp_path)                       # restart: the seen set comes from the file
    fresh.thin_coverage(batch[2:])
    fresh.append_rows(batch[2:])
    stored = [json.loads(line) for line in (tmp_path / "rows.jsonl").open()]
    assert [r.get("orig_pcs") for r in stored] == [[1, 2, 3], None, [4], [8]]
    (tmp_path / "controls.jsonl").write_text(json.dumps(
        {"round": 3, "group": 1, "app": 5, "reproduced": True, "site": "entry", "pad": 2, "extra": 4}) + "\n")
    got = [(r["round"], r["app"], r["status"]) for r in iter_rows(tmp_path)]
    assert got == [(1, 5, "FAITHFUL"), (2, 5, "CO_DIVERGED"), (2, 7, "DIVERGES"), (3, 5, "COST_ARTIFACT")]
    run.save("targets.json", [{"app": 5}, {"app": 7}])
    table = summarize(run)
    assert "4 judged (group, app) rows" in table
    assert "| 5 | 3 | 3 | 1 | 0 | 1 / 0 | 0 / 1 | 0 | 0 | 4 |" in table      # pcs {1,2,3,8}
