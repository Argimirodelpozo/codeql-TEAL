"""Verdict logic of the historical-replay differential
(``tests/behavioral_lift/timetravel.py``). The replay itself needs the network and
a built ``ttreplay``; what decides FAITHFUL vs DIVERGES is pure and pinned here.
"""
from __future__ import annotations

from tests.behavioral_lift.timetravel import _entry_mutant, classify, first_diff, instruction_count


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
