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
    orig = {"groups": [_group(0), _group(1), _group(2), _group(3, match=False, error="eval drift")]}
    # Group 0 rejected (commits nothing -> later groups stay comparable), group 1
    # commits a different log (poisons 2), group 3 is the ORACLE's miss.
    bad_log = {"index": 0, "match_chain": False,
               "apply_json": '{"dt": {"lg": ["a", "b"]}}', "chain_json": '{"dt": {"lg": ["a"]}}'}
    lifted = {"groups": [_group(0, match=False, error="transaction rejected by ApprovalProgram"),
                         _group(1, match=False, txns=[bad_log]), _group(2), _group(3)]}
    rows = {r["group"]: r for r in classify(orig, lifted)}
    assert rows[0]["status"] == "DIVERGES" and "rejected" in rows[0]["detail"]
    assert rows[1]["status"] == "DIVERGES" and rows[1]["detail"] == "txn 0: $.dt.lg: length 2 != 1"
    assert rows[2]["status"] == "AFTER_DIVERGENCE"           # 1 committed different state
    assert rows[3]["status"] == "REPLAY_MISS" and rows[3]["detail"] == "eval drift"

    # Controls: an equal run is FAITHFUL only when the box writes agree too; a
    # cost failure is BUDGET and, committing nothing, poisons nothing.
    assert [r["status"] for r in classify({"groups": [_group(0)]}, {"groups": [_group(0)]})] == ["FAITHFUL"]
    boxes = classify({"groups": [_group(0, boxes={"k": "AQ=="})]}, {"groups": [_group(0, boxes={"k": "Ag=="})]})
    assert boxes[0]["status"] == "DIVERGES" and boxes[0]["detail"].startswith("box writes: $.k")
    budget = classify({"groups": [_group(0), _group(1)]},
                      {"groups": [_group(0, match=False, error="pc=12 dynamic cost budget exceeded"), _group(1)]})
    assert [r["status"] for r in budget] == ["BUDGET", "FAITHFUL"]
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
