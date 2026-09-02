"""Pin for the 2026-09-02 audit's cfg-layer defect (findings.md §7.1). One test
for the defect, controls folded in.

§7.1 was filed as "legacy (no-`proto`) shared callee loses the call site's
guard". The `proto` half of the hypothesis was wrong — the legacy and `proto`
twins behaved identically — and the real roots were two, both in the carry of
caller facts across a `callsub` return (`cfg/path_predicates._compute`):

  1. only predicates rooted in immutable txn/global FIELDS were carried, so a
     guard on a state read (`Sender == app_global_get "seller" || Sender ==
     Creator`) was dropped at the return, although the SSA VALUE it is about is
     defined before the call and cannot be recomputed by it;
  2. the carry was per BLOCK and refused any return target with a non-`retsub`
     predecessor, so a guarded arm whose continuation is also a `b` target
     (mainnet app_1400025115 `label12`/`label15`) lost its guard at the join.
"""
from __future__ import annotations

from pathlib import Path

from tealql.security import DETECTORS
from tealql.tealtools.ssa import SSAProgram

_V = "#pragma version 8\n"

_HEAD = (
    "txn OnCompletion\nint DeleteApplication\n==\nassert\n"
    "txn NumAppArgs\nbnz admin\n"
)
_CALL = 'byte "seller"\napp_global_get\ncallsub helper\nint 1\nreturn\n'
# `||` of two pins, one of them a STATE read — not field-rooted.
_OR_GUARD = (
    'txn Sender\nbyte "seller"\napp_global_get\n==\n'
    "txn Sender\nglobal CreatorAddress\n==\n||\nassert\n"
)
_LEGACY_HELPER = "helper:\nstore 10\nretsub\n"
_PROTO_HELPER = "helper:\nproto 1 0\nframe_dig -1\nstore 10\nretsub\n"


def _prog(tmp_path: Path, src: str, name: str) -> SSAProgram:
    p = tmp_path / name
    p.write_text(_V + src)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return prog


def _deletable_exits(prog: SSAProgram) -> set[int]:
    return {v.line for v in DETECTORS["unprotected-deletable"](prog).detect()}


def test_call_site_guard_survives_shared_callee_return(tmp_path):
    """A shared callee called from a public arm (exit :12, TP) and from an arm
    guarded by `Sender == seller_state || Sender == Creator` (exit :27): the
    guarded exit must be CLEAN — the guard is on values defined before the
    call, and the return target's `retsub` edge is taken only from that call.
    Legacy and `proto` twins must agree (the filed hypothesis said they did
    not; both were flagged).

    Control 1: the guarded arm's continuation is ALSO reached by a `bnz` from
    the public arm — the carry is per `retsub` EDGE, so the branch path keeps
    its own (guardless) facts and the shared exit stays flagged. A per-block
    injection would union the guard in and lose the TP.

    Control 2: self-recursion — NOTHING is carried across a recursive call,
    txn-field predicates included. The `retsub` block's facts belong to the
    INNER activation and the call site's to the OUTER; the static SSA identity
    conflates them, and on main their union (`NumAppArgs == 7` carried, `!= 7`
    from the base case) made the return target CONTRADICTORY, i.e. infeasible.
    The control asserts the closure sees the recursion and that the return
    target carries no contradiction and none of the call-path asserts."""
    for name, helper in (("legacy.teal", _LEGACY_HELPER),
                         ("proto.teal", _PROTO_HELPER)):
        prog = _prog(tmp_path, _HEAD + _CALL + "admin:\n" + _OR_GUARD + _CALL
                     + helper, name)
        assert _deletable_exits(prog) == {12}, name

    # Control 1 — mixed predecessors: retsub edge (guarded call) + `bnz` from
    # the public arm into the same label.
    shared = _prog(
        tmp_path,
        _HEAD
        + 'byte "seller"\napp_global_get\ncallsub helper\n'
        + "txn Fee\nbnz shared\n"           # :12  public path jumps into `shared`
        + "int 1\nreturn\n"                 # :14  public exit (TP)
        + "admin:\n" + _OR_GUARD
        + 'byte "seller"\napp_global_get\ncallsub helper\n'
        + "shared:\nint 1\nreturn\n"        # :30  reachable unguarded via :12
        + _LEGACY_HELPER,
        "shared.teal",
    )
    assert _deletable_exits(shared) == {14, 30}

    # Control 2 — recursion. Line numbers: the asserts sit on the recursive
    # path only, so they reach the return target ONLY via the carry.
    rec = _prog(
        tmp_path,
        "callsub rec\nint 1\nreturn\n"
        "rec:\n"
        "txn NumAppArgs\nint 7\n==\nbz out\n"          # :6-:9
        'byte "k"\napp_global_get\nint 1\n==\nassert\n'  # :10-:14 state-rooted
        "txn Fee\nint 0\n==\nassert\n"                  # :15-:18 field-rooted
        "callsub rec\n"                                 # :19 recursive call
        "txn Fee\npop\n"                                # :20 return target
        "out:\nretsub\n",
        "rec.teal",
    )
    from tealql.tealtools.cfg.path_predicates import (
        PathPredicateAnalysis, predicates_contradict)
    from tealql.tealtools.cfg.subroutines import (
        call_executed_blocks, sound_return_targets)
    pp = PathPredicateAnalysis(rec)
    target = rec.block_containing("rec.teal", 20)
    call_bb = rec.block_containing("rec.teal", 19)
    assert target is not None and call_bb is not None
    executed = call_executed_blocks(rec)[call_bb]
    assert executed is not None and call_bb in executed, "self-recursion is in its own closure"
    assert call_bb not in sound_return_targets(rec)[1], "recursive call site refused"
    preds = pp.bb_preds[target]
    assert not predicates_contradict(preds), preds
    # The two asserts (lines 14 and 18) sit only on the call path: absent.
    assert not {c for c in preds if c.value.line in (14, 18)}, preds
