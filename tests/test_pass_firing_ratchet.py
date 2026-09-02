"""Every guarded lift pass must keep FIRING — a rotted guard is otherwise silent.

The mixed-cell / divergent-legacy machinery is a ladder of passes that each REFUSE
when their guards don't hold, and every refusal falls through to a total, honest
representation. That safety is the point — and it is exactly what makes a broken
guard invisible: nothing raises, no shape changes, the fallback quietly takes over
and every other gate stays green. The behavioural sweep can't see it either, since
the fallback is still correct, just less precise.

So the passes count themselves (``pre_ir.Program.pass_stats``) and this pins the
counts, in the two directions that matter:

* **the fixture floor** — each pass, given the hostile shape it was built for,
  must still fire. This is the anti-rot instrument.
* **the corpus ratchet** — exact counts over pinned mainnet probes, which catches
  the opposite drift: a pass that starts (or stops) firing on REAL contracts.
  It also encodes the measured claim that the mixed-cell ladder is
  hostile-TEAL-only — ``tail_dup_joins`` / ``split_mixed_phis`` /
  ``phi_arms_given_up`` are 0 on every one of the 1019 probes, so a nonzero here
  means real contracts started hitting shapes only hand-written TEAL used to.

A count moving is not automatically a bug — but it is never nothing. Re-measure,
understand which contracts moved and why, then update the baseline in the same
commit as the change that moved it. ``phi_arms_given_up`` is the one number that
should only ever FALL: each unit is a value the model stopped tracking.
(``tests/test_crossfamily_phi_arm.py`` ratchets its nonzero side on a real
6259-line contract.)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.lift import lift
from tealql.tealtools.ssa import SSAProgram

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"


def _stats(path) -> dict:
    """``pass_stats`` for a program, zeros dropped."""
    return {k: v for k, v in lift(SSAProgram(str(path))).pass_stats.items() if v}


# --- the fixture floor ------------------------------------------------------
#: shape name -> (TEAL, the firing it MUST produce). One entry per guarded pass,
#: using the smallest program that reaches it; these are the same shapes pinned
#: behaviourally in `test_adversarial_totality.py`, here asserting the pass ran
#: at all rather than what it produced.
_SHAPES = {
    # A divergent legacy sub (retsub sites leave different depths) called twice:
    # one body copy per site, and each copy's shallow arm is a doomed underflow.
    "divergent_legacy_two_sites": (
        "#pragma version 8\nint 7\ntxn NumAppArgs\nbnz second\ncallsub helper\n"
        "pop\npop\nint 1\nreturn\nsecond:\nint 9\ncallsub helper\npop\npop\npop\n"
        "int 1\nreturn\nhelper:\ntxn NumLogs\nbnz deep\nretsub\ndeep:\nint 5\nretsub\n",
        {"splice_subs": 1, "splice_sites": 2, "doomed_edges": 2},
    ),
    # A self-contained mixed-type join feeding a dynamic scratch write: the join
    # is DELETED, one copy per predecessor.
    "tail_duplicated_join": (
        '#pragma version 8\nint 0\ntxn NumAppArgs\nbnz two\nbyte "aa"\nb join\n'
        "two:\nint 8\njoin:\nstores\nint 1\nreturn\n",
        {"tail_dup_joins": 1},
    ),
    # A loop-invariant mixed cell at a self-loop header: version the loop once
    # per entry family, so the any-typed store keeps both exact values.
    "versioned_mixed_self_loop": (
        "#pragma version 8\ntxn NumAppArgs\nbnz two\ntxn Sender\nb loop\n"
        "two:\nglobal LatestTimestamp\nloop:\ndup\nint 1\nswap\nstores\n"
        "txn NumLogs\nbnz loop\npop\nint 1\nreturn\n",
        {"tail_dup_joins": 1},
    ),
    # A mixed-type merge whose only consumer is a STATIC scratch store: sunk into
    # the predecessors, one single-typed store per edge.
    "sunk_mixed_scratch_store": (
        '#pragma version 8\ntxn NumAppArgs\nbnz two\nbyte "aa"\nb join\n'
        "two:\nint 8\njoin:\nstore 0\nint 1\nreturn\n",
        {"sink_mixed_scratch": 1},
    ),
    # A shallow arm whose underflow sits one UNCONDITIONAL jump past the join —
    # the doom walk has to follow the chain to see it.
    "doom_across_an_unconditional_chain": (
        "#pragma version 8\ntxn NumAppArgs\nbnz deep\nb join\ndeep:\nint 5\n"
        "join:\nint 1\npop\nb tail\ntail:\npop\nint 1\nreturn\n",
        {"doomed_edges": 1},
    ),
    # A LIVE shallow arm whose join body nets positive through `dup` — the doom
    # profile modelled every shuffle as net-zero, dooming this real approving
    # path to Fail (a live path became an unconditional reject).
    "dup_in_join_live_arm_is_not_doomed": (
        "#pragma version 8\ntxn ApplicationID\nbnz deep\nint 1\nb join\n"
        "deep:\nint 1\nint 2\nint 3\njoin:\ndup\npop\npop\nint 1\nreturn\n",
        {"doomed_edges": 0},
    ),
    # The inverse direction: `bury` nets NEGATIVE (-1), so a shallow arm that
    # genuinely underflows through it must be doomed — modelled as net-zero the
    # padded zero approved where the real machine panics.
    "bury_underflow_is_doomed": (
        "#pragma version 8\ntxn ApplicationID\nbnz deep\nint 1\nb join\n"
        "deep:\nint 1\nint 2\njoin:\nbury 1\npop\nint 1\nreturn\n",
        {"doomed_edges": 1},
    ),
    # Main enters on an EMPTY stack (the one exact entry depth): a straight-line
    # dip below it is a certain underflow — `_simulate_op` used to clamp the pops
    # and the lift APPROVED. The block itself is doomed, not an edge.
    "main_entry_underflow_is_doomed": (
        "#pragma version 8\nint 1\ncover 3\nreturn\n",
        {"doomed_blocks": 1, "doomed_edges": 0},
    ),
    # `bury 0` fails unconditionally in the AVM; it used to be dropped.
    "bury0_is_doomed": (
        "#pragma version 8\nint 1\nint 1\nbury 0\nreturn\n",
        {"doomed_blocks": 1},
    ),
    # A proto sub's entry depth is NOT exact — plain stack ops may legally reach
    # below its params into the caller's residual — so a sub dip stays LIVE.
    "sub_below_frame_reach_is_not_doomed": (
        "#pragma version 10\nint 1\nint 2\nint 3\ncallsub sub\nreturn\nsub:\n"
        "proto 1 1\ntxn NumAppArgs\nbz shallow\nint 7\nb join\nshallow:\njoin:\n"
        "pop\npop\nint 5\nint 6\nint 1\nretsub\n",
        {"doomed_blocks": 0, "doomed_edges": 0},
    ),
    # A LIVE cross-family constant (`int 5` merged with `byte "hello"` under
    # `len`) is an explicit unknown, never itob-coerced to 0x…05.
    "live_cross_family_const_gives_up": (
        '#pragma version 10\ntxn NumAppArgs\nbz A\nint 5\nb J\nA:\nbyte "hello"\n'
        "J:\nlen\nreturn\n",
        {"cross_family_consts": 1, "phi_arms_given_up": 0},
    ),
}


@pytest.mark.parametrize("name", sorted(_SHAPES))
def test_the_pass_still_fires_on_its_own_shape(name, tmp_path):
    """The guard rot check: this shape exists to reach exactly this pass."""
    teal, expected = _SHAPES[name]
    p = tmp_path / f"{name}.teal"
    p.write_text(teal)
    got = _stats(p)
    for key, want in expected.items():
        assert got.get(key, 0) == want, (
            f"{name}: {key} fired {got.get(key, 0)}x, expected {want}x. A guard "
            f"that stopped holding is SILENT — the fallback is still correct, so "
            f"only this test can see it. Full stats: {got}")


# --- the corpus ratchet -----------------------------------------------------
#: Pinned probes, not a slice of a sorted listing: a prefix contains none of the
#: divergent-legacy contracts, so it would ratchet nothing. Chosen as the first
#: 14 probes on which any of these passes fires (measured 2026-08-05), which
#: keeps the whole check to a few seconds.
_CORPUS_SAMPLE = [
    "app_1050006430.teal", "app_1050006840.teal", "app_1050027991.teal",
    "app_1050051479.teal", "app_1050053392.teal", "app_1050053885.teal",
    "app_1050058216.teal", "app_1050114602.teal", "app_1050134592.teal",
    "app_1050186549.teal", "app_1050187510.teal", "app_1050193569.teal",
    "app_1100009529.teal", "app_1100197957.teal",
]

#: Aggregate firings over _CORPUS_SAMPLE. Update deliberately, never reflexively.
_CORPUS_BASELINE = {
    "splice_subs": 6,          # divergent legacy subs given per-site copies
    "splice_sites": 11,        # copies made (one per call site)
    # 67 → 6 (2026-09-01): the doom profile modelled every stack shuffle as
    # net-zero (`run += n_in` instead of `+= len(m)`), so `dup`/`cover`-heavy
    # compiled joins were mass-doomed — 61 of the 67 were LIVE approving paths
    # lifted to Fail. Verified against the full corpus semantics + backend
    # tiers; the 6 that remain are the splice shallow arms, real underflows.
    "doomed_edges": 6,         # shallow join arms that reject as the underflow they are
    "sink_mixed_scratch": 1,   # mixed-type merges sunk into per-edge stores
    "specialize_returns": 0,
    "dup_cross_sub_blocks": 6,
    # The mixed-cell ladder is hostile-TEAL-only: 0 across all 1019 probes.
    "tail_dup_joins": 0,
    "split_mixed_phis": 0,
    "phi_arms_given_up": 0,
    # 2026-09-02: hostile-only as well — no compiled contract underflows from
    # main's entry or carries a live cross-family constant.
    "doomed_blocks": 0,
    "cross_family_consts": 0,
}


@pytest.mark.skipif(not PROBES.is_dir(), reason="probe corpus not present")
def test_the_corpus_firing_counts_hold():
    """Reach on REAL contracts, both directions: a pass that goes quiet here has
    lost contracts it used to serve, and one that wakes up means real code
    started hitting a shape only hand-written TEAL used to."""
    total = dict.fromkeys(_CORPUS_BASELINE, 0)
    per_file: dict = {}
    for name in _CORPUS_SAMPLE:
        path = PROBES / name
        if not path.is_file():
            pytest.skip(f"pinned probe missing: {name}")
        st = _stats(path)
        if st:
            per_file[name] = st
        for key, value in st.items():
            if key in total:
                total[key] += value
    assert total == _CORPUS_BASELINE, (
        "pass firing on the pinned corpus moved.\n"
        f"  expected: {_CORPUS_BASELINE}\n"
        f"  got:      {total}\n"
        f"  per file: {per_file}\n"
        "Re-measure, understand WHICH contracts moved, then update the baseline "
        "in the same commit as the change that moved it.")
