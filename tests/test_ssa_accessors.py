"""The ssa/ accessors that stop downstream from re-deriving them by hand.

Each of these existed as open-coded copies across the codebase, and in each case
one of the copies was wrong or carried a HAZARD comment about the trap:

* ``BasicBlock.slot(k)`` — the TOP-first slot vs BOTTOM-first ``exit_stack`` flip,
  spelled at five sites;
* ``SSAProgram.entry_blocks()`` — "the first block", not "the block with no
  predecessors", which is a different set for a top-level retry loop;
* ``SSAProgram.phi_users(v)`` — phi-argument references, which ``SSAVar.uses``
  does not record.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"

# `top:` labels the FIRST instruction and the tail branches back to it, so the
# entry block is its own predecessor and the pred-free set is EMPTY.
_RETRY_LOOP_TEAL = """#pragma version 8
top:
intcblock 0 1
txn ApplicationID
bnz top
intc_1
return
"""


def test_slot_reads_top_first_with_a_length_guard():
    probe = PROBES / "app_3300088574.teal"
    if not probe.exists():
        pytest.skip("probe not present")
    prog = SSAProgram(str(probe))
    bb = next((b for b in prog.blocks.values() if len(b.exit_stack) >= 2), None)
    if bb is None:
        pytest.skip("no block with a 2-deep exit stack")
    assert bb.slot(1) is bb.exit_stack[-1], "slot(1) must be the TOP of the stack"
    assert bb.slot(2) is bb.exit_stack[-2]
    # Out of range and nonsense indices answer None rather than wrapping around,
    # which is the whole point of having one spelling.
    assert bb.slot(len(bb.exit_stack) + 1) is None
    assert bb.slot(0) is None and bb.slot(-1) is None


def test_entry_blocks_finds_a_branch_target_entry(tmp_path):
    """The case the pred-free spelling misses: the first block IS a branch target,
    so it has a predecessor and `not b.predecessors` yields nothing at all."""
    p = tmp_path / "retry.teal"
    p.write_text(_RETRY_LOOP_TEAL)
    prog = SSAProgram(str(p))
    entries = prog.entry_blocks()
    assert len(entries) == 1, f"expected one entry per file, got {entries}"
    entry = entries[0]
    assert entry.first_line == min(b.first_line for b in prog.blocks.values())
    assert entry.predecessors, (
        "fixture no longer has a branch-target entry, so it stops testing the "
        "case that motivated entry_blocks")


@pytest.mark.parametrize("probe", ["app_1050114602.teal", "app_3300088574.teal"])
def test_phi_users_matches_a_hand_rolled_index(probe):
    """Same answer as the by-hand index every consumer was building, and it
    records what ``uses`` cannot."""
    path = PROBES / probe
    if not path.exists():
        pytest.skip(f"{probe} not present")
    prog = SSAProgram(str(path))
    expected: dict = {}
    for p in prog.phis.values():
        for a in p.args:
            expected.setdefault(id(a), []).append(p)
    if not expected:
        pytest.skip("no phi args in this probe")
    for vid, phis in expected.items():
        arg = next(a for p in prog.phis.values() for a in p.args if id(a) == vid)
        assert prog.phi_users(arg) == phis
    # A value no phi consumes answers empty, not KeyError.
    assert prog.phi_users(object()) == []


def test_phi_users_cache_can_be_invalidated():
    probe = PROBES / "app_1050114602.teal"
    if not probe.exists():
        pytest.skip("probe not present")
    prog = SSAProgram(str(probe))
    prog.phi_users(object())                       # build the cache
    assert getattr(prog, "_phi_users_index", None) is not None
    prog._invalidate_phi_users()
    assert getattr(prog, "_phi_users_index", None) is None
    prog.phi_users(object())                       # rebuilds without raising
    assert getattr(prog, "_phi_users_index", None) is not None
