"""Tests for group_reasoning.array_counts + relative_slot (relative-index group
members + per-member array sizing).

These are ADDITIVE to analyze()/classify() -- they recover the two facts v1
punted on: a `gtxns`/`gtxnsa` at a `GroupIndex +/- k` sibling, and the minimum
array-element count each addressed member must carry (or the read panics). The
motivating case is the wormhole completeTransfer handler, whose vacuity was a
missing per-sibling NumAppArgs/NumAccounts sizing.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/group_shape"


def _prog(case: str):
    teal = FIX / case / "prog.teal"
    if not teal.exists():
        pytest.skip(f"fixture not present: {teal}")
    from tealql.tealtools.ssa import SSAProgram
    try:
        prog = SSAProgram(str(teal))
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")
    prog.propagate_constants()
    prog.propagate_scratch_constants()
    return prog


class TestRelativeSlot:
    def test_group_index_plus_minus_and_const(self):
        from tealql.tealtools.cfg.group import relative_slot
        from tealql.tealtools.ssa.models import Const, SSAVar

        # A bare GroupIndex-producing var resolves to "this"; a constant to gtxn[N].
        # (relative arithmetic is covered end-to-end by array_counts below, which
        # only classifies a slot via the same relative_slot path.)
        class _FakeAsg:
            def __init__(self, op, imm, inputs):
                self.op, self.immediates, self.inputs = op, imm, inputs

        gi = SSAVar("f", 1, 0)
        gi.defined_by = _FakeAsg("txn", "GroupIndex", [])
        assert relative_slot(gi) == "this"

        one = SSAVar("f", 2, 0)
        one.const_value = Const("int", "1")
        minus = SSAVar("f", 3, 0)
        minus.defined_by = _FakeAsg("-", "", [one, gi])   # inputs=[top, deeper]=1,GI
        assert relative_slot(minus) == "this-1"

        plus = SSAVar("f", 4, 0)
        plus.defined_by = _FakeAsg("+", "", [one, gi])
        assert relative_slot(plus) == "this+1"

        c = SSAVar("f", 5, 0)
        c.const_value = Const("int", "2")
        assert relative_slot(c) == "gtxn[2]"


class TestArrayCounts:
    def test_recovers_relative_members_and_minima(self):
        from tealql.tealtools.cfg.group import array_counts
        ac = array_counts(_prog("array_counts"))
        # preceding sibling: ApplicationArgs 1 => NumAppArgs>=2; Accounts 2 => NumAccounts>=2
        assert ac.get("this-1") == {"NumAppArgs": 2, "NumAccounts": 2}
        # following sibling: ApplicationArgs 0 => NumAppArgs>=1
        assert ac.get("this+1") == {"NumAppArgs": 1}
        # own txn: Accounts 3 => NumAccounts>=3, ApplicationArgs 2 => NumAppArgs>=3
        assert ac.get("this") == {"NumAccounts": 3, "NumAppArgs": 3}
