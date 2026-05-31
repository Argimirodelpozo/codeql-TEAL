"""Tests for the block-argument out-of-SSA view (``tealtools.block_args``)
and the ``BasicBlock.exit_stack`` surfacing it relies on.

Uses the ``conditional_swap`` fixture — a conditional ``swap`` before a merge,
whose two stack slots are *anti-correlated* (same value-set {a, b}, opposite
per path). This is the case where phi-materialisation collapses (last-writer-
wins at the co-defined leaves) but block-args must keep the per-edge values
distinct. Skips if the DB isn't available.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/conditional_swap"


def _prog():
    db = FIX / "db"
    if not db.exists():
        pytest.skip(f"fixture DB not present: {db}")
    from tealtools.ssa import SSAProgram
    try:
        return SSAProgram(str(db), verbose=False)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")


def _by_line(prog, line):
    return next(b for b in prog.blocks.values() if b.first_line == line)


class TestExitStackSurfaced:
    def test_public_block_has_exit_stack(self):
        prog = _prog()
        assert all(hasattr(b, "exit_stack") for b in prog.blocks.values())

    def test_entry_exit_stack_holds_the_two_pushed_values(self):
        # L2 block pushes NumAppArgs (L2) and NumAssets (L3); the bz at L5
        # pops the condition, leaving those two, bottom-first.
        prog = _prog()
        es = _by_line(prog, 2).exit_stack
        labels = [getattr(o, "identifier", None) for o in es]
        assert "V#1@L2" in labels and "V#1@L3" in labels


class TestBlockArgsSwap:
    def _form(self):
        from tealtools.block_args import to_block_args
        prog = _prog()
        return prog, to_block_args(prog)

    def test_join_is_parameterised_by_its_phis(self):
        prog, form = self._form()
        merge = _by_line(prog, 7)
        assert len(merge.predecessors) == 2          # a real join
        assert form.params[merge] == sorted(
            merge.phis, key=lambda p: p.stack_index
        )
        assert len(form.params[merge]) == 2

    def test_every_edge_into_join_carries_one_arg_per_param(self):
        prog, form = self._form()
        merge = _by_line(prog, 7)
        for pred in merge.predecessors:
            e = form.edge(pred, merge)
            assert e is not None
            assert len(e.args) == len(form.params[merge])
            assert all(a is not None for a in e.args)   # no dead/missing slot

    def test_per_edge_values_are_anticorrelated_not_collapsed(self):
        # The soundness point: each slot receives a DIFFERENT value on each
        # incoming edge (the swap), and the two edges' arg tuples differ.
        # A per-leaf materialisation cannot express this without coalescing.
        prog, form = self._form()
        merge = _by_line(prog, 7)
        a_from_2 = form.edge(_by_line(prog, 2), merge).args
        a_from_6 = form.edge(_by_line(prog, 6), merge).args
        assert a_from_2 != a_from_6
        # every slot genuinely takes >=2 distinct values across the edges
        for i in range(len(form.params[merge])):
            assert a_from_2[i] is not a_from_6[i]

    def test_per_edge_values_match_phi_incoming_set(self):
        # Faithfulness: the per-edge value of slot k, gathered over all
        # predecessors, is exactly that phi's incoming value-set.
        prog, form = self._form()
        merge = _by_line(prog, 7)
        for k, ph in enumerate(form.params[merge]):
            per_edge = {
                id(form.edge(pr, merge).args[k]) for pr in merge.predecessors
            }
            assert per_edge == {id(a) for a in ph.args}

    def test_render_runs(self):
        _prog_, form = self._form()
        text = form.render()
        # phi-at-join at the real merge, carry-over on the jumps, preds header
        assert "= phi(L" in text          # join shows phi(pred: value, ...)
        assert "-> L7(" in text           # jump carries values to the join
        assert "(preds:" in text
