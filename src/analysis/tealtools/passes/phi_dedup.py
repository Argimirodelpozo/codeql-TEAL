"""Phi de-duplication — collapse redundant phi nodes to one.

PySSA's constant-stack ``[1..STACK_MAX]`` unroll over-generates phi
objects: on a real contract (xgov) ~21k phis exist where only a few
hundred are distinct, hundreds of identical phi objects sharing one
merge point. Left alone, :meth:`SSAProgram.materialize_phis` then emits
a ``mat_phi`` copy per (phi, contributing-leaf) pair, exploding into
~100k copy assignments.

This pass merges phis that are provably the same value: identical
``(basic_block, kind, ordered-args)``. Same merge point + same kind +
same per-predecessor operands ⇒ same phi function ⇒ same value, so one
representative replaces the rest and every reference (assignment inputs,
other phis' args, the BB phi lists, ``prog.phis``) is rewired to it.

Run to a fixpoint: merging a group rewires phi-args that pointed at the
duplicates to the canonical, which can make further phis identical.
Sound but deliberately conservative — the ``basic_block`` component of
the key means phis at *different* merge points are never merged even
with the same args (their per-path selection can differ), and cyclic
phi groups that are equal-up-to-congruence may stay separate (a missed
merge, never a wrong one).

Best run just before :meth:`SSAProgram.materialize_phis`; it also makes
every phi-iterating analysis cheaper. Idempotent. Mutates in place.
"""
from __future__ import annotations

from ..ssa import Phi, SSAProgram, SSAVar


def _arg_id(operand) -> tuple:
    """Stable identity for a phi arg. Phis use their ``(file, line,
    kind, stack_index)`` key — unique per phi, and after a merge the
    duplicates' references already point at the canonical, so equal ids
    mean the same value."""
    if isinstance(operand, SSAVar):
        return ("v", operand.file, operand.line, operand.index)
    if isinstance(operand, Phi):
        return ("p", operand.file, operand.line, operand.kind, operand.stack_index)
    cv = getattr(operand, "value", None)
    return ("c", getattr(operand, "kind", None), cv)


def _phi_sig(ph: Phi) -> tuple:
    bb = ph.basic_block
    bb_key = (bb.file, bb.first_line, bb.last_line) if bb is not None else None
    return (bb_key, ph.kind, tuple(_arg_id(a) for a in ph.args))


def _apply_redirects(prog: SSAProgram, redirects: dict) -> None:
    """Rewire every reference to a duplicate phi to its canonical."""
    # Assignment inputs.
    for a in prog.assignments:
        for i, inp in enumerate(a.inputs):
            rep = redirects.get(inp)
            if rep is not None:
                a.inputs[i] = rep
                rep.uses.append(a)
    # Other phis' args (survivors may reference a duplicate).
    for ph in prog.phis.values():
        for i, arg in enumerate(ph.args):
            rep = redirects.get(arg)
            if rep is not None:
                ph.args[i] = rep
    # BB phi lists + the prog.phis registry. Rebuild the registry by
    # value (robust to however it is keyed) rather than popping by key.
    for ph in redirects:
        bb = ph.basic_block
        if bb is not None and ph in bb.phis:
            bb.phis.remove(ph)
        ph.uses = []
    prog.phis = {k: v for k, v in prog.phis.items() if v not in redirects}


def dedup_phis(prog: SSAProgram) -> int:
    """Merge identical phis to a fixpoint. Returns the number of phi
    objects removed."""
    removed = 0
    while True:
        by_sig: dict[tuple, Phi] = {}
        redirects: dict[Phi, Phi] = {}
        # Deterministic order so the canonical pick is stable.
        for ph in sorted(
            prog.phis.values(),
            key=lambda p: (p.file, p.line, p.kind, p.stack_index),
        ):
            sig = _phi_sig(ph)
            rep = by_sig.get(sig)
            if rep is None:
                by_sig[sig] = ph
            else:
                redirects[ph] = rep
        if not redirects:
            break
        _apply_redirects(prog, redirects)
        removed += len(redirects)
    return removed
