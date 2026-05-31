"""Phi de-duplication — collapse redundant phi nodes to one.

PySSA's constant-stack ``[1..STACK_MAX]`` unroll over-generates phi
objects: on a real contract (xgov) ~21k phis exist where only a few
hundred are distinct, hundreds of identical phi objects sharing one
merge point. Left alone, :meth:`SSAProgram.materialize_phis` then emits
a ``mat_phi`` copy per (phi, contributing-leaf) pair, exploding into
~100k copy assignments.

This pass first normalises each phi's args — dropping duplicate *values*
(order-preserving), since a repeated value adds nothing to the may-set —
then merges phis with identical (value-normalised) args, rewiring every
reference (assignment inputs, other phis' args, the BB phi lists,
``prog.phis``) to one representative. The arg-normalisation both lets
value-equal phis (e.g. ones differing only by repeated ``0`` consts the
unroll appended) share a signature, and cuts the number of mat_phi
copies materialisation emits.

Soundness rests on how phis are *consumed*, not on per-predecessor
matching. A phi's ``args`` is a dedup-by-identity ordered *set* (built
by :meth:`PySSA._add_arg`), not a strict one-arg-per-predecessor list,
so equal args does not by itself mean "equal per-predecessor
selection". What makes the merge sound is that every consumer treats a
phi as the **may-set** of its args and nothing reads ``args[i]``
positionally against ``predecessor[i]``:

  - constant folding: a phi is constant iff *all* args agree;
  - ranges / bytemath: a phi's range is the *union* of its args';
  - taint: a phi is tainted iff *any* arg is;
  - materialisation: the mat_phi SCC graph iterates ``args`` set-wise.

So two phis with the same arg *set* are interchangeable for every
analysis, and the ``(ordered-args)`` key is a stricter subset of that.
Verified value-preserving: const / range resolution is byte-identical
before vs after dedup on xgov (57k SSAVars, 0 differences).

Neither ``kind`` nor ``basic_block`` is in the key. ``kind`` is constant
(PySSA's ``_apply_pyssa_to`` collapses the QL Direct/Indirect
distinction and registers every phi as ``DirectPhi``). ``basic_block``
is omitted because no consumer distinguishes phis by merge point: every
analysis uses a phi's args as a may-set, and materialisation places its
copies at each *leaf*'s def site rather than the phi's BB — so merging
value-equal phis across different merge points is observationally
invisible. This is the assumption the pass rests on: a future analysis
that reasoned about a phi *per merge point* (which arg came from which
predecessor) would need to run before this pass or re-key it. On xgov
the merge-point-agnostic key takes 21065 phis to ~109 (vs ~667 with a
per-BB key), const/range resolution byte-identical either way. Run to a
fixpoint (merging rewires phi-args, exposing further identical phis);
cyclic phi groups equal-only-up-to-congruence may stay separate (a
missed merge, never a wrong one).

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
    # Keyed on the (value-normalised) arg sequence only — NOT the merge
    # point. Two phis with the same args are the same may-set, and every
    # consumer treats a phi as that may-set; crucially nothing reads
    # ``phi.basic_block`` (materialisation places copies at each *leaf*'s
    # def site, not the phi's BB), so merging value-equal phis across
    # different merge points is observationally invisible. Verified
    # value-preserving on xgov (const/range byte-identical; 667 -> 109).
    return tuple(_arg_id(a) for a in ph.args)


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


def _normalize_args(ph: Phi) -> bool:
    """Drop duplicate-*value* args (order-preserving) from ``ph``. A
    repeated value contributes nothing to the phi's may-set, so removing
    it changes no analysis (and even the precise per-path value is
    unchanged — it's the same value whichever predecessor supplied it).
    Doing so lets value-equal phis share a signature and cuts the number
    of mat_phi copies. Returns True if anything was removed."""
    seen: set = set()
    kept: list = []
    for a in ph.args:
        aid = _arg_id(a)
        if aid not in seen:
            seen.add(aid)
            kept.append(a)
    if len(kept) != len(ph.args):
        ph.args[:] = kept
        return True
    return False


def dedup_phis(prog: SSAProgram) -> int:
    """Merge value-equal phis to a fixpoint. Each round first normalises
    args (drops duplicate values — see :func:`_normalize_args`; also mops
    up duplicates a prior round's rewiring introduced), then merges phis
    with an identical ``(basic_block, ordered-args)`` signature. Returns
    the number of phi objects removed."""
    removed = 0
    while True:
        changed = False
        for ph in prog.phis.values():
            if _normalize_args(ph):
                changed = True
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
        if redirects:
            _apply_redirects(prog, redirects)
            removed += len(redirects)
            changed = True
        if not changed:
            break
    return removed
