"""EXACT below-band effect summaries for clobber-class callees.

A proto'd callee whose plain stack ops reach under its own band (`cover 3`
under a ``proto 1 1`` — legal, runs, verified live on a node) rewrites the
CALLER's residual. The simulation's answer so far was withdrawal: blank the
residual values, keep the height (``unsafe_callees``). Honest, but a refusal
— and an unnecessary one, because every AVM stack op's effect is STATIC
(immediates decide arity and permutation), so what the callee does to the
cells beneath its band is a computable function of those cells.

This module computes that function where it is exact and cheap to hold:

* proto'd (there is a band to be below);
* no ``callsub`` in the body (a nested call needs summary composition);
* TREE-SHAPED intra-routine CFG, no loops (every block has at most one
  in-body predecessor): no joins means no cell merges inside the callee, so
  each ``retsub`` sees exactly one root-to-exit path. Loops and joins
  refuse — an internal merge would need phis minted in a second walk over
  blocks the main simulation already owns, a slot-identity collision.

Two passes. Pass 1 walks each path tracking height relative to the band
base; the deepest dip is ``K``, the number of caller cells the callee can
touch. Pass 2 walks a concrete bottom-first list

    [_Below(K), ..., _Below(1), _CalleeParam(0), ..., _CalleeParam(A-1)]

with real semantics: shuffles permute via ``_canon_shuffle``, other ops pop
their arity and push their own output PyVars, frame ops address
``K + A + n`` (below-frame ones mark the path DEAD — the AVM rejects them
at runtime, verified live). List bottom indices ARE absolute positions, so
at a ``retsub`` the below-band region is simply ``virtual[0..K-1]`` — what
the caller's residual holds after the call. A path whose exit height is
below the frame is DEAD too (the AVM re-checks the bound at ``retsub``).

Any LIVE path the model cannot place exactly refuses the WHOLE summary —
a partial summary would be the resolved-subset trap (naming some paths'
effect as THE effect).

The result per callee::

    Summary(reach=K, paths=[(retsub PyBlock, {depth j: cell})])

with ``j`` counted 1 = just under the deepest arg, and a cell one of
``_Below(i)`` (the caller's pre-call cell at depth ``i``), ``_CalleeParam(p)``
(the call's argument, 0 = deepest), or a PyVar the callee produced. A depth
absent from a path's map is untouched on that path. The call site rewrites
its residual's top-``K`` cells through the maps, merging across ``retsub``
paths with the same trail-style phis the divergent-legacy recovery uses —
real values, no blanking.
"""
from __future__ import annotations

from ..avm import op_arity
from .models import _canon_shuffle

_SHUFFLES = frozenset({"swap", "dup", "dup2", "dupn", "cover", "uncover",
                       "dig", "bury"})


class _Below:
    """The caller's residual cell at depth ``j`` (1 = just under the args),
    as it was BEFORE the call."""

    __slots__ = ("j",)

    def __init__(self, j: int):
        self.j = j

    def __repr__(self) -> str:
        return f"B{self.j}"


class _CalleeParam:
    """The call's argument ``p`` (0 = deepest), resolved at the call site."""

    __slots__ = ("p",)

    def __init__(self, p: int):
        self.p = p

    def __repr__(self) -> str:
        return f"P{self.p}"


class Summary:
    __slots__ = ("reach", "paths")

    def __init__(self, reach: int, paths: list):
        self.reach = reach
        self.paths = paths


def _imm_int(op):
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


def _succs_in(b, body):
    if b.ops and b.ops[-1].op in ("retsub", "return", "err", "callsub"):
        return []
    return [s for s in b.succs if s in body]


def _tree_shaped(callee, body) -> bool:
    npred: dict = {}
    for b in body:
        if b.ops and b.ops[-1].op == "callsub":
            return False
        for s in _succs_in(b, body):
            npred[s] = npred.get(s, 0) + 1
            if npred[s] > 1 or s is callee:
                return False
    return True


def _op_effect(o):
    """``(n_in, n_out)`` with the frame overrides the walk needs."""
    if o.op == "frame_dig":
        return (0, 1)
    if o.op == "frame_bury":
        return (1, 0)
    return op_arity(o.op, o.immediates)


def summarize(callee, body, proto) -> "Summary | None":
    """The below-band effect of ``callee`` (its entry block), or None."""
    a_in = proto[0]
    body = set(body)
    if not _tree_shaped(callee, body):
        return None

    # Pass 1: deepest dip below the band base over every path. Heights are
    # exact per path on a tree (one predecessor each).
    k_reach = 0
    wl = [(callee, a_in)]
    while wl:
        b, h = wl.pop()
        for o in b.ops:
            if o.op == "proto":
                continue
            n_in, n_out = _op_effect(o)
            h -= n_in
            k_reach = max(k_reach, -h if h < 0 else 0)
            h += n_out
        wl.extend((s, h) for s in _succs_in(b, body))
    if k_reach == 0:
        return None                    # never reaches below — nothing to say

    below = {j: _Below(j) for j in range(1, k_reach + 1)}
    params = [_CalleeParam(p) for p in range(a_in)]
    init = [below[j] for j in range(k_reach, 0, -1)] + params

    paths: list = []
    refused = False

    def walk(b, virtual):
        nonlocal refused
        if refused:
            return
        virtual = list(virtual)
        for o in b.ops:
            if o.op == "proto":
                continue
            if o.op in ("frame_dig", "frame_bury"):
                n = _imm_int(o)
                if n is None:
                    refused = True
                    return
                if a_in + n < 0:
                    return             # below-frame frame op: path is DEAD
                pos = k_reach + a_in + n
                if o.op == "frame_dig":
                    if 0 <= pos < len(virtual):
                        virtual.append(o.outputs[0] if o.outputs
                                       else virtual[pos])
                    else:
                        refused = True
                        return
                else:
                    if not virtual:
                        refused = True
                        return
                    v = virtual.pop()
                    if 0 <= pos < len(virtual):
                        virtual[pos] = v
                    elif pos == len(virtual):
                        virtual.append(v)
                    else:
                        refused = True
                        return
                continue
            if o.op in _SHUFFLES:
                n_in, mapping = _canon_shuffle(o.op, o.immediates)
                if mapping is None or n_in > len(virtual):
                    refused = True     # bury 0 / malformed / over-deep
                    return
                ins = [virtual.pop() for _ in range(n_in)]   # top-first
                for v in reversed([ins[m] for m in mapping]):
                    virtual.append(v)
                continue
            n_in, _n_out = op_arity(o.op, o.immediates)
            if n_in > len(virtual):
                refused = True
                return
            del virtual[len(virtual) - n_in:]
            virtual.extend(o.outputs)

        last = b.ops[-1].op if b.ops else None
        if last == "retsub":
            if len(virtual) < k_reach + a_in:
                return                 # stack below frame at retsub: DEAD
            exit_map = {}
            for j in range(1, k_reach + 1):
                cell = virtual[k_reach - j]
                if not (isinstance(cell, _Below) and cell.j == j):
                    exit_map[j] = cell
            paths.append((b, exit_map))
            return
        if last in ("return", "err"):
            return
        for s in _succs_in(b, body):
            walk(s, virtual)

    walk(callee, init)
    if refused or not paths:
        return None
    return Summary(k_reach, paths)


def build_summaries(blocks, bb_to_sub, proto_io, unsafe_callees) -> dict:
    """``{callee entry PyBlock: Summary}`` for every unsafe proto'd callee
    the v1 shape limits can hold exactly."""
    bodies: dict = {}
    for b in blocks:
        bodies.setdefault(bb_to_sub.get(b), []).append(b)
    out: dict = {}
    for callee in unsafe_callees:
        proto = proto_io.get(callee)
        if proto is None:
            continue
        s = summarize(callee, bodies.get(callee, ()), proto)
        if s is not None:
            out[callee] = s
    return out
