"""Iterative dominator-set computation — one source of truth, parameterised by
accessor callables so every node type (BasicBlock, SuperBlock, lifted-IR block
id) shares it. Stays pure — no ``tealtools`` imports — so any layer can use it
without an import cycle.
"""
from __future__ import annotations

from typing import Callable, Hashable, Iterable, TypeVar

N = TypeVar("N", bound=Hashable)


def iterative_dominators(
    nodes: Iterable[N],
    entries: Iterable[N],
    preds_of: Callable[[N], Iterable[N]],
) -> dict[N, set[N]]:
    """Dominator sets over a directed graph, reflexively including each node.

    HAZARD: a non-entry node with no predecessors is left SATURATED (dominated by
    everything) — the conventional unreachable treatment, which means an empty
    ``entries`` makes every node dominate every node.
    """
    nodes = list(nodes)
    all_nodes = set(nodes)
    entry_set = set(entries)
    dom: dict[N, set[N]] = {
        n: ({n} if n in entry_set else set(all_nodes)) for n in nodes
    }
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n in entry_set:
                continue
            preds = list(preds_of(n))
            if not preds:
                continue  # unreachable; leave saturated
            new = {n} | set.intersection(*(dom[p] for p in preds))
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom


def program_entries(blocks) -> list:
    """Per file, the block holding that file's FIRST instruction — where TEAL
    starts executing, even when that block is a branch target (so it HAS preds).

    HAZARD: "blocks with no predecessors" is NOT an entry criterion — a program
    whose first block is a branch target (top-level retry loop) has none, and an
    empty entry set leaves ``iterative_dominators`` saturated, silently crediting
    guards everywhere. Predecessor-less non-first blocks are dead code."""
    first: dict = {}
    for b in blocks:
        cur = first.get(b.file)
        if cur is None or b.first_line < cur.first_line:
            first[b.file] = b
    return sorted(first.values(), key=lambda b: (b.file, b.first_line))


def all_blocks(prog) -> set:
    """Every ``BasicBlock`` reachable either way from a block owning an
    assignment or phi (duck-typed on ``prog`` to stay import-free)."""
    seed = set()
    for a in prog.assignments:
        if a.basic_block is not None:
            seed.add(a.basic_block)
    for ph in prog.phis.values():
        bb = getattr(ph, "basic_block", None)
        if bb is not None:
            seed.add(bb)
    allb = set(seed)
    stack = list(seed)
    while stack:
        b = stack.pop()
        for nb in (*b.predecessors, *b.successors):
            if nb not in allb:
                allb.add(nb)
                stack.append(nb)
    return allb


def reachable_avoiding(entries: list, avoid) -> set:
    """Blocks reachable from ``entries`` over ``successors`` while avoiding
    ``avoid`` — the shared approximate-dominance primitive: ``A`` dominates ``U``
    iff ``U`` is reachable normally but missing here.

    HAZARD: over-approximates on the raw interprocedural CFG, so the dominance
    test is conservative — a fact is at worst skipped, never applied unsoundly."""
    seen = {e for e in entries if e is not avoid}
    stack = list(seen)
    while stack:
        b = stack.pop()
        for s in b.successors:
            if s is avoid or s in seen:
                continue
            seen.add(s)
            stack.append(s)
    return seen


class AssertDominance:
    """Approximate "the guard at ``guard_block`` dominates ``target_block``" by
    reachability (within one block, by line order) — the shared substrate for the
    assert-guarded analyses (relational bounds, range-from-assert, byte-length
    propagation, byte-taint validation), conservative per
    :func:`reachable_avoiding`.

    Most callers want :meth:`narrowing_is_sound` rather than :meth:`dominates`:
    dominance alone is only half the condition for applying a guard's fact to a
    value, and the missing half is not obvious."""

    def __init__(self, prog):
        # HAZARD: real per-file entries, NOT "blocks with no predecessors" — an
        # empty entry set makes ``reachable_avoiding`` return {} and EVERY guard
        # "dominate" every target, applying validation facts unsoundly.
        self._entries = program_entries(all_blocks(prog))
        self._reach: dict = {}
        self._prog = prog
        self._phi_fed: "set | None" = None

    @property
    def phi_fed(self) -> set:
        """``id()`` of every value that feeds a phi.

        HAZARD: a phi arg arrives on ONE specific predecessor edge, and that
        edge may bypass the guard entirely — but :meth:`dominates` only ever
        sees a value's OP uses, never its phi consumers, so it cannot tell.
        Any narrowing of a phi-fed value is therefore unsound."""
        if self._phi_fed is None:
            self._phi_fed = {id(arg) for ph in self._prog.phis.values()
                             for arg in ph.args}
        return self._phi_fed

    def narrowing_is_sound(self, value, guard_block, guard_line: int,
                           *, exclude=None) -> bool:
        """May a guard at ``guard_block``:``guard_line`` narrow ``value``?

        Two conditions, and both are soundness rather than precision:

        * ``value`` must not be phi-fed (see :attr:`phi_fed`);
        * EVERY other op use of it must be dominated by the guard, since the
          narrowed fact lands on the SSAVar and is then read at every use —
          one branch's ``btoi(X)`` must not cap ``X`` in the other branch.

        ``exclude`` is the use that FORMS the guard, which is dominated by
        definition and would otherwise never qualify.

        The vacuous case — a value whose ONLY op use is the guard — passes
        ``all([])`` on zero dominance evidence, deliberately: nothing else
        reads a value with no other uses. A caller that needs strictness
        anyway must add its own ``if uses and ...`` before calling, as
        byte_taint's slice branch does.

        HAZARD: the phi test does NOT double as a non-vacuity check, though a
        comment here long claimed it did — measured on 200 mainnet contracts,
        0 of 7568 vacuous values were phi-fed."""
        if id(value) in self.phi_fed:
            return False
        return all(
            self.dominates(guard_block, u.basic_block, guard_line,
                           u.location.line)
            for u in getattr(value, "uses", ()) if u is not exclude
        )

    def dominates(self, guard_block, target_block, guard_line: int,
                  target_line: int) -> bool:
        if target_block is None:
            return False
        if target_block is guard_block:
            return target_line > guard_line
        reach = self._reach.get(guard_block)
        if reach is None:
            reach = self._reach[guard_block] = reachable_avoiding(
                self._entries, guard_block)
        return target_block not in reach
