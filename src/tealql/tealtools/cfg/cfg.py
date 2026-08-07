"""Basic-block CFG view of a TEAL program: reachability, dominance, loop
membership, DOT rendering — a thin view over ``SSAProgram``'s BBs.

HAZARD: results are cached lazily on the instance; rebuild via :meth:`CFG.of`
if the underlying ``SSAProgram`` changes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..ssa import BasicBlock, SSAProgram
from .._utils.dot import bb_label, escape, header, render, sanitize_id
from .dominance import (control_dependence, iterative_dominators,
                        program_entries)


@dataclass
class CFG:
    """A basic-block CFG for an :class:`SSAProgram`."""

    prog: SSAProgram
    blocks: list[BasicBlock] = field(default_factory=list)

    # --- construction --------------------------------------------------

    @classmethod
    def of(cls, prog: SSAProgram) -> "CFG":
        """Collect the BBs SSA construction already laid out into a CFG view."""
        return cls(
            prog=prog,
            blocks=sorted(
                prog.blocks.values(),
                key=lambda b: (b.file, b.first_line),
            ),
        )

    # --- structural queries -------------------------------------------

    @property
    def entries(self) -> list[BasicBlock]:
        """Per file, the BB holding that file's first instruction.

        HAZARD: NOT "BBs with no predecessors" — a program whose first block is
        a branch target (top-level loop) has none, and an empty entry set
        saturates dominance into everything-dominates-everything.
        Predecessor-less non-first BBs are dead code, not entries."""
        return program_entries(self.blocks)

    @property
    def exits(self) -> list[BasicBlock]:
        """BBs where the program can end: no successors (return / err), or a
        branch that runs off the end of the program.

        HAZARD: the second case has no ``successors`` entry to see — there is
        no target block — so it must be read off
        :attr:`SSAProgram.off_end_exits`. Missing it drops a real exit from the
        reversed graph, and post-dominance then over-concludes."""
        off_end = getattr(self.prog, "off_end_exits", ())
        return [b for b in self.blocks
                if not b.successors or b._key() in off_end]

    def block_at(self, file: str, line: int) -> Optional[BasicBlock]:
        """The BB whose source range contains ``(file, line)``."""
        return self.prog.block_containing(file, line)

    # --- reachability -------------------------------------------------

    def reachable_from(self, src: BasicBlock) -> set[BasicBlock]:
        """All BBs reachable from ``src``, including ``src`` itself."""
        seen: set[BasicBlock] = {src}
        queue: deque[BasicBlock] = deque([src])
        while queue:
            bb = queue.popleft()
            for s in bb.successors:
                if s not in seen:
                    seen.add(s)
                    queue.append(s)
        return seen

    def reachable_to(self, dst: BasicBlock) -> set[BasicBlock]:
        """All BBs that can reach ``dst``, including ``dst`` itself."""
        seen: set[BasicBlock] = {dst}
        queue: deque[BasicBlock] = deque([dst])
        while queue:
            bb = queue.popleft()
            for p in bb.predecessors:
                if p not in seen:
                    seen.add(p)
                    queue.append(p)
        return seen

    def reaches(self, src: BasicBlock, dst: BasicBlock) -> bool:
        """``True`` iff ``dst`` is reachable from ``src``."""
        if src is dst:
            return True
        return dst in self.reachable_from(src)

    # --- path enumeration ---------------------------------------------

    def paths(
        self,
        src: BasicBlock,
        dst: BasicBlock,
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[BasicBlock]]:
        """All *simple* (cycle-free) paths from ``src`` to ``dst``, shortest first.

        HAZARD: the result is TRUNCATED at ``max_paths`` (default 100) and pruned
        past ``max_length`` BBs, so a short result is no proof no other path
        exists. A BB never repeats, so loops need source-level unrolling.
        """
        if src is dst:
            return [[src]]
        out: list[list[BasicBlock]] = []

        # Explicit stack, not recursion: with `max_length=None` the walk is bounded
        # only by the block count, and ~1000-block programs overflow the limit.
        work: list = [(src, [src], {src})]
        while work:
            node, path, visited = work.pop()
            if len(out) >= max_paths:
                break
            if max_length is not None and len(path) > max_length:
                continue
            # Reversed so the pops preserve the original successor order.
            for s in reversed(list(node.successors)):
                if s in visited:
                    continue
                new_path = path + [s]
                if s is dst:
                    out.append(new_path)
                    if len(out) >= max_paths:
                        break
                    continue
                work.append((s, new_path, visited | {s}))
        out.sort(key=len)
        return out

    # --- dominance ----------------------------------------------------

    def dominators(self, target: BasicBlock) -> set[BasicBlock]:
        """BBs through which every entry-to-``target`` path passes; reflexive."""
        return self._all_dominators()[target]

    def post_dominators(self, source: BasicBlock) -> set[BasicBlock]:
        """BBs through which every ``source``-to-exit path passes; reflexive."""
        return self._all_post_dominators()[source]

    def dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        """``True`` iff every path from a CFG entry to ``b`` crosses ``a``."""
        return a in self.dominators(b)

    def strictly_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        return a is not b and self.dominates(a, b)

    def post_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        """``True`` iff every path from ``b`` to a CFG exit crosses ``a``."""
        return a in self.post_dominators(b)

    def strictly_post_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        return a is not b and self.post_dominates(a, b)

    def immediate_dominator(self, bb: BasicBlock) -> Optional[BasicBlock]:
        """The closest strict dominator of ``bb``; ``None`` for entries."""
        strict = self.dominators(bb) - {bb}
        if not strict:
            return None
        # idom = the strict dominator dominated by every other one (lowest in
        # the dominance tree).
        all_doms = self._all_dominators()
        for d in strict:
            if all(other is d or other in all_doms[d] for other in strict):
                return d
        return None  # disconnected / unreachable from any entry

    def immediate_post_dominator(self, bb: BasicBlock) -> Optional[BasicBlock]:
        """The unique closest strict post-dominator of ``bb``."""
        strict = self.post_dominators(bb) - {bb}
        if not strict:
            return None
        all_post = self._all_post_dominators()
        for d in strict:
            if all(other is d or other in all_post[d] for other in strict):
                return d
        return None

    def _all_dominators(self) -> dict[BasicBlock, set[BasicBlock]]:
        cached = getattr(self, "_dom_cache", None)
        if cached is not None:
            return cached
        dom = iterative_dominators(
            self.blocks, self.entries, lambda b: b.predecessors,
        )
        self._dom_cache = dom  # type: ignore[attr-defined]
        return dom

    def _all_post_dominators(self) -> dict[BasicBlock, set[BasicBlock]]:
        cached = getattr(self, "_pdom_cache", None)
        if cached is not None:
            return cached
        # Post-dominance is dominance on the reversed CFG: exits become entries.
        post = iterative_dominators(
            self.blocks, self.exits, lambda b: b.successors,
        )
        # HAZARD: a block reaching NO exit (infinite-loop region, or a whole
        # program with no return/err) is unreachable on the reversed graph and
        # comes out SATURATED — reading as "everything post-dominates it", the
        # unsound direction for "is this check unavoidable after that action".
        # Nothing post-dominates a block that never terminates.
        can_exit: set = set(self.exits)
        stack = list(can_exit)
        while stack:
            b = stack.pop()
            for p in b.predecessors:
                if p not in can_exit:
                    can_exit.add(p)
                    stack.append(p)
        for b in self.blocks:
            if b not in can_exit:
                post[b] = {b}
        self._pdom_cache = post  # type: ignore[attr-defined]
        return post

    # --- control dependence -------------------------------------------

    def control_dependence(self) -> dict:
        """``BasicBlock -> {(branch block, edge label)}`` — the branches whose
        OUTCOME decides whether the block runs.

        Sharper than dominance for "what gates this": a dominator may be crossed
        by every path while gating nothing, whereas a control dependence could
        have skipped the block. **An empty set means the block runs
        unconditionally** — for a fund-moving sink, that is the finding.

        Edge labels are the CFG builder's own polarity (``true`` / ``false`` /
        ``normal``), or ``None`` where a branch's arms collapse onto one block
        and it therefore partitions nothing."""
        cached = getattr(self, "_cd_cache", None)
        if cached is not None:
            return cached
        polarity = getattr(self.prog, "edge_polarity", {})

        def label(a: BasicBlock, b: BasicBlock):
            kinds = polarity.get((a._key(), b._key()), frozenset())
            return next(iter(kinds)) if len(kinds) == 1 else None

        # A block ending in `assert` continues OR the program dies. Without
        # that alternative its single successor post-dominates it and the
        # assert — the dominant guard idiom in compiler output — gates nothing.
        may_abort = [b for b in self.blocks
                     if b.assignments and b.assignments[-1].op == "assert"]
        cd = control_dependence(
            self.blocks, lambda b: b.successors, self.exits,
            may_abort=may_abort, edge_label=label,
        )
        self._cd_cache = cd  # type: ignore[attr-defined]
        return cd

    def gating_branches(self, bb: BasicBlock) -> set:
        """Every branch gating ``bb``, TRANSITIVELY — control dependence is not
        transitive by construction, so a guard two levels up is only visible by
        walking the graph."""
        cd = self.control_dependence()
        out: set = set()
        work = list(cd.get(bb, ()))
        while work:
            entry = work.pop()
            if entry in out:
                continue
            out.add(entry)
            work.extend(cd.get(entry[0], ()))
        return out

    def control_dependence_dot(
        self, *, file: Optional[str] = None, rankdir: str = "TB",
    ) -> str:
        """The CDG as Graphviz DOT: an edge ``guard -> gated`` per dependence,
        coloured by polarity, with unconditional blocks boxed in red.

        Reads inverted from the CFG on purpose — an arrow points from a branch
        to what it GATES, so the guards of any block are its in-edges, and a
        block with none runs unconditionally."""
        cd = self.control_dependence()
        blocks = [b for b in self.blocks if file is None or b.file == file]
        shown = set(blocks)
        out: list[str] = header("CDG", rankdir=rankdir)
        for bb in blocks:
            style = ('shape=box, style="rounded,filled", fillcolor="#f4f4f8"'
                     if cd.get(bb) else
                     # Nothing can skip it.
                     'shape=box, style="rounded,filled", fillcolor="#ffe8e6",'
                     ' color="#c0392b", penwidth=2')
            label = f"L{bb.first_line}-L{bb.last_line}"
            out.append(f'  {_bb_id(bb)} [label="{escape(label)}", {style}];')
        for bb in blocks:
            for branch, polarity in sorted(
                cd.get(bb, ()), key=lambda e: (e[0].first_line, str(e[1]))
            ):
                if branch not in shown:
                    continue
                colour = {"true": '"#2a8f3c"', "false": '"#c0392b"'}.get(
                    polarity, '"#777777"')
                tag = polarity if polarity in ("true", "false") else ""
                out.append(f'  {_bb_id(branch)} -> {_bb_id(bb)} '
                           f'[color={colour}, fontcolor={colour}, label="{tag}"];')
        out.append("}")
        return "\n".join(out)

    def draw_control_dependence(
        self, *, file: Optional[str] = None, format: str = "svg",
        engine: str = "dot", rankdir: str = "TB",
    ):
        """Render :meth:`control_dependence_dot` (Jupyter-renderable SVG)."""
        return render(self.control_dependence_dot(file=file, rankdir=rankdir),
                      format=format, engine=engine)

    # --- loop membership ----------------------------------------------

    def in_loop(self, bb: BasicBlock) -> bool:
        """``True`` iff ``bb`` is on a CFG cycle."""
        return bb in self.loop_blocks()

    def loop_blocks(self) -> set[BasicBlock]:
        """Every BB participating in any cycle — one cached SCC pass, since
        ``in_loop`` is called per block."""
        cached = getattr(self, "_loop_blocks_cache", None)
        if cached is not None:
            return cached
        import networkx as nx

        g = nx.DiGraph()
        g.add_nodes_from(self.blocks)
        for b in self.blocks:
            for s in b.successors:
                g.add_edge(b, s)
        out: set[BasicBlock] = set()
        for comp in nx.strongly_connected_components(g):
            if len(comp) > 1:
                out |= comp
            else:
                (only,) = comp
                if g.has_edge(only, only):
                    out.add(only)
        self._loop_blocks_cache = out  # type: ignore[attr-defined]
        return out

    # --- DOT rendering ------------------------------------------------

    def to_dot(
        self,
        *,
        file: Optional[str] = None,
        rankdir: str = "TB",
        with_assignments: bool = True,
    ) -> str:
        """Render the CFG as a Graphviz DOT string, optionally restricted to
        the BBs of one source ``file``."""
        blocks = (
            self.blocks if file is None
            else [b for b in self.blocks if b.file == file]
        )
        out: list[str] = header("CFG", rankdir=rankdir)
        for bb in blocks:
            nid = _bb_id(bb)
            label = _bb_label(bb, with_assignments=with_assignments)
            out.append(f'  {nid} [label="{label}"];')
        emitted: set[tuple[str, str]] = set()
        for bb in blocks:
            nid = _bb_id(bb)
            for s in bb.successors:
                if file is not None and s.file != file:
                    continue
                sid = _bb_id(s)
                key = (nid, sid)
                if key in emitted:
                    continue
                emitted.add(key)
                out.append(f"  {nid} -> {sid};")
        out.append("}")
        return "\n".join(out)


def _bb_id(bb: BasicBlock) -> str:
    return f"bb_{sanitize_id(bb.file)}_{bb.first_line}_{bb.last_line}"


def _bb_label(bb: BasicBlock, *, with_assignments: bool) -> str:
    head = f"BB L{bb.first_line}-L{bb.last_line}"
    lines = []
    if with_assignments:
        for a in bb.assignments:
            body = f"{a.op} {a.immediates.strip()}".strip()
            lines.append(f"L{a.location.line}: {body}")
    return bb_label(head, lines)
