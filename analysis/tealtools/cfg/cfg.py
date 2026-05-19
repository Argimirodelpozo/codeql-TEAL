"""Basic-block CFG view of a TEAL program.

Thin abstraction over :class:`tealtools.ssa.SSAProgram`'s already-built
BB structure. Three concerns only:

1. **Build** — :meth:`CFG.of` collects ``prog.blocks`` into one object.
2. **Predicates** — reachability (forward / backward), dominance,
   loop membership, entry / exit identification.
3. **Render** — ``to_dot()`` emits a Graphviz string.

Everything is per-method-cached lazily; rebuild via :meth:`CFG.of` if
the underlying ``SSAProgram`` changes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..ssa import BasicBlock, SSAProgram


@dataclass
class CFG:
    """A basic-block CFG for an :class:`SSAProgram`."""

    prog: SSAProgram
    blocks: list[BasicBlock] = field(default_factory=list)

    # --- construction --------------------------------------------------

    @classmethod
    def of(cls, prog: SSAProgram) -> "CFG":
        """Build the CFG view from a program. Cheap — just collects
        the BBs already laid out by SSA construction."""
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
        """BBs with no predecessors (program / subroutine entry points)."""
        return [b for b in self.blocks if not b.predecessors]

    @property
    def exits(self) -> list[BasicBlock]:
        """BBs with no successors (program-end terminators: return / err)."""
        return [b for b in self.blocks if not b.successors]

    def block_at(self, file: str, line: int) -> Optional[BasicBlock]:
        """The BB whose source range contains ``(file, line)``."""
        return self.prog.block_containing(file, line)

    # --- reachability -------------------------------------------------

    def reachable_from(self, src: BasicBlock) -> set[BasicBlock]:
        """All BBs reachable from ``src`` along the CFG. Includes
        ``src`` itself even if it has no successors."""
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
        """All BBs that can reach ``dst`` (i.e. on some path to it).
        Includes ``dst``."""
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
        """All *simple* (cycle-free) paths from ``src`` to ``dst``,
        sorted by length (shortest first).

        ``max_paths``: cap the number of paths returned — programs
        with many branches can blow up exponentially. Default 100.
        ``max_length``: optional per-path BB-count cap; if a search
        branch grows past it, it's pruned. ``None`` = no cap.

        Cycles are broken by the simple-path constraint: a BB never
        appears twice in the same path. For loop-aware enumeration,
        unroll the loop in the source first.
        """
        if src is dst:
            return [[src]]
        out: list[list[BasicBlock]] = []

        def dfs(node: BasicBlock, path: list[BasicBlock], visited: set[BasicBlock]) -> None:
            if len(out) >= max_paths:
                return
            if max_length is not None and len(path) > max_length:
                return
            for s in node.successors:
                if s in visited:
                    continue  # skip back-edge / cycle
                new_path = path + [s]
                if s is dst:
                    out.append(new_path)
                    if len(out) >= max_paths:
                        return
                    continue
                dfs(s, new_path, visited | {s})

        dfs(src, [src], {src})
        out.sort(key=len)
        return out

    # --- dominance ----------------------------------------------------

    def dominators(self, target: BasicBlock) -> set[BasicBlock]:
        """All BBs that dominate ``target`` — every path from a CFG
        entry to ``target`` passes through every dominator. Includes
        ``target`` itself.

        Standard fixpoint: ``dom(entry) = {entry}``;
        ``dom(b) = {b} ∪ ⋂_p dom(p)`` over predecessors.
        """
        return self._all_dominators()[target]

    def post_dominators(self, source: BasicBlock) -> set[BasicBlock]:
        """All BBs that post-dominate ``source`` — every path from
        ``source`` to a CFG exit passes through every post-dominator.
        Symmetric to :meth:`dominators` on the reversed CFG."""
        return self._all_post_dominators()[source]

    def dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        """``True`` iff every path from a CFG entry to ``b`` passes
        through ``a``. Reflexive: ``dominates(b, b) is True``."""
        return a in self.dominators(b)

    def strictly_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        return a is not b and self.dominates(a, b)

    def post_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        """``True`` iff every path from ``b`` to a CFG exit passes
        through ``a``. Reflexive."""
        return a in self.post_dominators(b)

    def strictly_post_dominates(self, a: BasicBlock, b: BasicBlock) -> bool:
        return a is not b and self.post_dominates(a, b)

    def immediate_dominator(self, bb: BasicBlock) -> Optional[BasicBlock]:
        """The unique closest strict dominator of ``bb``, if any.
        Entries (and unreachable BBs) return ``None``."""
        strict = self.dominators(bb) - {bb}
        if not strict:
            return None
        # idom = the dominator that's dominated by every other strict
        # dominator (i.e. lowest in the dominance tree).
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
        all_blocks = set(self.blocks)
        entries = set(self.entries)
        dom: dict[BasicBlock, set[BasicBlock]] = {
            bb: ({bb} if bb in entries else set(all_blocks))
            for bb in self.blocks
        }
        changed = True
        while changed:
            changed = False
            for bb in self.blocks:
                if bb in entries:
                    continue
                if not bb.predecessors:
                    continue  # unreachable; leave as-is
                new = {bb} | set.intersection(
                    *(dom[p] for p in bb.predecessors)
                )
                if new != dom[bb]:
                    dom[bb] = new
                    changed = True
        self._dom_cache = dom  # type: ignore[attr-defined]
        return dom

    def _all_post_dominators(self) -> dict[BasicBlock, set[BasicBlock]]:
        cached = getattr(self, "_pdom_cache", None)
        if cached is not None:
            return cached
        all_blocks = set(self.blocks)
        exits = set(self.exits)
        post: dict[BasicBlock, set[BasicBlock]] = {
            bb: ({bb} if bb in exits else set(all_blocks))
            for bb in self.blocks
        }
        changed = True
        while changed:
            changed = False
            for bb in self.blocks:
                if bb in exits:
                    continue
                if not bb.successors:
                    continue
                new = {bb} | set.intersection(
                    *(post[s] for s in bb.successors)
                )
                if new != post[bb]:
                    post[bb] = new
                    changed = True
        self._pdom_cache = post  # type: ignore[attr-defined]
        return post

    # --- loop membership ----------------------------------------------

    def in_loop(self, bb: BasicBlock) -> bool:
        """``True`` iff ``bb`` is on a CFG cycle (reachable from itself
        via at least one edge)."""
        for s in bb.successors:
            if bb in self.reachable_from(s):
                return True
        return False

    def loop_blocks(self) -> set[BasicBlock]:
        """Every BB that participates in any cycle. Useful for
        cost / iteration analyses that need to flag unbounded
        regions conservatively."""
        return {bb for bb in self.blocks if self.in_loop(bb)}

    # --- DOT rendering ------------------------------------------------

    def to_dot(
        self,
        *,
        file: Optional[str] = None,
        rankdir: str = "TB",
        with_assignments: bool = True,
    ) -> str:
        """Render the CFG as a Graphviz DOT string.

        ``file``: restrict to BBs in this source file (e.g. when a DB
        spans multiple ``.teal`` sources).
        ``with_assignments``: include each BB's opcode list in the
        node label. Set ``False`` for a tiny, structural-only graph.
        """
        blocks = (
            self.blocks if file is None
            else [b for b in self.blocks if b.file == file]
        )
        out: list[str] = ["digraph CFG {"]
        out.append(f"  rankdir={rankdir};")
        out.append('  node [shape=box, fontname="monospace"];')
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
    safe = bb.file.replace("/", "_").replace(".", "_").replace("-", "_")
    return f"bb_{safe}_{bb.first_line}_{bb.last_line}"


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _bb_label(bb: BasicBlock, *, with_assignments: bool) -> str:
    head = f"BB L{bb.first_line}-L{bb.last_line}"
    if not with_assignments or not bb.assignments:
        return _dot_escape(head)
    lines = [head]
    for a in bb.assignments:
        op = a.op
        im = a.immediates.strip()
        body = f"{op} {im}".strip()
        lines.append(f"L{a.location.line}: {body}")
    # `\\l` left-aligns each line in DOT.
    return _dot_escape("\\l".join(lines)) + "\\l"
