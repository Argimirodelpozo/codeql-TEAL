"""Cross-contract *super*-CFG: one basic-block graph spanning a caller plus every
transitively-reachable callee, so reachability / dominance / path queries span
the whole call graph (e.g. "does a caller guard dominate a callee sink?").

Blocks are qualified by the contract they live in (:class:`SuperBlock`,
``app_id=None`` = the root caller). At each appcall site — a clean BB boundary,
since ``itxn_submit`` ENDS a basic block (:mod:`tealql.tealtools.cfg.build`) — two
edges are spliced in ADDITIVELY, without mutating any per-program CFG: a **call**
edge (submit BB -> callee entry) and a **return** edge (each callee exit -> the
submit BB's intra successors). The submit BB's own fall-through is kept, so it
stays the classic call-to-return-site edge carrying the caller's locals.

HAZARD: context-insensitive, so it OVER-approximates — a callee shared by several
call sites returns to EVERY caller's continuation (call/return mismatch), and
``err`` exits get return edges though a rejecting callee aborts the whole atomic
group. Sound for reachability; matching calls to returns (IFDS-style) and
approve-vs-reject are the consuming analysis's job, not the graph's.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..ssa import BasicBlock, SSAProgram
from ..intercontract.analysis import AppcallSite, Registry, XContractGraph
from .._utils.dot import bb_label, header, sanitize_id
from .cfg import CFG
from .dominance import iterative_dominators


@dataclass(frozen=True)
class SuperBlock:
    """A basic block qualified by its contract (``app_id=None`` = root caller,
    an ``int`` = a callee AppID)."""

    app_id: Optional[int]
    bb: BasicBlock

    def __repr__(self) -> str:
        scope = "root" if self.app_id is None else f"app{self.app_id}"
        return f"{scope}:L{self.bb.first_line}-L{self.bb.last_line}"


@dataclass(frozen=True)
class SuperEdge:
    """A typed inter-program edge (``kind`` is ``"call"`` or ``"return"``); intra
    edges are not recorded here, they live in the per-program CFGs."""

    src: SuperBlock
    dst: SuperBlock
    kind: str
    site: AppcallSite


@dataclass
class SuperCFG:
    """A CFG spanning a caller and its transitive callees, mirroring the
    :class:`CFG` query surface over the unified super-adjacency."""

    cfgs: dict[Optional[int], CFG]
    inter_edges: list[SuperEdge]
    _succ: dict[SuperBlock, list[SuperBlock]] = field(default_factory=dict)
    _pred: dict[SuperBlock, list[SuperBlock]] = field(default_factory=dict)

    # --- construction --------------------------------------------------

    @classmethod
    def build(
        cls,
        caller: SSAProgram,
        registry: Registry | str,
        *,
        max_depth: int = 4,
    ) -> "SuperCFG":
        """Build the super-CFG transitively from ``caller`` over ``registry``
        (a :class:`Registry`, or a path to one)."""
        if isinstance(registry, str):
            from ..intercontract.analysis import load_registry
            registry = load_registry(registry)
        xg = XContractGraph.build(caller, registry, max_depth=max_depth)
        cfgs: dict[Optional[int], CFG] = {None: CFG.of(xg.caller)}
        for app_id, prog in xg.callees.items():
            cfgs[app_id] = CFG.of(prog)
        return cls._assemble(cfgs, xg)

    @classmethod
    def _assemble(cls, cfgs: dict[Optional[int], CFG], xg: XContractGraph) -> "SuperCFG":
        succ: dict[SuperBlock, list[SuperBlock]] = {}
        pred: dict[SuperBlock, list[SuperBlock]] = {}

        def node(app_id: Optional[int], bb: BasicBlock) -> SuperBlock:
            sb = SuperBlock(app_id, bb)
            succ.setdefault(sb, [])
            pred.setdefault(sb, [])
            return sb

        def link(u: SuperBlock, v: SuperBlock) -> None:
            succ[u].append(v)
            pred[v].append(u)

        # 1. Every program's intra-CFG edges, qualified by AppID.
        for app_id, cfg in cfgs.items():
            for bb in cfg.blocks:
                u = node(app_id, bb)
                for s in bb.successors:
                    link(u, node(app_id, s))

        # 2. One call + return splice per appcall edge in the call graph.
        inter: list[SuperEdge] = []
        for edge in xg.edges:
            caller_id = edge.caller_app_id
            site = edge.site
            callee_id = site.app_id
            caller_cfg = cfgs.get(caller_id)
            callee_cfg = cfgs.get(callee_id)
            if caller_cfg is None or callee_cfg is None:
                continue
            submit_bb = caller_cfg.block_at(site.file, site.submit_line)
            entry_bb = _program_entry(callee_cfg)
            if submit_bb is None or entry_bb is None:
                continue
            submit_sb = node(caller_id, submit_bb)
            entry_sb = node(callee_id, entry_bb)
            link(submit_sb, entry_sb)
            inter.append(SuperEdge(submit_sb, entry_sb, "call", site))
            # Continuations = the submit BB's intra successors (the fall-through
            # after the submit).
            continuations = [node(caller_id, s) for s in submit_bb.successors]
            for ex in callee_cfg.exits:
                ex_sb = node(callee_id, ex)
                for cont in continuations:
                    link(ex_sb, cont)
                    inter.append(SuperEdge(ex_sb, cont, "return", site))

        return cls(cfgs=cfgs, inter_edges=inter, _succ=succ, _pred=pred)

    # --- structural queries -------------------------------------------

    def blocks(self) -> list[SuperBlock]:
        return list(self._succ.keys())

    def successors(self, sb: SuperBlock) -> list[SuperBlock]:
        return self._succ.get(sb, [])

    def predecessors(self, sb: SuperBlock) -> list[SuperBlock]:
        return self._pred.get(sb, [])

    @property
    def root_entry(self) -> Optional[SuperBlock]:
        """The root caller's program entry — the single true entry of the whole
        super-CFG, since callee entries gain a call-edge predecessor."""
        entry = _program_entry(self.cfgs[None])
        return SuperBlock(None, entry) if entry is not None else None

    @property
    def entries(self) -> list[SuperBlock]:
        """Super-blocks with no predecessor: the root entry plus unreachable
        blocks (never a callee entry — its call edge is a predecessor)."""
        return [sb for sb in self._succ if not self._pred.get(sb)]

    @property
    def exits(self) -> list[SuperBlock]:
        """Super-blocks with no successor — exits that return to no caller."""
        return [sb for sb in self._succ if not self._succ.get(sb)]

    # --- reachability -------------------------------------------------

    def reachable_from(self, src: SuperBlock) -> set[SuperBlock]:
        seen: set[SuperBlock] = {src}
        queue: deque[SuperBlock] = deque([src])
        while queue:
            for s in self.successors(queue.popleft()):
                if s not in seen:
                    seen.add(s)
                    queue.append(s)
        return seen

    def reachable_to(self, dst: SuperBlock) -> set[SuperBlock]:
        seen: set[SuperBlock] = {dst}
        queue: deque[SuperBlock] = deque([dst])
        while queue:
            for p in self.predecessors(queue.popleft()):
                if p not in seen:
                    seen.add(p)
                    queue.append(p)
        return seen

    def reaches(self, src: SuperBlock, dst: SuperBlock) -> bool:
        return src is dst or dst in self.reachable_from(src)

    # --- path enumeration ---------------------------------------------

    def paths(
        self,
        src: SuperBlock,
        dst: SuperBlock,
        *,
        max_paths: int = 100,
        max_length: Optional[int] = None,
    ) -> list[list[SuperBlock]]:
        """All simple (cycle-free) paths ``src`` -> ``dst`` across the boundary,
        shortest first; the caps and their hazard mirror :meth:`CFG.paths`."""
        if src == dst:
            return [[src]]
        out: list[list[SuperBlock]] = []

        def dfs(node: SuperBlock, path: list[SuperBlock], visited: set[SuperBlock]) -> None:
            if len(out) >= max_paths:
                return
            if max_length is not None and len(path) > max_length:
                return
            for s in self.successors(node):
                if s in visited:
                    continue
                new_path = path + [s]
                if s == dst:
                    out.append(new_path)
                    if len(out) >= max_paths:
                        return
                    continue
                dfs(s, new_path, visited | {s})

        dfs(src, [src], {src})
        out.sort(key=len)
        return out

    # --- dominance ----------------------------------------------------

    def dominators(self, target: SuperBlock) -> set[SuperBlock]:
        """Super-blocks every root-entry-to-``target`` path crosses — spanning the
        appcall boundary, so a caller block can dominate a callee block."""
        return self._all_dominators().get(target, {target})

    def dominates(self, a: SuperBlock, b: SuperBlock) -> bool:
        return a in self.dominators(b)

    def strictly_dominates(self, a: SuperBlock, b: SuperBlock) -> bool:
        return a is not b and self.dominates(a, b)

    def _all_dominators(self) -> dict[SuperBlock, set[SuperBlock]]:
        cached = getattr(self, "_dom_cache", None)
        if cached is not None:
            return cached
        # HAZARD: entry = the root program's real entry ONLY. ``self.entries``
        # (no-pred super-blocks) is empty when the root's first block is a branch
        # target, which would saturate dominance; dead no-pred blocks aren't
        # entries.
        root = self.root_entry
        dom = iterative_dominators(
            self._succ.keys(),
            [root] if root is not None else self.entries,
            lambda sb: self._pred.get(sb, ()),
        )
        self._dom_cache = dom  # type: ignore[attr-defined]
        return dom

    # --- DOT rendering ------------------------------------------------

    def to_dot(self, *, with_assignments: bool = False) -> str:
        """Render the super-CFG: one Graphviz cluster per contract, intra edges
        solid, call edges blue, return edges red (dashed)."""
        out: list[str] = header("SuperCFG")
        for app_id, cfg in self.cfgs.items():
            scope = "root" if app_id is None else f"app{app_id}"
            out.append(f'  subgraph cluster_{scope} {{')
            out.append(f'    label="{scope}";')
            for bb in cfg.blocks:
                sb = SuperBlock(app_id, bb)
                out.append(f'    {_sb_id(sb)} [label="{_sb_label(sb, with_assignments)}"];')
            for bb in cfg.blocks:
                u = SuperBlock(app_id, bb)
                for s in bb.successors:
                    out.append(f"    {_sb_id(u)} -> {_sb_id(SuperBlock(app_id, s))};")
            out.append("  }")
        for e in self.inter_edges:
            style = ('color=blue' if e.kind == "call"
                     else 'color=red, style=dashed')
            out.append(f'  {_sb_id(e.src)} -> {_sb_id(e.dst)} [{style}];')
        out.append("}")
        return "\n".join(out)


# --- helpers ------------------------------------------------------


def _program_entry(cfg: CFG) -> Optional[BasicBlock]:
    """A program's main entry: the topmost of :attr:`CFG.entries` (per-file
    first blocks), i.e. where execution starts."""
    ents = cfg.entries
    if not ents:
        return None
    return min(ents, key=lambda b: (b.file, b.first_line))


def _sb_id(sb: SuperBlock) -> str:
    scope = "root" if sb.app_id is None else f"app{sb.app_id}"
    return f"n_{scope}_{sanitize_id(sb.bb.file)}_{sb.bb.first_line}_{sb.bb.last_line}"


def _sb_label(sb: SuperBlock, with_assignments: bool) -> str:
    lines = []
    if with_assignments:
        for a in sb.bb.assignments:
            lines.append(f"L{a.location.line}: {a.op} {a.immediates.strip()}".rstrip())
    return bb_label(f"{sb!r}", lines)
