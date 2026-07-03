"""Structural partition of a TEAL program.

Splits a :class:`tealql.tealtools.ssa.SSAProgram` into the three structural
roles a downstream analysis usually wants to isolate:

  - **subroutines** — every ``callsub``-reachable routine, with its
    entry BB, body BBs, label name, and the call sites that invoke it.
  - **call sites** ("f-calls") — every ``callsub`` op, with the
    subroutine it targets and the BB control returns to.
  - **routing** — the entry dispatch skeleton of the main flow: the
    maximal region, rooted at a program entry, of BBs that only branch
    / fall through (no side effects, no ``return`` / ``err`` / call) —
    i.e. the OnCompletion / method-selector dispatch that decides which
    handler runs. ``dispatch`` is the subset of routing BBs whose
    branch is on a recognised routing field.
  - **handlers** — the remaining main-flow BBs (the per-route bodies
    that do the actual work).

This is a data/partition API only — no rendering. Every BB belongs to
exactly one of: a subroutine body, the routing region, or the handler
region. Built on :func:`tealql.tealtools.control_tree.identify_subroutines`
(the same interprocedural pre-pass the control tree uses), so it agrees
with the control tree on what the subroutines are.

    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.structure import analyze_structure

    s = analyze_structure(SSAProgram("contract.teal"))
    for sub in s.subroutines:
        print(sub.name, len(sub.body), "called from", [c.line for c in sub.callers])
    routing_code = s.assignments_in(s.routing)   # feed a detector, etc.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .ssa import Assignment, BasicBlock, SSAProgram


# Ops that make a BB a *handler* (does real work) rather than pure
# dispatch. A BB containing any of these is never part of the routing
# region.
_SIDE_EFFECT_OPS = frozenset({
    "itxn_begin", "itxn_next", "itxn_submit", "itxn_field",
    "app_global_put", "app_local_put", "app_global_del", "app_local_del",
    "box_put", "box_create", "box_replace", "box_del",
    "log",
})

# Terminators that end a path (a trivial approve/reject handler) rather
# than route onward; reaching one closes the routing region.
_TERMINAL_OPS = frozenset({"return", "err"})
_CALL_OPS = frozenset({"callsub", "retsub"})

_COND_BRANCH = frozenset({"bnz", "bz", "switch", "match"})

# txn fields a dispatch typically branches on.
_ROUTING_FIELDS = frozenset({
    "OnCompletion", "TypeEnum", "Type", "NumAppArgs", "ApplicationID",
})

_TERM_OPS = _TERMINAL_OPS | _CALL_OPS


def _terminator(bb: BasicBlock) -> Optional[str]:
    """Last control-flow op of ``bb`` (mat-phi-copy tolerant)."""
    last: Optional[str] = None
    branch_or_term = _COND_BRANCH | {"b"} | _TERM_OPS
    for a in bb.assignments:
        if a.op in branch_or_term:
            last = a.op
    return last


def _has_side_effect(bb: BasicBlock) -> bool:
    return any(a.op in _SIDE_EFFECT_OPS for a in bb.assignments)


def _is_routing_internal(bb: BasicBlock) -> bool:
    """A BB belongs to the routing skeleton iff it does no real work and
    doesn't terminate / call — i.e. it only branches or falls through to
    more dispatch."""
    if _has_side_effect(bb):
        return False
    term = _terminator(bb)
    return term not in _TERM_OPS  # None (fall-through) or a branch is fine


@dataclass(frozen=True)
class CallSite:
    """One ``callsub`` invocation."""

    callsub_bb: BasicBlock
    line: int
    target_entry: Optional[BasicBlock]
    target_name: Optional[str]
    continuation_bb: Optional[BasicBlock]


@dataclass(frozen=True)
class Subroutine:
    """A ``callsub``-reachable routine."""

    entry_bb: BasicBlock
    name: Optional[str]
    body: frozenset[BasicBlock]
    callers: tuple[CallSite, ...] = ()


@dataclass
class ProgramStructure:
    """A structural partition of ``prog``. Every BB is in exactly one of
    ``routing``, ``handlers``, or some subroutine's ``body``."""

    prog: SSAProgram
    routing: frozenset[BasicBlock]
    handlers: frozenset[BasicBlock]
    dispatch: frozenset[BasicBlock]
    subroutines: tuple[Subroutine, ...]
    call_sites: tuple[CallSite, ...]

    def role_of(self, bb: BasicBlock) -> str:
        """``"routing"`` / ``"handler"`` / ``"subroutine"`` for ``bb``."""
        if bb in self.routing:
            return "routing"
        if any(bb in s.body for s in self.subroutines):
            return "subroutine"
        return "handler"

    def subroutine_of(self, bb: BasicBlock) -> Optional[Subroutine]:
        for s in self.subroutines:
            if bb in s.body:
                return s
        return None

    def assignments_in(self, bbs) -> list[Assignment]:
        """All assignments in ``bbs`` (a BB iterable), sorted by source
        position — a ready-to-feed slice for another analysis."""
        bb_set = set(bbs)
        out = [a for bb in bb_set for a in bb.assignments]
        out.sort(key=lambda a: (a.location.file, a.location.line))
        return out

    def handler_functions(self) -> list[tuple[str, frozenset]]:
        """Partition the handler BBs into per-route "functions" — the
        connected components of the handler subgraph (each dispatch
        target's body is its own component, since separate route bodies
        connect only through the routing region). Each is named by its
        entry BB's source label, else ``f{N}`` in entry order. Returns
        ``[(name, frozenset[BasicBlock])]`` ordered by entry line."""
        import networkx as nx

        h: "nx.Graph" = nx.Graph()
        h.add_nodes_from(self.handlers)
        for bb in self.handlers:
            for s in bb.successors:
                if s in self.handlers:
                    h.add_edge(bb, s)
        comps = sorted(
            nx.connected_components(h),
            key=lambda c: min(b.first_line for b in c),
        )
        labels = _label_map(self.prog)
        out: list[tuple[str, frozenset]] = []
        n = 0
        for comp in comps:
            entry = min(comp, key=lambda b: b.first_line)
            name = labels.get((entry.file, entry.first_line))
            if not name:
                n += 1
                name = f"f{n}"
            out.append((name, frozenset(comp)))
        return out

    def _is_arc4(self) -> bool:
        """Heuristic: the program reads the ABI method selector
        (``txna ApplicationArgs 0``) and has a dispatch — i.e. it routes
        like an ARC4 router."""
        if not self.dispatch:
            return False
        return any(
            a.op == "txna" and a.immediates.strip() == "ApplicationArgs 0"
            for a in self.prog.assignments
        )

    def _render_region(
        self, bbs, *, show_ranges: bool, max_width: Optional[int] = 160,
    ) -> list[str]:
        """Functional lines for ``bbs``, with BB-head labels interleaved
        so internal branch targets stay visible. ``max_width`` truncates
        very long lines (raw-SSA phi expansions can be enormous before
        the const/materialize passes collapse them); ``None`` disables."""
        bb_set = set(bbs)
        head_lines = {(bb.file, bb.first_line) for bb in bb_set}
        labels = _label_map(self.prog)
        items: list[tuple] = []
        for (f, ln) in head_lines:
            name = labels.get((f, ln))
            if name:
                items.append((ln, 0, f"  {name}:"))
        for a in self.assignments_in(bb_set):
            body = a.functional(show_ranges=show_ranges)
            if max_width is not None and len(body) > max_width:
                body = body[:max_width - 1] + "…"
            items.append((a.location.line, 1, f"    L{a.location.line:>4}: {body}"))
        items.sort(key=lambda x: (x[0], x[1]))
        return [text for _, _, text in items] or ["    (empty)"]

    def render(self, *, show_ranges: bool = False, max_width: Optional[int] = 160) -> str:
        """Decompilation-style dump: the routing region, then each
        handler function, then each subroutine — each as a labelled
        section with its actual functional lines below."""
        out: list[str] = []
        rname = "arc4_routing" if self._is_arc4() else "routing"
        out.append(f"{rname}:  // {len(self.routing)} BB(s)"
                   + (f", {len(self.dispatch)} dispatch" if self.routing else ""))
        out += self._render_region(self.routing, show_ranges=show_ranges, max_width=max_width)
        out.append("")
        for name, bbs in self.handler_functions():
            out.append(f"{name}():  // handler, {len(bbs)} BB(s)")
            out += self._render_region(bbs, show_ranges=show_ranges, max_width=max_width)
            out.append("")
        for sub in self.subroutines:
            callers = ", ".join(f"L{c.line}" for c in sub.callers) or "uncalled"
            out.append(
                f"{sub.name or '?'}():  // subroutine, {len(sub.body)} BB(s), "
                f"called from {callers}"
            )
            out += self._render_region(sub.body, show_ranges=show_ranges, max_width=max_width)
            out.append("")
        return "\n".join(out).rstrip() + "\n"

    def print(self, *, show_ranges: bool = False) -> None:
        print(self.render(show_ranges=show_ranges))


def _label_map(prog: SSAProgram) -> dict:
    """``(file, line) -> label name`` from the program's label table."""
    out: dict = {}
    for f, ln, code in prog.labels:
        out[(f, ln)] = code.rstrip(":").strip()
    return out


def _branches_on_routing_field(bb: BasicBlock, depth: int = 3) -> bool:
    """True if ``bb``'s terminator is a conditional branch whose
    condition derives from a recognised routing field (OnCompletion /
    TypeEnum / … / the ABI selector ``txna ApplicationArgs 0``)."""
    cond = None
    for a in bb.assignments:
        if a.op in _COND_BRANCH and a.inputs:
            cond = a.inputs[0]
    if cond is None:
        return False
    return _flows_from_routing_field(cond, depth)


def _flows_from_routing_field(operand, depth: int) -> bool:
    from .ssa import SSAVar
    if depth <= 0 or not isinstance(operand, SSAVar):
        return False
    a = operand.defined_by
    if a is None:
        return False
    if a.op == "txn" and a.immediates.strip() in _ROUTING_FIELDS:
        return True
    if a.op == "txna" and a.immediates.strip() == "ApplicationArgs 0":
        return True
    # Comparison / boolean combinator: recurse into operands.
    for inp in a.inputs:
        if _flows_from_routing_field(inp, depth - 1):
            return True
    return False


def analyze_structure(prog: SSAProgram) -> ProgramStructure:
    """Partition ``prog`` into routing / handlers / subroutines / call
    sites. See the module docstring for the precise definitions."""
    from .control_tree import identify_subroutines

    info = identify_subroutines(prog)
    bodies: dict = info["bodies"]
    callsub_target: dict = info["callsub_target"]
    continuations: dict = info["continuations"]
    labels = _label_map(prog)

    sub_body_bbs: set[BasicBlock] = set()
    for body in bodies.values():
        sub_body_bbs |= body

    # Call sites.
    call_sites: list[CallSite] = []
    callers_by_entry: dict = {}
    for cs_bb, target in callsub_target.items():
        # The callsub op's own line (last callsub in the BB).
        line = cs_bb.first_line
        for a in cs_bb.assignments:
            if a.op == "callsub":
                line = a.location.line
        tname = labels.get((target.file, target.first_line)) if target else None
        site = CallSite(
            callsub_bb=cs_bb,
            line=line,
            target_entry=target,
            target_name=tname,
            continuation_bb=continuations.get(cs_bb),
        )
        call_sites.append(site)
        if target is not None:
            callers_by_entry.setdefault(target, []).append(site)
    call_sites.sort(key=lambda c: (c.callsub_bb.file, c.line))

    # Subroutines.
    subroutines: list[Subroutine] = []
    for entry, body in bodies.items():
        subroutines.append(Subroutine(
            entry_bb=entry,
            name=labels.get((entry.file, entry.first_line)),
            body=frozenset(body),
            callers=tuple(callers_by_entry.get(entry, ())),
        ))
    subroutines.sort(key=lambda s: (s.entry_bb.file, s.entry_bb.first_line))

    # Routing: entry-rooted closure of routing-internal main-flow BBs.
    main_flow = [bb for bb in prog.blocks.values() if bb not in sub_body_bbs]
    main_set = set(main_flow)
    entries = [bb for bb in main_flow if not bb.predecessors]
    routing: set[BasicBlock] = set()
    stack = [bb for bb in entries if _is_routing_internal(bb)]
    while stack:
        bb = stack.pop()
        if bb in routing:
            continue
        routing.add(bb)
        for s in bb.successors:
            if s in main_set and s not in routing and _is_routing_internal(s):
                stack.append(s)

    handlers = frozenset(main_set - routing)
    dispatch = frozenset(bb for bb in routing if _branches_on_routing_field(bb))

    return ProgramStructure(
        prog=prog,
        routing=frozenset(routing),
        handlers=handlers,
        dispatch=dispatch,
        subroutines=tuple(subroutines),
        call_sites=tuple(call_sites),
    )
