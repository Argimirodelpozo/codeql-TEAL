"""Per-line stack simulation for a TEAL program.

Sits on top of :mod:`teal_ssa`. For every :class:`teal_ssa.Assignment`,
records the ordered stack contents BEFORE and AFTER the opcode executes,
using the same typed operands (:class:`SSAVar`, :class:`Phi`,
:class:`MatPhiVar`, :class:`Const`) the SSA layer already produced. No
new symbolic identities are introduced — retsub-output SSAVars surface
as :class:`Phi`\\ s at the post-callsub BB exactly the way the SSA model
already represents them, and the simulation just re-anchors them to a
per-line snapshot.

    from teal_ssa import SSAProgram
    from teal_stacksim import StackSimulation

    prog = SSAProgram("tests/dbs/xgov-db")
    sim = StackSimulation(prog)

    snap = sim.at(file="approval.teal", line=42)
    snap.in_stack    # bottom-first list of operands before line 42 runs
    snap.out_stack   # bottom-first list after line 42

    print(sim.render(file="approval.teal", line_range=(40, 60)))

Snapshots are immutable and hashable by ``(file, line)`` — the same
identity convention :mod:`teal_ast` uses, so a :class:`StackSnapshot`
can sit beside an :class:`teal_ast.AstNode` in any analysis-pass index.

Stack convention
----------------

``in_stack`` and ``out_stack`` are **bottom-first**: index ``0`` is the
deepest slot, index ``-1`` is the topmost. This matches Python's natural
list semantics — append to push, pop from the end. Note that this is the
*opposite* of :class:`Assignment`'s ``inputs`` / ``outputs``, which are
top-first; the simulation translates between the two when applying each
opcode's effect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional, Union

from teal_ssa import (
    Assignment,
    BasicBlock,
    Const,
    Location,
    MatPhiVar,
    Phi,
    SSAProgram,
    SSAVar,
)


# A single slot on the simulated stack. Reuses the SSA layer's typed
# operands directly so consumers of the simulation can chain into
# ``defined_by`` / ``uses`` / ``const_value`` / ``range`` without an
# extra indirection. ``Const`` only appears after :meth:`SSAProgram.
# eliminate_dead_constants` has been run.
StackSlot = Union[SSAVar, Phi, MatPhiVar, Const]


@dataclass(frozen=True)
class StackSnapshot:
    """Stack contents bracketing a single TEAL opcode.

    Identity is ``(file, line)``, matching :class:`teal_ast.AstNode` and
    :class:`teal_ssa.Assignment`. ``assignment`` back-references the SSA
    assignment so consumers can pivot to the typed inputs/outputs view.
    ``ast_node`` is the matching :class:`teal_ast.AstNode` from the
    underlying :mod:`teal_graphs` graph (``None`` only if the line has
    no syntactic node, which shouldn't happen for an Assignment).

    Both stack tuples are **bottom-first** — see module docstring.
    """

    location: Location
    in_stack: tuple[StackSlot, ...]
    out_stack: tuple[StackSlot, ...]
    assignment: Assignment
    ast_node: Optional[object] = None  # teal_ast.AstNode; not typed to avoid the import.

    @property
    def file(self) -> str:
        return self.location.file

    @property
    def line(self) -> int:
        return self.location.line

    def in_top(self, n: int = 1) -> tuple[StackSlot, ...]:
        """Topmost ``n`` IN slots, returned **top-first** (top of stack
        at index 0). Useful for matching against `assignment.inputs`,
        which is also top-first."""
        if n <= 0 or not self.in_stack:
            return ()
        return tuple(reversed(self.in_stack[-n:]))

    def out_top(self, n: int = 1) -> tuple[StackSlot, ...]:
        """Topmost ``n`` OUT slots, top-first."""
        if n <= 0 or not self.out_stack:
            return ()
        return tuple(reversed(self.out_stack[-n:]))

    def __repr__(self) -> str:
        in_s = _fmt_stack(self.in_stack)
        out_s = _fmt_stack(self.out_stack)
        return f"L{self.line}: in={in_s} out={out_s}"


def _fmt_slot(s: StackSlot) -> str:
    """Compact slot label. SSAVars / Phis / MatPhiVars use their
    existing ``__repr__``; constants render as their literal value."""
    if isinstance(s, Const):
        return s.value
    return repr(s)


def _fmt_stack(stack: tuple[StackSlot, ...]) -> str:
    if not stack:
        return "[]"
    return "[" + ", ".join(_fmt_slot(s) for s in stack) + "]"


class StackSimulation:
    """Per-line stack snapshots for a :class:`SSAProgram`.

    Construction walks each :class:`BasicBlock` once, deriving its entry
    stack from the BB's phis and applying each :class:`Assignment`'s
    stack effect line by line. The simulation is purely structural —
    it neither runs the propagation passes on ``prog`` nor mutates it.

    Re-running a propagation pass on ``prog`` after building the
    simulation does NOT update existing snapshots; rebuild the
    simulation if the SSA structure changed.
    """

    def __init__(self, prog: SSAProgram):
        self.prog = prog
        # Snapshots indexed two ways:
        # - by_assignment: primary store, keyed by the Python identity
        #   of the Assignment (Assignment is unhashable post-mutation
        #   in some passes, so we use ``id(...)``).
        # - by_line: convenience lookup keyed by ``(file, line)`` for
        #   line-anchored analysis passes that don't already hold the
        #   Assignment.
        self._by_assignment_id: dict[int, StackSnapshot] = {}
        self.by_line: dict[tuple[str, int], StackSnapshot] = {}
        # (file, line) -> AstNode lookup, lazily populated on demand.
        self._ast_index: Optional[dict[tuple[str, int], object]] = None
        # ``SSAProgram`` materialises phis lazily — only those referenced
        # by some ``Assignment.inputs`` survive ``__init__`` pass 1. The
        # simulation needs every BB-entry phi (including those whose
        # successor consumes 0 args, e.g. ``return`` at the post-callsub
        # line, where the retsub-output phi is on the stack but unread).
        # We patch them in by walking the underlying graph's PhiNodes.
        self._inject_unreferenced_bb_entry_phis()
        self._build()

    # -- construction ------------------------------------------------

    def _build(self) -> None:
        # Stable order: deeper-nested call patterns expect snapshots in
        # source-listing order on iteration; sort blocks accordingly.
        blocks = sorted(
            self.prog.blocks.values(),
            key=lambda bb: (bb.file, bb.first_line),
        )
        ast_index = self._get_ast_index()
        for bb in blocks:
            stack: list[StackSlot] = list(_bb_entry_stack(bb))
            for a in bb.assignments:
                in_stack = tuple(stack)
                # Consume top |a.inputs| slots. ``a.inputs`` is top-first
                # (inputs[0] is topmost); our stack is bottom-first, so
                # the topmost N elements are ``stack[-N:]``. We don't
                # validate equality with reversed(a.inputs) — the SSA
                # layer is authoritative; if they disagree the SSA
                # model has a bug and we want it to surface elsewhere.
                n_consumed = len(a.inputs)
                if n_consumed > 0:
                    stack = stack[:-n_consumed]
                # Push outputs. ``a.outputs`` is top-first too, so
                # to land outputs[0] on top we extend with the
                # bottom-first projection (i.e. reversed).
                stack.extend(reversed(a.outputs))
                out_stack = tuple(stack)
                snap = StackSnapshot(
                    location=a.location,
                    in_stack=in_stack,
                    out_stack=out_stack,
                    assignment=a,
                    ast_node=ast_index.get((a.location.file, a.location.line)),
                )
                self._by_assignment_id[id(a)] = snap
                self.by_line[(a.location.file, a.location.line)] = snap

    def _inject_unreferenced_bb_entry_phis(self) -> None:
        """Materialise phis that ``SSAProgram`` skipped because no
        :class:`Assignment` consumes them, then BOUND each BB's phi
        list to the actual entry stack depth.

        Two issues to fix here, both rooted in the underlying SSA model:

        (1) Lazy materialisation. ``SSAProgram`` only creates ``Phi``
            objects for phis referenced in some ``Assignment.inputs``.
            But ``return`` at the post-callsub line has 0 consumed
            args, so the retsub-output phi is never an ``inputs``
            operand — the value is still on the stack though.

        (2) Phi over-generation. ``phiNodeExitIndex`` in ``SSA.qll``
            enumerates slots ``[1..1000]``, so recursive subroutines
            get phantom IndirectPhis at every slot regardless of the
            real stack depth (the ``phiIsLive`` filter doesn't fully
            cut these down). The simulation truncates by the cached
            ``nodeStackDepth(bb.firstNode)`` value, which the
            ``stackHeights.ql`` query exposes via
            ``g.nodes[n]["stack_heights"]``.

        We only inject phis whose ``stack_index`` is within the BB's
        actual entry depth, and prune any pre-existing
        :class:`SSAProgram` phi on the same BB whose stack_index is
        out-of-bounds.
        """
        import teal_graphs as tg

        prog = self.prog
        bb_by_first_line: dict[tuple[str, int], BasicBlock] = {
            (bb.file, bb.first_line): bb for bb in prog.blocks.values()
        }
        # BB entry depth = max stack_height of bb.firstNode. For BBs
        # reachable along paths with different residual depths (e.g.
        # the retsub in a recursive subroutine that's called both from
        # depth-0 entry and from a depth-N callsite), the heights set
        # carries every possibility. We bound by ``max`` because:
        #
        #   - The SSA model only generates phis at slots [1..max_depth]
        #     that are reachable. ``max`` captures every real slot.
        #   - Using ``min`` would silently drop phis that ARE live on
        #     deeper-stack paths (the L42 retsub case in
        #     tests/framedig/06: heights {0,1,2}; min=0 hides the
        #     return-value phi).
        #
        # Phis at slots above ``max`` are the ``[1..1000]`` artifacts
        # from ``phiNodeExitIndex`` — those are what we want to clip.
        #
        # CAVEAT: ``nodeStackDepth`` in ``StackDepth.qll`` filters
        # forward-CFG-only for branch-induced edges (``b``, ``bz``,
        # ``bnz``, ``switch``, ``match``) — its propagation requires
        # ``cb.getLineNumber() < lineNum``. So back-edges from those
        # ops are silently dropped from the depth analysis, and a BB
        # reached by such a back-edge has an UNDER-reported max depth.
        # Applying the depth bound to such BBs would clip real,
        # SSA-live phis at deeper slots (the ``loop_dig_deep`` test
        # case demonstrates this — a ``dig 1`` inside the loop reads
        # a slot pushed by the previous iteration; the SSA emits a
        # DirectPhi at slot 2 of l_loop, but ``nodeStackDepth(l_loop)
        # = {1}`` because the bnz back-edge was filtered out).
        # Callsub back-edges are exempt — ``nodeStackDepth`` doesn't
        # restrict callsub propagation, so recursive subroutines
        # (the tests/framedig/06 itoa case) still get their
        # depth-bound trim.
        first_node_by_bb: dict[BasicBlock, object] = {}
        for n in prog._graph.nodes:
            bb_id = prog._graph.nodes[n].get("bb")
            if bb_id is None:
                continue
            bb = prog.blocks.get(bb_id)
            if bb is None or bb.first_line != n.location.start_line:
                continue
            first_node_by_bb[bb] = n
        bb_entry_depth: dict[BasicBlock, int] = {}
        for bb, fn in first_node_by_bb.items():
            if _has_unsound_back_edge_predecessor(bb):
                # Skip the bound — we can't trust ``nodeStackDepth``
                # at this BB. Keep every phi the SSA emits.
                continue
            heights = prog._graph.nodes[fn].get("stack_heights")
            if heights:
                bb_entry_depth[bb] = max(heights)
        # Index graph PhiNodes for both injection and arg backfill.
        gphi_by_key: dict[tuple, tg.PhiNode] = {
            (n.location.file, n.location.start_line, n.kind, n.stack_index): n
            for n in prog._graph.nodes
            if isinstance(n, tg.PhiNode)
        }
        injected: list[Phi] = []
        for key, gp in gphi_by_key.items():
            bb = bb_by_first_line.get((gp.location.file, gp.location.start_line))
            # Skip phantom phis above the BB's actual entry depth. We
            # don't have height for synthetic BBs (none we know of) —
            # be permissive there and trust the SSA filter.
            if bb is not None:
                depth = bb_entry_depth.get(bb)
                if depth is not None and gp.stack_index > depth:
                    continue
            if key in prog.phis:
                continue  # already materialised by the lazy pass.
            p = Phi(file=gp.location.file, line=gp.location.start_line,
                    stack_index=gp.stack_index, kind=gp.kind)
            prog.phis[key] = p
            injected.append(p)
            if bb is not None:
                p.basic_block = bb
                bb.phis.append(p)
        # Backfill ``args`` on injected phis (and any reachable
        # transitive phis they reference). Mirrors ``SSAProgram``'s
        # pass 2 closure but seeded from the freshly injected set.
        def _resolve_arg(x):
            if isinstance(x, tg.SSAVar):
                # Use ``prog.var(...)`` so identity is shared with any
                # SSAVar already created during pass 1.
                v = prog.var(x.file, x.line, x.output_index)
                if v is None:
                    v = SSAVar(x.file, x.line, x.output_index)
                    prog.vars[(x.file, x.line, x.output_index)] = v
                return v
            if isinstance(x, tg.PhiNode):
                k = (x.location.file, x.location.start_line, x.kind, x.stack_index)
                ph = prog.phis.get(k)
                if ph is None:
                    ph = Phi(file=x.location.file, line=x.location.start_line,
                             stack_index=x.stack_index, kind=x.kind)
                    prog.phis[k] = ph
                    injected.append(ph)
                return ph
            return x
        pending = list(injected)
        while pending:
            p = pending.pop()
            if p.args:
                continue
            gp = gphi_by_key.get((p.file, p.line, p.kind, p.stack_index))
            if gp is None:
                continue
            for a in gp.args:
                arg = _resolve_arg(a)
                p.args.append(arg)
                if isinstance(arg, Phi) and not arg.args:
                    pending.append(arg)
        # Prune any phi (newly injected OR pre-existing from the lazy
        # pass) whose ``stack_index`` exceeds the BB's entry depth, then
        # re-sort for a stable order in ``_bb_entry_stack``.
        for bb in prog.blocks.values():
            depth = bb_entry_depth.get(bb)
            if depth is not None:
                bb.phis = [p for p in bb.phis if p.stack_index <= depth]
            bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    def _get_ast_index(self) -> dict[tuple[str, int], object]:
        if self._ast_index is not None:
            return self._ast_index
        # Late import: keeps teal_stacksim importable even if teal_ast
        # is unavailable (e.g. minimal install used only for the SSA
        # rendering). The graph stores AstNode instances directly.
        try:
            import teal_ast  # noqa: F401
        except Exception:
            self._ast_index = {}
            return self._ast_index
        from teal_ast import AstNode
        idx: dict[tuple[str, int], object] = {}
        for node in self.prog._graph.nodes:
            if isinstance(node, AstNode):
                idx[(node.location.file, node.location.start_line)] = node
        self._ast_index = idx
        return idx

    # -- lookup -------------------------------------------------------

    def at(self, *, file: str, line: int) -> Optional[StackSnapshot]:
        """Snapshot at a specific source line. Returns ``None`` for
        lines that don't carry an :class:`Assignment` (labels, blank
        lines, lines outside any reachable BB)."""
        return self.by_line.get((file, line))

    def for_assignment(self, a: Assignment) -> Optional[StackSnapshot]:
        """Snapshot for an SSA :class:`Assignment`. Direct ``id``-keyed
        lookup so post-mutation Assignments still resolve."""
        return self._by_assignment_id.get(id(a))

    def __iter__(self) -> Iterable[StackSnapshot]:
        return iter(sorted(
            self._by_assignment_id.values(),
            key=lambda s: (s.file, s.line),
        ))

    def __len__(self) -> int:
        return len(self._by_assignment_id)

    def files(self) -> list[str]:
        return sorted({s.file for s in self._by_assignment_id.values()})

    # -- rendering ----------------------------------------------------

    def render(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
        max_slots: int = 12,
        show_in: bool = True,
        show_out: bool = True,
        layout: str = "auto",
    ) -> str:
        """Source-aligned listing: one entry per opcode, with IN/OUT stacks.

        ``max_slots`` truncates very deep stacks with a ``…+N`` marker.

        ``layout``:
            - ``"single"``: one row per opcode, columns aligned. Compact
              and easy to scan when stacks fit in roughly one terminal width.
            - ``"multi"``: opcode on its own line, IN/OUT on indented
              follow-up lines. Stays readable when one row's stack
              contains a phi-of-phi tree thousands of characters wide
              (xgov's recursive ``itoa_1`` is the canonical example).
            - ``"auto"`` (default): picks ``"multi"`` when any rendered
              stack exceeds 120 chars, ``"single"`` otherwise.
        """
        snaps = sorted(
            (
                s for s in self._by_assignment_id.values()
                if (file is None or s.file == file)
                and (line_range is None or line_range[0] <= s.line <= line_range[1])
            ),
            key=lambda s: (s.file, s.line),
        )
        if not snaps:
            return ""
        rows: list[tuple[str, str, str, str]] = []
        for s in snaps:
            line_str = f"L{s.line:>4}"
            op = s.assignment.ast_code
            in_str = _fmt_stack_truncated(s.in_stack, max_slots) if show_in else ""
            out_str = _fmt_stack_truncated(s.out_stack, max_slots) if show_out else ""
            rows.append((line_str, op, in_str, out_str))

        if layout == "auto":
            widest = max((len(r[2]) for r in rows), default=0)
            widest = max(widest, max((len(r[3]) for r in rows), default=0))
            layout = "multi" if widest > 120 else "single"

        if layout == "single":
            line_w = max(len(r[0]) for r in rows)
            op_w = max(len(r[1]) for r in rows)
            in_w = max(len(r[2]) for r in rows) if show_in else 0
            out: list[str] = []
            for line_str, op, in_str, out_str in rows:
                parts = [line_str.ljust(line_w), op.ljust(op_w)]
                if show_in:
                    parts.append(f"IN  {in_str.ljust(in_w)}")
                if show_out:
                    parts.append(f"OUT {out_str}")
                out.append("  ".join(parts))
            return "\n".join(out)

        # layout == "multi"
        line_w = max(len(r[0]) for r in rows)
        op_w = max(len(r[1]) for r in rows)
        indent = " " * (line_w + 2 + op_w + 2)
        out_lines: list[str] = []
        for line_str, op, in_str, out_str in rows:
            header = f"{line_str.ljust(line_w)}  {op.ljust(op_w)}"
            if show_in:
                out_lines.append(f"{header}  IN  {in_str}")
                if show_out:
                    out_lines.append(f"{indent}OUT {out_str}")
            elif show_out:
                out_lines.append(f"{header}  OUT {out_str}")
            else:
                out_lines.append(header)
        return "\n".join(out_lines)

    def print(self, **kwargs) -> None:
        print(self.render(**kwargs))


# --- helpers ---------------------------------------------------------


# Branch ops whose back-edges are filtered out by ``nodeStackDepth``'s
# forward-only propagation in ``StackDepth.qll`` (see ``cb.getLineNumber()
# < lineNum`` on each rule for ``BOpcode`` / ``SimpleConditionalBranches``
# / ``MultiTargetConditionalBranch``). Callsub edges are NOT filtered
# there, so they're sound to use as-is for the depth bound.
_UNSOUND_BACK_EDGE_OPS: frozenset = frozenset({
    "b", "bz", "bnz", "switch", "match",
})


def _has_unsound_back_edge_predecessor(bb: BasicBlock) -> bool:
    """True if ``bb`` is reached by an edge from a non-callsub branch
    op whose source line is greater than ``bb``'s entry line.

    Inspects each predecessor BB's last assignment. ``SSAProgram``'s
    pass 4 now correctly includes self-loops (a one-BB loop's
    back-edge appears as ``bb`` in its own ``predecessors``), so this
    helper doesn't need to walk the raw CFG graph anymore.
    """
    for pred in bb.predecessors:
        if not pred.assignments:
            continue
        last = pred.assignments[-1]
        if last.op in _UNSOUND_BACK_EDGE_OPS and last.location.line > bb.first_line:
            return True
    return False


def _bb_entry_stack(bb: BasicBlock) -> tuple[StackSlot, ...]:
    """Phis at the BB's entry, ordered bottom-first.

    A BB's phi list may carry parallel ``DirectPhi`` and ``IndirectPhi``
    views of one stack slot — see ``consumedDefAtScore`` in
    ``AST.qll`` for the same dedup convention. We keep at most one phi
    per ``stack_index``, preferring ``DirectPhi`` because its
    ``args`` enumerate concrete originating SSAVars (``IndirectPhi``
    only carries one upstream phi reference). Bottom-first order means
    the deepest stack_index sorts first, so the BB's topmost incoming
    slot ends up at ``stack[-1]``.
    """
    by_idx: dict[int, Phi] = {}
    for p in bb.phis:
        existing = by_idx.get(p.stack_index)
        if existing is None:
            by_idx[p.stack_index] = p
        elif existing.kind == "IndirectPhi" and p.kind == "DirectPhi":
            by_idx[p.stack_index] = p
    return tuple(by_idx[i] for i in sorted(by_idx, reverse=True))


def _fmt_stack_truncated(stack: tuple[StackSlot, ...], max_slots: int) -> str:
    if not stack:
        return "[]"
    if len(stack) <= max_slots:
        return "[" + ", ".join(_fmt_slot(s) for s in stack) + "]"
    # Keep the top half — the recently pushed values are usually what
    # the next opcode will consume, so truncate the deep end.
    keep = stack[-max_slots:]
    elided = len(stack) - max_slots
    return f"[…+{elided}, " + ", ".join(_fmt_slot(s) for s in keep) + "]"
