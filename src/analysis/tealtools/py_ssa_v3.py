"""SSA construction by per-BB stack simulation.

Phase 1: For each opcode in the program, instantiate one ``PyVar`` per
output. Identity is ``(file, line, output_index)`` with ``output_index``
1-based; ``index 1`` is the topmost output.

Phase 2: For each basic block, walk its opcodes in source order
simulating a stack:
  - Consume ``n_in`` operands from the top of the running local stack.
    If the local stack is empty when a consume hits, materialise the
    next entry phi (``phi_1`` first, then ``phi_2``, ...). Each BB's
    entry phis live conceptually as a stack at BB entry, top being
    ``phi_1`` and bottom being ``phi_n``; ``n`` is determined by how
    deep this BB's consumption reaches.
  - Push ``n_out`` outputs on the top of the local stack.

Entry phis are created empty — no args yet. Wiring them comes later.

``frame_dig`` / ``frame_bury`` carry a frame-pointer parameter (the
position of the stack frame when the subroutine was called); the value
is in ``[0, 1000]`` but is left undefined here. For Phase 2 we model
their stack effect by the TEAL spec (``frame_dig``: 0-in / 1-out;
``frame_bury``: 1-in / 0-out) — the actual frame access is determined
in a later pass that solves for ``fp``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .py_ssa import PyBlock, PyOp, PyPhi, PyVar
from .ssa import SSAProgram


def _reverse_postorder(blocks: list) -> list:
    """DFS post-order over forward CFG, then reverse — order in which
    each BB's CFG predecessors are visited first (for DAG-shaped CFGs).
    For cycles the back-edge sources come AFTER the head; fixpoint
    iteration handles those."""
    seen: set = set()
    order: list = []

    def dfs(b):
        if b in seen:
            return
        seen.add(b)
        for s in b.succs:
            dfs(s)
        order.append(b)

    for root in blocks:
        if not root.preds:
            dfs(root)
    for b in blocks:
        if b not in seen:
            dfs(b)
    order.reverse()
    return order


@dataclass
class V3SSA:
    """SSA built per-BB by stack simulation. Phis are top-first numbered:
    ``slot = 1`` is the top of the BB's entry phi stack."""

    blocks: list[PyBlock] = field(default_factory=list)
    vars: dict[tuple, PyVar] = field(default_factory=dict)
    # phi key: ``(bb_key, phi_number)`` where ``phi_number`` is 1-based
    # top-first (matches QL stack_index convention).
    phis: dict[tuple, PyPhi] = field(default_factory=dict)
    # set of possible stack heights at BB entry (Phase 3).
    heights: dict[PyBlock, set] = field(default_factory=dict)

    @classmethod
    def build(cls, prog: SSAProgram) -> "V3SSA":
        self = cls()
        self._phase1_instantiate(prog)
        self._phase2_consume()
        self._phase3_heights()
        self._phase4_resolve_frame_negative()
        self._phase5_live_filter()
        return self

    # -- Phase 1: instantiate SSAVars ---------------------------------------

    def _phase1_instantiate(self, prog: SSAProgram) -> None:
        """Build BBs from QL's CFG; instantiate one ``PyVar`` per opcode
        output. ``n_in`` / ``n_out`` come from the QL graph except for
        ``frame_dig`` / ``frame_bury``, which are overridden to TEAL-spec
        arities (the frame offset is solved separately)."""
        by_ql: dict[object, PyBlock] = {}
        for qbb in prog.blocks.values():
            b = PyBlock((qbb.file, qbb.first_line, qbb.last_line))
            for a in qbb.assignments:
                n_in = len(a.inputs)
                n_out = len(a.outputs)
                if a.op == "frame_dig":
                    n_in, n_out = 0, 1
                elif a.op == "frame_bury":
                    n_in, n_out = 1, 0
                elif a.op in ("callsub", "retsub"):
                    # Control transfers, no direct data-stack effect.
                    # QL inflates n_in on retsub (wide-arity) in some
                    # fixtures; collapse to the TEAL-spec semantics.
                    n_in, n_out = 0, 0
                op = PyOp(
                    op=a.op, immediates=a.immediates,
                    file=a.location.file, line=a.location.line,
                    n_in=n_in, n_out=n_out,
                )
                outs: list[PyVar] = []
                for k in range(1, n_out + 1):
                    v = PyVar(op.file, op.line, k)
                    self.vars[v.key()] = v
                    outs.append(v)
                op.outputs = outs
                b.ops.append(op)
            by_ql[qbb] = b

        # Wire CFG edges from QL.
        for qbb, b in by_ql.items():
            b.preds = sorted(
                (by_ql[p] for p in qbb.predecessors if p in by_ql),
                key=lambda x: x.key,
            )
            b.succs = sorted(
                (by_ql[s] for s in qbb.successors if s in by_ql),
                key=lambda x: x.key,
            )
        self.blocks = sorted(by_ql.values(), key=lambda b: b.key)

    # -- Phase 2: cross-BB stack simulation ---------------------------------

    def _phase2_consume(self) -> None:
        """Three-pass live-driven SSA construction.

        2A: per-BB lineage. Abstract sim with no entry depth assumed —
            count entry slots consumed, track surviving locals, record
            per-op input lineage.
        2B: backward live dataflow. Seed need_entry[B] with entry
            slots consumed by ops in B; ALSO seed sub-entry BBs with
            frame_dig N<0 reads (each frame_dig in sub S reads slot
            |N| of S's entry). Propagate to preds via the
            exit-slot-to-entry-slot mapping. Worklist fixpoint.
        2C: forward emit phis only at slots in need_entry[B].
            Worklist fixpoint, naturally bounded by max(need_entry[B]).
        """
        lineage = {b: self._bb_lineage(b) for b in self.blocks}
        # Identify subs and seed sub-entries with frame_dig N<0 reads
        # so the backward DF carries those needs through the sub's
        # CFG predecessors (the callsubs).
        self._bb_to_sub, self._proto_io = self._identify_subroutines()
        frame_seeds = self._frame_dig_seeds(self._bb_to_sub, self._proto_io)
        need_entry = self._backward_live(lineage, frame_seeds)
        self._forward_emit_live(lineage, need_entry)

    def _bb_lineage(self, b: PyBlock) -> dict:
        """Per-BB abstract sim. Returns:
        - ``consumed_count``: total entry slots consumed by ops in b.
        - ``surviving_locals``: top-first list of ``(op_idx, output_idx)``
          markers for locals that survive to exit.
        - ``op_input_lineages``: per-op input lineage; each input is
          either ``('local', op_idx, output_idx)`` or
          ``('entry', entry_slot)``. Top-first.
        """
        local_stack: list = []  # bottom-first; (op_idx, output_idx)
        consumed_count = 0
        op_input_lineages: list = []
        for op_idx, op in enumerate(b.ops):
            inputs_lin: list = []
            for _ in range(op.n_in):
                if local_stack:
                    item = local_stack.pop()
                    inputs_lin.append(("local", item[0], item[1]))
                else:
                    consumed_count += 1
                    inputs_lin.append(("entry", consumed_count))
            op_input_lineages.append(inputs_lin)
            for j in range(op.n_out, 0, -1):
                local_stack.append((op_idx, j))
        return {
            "consumed_count": consumed_count,
            "surviving_locals": list(reversed(local_stack)),
            "op_input_lineages": op_input_lineages,
        }

    def _identify_subroutines(self) -> tuple:
        """Identify sub-entry BBs (callsub targets) and assign each BB
        to its containing sub via subroutine-local CFG. Returns
        ``(bb_to_sub, proto_io)``."""
        import bisect

        op_lines: list = sorted(
            (op.file, op.line) for b in self.blocks for op in b.ops
        )
        line_to_bb: dict = {}
        for b in self.blocks:
            for op in b.ops:
                line_to_bb[(op.file, op.line)] = b

        def return_point(callsub_bb: PyBlock):
            last = callsub_bb.ops[-1]
            i = bisect.bisect_right(op_lines, (last.file, last.line))
            if i < len(op_lines) and op_lines[i][0] == last.file:
                return line_to_bb[op_lines[i]]
            return None

        sub_entries: set = set()
        for b in self.blocks:
            if b.ops and b.ops[-1].op == "callsub":
                for s in b.succs:
                    sub_entries.add(s)

        loc_succs: dict = {}
        for b in self.blocks:
            if not b.ops:
                loc_succs[b] = list(b.succs)
                continue
            last_op = b.ops[-1].op
            if last_op == "callsub":
                rp = return_point(b)
                loc_succs[b] = [rp] if rp is not None else []
            elif last_op in ("retsub", "return", "err"):
                loc_succs[b] = []
            else:
                loc_succs[b] = list(b.succs)

        mains = [
            b for b in self.blocks
            if not b.preds and b not in sub_entries
        ]
        bb_to_sub: dict = {}
        for root in mains + sorted(sub_entries, key=lambda x: x.key):
            stack = [root]
            while stack:
                b = stack.pop()
                if b in bb_to_sub:
                    continue
                bb_to_sub[b] = root
                for s in loc_succs[b]:
                    if s is not None and s not in bb_to_sub:
                        stack.append(s)

        proto_io: dict = {}
        for se in sub_entries:
            if se.ops and se.ops[0].op == "proto":
                parts = se.ops[0].immediates.split()
                try:
                    proto_io[se] = (int(parts[0]), int(parts[1]))
                except (ValueError, IndexError):
                    pass
        return bb_to_sub, proto_io

    def _frame_dig_seeds(self, bb_to_sub: dict, proto_io: dict) -> dict:
        """For each frame_dig N<0 in a proto sub, the sub's entry slot
        |N| is needed. Returns ``{sub_entry_bb: set_of_slots}``."""
        def imm_int(s: str) -> int:
            try:
                return int(s.strip().split()[0])
            except (ValueError, IndexError, AttributeError):
                return 0

        seeds: dict = {}
        for b in self.blocks:
            sub = bb_to_sub.get(b)
            if sub is None or sub not in proto_io:
                continue
            a, _r = proto_io[sub]
            for op in b.ops:
                if op.op not in ("frame_dig", "frame_bury"):
                    continue
                n = imm_int(op.immediates)
                if n >= 0 or -n > a:
                    continue
                seeds.setdefault(sub, set()).add(-n)
        return seeds

    def _backward_live(self, lineage: dict, frame_seeds: dict) -> dict:
        """Backward dataflow. Returns ``need_max[b]`` = max entry slot
        index (top-first, 1-based) that b needs to materialise.

        Tracks the maximum depth instead of the set of specific slots
        for efficiency (set-based propagation hot loops on dense CFGs
        with chain propagation). The trade-off: Phase 2C emits phis at
        every slot 1..max_need[b] rather than only at specifically-needed
        slots. The extras are bounded and Phase 5's live filter prunes
        any that aren't actually consumed.

        Propagation: if succ ``S`` needs depth ``M_S``, and ``M_S > L_b``,
        then b needs depth ``C_b + M_S - L_b`` (capped at ``STACK_MAX``).
        """
        STACK_MAX = 1000
        from collections import deque
        need_max: dict = {b: 0 for b in self.blocks}

        # Seed: max entry slot consumed by ops in each b.
        for b in self.blocks:
            for ins in lineage[b]["op_input_lineages"]:
                for lin in ins:
                    if lin[0] == "entry":
                        if lin[1] > need_max[b]:
                            need_max[b] = lin[1]
        # Seed sub-entries with max frame_dig N<0 slot.
        for sub_entry, slots in frame_seeds.items():
            if slots:
                m = max(slots)
                if m > need_max[sub_entry]:
                    need_max[sub_entry] = m

        wl: deque = deque(self.blocks)
        in_wl: set = set(self.blocks)
        while wl:
            b = wl.popleft()
            in_wl.discard(b)

            L_b = len(lineage[b]["surviving_locals"])
            C_b = lineage[b]["consumed_count"]

            new_max = need_max[b]
            for s in b.succs:
                Ms = need_max[s]
                if Ms > L_b:
                    propagated = C_b + Ms - L_b
                    if propagated > STACK_MAX:
                        propagated = STACK_MAX
                    if propagated > new_max:
                        new_max = propagated
            if new_max > need_max[b]:
                need_max[b] = new_max
                for p in b.preds:
                    if p not in in_wl:
                        wl.append(p)
                        in_wl.add(p)
        return need_max

    def _forward_emit_live(self, lineage: dict, need_entry: dict) -> None:
        """Forward worklist fixpoint. For each b, build entry_stack
        at depth ``max(need_entry[b])`` only; emit phis at multi-pred
        slots; sim b; record exit_stack. Iterate until exit_stacks
        stabilise."""
        for b in self.blocks:
            b.entry_phis = []
            b.entry_stack = []
            b.exit_stack = []

        from collections import deque
        order = _reverse_postorder(self.blocks)
        wl: deque = deque(order)
        in_wl: set = set(order)
        sim_done: set = set()

        while wl:
            b = wl.popleft()
            in_wl.discard(b)

            max_d = need_entry[b]  # now an int (max needed slot)
            new_entry = self._build_entry_stack(b, max_d)
            first_time = b not in sim_done
            entry_changed = new_entry != b.entry_stack
            if not first_time and not entry_changed:
                continue

            b.entry_stack = new_entry
            old_exit = list(b.exit_stack)
            self._sim_block(b)
            sim_done.add(b)

            if first_time or b.exit_stack != old_exit:
                for s in b.succs:
                    if s not in in_wl:
                        wl.append(s)
                        in_wl.add(s)

        for b in self.blocks:
            b.entry_phis.sort(key=lambda p: p.slot)

    def _build_entry_stack(self, b: PyBlock, max_depth: int) -> list:
        """Build b's entry_stack (bottom-first) at depth ``max_depth``
        by merging preds' exit_stacks slot-by-slot.

        Phi args only carry CONTRIBUTING preds — a pred whose
        exit_stack is shallower than slot k doesn't contribute (no
        phantom ``None`` placeholder). When only one pred contributes
        at a slot, the value is inherited directly without a phi.
        """
        if max_depth <= 0 or not b.preds:
            return []
        entry: list = [None] * max_depth
        for k in range(1, max_depth + 1):
            contribs: list = []
            for p in b.preds:
                if len(p.exit_stack) >= k:
                    contribs.append(p.exit_stack[-k])
            if not contribs:
                val = None
            elif len(contribs) == 1:
                val = contribs[0]
            elif len(set(id(c) for c in contribs)) == 1:
                # All contributing preds agree.
                val = contribs[0]
            else:
                phi_key = (b.key, k)
                phi = self.phis.get(phi_key)
                if phi is None:
                    phi = PyPhi(b.key, k)
                    self.phis[phi_key] = phi
                    b.entry_phis.append(phi)
                phi.args = list(contribs)
                val = phi
            entry[max_depth - k] = val
        return entry

    def _sim_block(self, b: PyBlock) -> None:
        """Run b's ops over entry_stack, recording op.inputs and
        exit_stack. local_stack is bottom-first (``local_stack[-1]``
        is the top). When n_in exceeds available depth, op.inputs gets
        ``None`` for the missing slots — this signals under-flow."""
        local_stack: list = list(b.entry_stack)
        for op in b.ops:
            op.inputs = []
            for _ in range(op.n_in):
                if local_stack:
                    op.inputs.append(local_stack.pop())
                else:
                    op.inputs.append(None)
            for v in reversed(op.outputs):
                local_stack.append(v)
        b.exit_stack = local_stack

    # -- Phase 3: forward stack-height dataflow -----------------------------

    def _phase3_heights(self) -> None:
        """Forward worklist dataflow computing the set of possible
        stack heights at each BB's entry.

        Per-op stack delta uses TEAL-spec semantics regardless of QL's
        wide-arity reporting:

        - ``frame_dig`` / ``frame_bury`` use the overrides set in Phase
          1 (n_in=0/1 and 1/0 respectively).
        - ``callsub`` and ``retsub`` have delta = 0. The proto a/r net
          effect lands on the caller's post-callsub BB via the
          retsub→post-callsub CFG edge.
        - All other ops use the QL-graph arities (``n_out - n_in``).

        Heights are capped at ``STACK_MAX = 1000`` — the AVM's stack
        ceiling. Any path that would push past 1000 is dropped
        (the AVM would have aborted on that path at runtime).

        Multi-caller subs over-approximate slightly: each retsub
        propagates its full exit height set to *every* post-callsub
        successor, rather than restricting per calling-site. Tighten
        with calling-context-aware tracking if/when needed.
        """
        STACK_MAX = 1000

        # Seed: program-entry BBs (no preds) start at height 0.
        self.heights = {b: set() for b in self.blocks}
        entries = [b for b in self.blocks if not b.preds]
        if not entries and self.blocks:
            entries = [self.blocks[0]]
        for b in entries:
            self.heights[b].add(0)

        # Per-BB net stack delta. TEAL-spec semantics; ignore QL's
        # wide-arity inflation for control ops.
        def op_delta(op: PyOp) -> int:
            if op.op in ("callsub", "retsub"):
                return 0
            return op.n_out - op.n_in

        bb_delta: dict = {
            b: sum(op_delta(op) for op in b.ops) for b in self.blocks
        }

        from collections import deque
        wl: deque = deque(entries)
        in_wl: set = set(entries)
        while wl:
            b = wl.popleft()
            in_wl.discard(b)
            delta = bb_delta[b]
            exit_h: set = set()
            for h in self.heights[b]:
                nh = h + delta
                if 0 <= nh <= STACK_MAX:
                    exit_h.add(nh)
            for s in b.succs:
                new = exit_h - self.heights[s]
                if new:
                    self.heights[s] |= new
                    if s not in in_wl:
                        wl.append(s)
                        in_wl.add(s)

    # -- Phase 4: resolve frame_dig / frame_bury for negative offsets -------

    def _phase4_resolve_frame_negative(self) -> None:
        """Resolve ``frame_dig N`` / ``frame_bury N`` reads/writes for
        ``N < 0`` (arg access in proto subs).

        For each frame op in a BB owned by sub S with ``proto a r``:
          - slot = ``|N|`` (1-based, matching our top-first phi numbering).
          - Must have ``slot <= a`` (else out of bounds per the AVM
            ``proto.clear`` check).
          - Materialise S's entry phi at ``slot`` if it doesn't already
            exist (Phase 2 didn't materialise it because frame_dig's
            n_in is overridden to 0).
          - ``frame_dig``: ``op.inputs = [that phi]``.
          - ``frame_bury``: leave ``op.inputs`` (set in Phase 2: the
            consumed top of stack) alone, but tag the target slot as
            ``op.frame_target`` so a later memory-SSA pass can model
            the write's effect on subsequent reads.

        ``N >= 0`` is deferred — needs cross-BB local-stack tracking.
        """
        import bisect

        # Source-order line index for finding callsub return points.
        op_lines: list[tuple] = sorted(
            (op.file, op.line) for b in self.blocks for op in b.ops
        )
        line_to_bb: dict = {}
        for b in self.blocks:
            for op in b.ops:
                line_to_bb[(op.file, op.line)] = b

        def return_point(callsub_bb: PyBlock):
            last = callsub_bb.ops[-1]
            i = bisect.bisect_right(op_lines, (last.file, last.line))
            if i < len(op_lines) and op_lines[i][0] == last.file:
                return line_to_bb[op_lines[i]]
            return None

        # Sub-entries: targets of callsubs.
        sub_entries: set = set()
        for b in self.blocks:
            if b.ops and b.ops[-1].op == "callsub":
                for s in b.succs:
                    sub_entries.add(s)

        # Subroutine-local CFG: callsub passes over to its return point;
        # retsub / return / err are routine terminators.
        loc_succs: dict = {}
        for b in self.blocks:
            if not b.ops:
                loc_succs[b] = list(b.succs)
                continue
            last_op = b.ops[-1].op
            if last_op == "callsub":
                rp = return_point(b)
                loc_succs[b] = [rp] if rp is not None else []
            elif last_op in ("retsub", "return", "err"):
                loc_succs[b] = []
            else:
                loc_succs[b] = list(b.succs)

        # Assign each BB to its containing routine via callees-first DFS
        # over the subroutine-local CFG, starting from main entries and
        # sub-entries.
        mains = [
            b for b in self.blocks
            if not b.preds and b not in sub_entries
        ]
        bb_to_sub: dict = {}
        roots = mains + sorted(sub_entries, key=lambda x: x.key)
        for root in roots:
            stack = [root]
            while stack:
                b = stack.pop()
                if b in bb_to_sub:
                    continue
                bb_to_sub[b] = root
                for s in loc_succs[b]:
                    if s is not None and s not in bb_to_sub:
                        stack.append(s)

        # Proto info: a, r for each proto sub.
        proto_io: dict = {}
        for se in sub_entries:
            if se.ops and se.ops[0].op == "proto":
                parts = se.ops[0].immediates.split()
                try:
                    proto_io[se] = (int(parts[0]), int(parts[1]))
                except (ValueError, IndexError):
                    pass

        def imm_int(s: str) -> int:
            try:
                return int(s.strip().split()[0])
            except (ValueError, IndexError, AttributeError):
                return 0

        # Resolve. Look up the symbol at sub_entry.entry_stack[-slot]
        # (= top-first slot |N| of sub-entry's incoming stack). For a
        # single-caller sub this is the caller's value directly; for a
        # multi-caller sub it's the phi Phase 2 created at that slot.
        for b in self.blocks:
            sub = bb_to_sub.get(b)
            if sub is None:
                continue
            proto = proto_io.get(sub)
            if proto is None:
                continue  # non-proto: skip — frame ops are only valid with proto
            a, _r = proto
            for op in b.ops:
                if op.op not in ("frame_dig", "frame_bury"):
                    continue
                n = imm_int(op.immediates)
                if n >= 0:
                    continue  # N >= 0 deferred (local access)
                slot = -n
                if slot > a:
                    continue  # out-of-bounds per proto.clear check
                if len(sub.entry_stack) < slot:
                    continue  # sub's entry isn't deep enough (shouldn't happen)
                target = sub.entry_stack[-slot]
                if op.op == "frame_dig":
                    op.inputs = [target]
                else:
                    op.frame_target = target  # frame_bury: target slot

    # -- Phase 5: live-phi filter -------------------------------------------

    def _phase5_live_filter(self) -> None:
        """Drop phis not transitively consumed by any opcode's
        ``op.inputs``. Backward walk: start from phis referenced as
        op.inputs, then follow phi.args, marking everything reachable
        as live. Phis not marked are removed from ``self.phis`` and
        from each BB's ``entry_phis``."""
        live: set = set()
        work: list = []

        # Seed: any phi referenced by an opcode's inputs.
        for b in self.blocks:
            for op in b.ops:
                for inp in op.inputs:
                    if isinstance(inp, PyPhi) and inp not in live:
                        live.add(inp)
                        work.append(inp)

        # Backward propagation through phi.args.
        while work:
            phi = work.pop()
            for a in phi.args:
                if isinstance(a, PyPhi) and a not in live:
                    live.add(a)
                    work.append(a)

        # Drop dead phis.
        for key in list(self.phis.keys()):
            if self.phis[key] not in live:
                del self.phis[key]
        for b in self.blocks:
            b.entry_phis = [p for p in b.entry_phis if p in live]
            # Also clean dead phis out of entry_stack so renderers /
            # downstream don't trip over stale references.
            b.entry_stack = [
                e if not isinstance(e, PyPhi) or e in live else None
                for e in b.entry_stack
            ]
            b.exit_stack = [
                e if not isinstance(e, PyPhi) or e in live else None
                for e in b.exit_stack
            ]

    # -- rendering / demo ---------------------------------------------------

    def render(self) -> str:
        """Per-BB dump showing materialised entry phis and per-op
        consumption."""
        def lbl(o) -> str:
            if isinstance(o, PyVar):
                return f"V#{o.idx}@L{o.line}"
            if isinstance(o, PyPhi):
                return f"φ_{o.slot}@L{o.bb_key[1]}"
            return repr(o)

        out: list[str] = []
        for b in self.blocks:
            heights = sorted(self.heights.get(b, set()))
            if not heights:
                hs = "heights={}"
            elif len(heights) <= 6:
                hs = f"heights={{{','.join(map(str, heights))}}}"
            else:
                # Truncate long ranges: just show min..max + count
                hs = f"heights=[{heights[0]}..{heights[-1]}] ({len(heights)} values)"
            out.append(f"# BB L{b.key[1]}-{b.key[2]}  "
                       f"entry_phis={len(b.entry_phis)}  {hs}")
            for phi in b.entry_phis:
                args = ", ".join(
                    lbl(a) if a is not None else "?" for a in phi.args
                )
                out.append(f"        {lbl(phi)} = phi({args})")
            for op in b.ops:
                ins = ", ".join(lbl(i) for i in op.inputs)
                rhs = f"{op.op} {op.immediates}".strip()
                body = f"{rhs} ({ins})"
                if op.outputs:
                    body = f"{', '.join(lbl(v) for v in op.outputs)} = {body}"
                out.append(f"  L{op.line:>4}: {body}")
            out.append("")
        return "\n".join(out)


def _demo(db_path: str) -> None:
    import time
    t0 = time.perf_counter()
    prog = SSAProgram(db_path, verbose=False)
    t_ql = time.perf_counter() - t0
    t0 = time.perf_counter()
    v3 = V3SSA.build(prog)
    t_v3 = time.perf_counter() - t0
    if len(v3.blocks) <= 30:
        print(v3.render())
    else:
        print(f"({len(v3.blocks)} blocks — full render suppressed)")
    print(
        f"[v3] QL load: {t_ql:.2f}s  build: {t_v3 * 1000:.1f}ms  "
        f"blocks={len(v3.blocks)}  vars={len(v3.vars)}  phis={len(v3.phis)}"
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m tealtools.py_ssa_v3 <codeql-db-path>", file=sys.stderr)
        raise SystemExit(2)
    _demo(sys.argv[1])
