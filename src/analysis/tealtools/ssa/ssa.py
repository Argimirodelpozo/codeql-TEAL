"""Canonical SSA module.

Re-exports the data classes from :mod:`tealtools.ssa.models`
(``SSAVar``, ``Phi``, ``Assignment``, ``BasicBlock``, ``Const``,
``Location``, ``MatPhiVar``, ``TealType``, ``IntRange``) and the
``SSAProgram`` class from :mod:`tealtools.ssa.program`, and provides
:meth:`PySSA.build` — the pure-Python SSA builder that returns an
``SSAProgram`` directly, ready for every existing analysis (constant
propagation, taint, detectors, reports).

Canonical idiom:

```python
from tealtools.ssa import SSAProgram, PySSA

prog_ql = SSAProgram(db, verbose=False)
prog    = PySSA.build(prog_ql)
# every existing analysis runs on prog.
```

Pipeline (:meth:`PySSA._construct`):

  1. Instantiate PyVars per opcode output.
  2. BB arities + surviving locals (``outStackOrder``).
  3. Direct placement at slots where some pred has a local.
  4. Indirect propagation via ``phiNodeExitIndex`` (worklist, capped).
  5. Heights (forward stack-delta DF; diagnostic).
  6. Per-BB sim to fill ``op.inputs`` / ``b.exit_stack``;
     ``frame_dig`` / ``frame_bury`` (any-sign N) expand to QL's
     fat-stack convention (consume the band from current top down to
     the target slot, emit fresh outputs covering the post-stack).
  8. Liveness filter (drop phis not transitively consumed by any op).

``phiNodeExitIndex(k, b) = L_b + k - C_b`` if ``k > C_b``, else
undefined (consumed). Unified ``PyPhi`` class — kind=Direct/Indirect
is collapsed; chain structure is preserved on the args graph (which
can be cyclic at constant-stack CFG loops; traversal must use
``seen`` sets).

CLI: ``python -m tealtools.ssa <codeql-db>`` (renders the PySSA build).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

# Data classes live in .models; the SSAProgram class lives in
# .program. External consumers go through the package __init__ which
# re-exports both.
from .models import (  # noqa: F401
    Assignment,
    BasicBlock,
    Const,
    IntRange,
    Location,
    MatPhiVar,
    Operand as QLOperand,
    Phi,
    SSAVar,
    TealType,
    _CONST_BLOCK_REF_NAMES,
    _OP_RANGE_SEEDS,
    _TERMINATOR_OPS,
    _shuffle_mapping,
)
from .program import SSAProgram  # noqa: F401
from ..opcode_sigs import op_arity


STACK_MAX = 1000


# A reconstructed-SSA operand. ``None`` marks a slot the builder could
# not resolve (a depth mismatch surfaced rather than hidden).
Operand = Union["PyVar", "PyPhi"]


class PyVar:
    """An SSA variable: one stack value produced by one opcode output.

    Identity is ``(file, line, idx)`` with ``idx`` 1-based; ``idx == 1``
    is the opcode's topmost output.
    """

    __slots__ = ("file", "line", "idx")

    def __init__(self, file: str, line: int, idx: int):
        self.file = file
        self.line = line
        self.idx = idx

    def key(self) -> tuple:
        return (self.file, self.line, self.idx)

    def __hash__(self) -> int:
        return hash(self.key())

    def __eq__(self, other) -> bool:
        return isinstance(other, PyVar) and self.key() == other.key()

    def __repr__(self) -> str:
        return f"V#{self.idx}@L{self.line}"


class PyPhi:
    """A phi at a basic block's entry, for one stack slot.

    Identity is ``(bb_key, slot)`` — ``bb_key`` is ``(file, first_line,
    last_line)``; ``slot`` is 1-based top-first (top of the entry
    stack is slot 1) to match QL's ``stack_index`` convention.

    ``args`` is the merged-in incoming values from preds — each entry
    is a :class:`PyVar` (op-defined) or a :class:`PyPhi` (chain
    predecessor in propagation). The args graph can be cyclic at
    constant-stack CFG loops; consumers must walk with a ``visited``
    set.
    """

    __slots__ = ("bb_key", "slot", "args")

    def __init__(self, bb_key: tuple, slot: int):
        self.bb_key = bb_key
        self.slot = slot
        self.args: list[Optional[Operand]] = []

    def key(self) -> tuple:
        return (self.bb_key, self.slot)

    def __hash__(self) -> int:
        return hash(self.key())

    def __eq__(self, other) -> bool:
        return isinstance(other, PyPhi) and self.key() == other.key()

    def __repr__(self) -> str:
        return f"φ{self.slot}@L{self.bb_key[1]}"


@dataclass
class PyOp:
    """An opcode in SSA form: ``outputs = op immediates (inputs)``.

    ``n_in`` / ``n_out`` are arities from the QL graph (overridden for
    ``frame_dig`` / ``frame_bury`` / ``callsub`` / ``retsub`` to the
    TEAL-spec values; see :meth:`PySSA._phase1_instantiate`).
    ``inputs`` / ``outputs`` are filled by the per-BB simulator.
    """

    op: str
    immediates: str
    file: str
    line: int
    n_in: int
    n_out: int
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)


class PyBlock:
    """A basic block: ordered opcodes plus its CFG neighbours.

    ``preds`` / ``succs`` are the raw CFG (callsubs and retsubs
    included).
    """

    __slots__ = (
        "key", "ops", "preds", "succs",
        "entry_phis", "entry_stack", "exit_stack",
    )

    def __init__(self, key: tuple):
        self.key = key  # (file, first_line, last_line)
        self.ops: list[PyOp] = []
        self.preds: list["PyBlock"] = []
        self.succs: list["PyBlock"] = []
        self.entry_phis: list[PyPhi] = []
        self.entry_stack: list[Operand] = []
        self.exit_stack: list[Operand] = []

    def __repr__(self) -> str:
        return f"BB(L{self.key[1]}-{self.key[2]})"


# ---------------------------------------------------------------------------
# PySSA — the SSA builder.
# ---------------------------------------------------------------------------


@dataclass
class PySSA:
    blocks: list[PyBlock] = field(default_factory=list)
    vars: dict[tuple, PyVar] = field(default_factory=dict)
    # phi key: ``(bb_key, slot)`` — slot is 1-based top-first.
    phis: dict[tuple, PyPhi] = field(default_factory=dict)
    # Per-BB cache populated in phase 2.
    _consumed: dict[PyBlock, int] = field(default_factory=dict)
    _locals: dict[PyBlock, int] = field(default_factory=dict)
    # Per-BB list of (survivor_PyVar, outStackOrder) top-first.
    _surv: dict[PyBlock, list] = field(default_factory=dict)
    # Subroutine metadata.
    _bb_to_sub: dict = field(default_factory=dict)
    _proto_io: dict = field(default_factory=dict)

    @classmethod
    def build(cls, prog: SSAProgram) -> SSAProgram:
        """End-to-end: construct SSA from a QL-loaded ``SSAProgram``
        and return a fresh ``SSAProgram`` shell wired up with the
        PySSA-built structures. Internal builder state is attached
        to the result as ``prog._pyssa`` for the chain helpers
        (:meth:`SSAProgram.chain_predecessors` et al.) — nothing in
        the analysis layer touches it directly.

        Note: :meth:`SSAProgram.__init__` already routes through
        :func:`_apply_pyssa_to` internally, so calling ``PySSA.build``
        on a prog produced by ``SSAProgram(db)`` is idempotent — it
        re-runs the same PySSA construction and returns an
        equivalently-built fresh prog."""
        py = cls._construct(prog)
        return _to_ssaprogram(py, source=prog)

    @classmethod
    def _construct(cls, prog: SSAProgram) -> "PySSA":
        """Run the PySSA construction phases and return the builder
        instance. Use :meth:`build` for the canonical
        SSAProgram-returning entry point; this is exposed for
        diagnostics (e.g. ``python -m tealtools.ssa``).

        (The former phase 5 "heights" was removed: it ran a forward
        height fixpoint whose result was never read — and it blew up to
        ~STACK_MAX entries per BB on recursive subroutines.)"""
        self = cls()
        self._phase1_instantiate(prog)
        self._phase2_arities()
        self._phase3_direct_placement()
        self._phase4_indirect_propagation()
        self._phase6_sim_blocks()
        self._phase8_live_filter()
        return self

    # ----- Phase 1: instantiate PyVars -----------------------------------

    def _phase1_instantiate(self, prog: SSAProgram) -> None:
        by_ql: dict[object, PyBlock] = {}
        for qbb in prog.blocks.values():
            b = PyBlock((qbb.file, qbb.first_line, qbb.last_line))
            for a in qbb.assignments:
                # Arities from the opcode signature table (replaces QL's
                # ssaInputs/ssaOutputs row-counts). op_arity returns the
                # simple phase-1 counts for frame_dig/frame_bury/callsub/
                # retsub; their fat forms are rebuilt by later phases.
                n_in, n_out = op_arity(a.op, a.immediates)
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

    # ----- Phase 2: BB arities + surviving locals ------------------------

    def _phase2_arities(self) -> None:
        for b in self.blocks:
            local_stack: list = []  # bottom-first PyVars
            consumed = 0
            for op in b.ops:
                for _ in range(op.n_in):
                    if local_stack:
                        local_stack.pop()
                    else:
                        consumed += 1
                for v in reversed(op.outputs):
                    local_stack.append(v)
            self._consumed[b] = consumed
            self._locals[b] = len(local_stack)
            # outStackOrder: rank among surviving locals, top-first 1-based.
            top_first = list(reversed(local_stack))
            self._surv[b] = [(v, k + 1) for k, v in enumerate(top_first)]

    def _phi_node_exit_index(self, k: int, b: PyBlock) -> int | None:
        """Slot the phi at entry slot ``k`` of ``b`` ends up at in
        ``b``'s exit, or ``None`` if the phi is consumed (``k <=
        consumed_count``). ``L + k - C``."""
        C = self._consumed[b]
        if k <= C:
            return None
        L = self._locals[b]
        new_k = L + k - C
        if new_k > STACK_MAX:
            return None
        return new_k

    # ----- Phase 3: Direct placement -------------------------------------

    def _phase3_direct_placement(self) -> None:
        """For each surviving local PyVar ``v`` at slot ``k`` of BB
        ``b``, for each successor ``s``, add ``v`` to
        ``phi(k, s).args``."""
        for b in self.blocks:
            for v, k in self._surv[b]:
                for s in b.succs:
                    self._add_arg(s, k, v)

    def _add_arg(self, bb: PyBlock, slot: int, arg) -> bool:
        """Get-or-create ``phi(slot, bb)`` and append ``arg`` if not
        already in args (identity check). Returns True if the arg was
        newly added."""
        key = (bb.key, slot)
        phi = self.phis.get(key)
        if phi is None:
            phi = PyPhi(bb.key, slot)
            self.phis[key] = phi
            bb.entry_phis.append(phi)
        # Dedupe by identity.
        for a in phi.args:
            if a is arg:
                return False
        phi.args.append(arg)
        return True

    # ----- Phase 4: Indirect propagation (worklist) ----------------------

    def _phase4_indirect_propagation(self) -> None:
        """Forward-propagate every existing phi through the CFG via
        ``phiNodeExitIndex``. Each phi ``P`` at ``(k, b)`` that
        survives ``b`` (k' defined) propagates to ``phi(k', s).args``
        for each succ ``s``. Iterate until no new args added or slot
        caps out."""
        wl: deque = deque(self.phis.values())
        in_wl: set = set(id(p) for p in wl)
        while wl:
            P = wl.popleft()
            in_wl.discard(id(P))
            bb_key, k = P.bb_key, P.slot
            b = self._bb_by_key.get(bb_key)
            if b is None:
                continue
            k2 = self._phi_node_exit_index(k, b)
            if k2 is None:
                continue
            for s in b.succs:
                if self._add_arg(s, k2, P):
                    new_phi = self.phis[(s.key, k2)]
                    if id(new_phi) not in in_wl:
                        wl.append(new_phi)
                        in_wl.add(id(new_phi))

    # ----- Phase 6: simulate each BB to fill op.inputs / exit_stack -----

    def _phase6_sim_blocks(self) -> None:
        """For each BB, build entry_stack from placed phis and run a
        stack sim to populate ``op.inputs`` / ``op.outputs`` and
        ``b.exit_stack``.

        Negative-N ``frame_dig`` / ``frame_bury`` are modelled with
        QL's fat-stack convention: each op consumes the entire stack
        band from the current top down to (and including) the target
        frame slot, and emits a fresh set of outputs covering the
        post-stack. For ``frame_dig`` n_out == n_in + 1 (band + dug
        copy on top); for ``frame_bury`` n_out == n_in - 1 (band minus
        popped top, target replaced). This matches QL's
        :func:`_shuffle_mapping` so taint / constant / range
        propagation can carry passthrough values through long
        frame-access chains."""
        # 6a: pre-compute b.entry_stack for every BB so per-op fat
        # expansion below can read sub.entry_stack regardless of
        # iteration order.
        # Max phi slot per BB in a single pass over self.phis. The previous
        # per-block ``[s for (bb_key, s) in self.phis if bb_key == b.key]``
        # rescanned every phi for every block — O(blocks x phis), which is
        # tens of millions of iterations once a contract hits the
        # [1..STACK_MAX] indirect-phi space (phis number 100k+).
        max_slot_by_bb: dict = {}
        for (bb_key, s) in self.phis:
            if s > max_slot_by_bb.get(bb_key, 0):
                max_slot_by_bb[bb_key] = s
        for b in self.blocks:
            max_slot = max_slot_by_bb.get(b.key, 0)
            entry = [None] * max_slot
            for k in range(1, max_slot + 1):
                phi = self.phis.get((b.key, k))
                entry[max_slot - k] = phi
            b.entry_stack = entry

        # 6b: bb_to_sub / proto_io setup — used to look up the
        # routine's arg count + entry stack for each fat expansion.
        self._compute_subs_and_protos()

        # 6c: per-BB simulator.
        for b in self.blocks:
            local_stack: list = list(b.entry_stack)
            sub = self._bb_to_sub.get(b)
            proto = self._proto_io.get(sub) if sub is not None else None
            for op in b.ops:
                if (op.op in ("frame_dig", "frame_bury")
                        and proto is not None and sub is not None
                        and self._try_expand_frame_op(op, local_stack, sub, proto)):
                    continue
                op.inputs = []
                for _ in range(op.n_in):
                    if local_stack:
                        op.inputs.append(local_stack.pop())
                    else:
                        op.inputs.append(None)
                for v in reversed(op.outputs):
                    local_stack.append(v)
            b.exit_stack = local_stack

    # ----- Phase 6 helpers ------------------------------------------------

    def _compute_subs_and_protos(self) -> None:
        """Populate ``self._bb_to_sub`` (every BB → its owning routine
        entry BB) and ``self._proto_io`` (sub entry BB → (args, returns)
        from its ``proto`` opcode). Independent of stack sim — only
        depends on CFG shape and proto immediates from phase 1."""
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
        self._bb_to_sub = bb_to_sub

        proto_io: dict = {}
        for se in sub_entries:
            if se.ops and se.ops[0].op == "proto":
                parts = se.ops[0].immediates.split()
                try:
                    proto_io[se] = (int(parts[0]), int(parts[1]))
                except (ValueError, IndexError):
                    pass
        self._proto_io = proto_io

    def _try_expand_frame_op(
        self, op: PyOp, local_stack: list, sub: PyBlock, proto: tuple,
    ) -> bool:
        """Rewrite ``frame_dig N`` / ``frame_bury N`` (either sign of
        ``N``) to QL's fat-stack convention. Returns ``True`` on
        rewrite; ``False`` to fall back to the narrow path.

        The target slot lives at bottom-first stack index
        ``len(sub.entry_stack) + N``:
        - For ``N < 0`` (args below frame_base): ``len - |N|`` — args
          occupy the top of the sub's pre-stack.
        - For ``N >= 0`` (locals above frame_base): ``len + N`` —
          locals must already have been pushed before this read/write.

        The consumed band is everything at and above the target in the
        current ``local_stack`` (top down to target, inclusive).
        ``frame_dig`` emits ``n_consumed + 1`` outputs (band + dug copy
        on top, per :func:`_shuffle_mapping`); ``frame_bury`` emits
        ``n_consumed - 1`` (band with target replaced, top popped)."""
        try:
            n = int(op.immediates.strip().split()[0])
        except (ValueError, IndexError, AttributeError):
            return False
        # Unified position: arg slot -K at index ``len - K``; local
        # slot +K at index ``len + K``. Frame_base sits at index
        # ``len(sub.entry_stack)``.
        target_idx = len(sub.entry_stack) + n
        if target_idx < 0 or target_idx >= len(local_stack):
            return False
        # n_consumed = depth from top to target inclusive (band size).
        n_consumed = len(local_stack) - target_idx
        # Top-first band — first element was the previous top.
        band_topfirst = list(reversed(local_stack[target_idx:]))

        if op.op == "frame_dig":
            n_out_new = n_consumed + 1
        else:  # frame_bury -- need at least one slot above the target to pop.
            if n_consumed < 1:
                return False
            n_out_new = n_consumed - 1
        op.inputs = list(band_topfirst)
        del local_stack[target_idx:]
        new_outs: list = []
        for k in range(1, n_out_new + 1):
            v = PyVar(op.file, op.line, k)
            self.vars[v.key()] = v
            new_outs.append(v)
        op.outputs = new_outs
        op.n_in = n_consumed
        op.n_out = n_out_new
        # ``new_outs`` is top-first per shuffle convention; push back bottom-first.
        local_stack.extend(reversed(new_outs))
        return True

    # ----- Phase 8: liveness filter --------------------------------------

    def _phase8_live_filter(self) -> None:
        """Drop phis not transitively consumed by any op.inputs."""
        live: set = set()
        work: list = []
        for b in self.blocks:
            for op in b.ops:
                for inp in op.inputs:
                    if isinstance(inp, PyPhi) and inp not in live:
                        live.add(inp)
                        work.append(inp)
        while work:
            phi = work.pop()
            for a in phi.args:
                if isinstance(a, PyPhi) and a not in live:
                    live.add(a)
                    work.append(a)

        for key in list(self.phis.keys()):
            if self.phis[key] not in live:
                del self.phis[key]
        for b in self.blocks:
            b.entry_phis = [p for p in b.entry_phis if p in live]
            b.entry_stack = [
                None if isinstance(e, PyPhi) and e not in live else e
                for e in b.entry_stack
            ]
            b.exit_stack = [
                None if isinstance(e, PyPhi) and e not in live else e
                for e in b.exit_stack
            ]

    # ----- helper: bb-by-key lookup --------------------------------------

    @property
    def _bb_by_key(self) -> dict:
        if not hasattr(self, "__bb_by_key"):
            self.__bb_by_key = {b.key: b for b in self.blocks}
        return self.__bb_by_key

    # ----- diagnostic render --------------------------------------------

    def render(self) -> str:
        def lbl(o) -> str:
            if isinstance(o, PyVar):
                return f"V#{o.idx}@L{o.line}"
            if isinstance(o, PyPhi):
                return f"φ_{o.slot}@L{o.bb_key[1]}"
            if o is None:
                return "?"
            return repr(o)

        out: list[str] = []
        for b in self.blocks:
            out.append(f"# BB L{b.key[1]}-{b.key[2]}  "
                       f"entry_phis={len(b.entry_phis)}")
            for phi in sorted(b.entry_phis, key=lambda p: p.slot):
                args = ", ".join(lbl(a) for a in phi.args)
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


# ---------------------------------------------------------------------------
# _to_ssaprogram — PySSA → SSAProgram-compatible shell (internal).
# ---------------------------------------------------------------------------


def _fold_spec_fixed(a):
    """Lazy import wrapper around :func:`const_fold.fold_spec_fixed`.
    Kept module-private to avoid pulling the passes layer into
    ``ssa.py``'s top-level imports."""
    from ..passes.const_fold import fold_spec_fixed
    return fold_spec_fixed(a)


def _compute_inner_txn_fields(prog: SSAProgram) -> list:
    """Lazy import wrapper around
    :func:`..passes.inner_txn_fields.compute_inner_txn_fields`.
    Kept module-private to avoid pulling the passes layer into
    ``ssa.py``'s top-level imports."""
    from ..passes.inner_txn_fields import compute_inner_txn_fields
    return compute_inner_txn_fields(prog)


def _compute_scratch_influence(prog: SSAProgram) -> dict:
    """Lazy import wrapper around
    :func:`..passes.scratch_influence.compute_scratch_influence`.
    Kept module-private to avoid pulling the passes layer into
    ``ssa.py``'s top-level imports."""
    from ..passes.scratch_influence import compute_scratch_influence
    return compute_scratch_influence(prog)


def _to_ssaprogram(py: PySSA, source: SSAProgram) -> SSAProgram:
    """Translate a freshly-built :class:`PySSA` into a new
    ``SSAProgram`` shell using ``source`` as the read-only graph
    backend. See :func:`_apply_pyssa_to` for the version that mutates
    an existing program in place (used by ``SSAProgram.__init__`` to
    route SSA construction through PySSA)."""
    prog = SSAProgram.__new__(SSAProgram)
    _apply_pyssa_to(prog, py, source=source)
    return prog


def _collapse_phi_args_to_leaves(py: PySSA, phi_map: dict, var_map: dict) -> None:
    """Collapse each ``Phi``'s args to the transitive ``SSAVar`` leaves
    reachable through PySSA's ``PyPhi.args`` graph (SCC condensation,
    O(N+E) memoized per SCC). Matches QL's ``phiArgs.ql`` projection."""
    import networkx as nx
    _g = nx.DiGraph()
    _g.add_nodes_from(py.phis.values())
    for _py_p in py.phis.values():
        for _arg in _py_p.args:
            if isinstance(_arg, PyPhi):
                _g.add_edge(_py_p, _arg)
    _sccs = list(nx.strongly_connected_components(_g))
    _scc_of = {p: i for i, s in enumerate(_sccs) for p in s}
    _scc_succs = [set() for _ in _sccs]
    for _u, _v in _g.edges:
        _su, _sv = _scc_of[_u], _scc_of[_v]
        if _su != _sv:
            _scc_succs[_su].add(_sv)
    _scc_direct: list[list[PyVar]] = [[] for _ in _sccs]
    for _py_p in py.phis.values():
        _s = _scc_of[_py_p]
        for _arg in _py_p.args:
            if isinstance(_arg, PyVar):
                _scc_direct[_s].append(_arg)
    _cond = nx.DiGraph()
    _cond.add_nodes_from(range(len(_sccs)))
    for _u, _ss in enumerate(_scc_succs):
        for _v in _ss:
            _cond.add_edge(_u, _v)
    _scc_leaves: list[list[PyVar]] = [[] for _ in _sccs]
    for _s in reversed(list(nx.topological_sort(_cond))):
        _seen_ids: set = set()
        _out: list = []
        for _v in _scc_direct[_s]:
            if id(_v) not in _seen_ids:
                _seen_ids.add(id(_v))
                _out.append(_v)
        for _succ in _scc_succs[_s]:
            for _v in _scc_leaves[_succ]:
                if id(_v) not in _seen_ids:
                    _seen_ids.add(id(_v))
                    _out.append(_v)
        _scc_leaves[_s] = _out

    for py_p, p in phi_map.items():
        for _leaf_pv in _scc_leaves[_scc_of[py_p]]:
            _ssa = var_map.get(_leaf_pv)
            if _ssa is not None:
                p.args.append(_ssa)


def _build_assignments(prog: SSAProgram, py: PySSA, var_map: dict,
                       phi_map: dict, bb_map: dict) -> None:
    """Build ``prog.assignments`` (+ ``bb.assignments``, def/use back-refs,
    and spec-fixed const seeds) from the PySSA ops."""
    def _xlate(o):
        if o is None:
            return None
        if isinstance(o, PyVar):
            return var_map.get(o)
        if isinstance(o, PyPhi):
            return phi_map.get(o)
        return o

    for py_b in py.blocks:
        bb = bb_map[py_b]
        for py_op in py_b.ops:
            inputs = [
                _xlate(i) for i in py_op.inputs
                if _xlate(i) is not None
            ]
            outputs = [
                _xlate(v) for v in py_op.outputs
                if isinstance(v, PyVar) and _xlate(v) is not None
            ]
            a = Assignment(
                outputs=outputs,
                op=py_op.op,
                immediates=py_op.immediates,
                inputs=inputs,
                location=Location(py_op.file, py_op.line),
                ast_code=f"{py_op.op} {py_op.immediates}".strip(),
                basic_block=bb,
            )
            for v in outputs:
                v.defined_by = a
                # Inline seed for spec-fixed AVM ops whose value is a known
                # compile-time literal (e.g. ``global ZeroAddress``) —
                # replaces what ``mustValues.ql`` emitted for these ops.
                if v.const_value is None:
                    fold = _fold_spec_fixed(a)
                    if fold is not None:
                        v.const_value = fold
            for i in inputs:
                if hasattr(i, "uses"):
                    i.uses.append(a)
            prog.assignments.append(a)
            bb.assignments.append(a)

    prog.assignments.sort(key=lambda a: (a.location.file, a.location.line))


def _seed_consts_and_identity_steps(prog: SSAProgram, scratch_stores: dict) -> None:
    """Seed ``const_value`` through value-identity edges (shuffle pass-
    through + scratch reads, to a fixed point) and build the identity-flow
    step relation. Replaces ``mustValues.ql`` / ``valueIdentitySteps.ql``;
    stashes the relation on ``prog._graph.graph["identity_steps"]``.

    Pre-filters the candidate ops once so the fixpoint only scans ops that
    could seed a const, then iterates so identity-of-identity chains flow
    (e.g. const -> swap -> load -> swap -> consumer)."""
    _shuffle_candidates: list[tuple] = []
    _load_candidates: list = []
    for _a in prog.assignments:
        _m = _shuffle_mapping(_a)
        if _m is not None:
            _shuffle_candidates.append((_a, _m))
        if _a.op == "load" and len(_a.outputs) == 1:
            _load_candidates.append(_a)
    _changed = True
    while _changed:
        _changed = False
        for _a, _m in _shuffle_candidates:
            for _out_idx, _in_idx in enumerate(_m):
                if _out_idx >= len(_a.outputs) or _in_idx >= len(_a.inputs):
                    continue
                _out_v = _a.outputs[_out_idx]
                if not isinstance(_out_v, SSAVar) or _out_v.const_value is not None:
                    continue
                _in_cv = getattr(_a.inputs[_in_idx], "const_value", None)
                if _in_cv is not None:
                    _out_v.const_value = _in_cv
                    _changed = True
        for _a in _load_candidates:
            _out_v = _a.outputs[0]
            if not isinstance(_out_v, SSAVar) or _out_v.const_value is not None:
                continue
            _stores = scratch_stores.get(
                (_a.location.file, _a.location.line)
            )
            if not _stores:
                continue
            _resolved: list[Const] = []
            _ok = True
            for _sv_file, _sv_line, _sv_idx in _stores:
                _src_v = prog.vars.get((_sv_file, _sv_line, _sv_idx))
                _src_cv = _src_v.const_value if _src_v is not None else None
                if _src_cv is None:
                    _ok = False
                    break
                _resolved.append(_src_cv)
            if _ok and _resolved and all(c == _resolved[0] for c in _resolved):
                _out_v.const_value = _resolved[0]
                _changed = True

    _identity_steps: list = []

    def _ssavar_key(v: SSAVar) -> tuple:
        return ("var", v.file, v.line, v.index)

    def _endpoint_key(o):
        if isinstance(o, SSAVar):
            return _ssavar_key(o)
        if isinstance(o, Phi):
            return ("phi", o.file, o.line, o.kind, o.stack_index)
        return None

    # (a) shuffle pass-through
    for _a, _m in _shuffle_candidates:
        for _out_idx, _in_idx in enumerate(_m):
            if _out_idx >= len(_a.outputs) or _in_idx >= len(_a.inputs):
                continue
            _out_v = _a.outputs[_out_idx]
            _in_o = _a.inputs[_in_idx]
            if not isinstance(_out_v, SSAVar):
                continue
            _src = _endpoint_key(_in_o)
            if _src is None or _src == _ssavar_key(_out_v):
                continue
            _identity_steps.append((_src, _ssavar_key(_out_v)))

    # (b) single-source phi
    for _p in prog.phis.values():
        if not _p.args:
            continue
        _first = _p.args[0]
        if all(a is _first for a in _p.args[1:]):
            _src = _endpoint_key(_first)
            _snk = ("phi", _p.file, _p.line, _p.kind, _p.stack_index)
            if _src is not None and _src != _snk:
                _identity_steps.append((_src, _snk))

    # (c) scratch bridge
    for _a in _load_candidates:
        _out_v = _a.outputs[0]
        if not isinstance(_out_v, SSAVar):
            continue
        _stores = scratch_stores.get(
            (_a.location.file, _a.location.line)
        )
        if not _stores:
            continue
        _snk = _ssavar_key(_out_v)
        for _sv_file, _sv_line, _sv_idx in _stores:
            _identity_steps.append(
                (("var", _sv_file, _sv_line, _sv_idx), _snk)
            )

    if hasattr(prog._graph, "graph"):
        prog._graph.graph["identity_steps"] = _identity_steps


def _drop_unconsumed_phis(prog: SSAProgram) -> None:
    """Drop phis not transitively consumed by any op input, so ``prog.phis``
    is the consumer set rather than the full builder output."""
    _consumed: set = set()
    for _a in prog.assignments:
        for _inp in _a.inputs:
            if isinstance(_inp, Phi):
                _consumed.add(id(_inp))
    _reached: set = set(_consumed)
    _work: list = [p for p in prog.phis.values() if id(p) in _reached]
    while _work:
        _phi = _work.pop()
        for _arg in _phi.args:
            if isinstance(_arg, Phi) and id(_arg) not in _reached:
                _reached.add(id(_arg))
                _work.append(_arg)
    prog.phis = {k: p for k, p in prog.phis.items() if id(p) in _reached}
    for bb in prog.blocks.values():
        bb.phis = [p for p in bb.phis if id(p) in _reached]


def _apply_pyssa_to(
    prog: SSAProgram, py: PySSA, *, source: Optional[SSAProgram] = None,
) -> None:
    """Mutate ``prog`` to use ``py``-built SSA: rebuilds ``prog.vars`` /
    ``prog.phis`` / ``prog.assignments`` / ``prog.blocks`` from PySSA
    structures and discards whatever was there before.

    Used by:

    - :meth:`PySSA.build` (with ``source`` == a separate ``prog_ql``).
    - :meth:`SSAProgram.__init__` (with ``source is None`` — reads
      directly from ``prog`` for graph + var const/range/type
      annotations). This lets ``SSAProgram(db)`` route SSA
      construction through PySSA without an external bridge step.

    Steps:

    - Each :class:`PyVar` becomes an :class:`SSAVar`; each :class:`PyPhi`
      a :class:`Phi` (kind ``"DirectPhi"``). Phi args are collapsed to
      transitive ``SSAVar`` leaves via SCC condensation of the
      ``PyPhi.args`` graph (O(N+E) memoized per SCC).
    - Phis not transitively consumed by any op input are dropped, so
      ``prog.phis`` is the consumer set rather than the full builder
      output (the difference is large on wormhole-class contracts).
    - Original chain structure is preserved off the hot path via
      ``prog._pyssa`` / ``prog._phi_to_pyphi`` / ``prog._pyphi_to_phi``;
      ``SSAProgram.chain_predecessors`` / ``chain_root`` /
      ``chain_reaches`` query through it backend-agnostically.
    """
    # ``source`` defaults to ``prog`` for the in-place case. We read
    # const_value / range / type from source.vars (already populated
    # by the QL pre-pass) and reuse source._graph + source.labels.
    # Snapshot anything we'll re-read from ``src`` *before* wiping
    # ``prog`` — in the in-place case (``source is None``) ``src.vars``
    # IS ``prog.vars``, so the wipe would otherwise clobber the data
    # we need to copy over.
    src = source if source is not None else prog
    src_vars_snapshot = dict(getattr(src, "vars", {}))
    src_labels_snapshot = list(getattr(src, "labels", []))
    src_graph_snapshot = getattr(src, "_graph", None)
    src_db_path_snapshot = getattr(src, "db_path", None)

    prog.vars = {}
    prog.phis = {}
    prog.assignments = []
    prog.blocks = {}
    prog.labels = src_labels_snapshot
    prog.mat_phis = []
    prog._graph = src_graph_snapshot
    prog.db_path = src_db_path_snapshot
    # Match the exact state flags ``SSAProgram.__init__`` sets, so every
    # pass that gates on one of them finds it.
    prog._materialized = False
    prog._consts_propagated = False
    prog._dead_eliminated = False
    prog._scratch_propagated = False
    prog._ranges_propagated = False
    prog._shuffles_propagated = False
    prog._inputs_propagated = False

    # 1) SSAVars. Seed const_value / range / type from the source
    # prog's already-populated var table (QL pre-pass wired these from
    # ``const_outputs`` / ``must_outputs`` graph annotations).
    var_map: dict = {}  # PyVar -> SSAVar
    for key, py_v in py.vars.items():
        v = SSAVar(py_v.file, py_v.line, py_v.idx)
        var_map[py_v] = v
        prog.vars[key] = v
        src_v = src_vars_snapshot.get(key)
        if src_v is not None:
            if src_v.const_value is not None:
                v.const_value = src_v.const_value
            if src_v.range is not None:
                v.range = src_v.range
            if src_v.type is not None:
                v.type = src_v.type

    # 2) Phis. PySSA has one phi per (bb_key, slot); the QL
    # Direct/Indirect distinction is collapsed in PySSA's unified
    # model. Register under DirectPhi only. Lookups via
    # :meth:`SSAProgram.phi` are kind-agnostic so consumers that
    # receive a kind from a QL row (e.g.
    # ``inner_txn_report._resolve_operand``) still find the phi
    # whether they ask for ``DirectPhi`` or ``IndirectPhi``.
    phi_map: dict = {}  # PyPhi -> Phi
    for (bb_key, slot), py_p in py.phis.items():
        p = Phi(bb_key[0], bb_key[1], slot, "DirectPhi")
        phi_map[py_p] = p
        prog.phis[(bb_key[0], bb_key[1], "DirectPhi", slot)] = p

    # 3) BasicBlocks.
    bb_map: dict = {}
    for py_b in py.blocks:
        bb = BasicBlock(*py_b.key)
        bb_map[py_b] = bb
        prog.blocks[py_b.key] = bb
    for py_b, bb in bb_map.items():
        bb.predecessors = [bb_map[p] for p in py_b.preds if p in bb_map]
        bb.successors = [bb_map[s] for s in py_b.succs if s in bb_map]

    # 4) Attach phis to host BBs.
    for py_p, p in phi_map.items():
        bb = prog.blocks.get(py_p.bb_key)
        if bb is not None:
            p.basic_block = bb
            bb.phis.append(p)

    # 4.5) Surface each BB's exit stack (the per-edge slot values) onto the
    # public block, translated to public operands. Out-of-SSA / block-arg
    # lowering reads ``pred.exit_stack[k]`` for the value a successor's
    # slot-k phi receives on that edge -- info ``Phi.args`` (a dedup'd
    # value-set) no longer carries. Verbatim order (bottom-first); a dead
    # slot stays ``None``. Pure plumbing of construction data.
    for py_b, bb in bb_map.items():
        translated: list = []
        for o in py_b.exit_stack:
            if o is None:
                translated.append(None)
            elif o in var_map:
                translated.append(var_map[o])
            elif o in phi_map:
                translated.append(phi_map[o])
            else:
                translated.append(None)
        bb.exit_stack = translated

    # 5) Collapse each Phi's args to the transitive SSAVar leaves reachable
    # through PySSA's PyPhi.args graph (SCC condensation).
    _collapse_phi_args_to_leaves(py, phi_map, var_map)

    # 6) Build Assignments (+ bb back-refs, def/use links, spec-fixed seeds).
    _build_assignments(prog, py, var_map, phi_map, bb_map)

    # 6.4) Inner-transaction field grouping. For each ``itxn_field``
    # op, find the immediately-enclosing ``(start, end)`` pair via CFG
    # reach. Replaces ``innerTxnFields.ql``. The result lives at
    # ``prog._graph.graph["inner_txn_fields"]`` — same shape
    # :class:`tealtools.inner_txn_report.InnerTxnReport` expects.
    if prog._graph is not None and hasattr(prog._graph, "graph"):
        prog._graph.graph["inner_txn_fields"] = _compute_inner_txn_fields(prog)

    # 6.45) Scratch-slot reaching-definitions. Computes, for every
    # ``load N`` opcode, the set of ``store N`` value-SSAVars that may
    # reach it via the CFG (with kill analysis: a later ``store N``
    # supersedes an earlier one on the same path). Replaces
    # ``scratchInfluence.ql`` so we can drop that query from the load
    # path. Populates the graph annotation
    # ``prog._graph.nodes[load_node]["scratch_stores"]`` in the same
    # shape the QL loader used, so every existing consumer
    # (``propagate_scratch_constants``, taint engine step 2c,
    # ``detections.common._scratch_stores_for``, …) keeps working.
    _scratch_stores = _compute_scratch_influence(prog)
    if prog._graph is not None:
        _nodes_by_loc: dict = {}
        for _n in prog._graph.nodes:
            _loc = getattr(_n, "location", None)
            if _loc is not None:
                _nodes_by_loc.setdefault(
                    (_loc.file, _loc.start_line), []
                ).append(_n)
        for _load_key, _val_keys in _scratch_stores.items():
            for _node in _nodes_by_loc.get(_load_key, []):
                prog._graph.nodes[_node]["scratch_stores"] = list(_val_keys)

    # 6.5/6.6) Seed const_value through value-identity edges (shuffle
    # pass-through + scratch reads, to a fixed point) and build the
    # identity-flow step relation — both replacing what ``mustValues.ql``
    # / ``valueIdentitySteps.ql`` provided. Stashes the relation on
    # ``prog._graph.graph["identity_steps"]`` for ``propagate_constants``.
    _seed_consts_and_identity_steps(prog, _scratch_stores)

    # 7) Drop phis not transitively consumed by any op input.
    _drop_unconsumed_phis(prog)

    for bb in prog.blocks.values():
        bb.assignments.sort(key=lambda a: a.location.line)
        bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    # 8) Auxiliary chain-structure refs for analyses that need them
    # (chain root, propagation graph). Off the hot path: nothing in
    # ``prog.phis`` iteration touches these.
    prog._pyssa = py
    prog._phi_to_pyphi = {p: pp for pp, p in phi_map.items()}
    prog._pyphi_to_phi = dict(phi_map)

    return prog


def _demo(db_path: str) -> None:
    """Render the PySSA-built SSA for a database. Uses the internal
    :meth:`PySSA._construct` to get the builder instance directly so
    we can call :meth:`PySSA.render` for the diagnostic dump — every
    other caller should use :meth:`PySSA.build` which returns the
    wrapped ``SSAProgram``."""
    import time
    t0 = time.perf_counter()
    prog = SSAProgram(db_path, verbose=False)
    t_ql = time.perf_counter() - t0
    t0 = time.perf_counter()
    py = PySSA._construct(prog)
    t_py = time.perf_counter() - t0
    if len(py.blocks) <= 30:
        print(py.render())
    else:
        print(f"({len(py.blocks)} blocks — full render suppressed)")
    print(
        f"[ssa] QL load: {t_ql:.2f}s  build: {t_py * 1000:.1f}ms  "
        f"blocks={len(py.blocks)}  vars={len(py.vars)}  phis={len(py.phis)}"
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m tealtools.ssa <codeql-db-path>",
              file=sys.stderr)
        raise SystemExit(2)
    _demo(sys.argv[1])
