"""Canonical SSA module — the pure-Python SSA builder.

Provides :meth:`PySSA.build`, which returns an :class:`SSAProgram` (from
:mod:`tealql.tealtools.ssa.program`) directly, ready for every existing analysis
(constant propagation, taint, detectors, reports). The data classes it works
over live in :mod:`tealql.tealtools.ssa.models`; external consumers import them (and
``SSAProgram``) from the package ``__init__``, which is the re-export surface.

Canonical idiom:

```python
from tealql.tealtools.ssa import SSAProgram, PySSA

prog = SSAProgram("contract.teal")   # a .teal file or a dir of them
# every existing analysis runs on prog.
```

Pipeline (:meth:`PySSA._construct`):

  1. Instantiate PyVars per opcode output.
  2. BB arities + surviving locals (``outStackOrder``).
  3. Phi placement: Braun on-demand construction (``_phase_braun`` + the
     forward depth cap ``_compute_entry_depths``) -- minimal SSA, ~160-209x
     faster than the maximal-then-pruned placement it replaced. (Two superseded
     alternates, an eager placement and a join-only worklist, were reachable
     only via ``TEAL_SSA_EAGER`` / ``TEAL_SSA_JOIN_ONLY``. Nothing ever set
     either, so they were three phi-placement algorithms deep in the most
     safety-critical file here with only one of them ever run -- and the
     join-only path spiralled on net-changing loops, so it was not even a
     working fallback. Both deleted.)
  (The former phase 5 "heights" forward stack-delta DF was REMOVED -- its
     result was never read and it blew up on recursive subroutines.)
  6. Per-BB sim to fill ``op.inputs`` / ``b.exit_stack``;
     ``frame_dig`` / ``frame_bury`` (any-sign N) expand under the
     fat-stack convention (consume the band from current top down to
     the target slot, emit fresh outputs covering the post-stack).
  8. Liveness filter (drop phis not transitively consumed by any op).

``phiNodeExitIndex(k, b) = L_b + k - C_b`` if ``k > C_b``, else
undefined (consumed). Unified ``PyPhi`` class — kind=Direct/Indirect
is collapsed; chain structure is preserved on the args graph (which
can be cyclic at constant-stack CFG loops; traversal must use
``seen`` sets).

CLI: ``python -m tealql.tealtools.ssa <teal-source>`` (renders the PySSA build).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

# Data classes the builder works over; the re-export surface for external
# consumers is the package __init__, not this module.
from .models import (
    Assignment,
    BasicBlock,
    Const,
    Location,
    Phi,
    SSAVar,
    _shuffle_mapping,
)
from .program import SSAProgram
from ..avm import op_arity


STACK_MAX = 1000

# Sentinel for "entry slot not yet resolved" (``None`` is a valid resolved
# value — an entry slot with no incoming definition).
_MISSING = object()


def _frame_imm(op):
    """The N of a frame_dig/frame_bury, or None."""
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


# A reconstructed-SSA operand. ``None`` marks a slot the builder could
# not resolve (a depth mismatch surfaced rather than hidden).
Operand = Union["PyVar", "PyPhi"]


class PyVar:
    """An SSA variable: one stack value produced by one opcode output.

    Identity is ``(file, line, idx)`` with ``idx`` 1-based; ``idx == 1``
    is the opcode's topmost output.
    """

    __slots__ = ("file", "line", "idx", "_hash")

    def __init__(self, file: str, line: int, idx: int):
        self.file = file
        self.line = line
        self.idx = idx
        # Identity (file, line, idx) is immutable, so cache the hash: the phi-leaf
        # collapse hashes PyVars tens of millions of times on big proto contracts,
        # and rebuilding+hashing the key tuple each call dominated SSA construction.
        self._hash = hash((file, line, idx))

    def key(self) -> tuple:
        return (self.file, self.line, self.idx)

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other) -> bool:
        return (isinstance(other, PyVar) and self.idx == other.idx
                and self.line == other.line and self.file == other.file)

    def __repr__(self) -> str:
        return f"V#{self.idx}@L{self.line}"


class PyPhi:
    """A phi at a basic block's entry, for one stack slot.

    Identity is ``(bb_key, slot)`` — ``bb_key`` is ``(file, first_line,
    last_line)``; ``slot`` is 1-based top-first (top of the entry
    stack is slot 1, the stack-index convention).

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

    ``n_in`` / ``n_out`` are arities from the loaded graph (overridden for
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
    # Braun on-demand construction state (the default; TEAL_SSA_EAGER /
    # TEAL_SSA_JOIN_ONLY select the superseded alternates).
    _surv_by_slot: dict = field(default_factory=dict)   # block -> {slot: PyVar}
    _entry_val: dict = field(default_factory=dict)       # (bb_key, slot) -> value
    # Both keyed by PyPhi.key() == (bb_key, slot) — NEVER by id(): a removed
    # trivial phi loses its last strong reference (popped from self.phis /
    # entry_phis), and with __slots__ CPython reuses the freed address, so an
    # id() key can alias a NEW live phi and resolve it to the OLD phi's value.
    # (bb_key, slot) is unique per phi (the _entry_val memo creates at most one).
    _replaced: dict = field(default_factory=dict)        # PyPhi.key() -> replacement
    _phi_users: dict = field(default_factory=dict)       # PyPhi.key() -> set[PyPhi]
    _max_entry: dict = field(default_factory=dict)       # bb_key -> max entry slot read
    # block -> frame-aware exit-stack sim (or None); see _build_frame_exit_sim.
    _frame_sim_cache: dict = field(default_factory=dict)

    @classmethod
    def build(cls, prog: SSAProgram) -> SSAProgram:
        """End-to-end: construct SSA from a graph-loaded ``SSAProgram``
        and return a fresh ``SSAProgram`` shell wired up with the
        PySSA-built structures. Internal builder state is attached
        to the result as ``prog._pyssa`` for the chain helpers
        (:meth:`SSAProgram.chain_predecessors` et al.) — nothing in
        the analysis layer touches it directly.

        Note: :meth:`SSAProgram.__init__` already routes through
        :func:`_apply_pyssa_to` internally, so calling ``PySSA.build``
        on a prog produced by ``SSAProgram(source)`` is idempotent — it
        re-runs the same PySSA construction and returns an
        equivalently-built fresh prog."""
        py = cls._construct(prog)
        return _to_ssaprogram(py, source=prog)

    @classmethod
    def _construct(cls, prog: SSAProgram) -> "PySSA":
        """Run the PySSA construction phases and return the builder
        instance. Use :meth:`build` for the canonical
        SSAProgram-returning entry point; this is exposed for
        diagnostics (e.g. ``python -m tealql.tealtools.ssa``).

        (The former phase 5 "heights" was removed: it ran a forward
        height fixpoint whose result was never read — and it blew up to
        ~STACK_MAX entries per BB on recursive subroutines.)"""
        self = cls()
        self._phase1_instantiate(prog)
        self._phase2_arities()
        # Phi placement: Braun on-demand construction (``_phase_braun`` + the
        # forward depth cap ``_compute_entry_depths``). Minimal SSA, ~160-209x
        # faster than the maximal-then-pruned placement it replaced (xgov
        # 0.95s/77k phis -> 0.01s/11; folks-v3 3.15s/160k -> 0.02s/25) and
        # behaviourally identical to it (puya corpus 513/0, Tier-3 5/5,
        # live-AVM 35-corpus 33/0). The depth cap fixes the loop spiral at its
        # slot-model root (a net-changing loop's ``L+k-C`` map climbs to
        # STACK_MAX under ANY construction).
        self._phase_braun()
        self._phase6_sim_blocks()
        self._phase8_live_filter()
        return self

    # ----- Phase 1: instantiate PyVars -----------------------------------

    def _phase1_instantiate(self, prog: SSAProgram) -> None:
        by_ql: dict[object, PyBlock] = {}
        for qbb in prog.blocks.values():
            b = PyBlock((qbb.file, qbb.first_line, qbb.last_line))
            for a in qbb.assignments:
                # Arities from the opcode signature table. op_arity
                # returns the simple phase-1 counts for
                # frame_dig/frame_bury/callsub/
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

    def _phase6_sim_blocks(self) -> None:
        """For each BB, build entry_stack from placed phis and run a
        stack sim to populate ``op.inputs`` / ``op.outputs`` and
        ``b.exit_stack``.

        Negative-N ``frame_dig`` / ``frame_bury`` are modelled with
        the fat-stack convention: each op consumes the entire stack
        band from the current top down to (and including) the target
        frame slot, and emits a fresh set of outputs covering the
        post-stack. For ``frame_dig`` n_out == n_in + 1 (band + dug
        copy on top); for ``frame_bury`` n_out == n_in - 1 (band minus
        popped top, target replaced). This agrees with
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
        if self._entry_val:
            # Braun mode: entry_stack carries the on-demand resolved value at
            # each read slot -- phi OR a collapsed (trivial-phi) value, which
            # has no entry in ``self.phis`` -- to its top-first depth.
            for b in self.blocks:
                depth = self._max_entry.get(b.key, 0)
                entry = [None] * depth
                for k in range(1, depth + 1):
                    entry[depth - k] = self._resolve(
                        self._entry_val.get((b.key, k)))
                b.entry_stack = entry
        else:
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
        # A single-pred block places no phis (nothing merges), so its phi-built
        # entry_stack (6a) is empty — losing the stack flowing in from its sole
        # pred and hiding any frame slot the pred set up via a stack op (e.g.
        # `bury`ing a box name) from a cross-block `frame_dig`. Seed such a block
        # from the pred's already-simulated exit_stack (same sub, not a proto
        # entry, pred already simulated — so order can't make this unsound).
        processed: set = set()
        for b in self.blocks:
            local_stack: list = list(b.entry_stack)
            if len(b.preds) == 1:
                (p,) = tuple(b.preds)
                if (p in processed and b not in self._proto_io
                        and self._bb_to_sub.get(b) is self._bb_to_sub.get(p)):
                    local_stack = list(p.exit_stack)
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
            processed.add(b)

    # ----- Phase 3+4: on-demand join-only phi placement ------------------

    def _phase_braun(self) -> None:
        """Braun et al. (2013) on-demand SSA, filled+sealed case. Place a phi at
        an entry slot only when it is READ (by an op here, or transitively by a
        successor), recursing into predecessors and collapsing trivial phis at
        creation. Memoising the phi BEFORE recursing breaks loop back-edge
        cycles without the join-only worklist's growing-slot spiral, and the
        trivial-phi cascade folds the constant-stack-loop chains to a single
        value rather than churning slots 1..STACK_MAX.

        Produces ``self.phis`` plus ``self._entry_val[(bb_key, slot)]`` — the
        value (phi / PyVar / collapsed) reaching each read entry slot. Phase 6
        reads the latter to build entry_stacks: a collapsed slot has no phi, so
        the entry_stack can't be rebuilt from ``self.phis`` alone."""
        import sys as _sys
        # The depth cap bounds recursion to the true stack depth x passthrough
        # chain length (~35 on folks-v3, never the STACK_MAX spiral); a modest
        # raise covers huge real contracts without the spiral's unbounded climb.
        # try/finally restores the prior limit so this construction-local need
        # never leaks process-wide -- including on the exception path, which now
        # matters: a build failure is caught (LiftError) rather than aborting the
        # process, so an un-restored limit WOULD leak into later work.
        _prev_reclimit = _sys.getrecursionlimit()
        _sys.setrecursionlimit(max(_prev_reclimit, 10_000))
        try:
            self._surv_by_slot = {b: {k: v for v, k in self._surv[b]}
                                  for b in self.blocks}
            self._depth = self._compute_entry_depths()
            # Routine/frame metadata BEFORE any demand: _read_exit consults the
            # frame-aware exit sim (frame_bury redefines its slot) from the very
            # first read, so proto info and frame entry depths must exist now.
            self._compute_subs_and_protos()
            self._frame_edepth = self._frame_entry_depths()
            # Demand: every entry slot an op consumes (top-first 1..C) per block.
            # The recursion pulls in the passthrough slots successors read.
            for b in self.blocks:
                for k in range(1, self._consumed[b] + 1):
                    self._read_entry(b, k)
            # Reconcile braun phi-placement with the phase-6c frame expander: a
            # `frame_dig N` (N>=0) reads ABSOLUTE frame position `nargs+N`, whose
            # top-first ENTRY slot is `entry_depth(b) - (nargs+N)`. That depth is only
            # realised in 6c, so without demanding the read here no join phi is placed
            # for a deep loop-invariant slot and it is dropped (silent 0). Compute the
            # per-block entry depth the SAME way 6c will (sub entry = nargs, frame_dig
            # +1 / frame_bury -1, every other op n_out-n_in), then demand EXACTLY each
            # frame_dig's slot. Exact (not 1..D): an over-broad demand deepens other
            # blocks and threads wrong values. Bounded by the forward cap in _read_entry.
            for b in self.blocks:
                sub = self._bb_to_sub.get(b)
                if sub is None or sub not in self._proto_io:
                    continue
                nargs = self._proto_io[sub][0]
                d = self._frame_edepth.get(b.key)
                if d is None:
                    continue
                for o in b.ops:
                    n = _frame_imm(o)
                    if o.op == "frame_dig" and n is not None and n >= 0:
                        k = d - (nargs + n)
                        if 1 <= k <= self._depth.get(b.key, 0):
                            self._read_entry(b, k)
            # Re-point any entry value / phi arg left at a since-removed phi.
            for key in list(self._entry_val):
                self._entry_val[key] = self._resolve(self._entry_val[key])
            for P in self.phis.values():
                P.args = [self._resolve(a) for a in P.args]
        finally:
            _sys.setrecursionlimit(_prev_reclimit)

    def _frame_entry_depths(self) -> dict:
        """`bb_key -> entry stack depth INCLUDING the sub's args`, simulated the
        way phase 6c builds local_stack: each sub entry starts at `nargs`, then
        every op applies its net (`frame_dig` +1, `frame_bury` -1, else
        n_out-n_in). Forward BFS within each sub; first (forward) reach wins, so a
        loop header keeps its preheader depth (same rule as _compute_entry_depths).
        Used only to locate each frame_dig's read slot for phi demand."""
        from collections import deque
        def net(op):
            if op.op == "frame_dig":
                return 1
            if op.op == "frame_bury":
                return -1
            return op.n_out - op.n_in
        ed = {}
        # sub entry blocks (proto subs) start at nargs; main-routine roots at 0.
        roots = {}
        for b in self.blocks:
            sub = self._bb_to_sub.get(b)
            if sub is b:                       # b is its own routine entry
                roots[b] = self._proto_io.get(sub, (0, 0))[0]
        wl = deque()
        for b, d0 in roots.items():
            ed[b.key] = d0
            wl.append(b)
        while wl:
            b = wl.popleft()
            d = ed[b.key]
            for o in b.ops:
                d += net(o)
            if d < 0:
                d = 0
            for s in b.succs:
                # stay within the routine (don't cross callsub/retsub edges)
                if (self._bb_to_sub.get(s) is self._bb_to_sub.get(b)
                        and s.key not in ed):
                    ed[s.key] = d
                    wl.append(s)
        return ed

    def _compute_entry_depths(self) -> dict:
        """``bb_key -> entry stack depth`` (top-first slot count) via a forward
        BFS from the no-pred entry block(s), ``exit = entry + L - C`` along each
        edge. On disagreement KEEP the first (forward) value: a loop header is
        reached from its preheader before its latch, so it keeps the true
        loop-invariant depth ``D``; the latch's differing proposal is the
        slot-model net artifact that drives the spiral and is ignored. The cap
        ``read_entry(b, k>D) -> None`` then never creates the spurious deep phis.

        (Interprocedural callsub/retsub edges can pollute depths *inside* a
        callee or a continuation, but the targeted loop header in the caller
        still gets its forward depth, which is what bounds the spiral.)"""
        from collections import deque
        depth: dict = {}
        wl: deque = deque()
        for b in self.blocks:
            if not b.preds:
                depth[b.key] = 0
                wl.append(b)
        while wl:
            b = wl.popleft()
            ex = depth[b.key] + self._locals[b] - self._consumed[b]
            if ex < 0:
                ex = 0
            for s in b.succs:
                if s.key not in depth:          # first (forward) reach wins
                    depth[s.key] = ex
                    wl.append(s)
        return depth

    def _resolve(self, v):
        """Follow the trivial-phi replacement chain to the surviving value."""
        n = 0
        while isinstance(v, PyPhi) and v.key() in self._replaced:
            v = self._replaced[v.key()]
            n += 1
            if n > STACK_MAX:        # paranoia — replacement chains are acyclic
                break
        return v

    def _read_exit(self, p: PyBlock, slot: int):
        """Value at predecessor ``p``'s EXIT slot ``slot`` (top-first): a slot
        within ``p``'s own locals (``slot <= L``) is the producing PyVar; a
        deeper slot is an entry value passing through, mapped back to ``p``'s
        entry slot ``slot - L + C`` (the inverse of ``L + k - C``).

        Blocks containing a ``frame_bury`` are answered from the frame-aware
        exit sim instead: the narrow phase-2 model treats ``frame_bury`` as a
        bare pop (no definition), so both branches above lie for such blocks —
        the buried slot reads as an untouched passthrough (a loop-carried slot
        then collapses to its pre-loop value) and the survivor ranks are
        shifted. See :meth:`_build_frame_exit_sim`."""
        sim = self._frame_sim_cache.get(p, _MISSING)
        if sim is _MISSING:
            sim = self._build_frame_exit_sim(p)
            self._frame_sim_cache[p] = sim
        if sim is not None:
            st, d = sim
            idx = len(st) - slot
            if idx >= 0:
                v = st[idx]
                if type(v) is tuple:            # ("entry", k) passthrough
                    return self._read_entry(p, v[1])
                return v
            # Deeper than the routine band: the caller's stack, untouched by
            # frame ops. Same passthrough arithmetic as the narrow path (the
            # fat and narrow conventions agree on net depth change).
            if slot > STACK_MAX:
                return None
            return self._read_entry(p, slot - (len(st) - d))
        L = self._locals[p]
        if slot <= L:
            return self._surv_by_slot[p].get(slot)
        if slot > STACK_MAX:
            # Same guard as ``_phi_node_exit_index``: a net-changing loop maps
            # the value to an ever-deeper slot each lap (the slot-model spiral);
            # cap it so the recursion terminates instead of growing unbounded.
            return None
        return self._read_entry(p, slot - L + self._consumed[p])

    def _build_frame_exit_sim(self, p: PyBlock):
        """Symbolic exit stack for a ``frame_bury``-containing block, or None
        when inapplicable (no parseable bury, block outside a proto'd sub,
        unknown entry depth, or the sim dips below the routine band).

        Simulates ``p`` over the routine's stack band in top-first-consistent
        bottom-first order: entry slot ``k`` sits at index ``d - k`` where ``d``
        is the routine-relative entry depth (args + locals — deeper caller
        stack is unreachable to frame ops and stays out of the band). Frame ops
        use their REAL semantics — ``frame_dig N`` pushes the value at frame
        position ``nargs + N``; ``frame_bury N`` pops the top INTO that
        position — while every other op applies its narrow phase-1 arity
        (pop ``n_in``, push ``outputs``), exactly like phase 2, so the two
        models agree wherever no bury interferes."""
        if not any(o.op == "frame_bury" and _frame_imm(o) is not None
                   for o in p.ops):
            return None
        sub = self._bb_to_sub.get(p)
        if sub is None or sub not in self._proto_io:
            return None
        d = getattr(self, "_frame_edepth", {}).get(p.key)
        if d is None or d < 0:
            return None
        nargs = self._proto_io[sub][0]
        st: list = [("entry", d - i) for i in range(d)]
        for o in p.ops:
            n = _frame_imm(o) if o.op in ("frame_dig", "frame_bury") else None
            if n is not None:
                pos = nargs + n
                if o.op == "frame_dig":
                    if not (0 <= pos < len(st)):
                        return None
                    st.append(st[pos])
                else:  # frame_bury
                    if not st or pos < 0 or pos > len(st) - 1:
                        return None
                    top = st.pop()
                    if pos < len(st):
                        st[pos] = top
                    # pos == len(st): degenerate self-bury — the value lands
                    # at/above the new top and is gone (fat n_out = 0).
                continue
            for _ in range(o.n_in):
                if not st:
                    return None      # dips below the band — model mismatch
                st.pop()
            for v in reversed(o.outputs):
                st.append(v)
        return (st, d)

    def _read_entry(self, b: PyBlock, k: int):
        """Value at ``b``'s ENTRY slot ``k`` (top-first), creating phis on
        demand (Braun ``readVariableRecursive`` — sealed-block path)."""
        key = (b.key, k)
        memo = self._entry_val.get(key, _MISSING)
        if memo is not _MISSING:
            return memo
        if k > self._depth.get(b.key, STACK_MAX):
            # Beyond the block's true entry stack depth -> a spurious slot the
            # net-changing-loop spiral would otherwise climb to. No such value
            # exists at runtime; stop here so no deep phi chain is created.
            self._entry_val[key] = None
            return None
        if k > self._max_entry.get(b.key, 0):
            self._max_entry[b.key] = k
        preds = b.preds
        if not preds:
            self._entry_val[key] = None          # routine entry / no incoming def
            return None
        if len(preds) == 1:
            v = self._read_exit(preds[0], k)
            self._entry_val[key] = v
            return v
        # Join: create the phi, memoise it (breaks back-edge cycles), fill args.
        P = PyPhi(b.key, k)
        self.phis[key] = P
        b.entry_phis.append(P)
        self._entry_val[key] = P
        for p in preds:
            a = self._read_exit(p, k)
            P.args.append(a)
            if isinstance(a, PyPhi):
                self._phi_users.setdefault(a.key(), set()).add(P)
        v = self._try_remove_trivial(P)
        self._entry_val[key] = v
        return v

    def _try_remove_trivial(self, P: PyPhi):
        """Braun ``tryRemoveTrivialPhi``: if ``P``'s args (ignoring self-refs)
        are a single distinct value ``v``, replace ``P`` with ``v`` and re-check
        every phi that referenced ``P`` (cascade). Returns ``P``'s replacement.

        ITERATIVE (a depth-first worklist), not recursive: the cascade can chain
        through a long phi web and a deep chain would overflow the stack. The
        cascade only ever RETURNS into the very first phi (recursive-call returns
        were discarded), so only the initial ``P``'s result matters; the rest is
        side effects. Depth-first + the sorted user order is preserved exactly (a
        LIFO stack with users pushed in reverse pops them in sorted order and
        finishes each user's own cascade before the next sibling) — the cascade is
        order-sensitive (processing u1 before u2 can change u2's triviality; an
        unstable order made SSA construction NONDETERMINISTIC), so this MUST match
        the recursion's traversal."""
        result = None
        first = True
        stack: list = [P]
        while stack:
            cur = stack.pop()
            distinct: list = []
            for a in cur.args:
                a = self._resolve(a)
                if a is cur:
                    continue                      # self-reference
                if not any(a is d for d in distinct):
                    distinct.append(a)
            if len(distinct) > 1:                 # a genuine merge — keep it
                if first:
                    result, first = cur, False
                continue
            same = distinct[0] if distinct else None  # 0 distinct -> undefined slot
            if first:
                result, first = same, False
            self._replaced[cur.key()] = same
            self.phis.pop((cur.bb_key, cur.slot), None)
            b = self._bb_by_key.get(cur.bb_key)
            if b is not None:
                b.entry_phis = [ph for ph in b.entry_phis if ph is not cur]
            # Sort users by their STABLE identity (bb_key, slot) — `_phi_users` is
            # a set, and id() is not seed-stable; the (bb_key, slot) key is.
            users = sorted(self._phi_users.pop(cur.key(), ()), key=lambda u: u.key())
            for u in users:
                u.args = [same if a is cur else a for a in u.args]
                if isinstance(same, PyPhi):
                    self._phi_users.setdefault(same.key(), set()).add(u)
            for u in reversed(users):             # LIFO -> pops in sorted order
                stack.append(u)
        return result

    # ----- Phase 6 helpers ------------------------------------------------

    def _compute_subs_and_protos(self) -> None:
        """Populate ``self._bb_to_sub`` (every BB → its owning routine
        entry BB) and ``self._proto_io`` (sub entry BB → (args, returns)
        from its ``proto`` opcode). Independent of stack sim — only
        depends on CFG shape and proto immediates from phase 1."""
        # Ownership under the CONSTRUCTION policy — the exact semantics this
        # depth machinery was validated against live (verbatim) in
        # tealql.tealtools.subroutines.pyblock_partition.
        from ..subroutines import pyblock_partition
        self._bb_to_sub = pyblock_partition(self.blocks)

        sub_entries: set = set()
        for b in self.blocks:
            if b.ops and b.ops[-1].op == "callsub":
                for s in b.succs:
                    sub_entries.add(s)

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
        ``N``) to the fat-stack convention. Returns ``True`` on
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
        # `self.blocks` is fixed once (built in __init__) before this is used, so
        # the lookup is cached. (NB single-underscore name: a `__`-prefixed
        # attribute is name-mangled, so the old `hasattr("__bb_by_key")` never
        # matched the stored `_PySSA__bb_by_key` and the dict was rebuilt on
        # every call -- an O(calls x blocks) hot spot on large programs.)
        cache = getattr(self, "_bb_by_key_cache", None)
        if cache is None:
            cache = self._bb_by_key_cache = {b.key: b for b in self.blocks}
        return cache

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
    Kept module-private (and function-local) so ``ssa.py`` stays free
    of even sibling-module imports at load time."""
    from .const_fold import fold_spec_fixed
    return fold_spec_fixed(a)


def _compute_inner_txn_fields(prog: SSAProgram) -> list:
    """Lazy import wrapper around
    :func:`.inner_txn_fields.compute_inner_txn_fields`.
    Kept module-private (and function-local) so ``ssa.py`` stays free
    of even sibling-module imports at load time."""
    from .inner_txn_fields import compute_inner_txn_fields
    return compute_inner_txn_fields(prog)


def _compute_scratch_influence(prog: SSAProgram) -> dict:
    """Lazy import wrapper around
    :func:`.scratch_influence.compute_scratch_influence`.
    Kept module-private (and function-local) so ``ssa.py`` stays free
    of even sibling-module imports at load time."""
    from .scratch_influence import compute_scratch_influence
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
    O(N+E) memoized per SCC). This is the phi-args projection."""
    import networkx as nx
    # Graph nodes are integer indices, not the PyPhi objects: PyPhi.__hash__
    # rebuilds + hashes the ``(bb_key, slot)`` tuple, and using phis as nodes
    # called it millions of times across add_node / add_edge / SCC / lookups.
    # networkx iterates nodes + adjacency in INSERTION order, so inserting
    # ``0..N-1`` and the edges in the original phi order yields the identical SCC
    # condensation + leaf order -- only the per-lookup hashing gets cheaper.
    _phis = list(py.phis.values())
    _key2i = {p.key(): i for i, p in enumerate(_phis)}
    _g = nx.DiGraph()
    _g.add_nodes_from(range(len(_phis)))
    for _i, _py_p in enumerate(_phis):
        for _arg in _py_p.args:
            if isinstance(_arg, PyPhi):
                _g.add_edge(_i, _key2i[_arg.key()])
    _sccs = list(nx.strongly_connected_components(_g))
    _scc_of = [0] * len(_phis)
    for _si, _s in enumerate(_sccs):
        for _n in _s:
            _scc_of[_n] = _si
    _scc_succs = [set() for _ in _sccs]
    for _u, _v in _g.edges:
        _su, _sv = _scc_of[_u], _scc_of[_v]
        if _su != _sv:
            _scc_succs[_su].add(_sv)
    _scc_direct: list[list[PyVar]] = [[] for _ in _sccs]
    for _i, _py_p in enumerate(_phis):
        _s = _scc_of[_i]
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

    # Resolve each SCC's leaves to SSAVars ONCE: phis sharing an SCC share the
    # same leaf set, so the per-phi var_map.get was ~33M lookups on big proto
    # contracts. Same SSAVars in the same order -> byte-identical.
    _scc_leaf_ssa = [[s for _pv in _leaves if (s := var_map.get(_pv)) is not None]
                     for _leaves in _scc_leaves]
    for py_p, p in phi_map.items():
        p.args.extend(_scc_leaf_ssa[_scc_of[_key2i[py_p.key()]]])


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
                # compile-time literal (e.g. ``global ZeroAddress``).
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
    step relation (the constant / value-identity step relation);
    stashes the relation on ``prog._graph.graph["identity_steps"]``.

    Pre-filters the candidate ops once so the fixpoint only scans ops that
    could seed a const, then iterates so identity-of-identity chains flow
    (e.g. const -> swap -> load -> swap -> consumer)."""
    from . import scratch_influence as _scratch

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
                _k = (_sv_file, _sv_line, _sv_idx)
                if _k == _scratch.UNINIT_STORE:
                    # AVM scratch zero-init: a precisely-known int 0 that must
                    # agree with every real reaching store.
                    _resolved.append(Const("int", "0"))
                    continue
                if _k == _scratch.UNKNOWN_STORE:
                    _ok = False
                    break
                _src_v = prog.vars.get(_k)
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

    # (c) scratch bridge -- ONLY when the load has a single reaching store.
    # An identity step asserts snk *is* src, so a load fed by >1 store would get
    # one identity per store and const-prop would fold it to whichever store is
    # constant first -- unsound when another reaching store is a runtime value
    # (e.g. a slot that's 0 on a loop back-edge but a runtime btoi on entry).
    # The sound all-stores-agree case is handled by propagate_scratch_constants
    # (must-semantics); a multi-store load is a merge, not an identity.
    for _a in _load_candidates:
        _out_v = _a.outputs[0]
        if not isinstance(_out_v, SSAVar):
            continue
        _stores = scratch_stores.get(
            (_a.location.file, _a.location.line)
        )
        if not _stores or len(_stores) != 1:
            continue
        _sv_file, _sv_line, _sv_idx = next(iter(_stores))
        if (_sv_file, _sv_line, _sv_idx) in (_scratch.UNINIT_STORE,
                                             _scratch.UNKNOWN_STORE):
            continue      # no SSAVar identity behind a sentinel reaching def
        _identity_steps.append(
            (("var", _sv_file, _sv_line, _sv_idx), _ssavar_key(_out_v))
        )

    if hasattr(prog._graph, "graph"):
        prog._graph.graph["identity_steps"] = _identity_steps


def _drop_unconsumed_phis(prog: SSAProgram) -> None:
    """Drop phis not consumed by any op input, so ``prog.phis`` is the
    consumer set rather than the full builder output.

    A DIRECT filter: ``_collapse_phi_args_to_leaves`` has already run, so a
    public ``Phi.args`` holds only ``SSAVar``s and a phi can never be reached
    *through* another phi. This used to run a transitive worklist over
    phi-valued args, which was dead code (measured: zero phi-typed args across
    the corpus) that read as if phi-through-phi consumption were handled — so
    a future change to leaf collapse would have silently relied on it."""
    _reached: set = set()
    for _a in prog.assignments:
        for _inp in _a.inputs:
            if isinstance(_inp, Phi):
                _reached.add(id(_inp))
    assert not any(isinstance(_arg, Phi)
                   for _p in prog.phis.values() for _arg in _p.args), \
        "phi args must be leaf-collapsed before _drop_unconsumed_phis"
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

    - :meth:`PySSA.build` (with ``source`` == a separately-loaded program).
    - :meth:`SSAProgram.__init__` (with ``source is None`` — reads
      directly from ``prog`` for graph + var const/range/type
      annotations). This lets ``SSAProgram(source)`` route SSA
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
    # by the graph-loading pre-pass) and reuse source._graph + source.labels.
    # Snapshot anything we'll re-read from ``src`` *before* wiping
    # ``prog`` — in the in-place case (``source is None``) ``src.vars``
    # IS ``prog.vars``, so the wipe would otherwise clobber the data
    # we need to copy over.
    src = source if source is not None else prog
    src_vars_snapshot = dict(getattr(src, "vars", {}))
    src_labels_snapshot = list(getattr(src, "labels", []))
    src_graph_snapshot = getattr(src, "_graph", None)
    src_source_path_snapshot = getattr(src, "source_path", None)

    prog.vars = {}
    prog.phis = {}
    prog.assignments = []
    prog.blocks = {}
    prog.labels = src_labels_snapshot
    prog._graph = src_graph_snapshot
    prog.source_path = src_source_path_snapshot
    # Match the exact state flags ``SSAProgram.__init__`` sets, so every
    # pass that gates on one of them finds it.
    prog._consts_propagated = False
    prog._scratch_propagated = False
    prog._ranges_propagated = False
    prog._shuffles_propagated = False
    prog._inputs_propagated = False

    # 1) SSAVars. Seed const_value / range / type from the source
    # prog's already-populated var table (the pre-pass wired these from
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

    # 2) Phis. PySSA has one phi per (bb_key, slot); the
    # Direct/Indirect distinction is collapsed in PySSA's unified
    # model. Register under DirectPhi only. Lookups via
    # :meth:`SSAProgram.phi` are kind-agnostic so consumers that
    # receive a kind from a field row (e.g.
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

    # 6.4/6.45/6.6) Three consumer-specific analyses — inner-txn field
    # grouping, scratch-slot reaching-definitions, and const_value seeding
    # + the value-identity step relation — used to run EAGERLY here on
    # EVERY build (~58% of build time on a mid-size contract), even for
    # callers that never read their output. They are now computed-and-
    # cached pay-for-what-you-use, mirroring ``frame_resolution``:
    #   * ``inner_txn_fields``  -> ``SSAProgram._ensure_inner_txn_fields``
    #     (consumed by ``inner_txn_report.InnerTxnReport``);
    #   * ``scratch_stores``    -> ``SSAProgram._ensure_scratch_influence``
    #     (consumed by the lift, taint engine/graph, scratch_prop passes,
    #     ``tealql.security.common._scratch_stores_for``);
    #   * const_value seeding + ``identity_steps`` ->
    #     ``SSAProgram._ensure_identity_steps`` (triggered by
    #     ``propagate_constants``, which every ``const_value`` reader runs
    #     first). Each ``_ensure_*`` reproduces byte-for-byte what the eager
    #     block produced; the deferral is observationally neutral (see the
    #     methods in ``program.py``).

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


def _demo(source: str) -> None:
    """Render the PySSA-built SSA for a TEAL source. Uses the internal
    :meth:`PySSA._construct` to get the builder instance directly so
    we can call :meth:`PySSA.render` for the diagnostic dump — every
    other caller should use :meth:`PySSA.build` which returns the
    wrapped ``SSAProgram``."""
    import time
    t0 = time.perf_counter()
    prog = SSAProgram(source)
    t_graph = time.perf_counter() - t0
    t0 = time.perf_counter()
    py = PySSA._construct(prog)
    t_py = time.perf_counter() - t0
    if len(py.blocks) <= 30:
        print(py.render())
    else:
        print(f"({len(py.blocks)} blocks — full render suppressed)")
    print(
        f"[ssa] graph load: {t_graph:.2f}s  build: {t_py * 1000:.1f}ms  "
        f"blocks={len(py.blocks)}  vars={len(py.vars)}  phis={len(py.phis)}"
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m tealql.tealtools.ssa <teal-source>",
              file=sys.stderr)
        raise SystemExit(2)
    _demo(sys.argv[1])
