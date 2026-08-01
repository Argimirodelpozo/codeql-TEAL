"""The pure-Python SSA builder behind :class:`SSAProgram`.

Pipeline (:meth:`PySSA._construct`): instantiate PyVars per opcode output ->
BB arities + surviving locals -> Braun on-demand phi placement -> per-BB stack
sim filling ``op.inputs`` / ``b.exit_stack`` -> liveness filter.

HAZARD — slot model. Stack slots are 1-based TOP-FIRST. An entry-slot phi ``k``
of block ``b`` surfaces at exit slot ``L_b + k - C_b`` (locals, consumed), and is
undefined when ``k <= C_b`` (consumed inside the block). ``frame_dig`` /
``frame_bury`` (either sign of N) expand under the FAT-STACK convention: consume
the whole band from the current top down to the target slot, emit fresh outputs
covering the post-stack.

HAZARD — the ``PyPhi.args`` graph can be CYCLIC (constant-stack CFG loops), so
every traversal needs a ``seen`` set. ``PyPhi`` is unified: the public
Direct/Indirect kind distinction is collapsed here.

CLI: ``python -m tealql.tealtools.ssa <teal-source>`` renders the build.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

# The re-export surface for external consumers is the package __init__.
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

# "Not yet resolved" — distinct from ``None``, itself a valid resolved value
# (an entry slot with no incoming definition).
_MISSING = object()


def _frame_imm(op):
    """The N of a frame_dig/frame_bury, or None."""
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


# A reconstructed-SSA operand. ``None`` marks a slot the builder could not
# resolve (a depth mismatch surfaced rather than hidden).
Operand = Union["PyVar", "PyPhi"]


class PyVar:
    """One stack value produced by one opcode output — identity
    ``(file, line, idx)``, ``idx`` 1-based with ``idx == 1`` the topmost."""

    __slots__ = ("file", "line", "idx", "_hash")

    def __init__(self, file: str, line: int, idx: int):
        self.file = file
        self.line = line
        self.idx = idx
        # Identity is immutable, so cache the hash — the phi-leaf collapse hashes
        # PyVars tens of millions of times and rebuilding the key tuple dominated
        # construction.
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
    """A phi at a block's entry for one stack slot — identity
    ``((file, first_line, last_line), slot)``, ``slot`` 1-based top-first.

    HAZARD: ``args`` (the values merged in from preds, each a :class:`PyVar` or
    a chain-predecessor :class:`PyPhi`) forms a graph that can be CYCLIC at
    constant-stack CFG loops; walk it with a ``visited`` set."""

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
    """An opcode in SSA form, ``outputs = op immediates (inputs)``, with
    ``inputs`` / ``outputs`` filled by the per-BB simulator."""

    op: str
    immediates: str
    file: str
    line: int
    n_in: int
    n_out: int
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)


class PyBlock:
    """Ordered opcodes plus CFG neighbours — ``preds`` / ``succs`` are the RAW
    CFG, callsub and retsub edges included."""

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
    # Verified call/return pairings (see _compute_call_pairs):
    #   cont.key -> (callsub PyBlock, A, R, frozenset of verified retsub pred keys)
    #   callsub PyBlock -> (cont PyBlock, A, R)
    _call_pairs: dict = field(default_factory=dict)
    _pair_by_cs: dict = field(default_factory=dict)
    # (bb_key, slot) resolutions currently on the _read_entry stack — the
    # no-join-cycle guard (see _read_entry).
    _reading: set = field(default_factory=set)
    # Continuation keys whose callee may have rewritten the caller's residual
    # stack (see _classify_call_effects) — deep continuation slots refuse there;
    # depth crossings remain (permutes change no heights).
    _value_unsafe_conts: set = field(default_factory=set)
    # Subset of the above whose callee may have CLOBBERED the caller's residual
    # (an op consumed past the band). The lift cannot express that — its
    # re-simulation assumes a call leaves the residual alone — so it refuses
    # rather than emit a program with different behaviour.
    _residual_clobber_conts: set = field(default_factory=set)
    _clobber_callee_keys: set = field(default_factory=set)
    # Braun on-demand construction state.
    _surv_by_slot: dict = field(default_factory=dict)   # block -> {slot: PyVar}
    _entry_val: dict = field(default_factory=dict)       # (bb_key, slot) -> value
    # HAZARD: both keyed by PyPhi.key() == (bb_key, slot), NEVER by id(). A
    # removed trivial phi loses its last reference, and with __slots__ CPython
    # reuses the freed address — an id() key then aliases a NEW live phi and
    # resolves it to the OLD phi's value.
    _replaced: dict = field(default_factory=dict)        # PyPhi.key() -> replacement
    _phi_users: dict = field(default_factory=dict)       # PyPhi.key() -> set[PyPhi]
    _max_entry: dict = field(default_factory=dict)       # bb_key -> max entry slot read
    # block -> frame-aware exit-stack sim (or None); see _build_frame_exit_sim.
    _frame_sim_cache: dict = field(default_factory=dict)

    @classmethod
    def build(cls, prog: SSAProgram) -> SSAProgram:
        """Construct SSA from a graph-loaded ``SSAProgram`` and return a fresh
        one wired to the PySSA-built structures (idempotent — ``__init__``
        already routes through the same construction)."""
        py = cls._construct(prog)
        return _to_ssaprogram(py, source=prog)

    @classmethod
    def _construct(cls, prog: SSAProgram) -> "PySSA":
        """Run the construction phases and return the builder itself (for
        diagnostics); :meth:`build` is the SSAProgram-returning entry point."""
        self = cls()
        self._phase1_instantiate(prog)
        self._phase2_arities()
        # Braun on-demand placement + the forward depth cap in
        # `_compute_entry_depths`, which fixes the loop spiral at its slot-model
        # root: a net-changing loop's `L+k-C` map climbs to STACK_MAX under ANY
        # construction unless the cap stops it.
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
                # Narrow phase-1 arities; the fat frame_dig/frame_bury/callsub/
                # retsub forms are rebuilt by later phases.
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
        """Exit slot ``L + k - C`` of the phi at ``b``'s entry slot ``k``, or
        ``None`` when the phi is consumed inside ``b`` (``k <= C``)."""
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
        """Build each BB's entry_stack from the placed phis, then sim the block to
        populate ``op.inputs`` / ``op.outputs`` and ``b.exit_stack``.

        HAZARD: ``frame_dig`` / ``frame_bury`` use the FAT-STACK convention —
        the op consumes the whole band from the current top down to and
        including the target frame slot, and emits fresh outputs covering the
        post-stack (``frame_dig`` n_out == n_in + 1, band plus the dug copy on
        top; ``frame_bury`` n_out == n_in - 1, band with the target replaced).
        This must agree with :func:`_shuffle_mapping` or taint / const / range
        propagation stops carrying values through frame-access chains."""
        # 6a: entry_stack for every BB first, so the per-op fat expansion can
        # read sub.entry_stack regardless of iteration order.
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
            # Max phi slot per BB in ONE pass: the per-block scan it replaced was
            # O(blocks x phis), tens of millions of iterations at 100k+ phis.
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

        # 6b: routine arg counts + entry stacks, for each fat expansion.
        self._compute_subs_and_protos()

        # 6c: per-BB simulator. A single-pred block places no phis (nothing
        # merges), so its 6a entry_stack is empty — losing the stack from its
        # sole pred and hiding any frame slot that pred set up (e.g. a `bury`d
        # box name) from a cross-block `frame_dig`. Seed such a block from the
        # pred's exit_stack, gated on same-sub / non-proto-entry / already
        # simulated so iteration order can't make it unsound.
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
            # How much of the routine band sits BELOW this seed. Captured once,
            # from the seed length: both the true depth and local_stack move by
            # the same net per op, so the shortfall is constant for the block.
            _ed = getattr(self, "_frame_edepth", {}).get(b.key)
            missing_below = None if _ed is None else _ed - len(local_stack)
            for op in b.ops:
                if (op.op in ("frame_dig", "frame_bury")
                        and proto is not None and sub is not None
                        and self._try_expand_frame_op(
                            op, local_stack, sub, proto, missing_below)):
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
        """Braun et al. (2013) on-demand SSA (filled+sealed case): place a phi at
        an entry slot only when it is READ, recursing into predecessors and
        collapsing trivial phis at creation.

        Memoising the phi BEFORE recursing is what breaks loop back-edge cycles,
        and the trivial-phi cascade folds constant-stack-loop chains to a single
        value instead of churning slots 1..STACK_MAX.

        HAZARD: phase 6 must read ``self._entry_val[(bb_key, slot)]``, not
        ``self.phis``, to rebuild entry stacks — a collapsed slot has a value but
        no phi."""
        import sys as _sys
        # The depth cap bounds recursion to true stack depth x passthrough chain
        # length (~35 on real contracts), so a modest raise suffices. try/finally
        # restores the limit: a build failure is CAUGHT (LiftError), so an
        # un-restored limit would leak process-wide into later work.
        _prev_reclimit = _sys.getrecursionlimit()
        _sys.setrecursionlimit(max(_prev_reclimit, 10_000))
        try:
            self._surv_by_slot = {b: {k: v for v, k in self._surv[b]}
                                  for b in self.blocks}
            # Routine/frame metadata BEFORE the depth maps and any demand: both
            # depth BFSes cross verified call pairings, and _read_exit consults
            # the frame-aware exit sim (frame_bury redefines its slot) from the
            # very first read, so proto info and pairings must exist now.
            self._compute_subs_and_protos()
            self._compute_call_pairs()
            self._depth = self._compute_entry_depths()
            self._frame_edepth = self._frame_entry_depths()
            self._classify_call_effects()
            # Demand: every entry slot an op consumes (top-first 1..C) per block.
            # The recursion pulls in the passthrough slots successors read.
            for b in self.blocks:
                for k in range(1, self._consumed[b] + 1):
                    self._read_entry(b, k)
            # HAZARD: reconcile placement with the 6c frame expander. A
            # `frame_dig N` (N>=0) reads ABSOLUTE frame position `nargs+N`, i.e.
            # top-first entry slot `entry_depth(b) - (nargs+N)`, and that depth
            # only exists in 6c — without demanding the read here, a deep
            # loop-invariant slot gets no join phi and silently reads as 0.
            # `frame_bury N` needs the same demand for the opposite reason: its
            # fat form only runs when the band down to `nargs+N` is present in
            # the seed (`target_idx < len(local_stack)`), and the narrow
            # fallback is a bare pop that DROPS the buried value. Demand
            # EXACTLY each frame op's slot: an over-broad 1..D demand deepens
            # other blocks and threads wrong values.
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
                    if (o.op in ("frame_dig", "frame_bury")
                            and n is not None and n >= 0):
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
        """``bb_key -> entry stack depth INCLUDING the sub's args``, simulated
        exactly as phase 6c builds local_stack, to locate each frame_dig's read
        slot; first (forward) reach wins, as in :meth:`_compute_entry_depths`."""
        from collections import deque
        def net(op):
            if op.op == "frame_dig":
                return 1
            if op.op == "frame_bury":
                return -1
            return op.n_out - op.n_in
        ed = {}
        # proto sub entries start at nargs; main-routine roots at 0.
        roots = {}
        for b in self.blocks:
            sub = self._bb_to_sub.get(b)
            if sub is b:                       # b is its own routine entry
                roots[b] = self._proto_io.get(sub, (0, 0))[0]
        wl = deque()
        for b, d0 in roots.items():
            ed[b.key] = d0
            wl.append(b)
        conflicted: list = []
        while wl:
            b = wl.popleft()
            d = ed[b.key]
            for o in b.ops:
                d += net(o)
            if d < 0:
                d = 0
            # Cross a verified call to its continuation: the callee consumed the
            # top A and left R, so the caller's band continues at ``d - A + R``.
            # The CFG only reaches the continuation along the callee's retsub,
            # which the same-routine gate below rightly refuses — this crossing
            # is the caller-side depth that edge cannot carry. A negative result
            # means the args were not on this routine's band (the model does not
            # hold); refuse rather than clamp, an absent depth surfaces as None.
            targets: list = []
            pair = self._pair_by_cs.get(b)
            if pair is not None:
                cont, a, r = pair
                if d - a + r >= 0:
                    targets.append((cont, d - a + r))
            # Intra-FRAME successors only, as pyblock_partition walks them: a
            # callsub block's one CFG succ is the callee ENTRY and a retsub's
            # succs are continuations — both cross into a different frame, so
            # neither may carry this frame's depth. The same-routine test alone
            # is NOT that gate: under RECURSION the callee entry and the
            # internal call's continuation belong to this very sub, the edges
            # pass it, and the caller-side depth lands on a fresh-frame block
            # (first-reach luck used to bury the bogus proposal; the ambiguity
            # detector below would read it as height variance).
            term = b.ops[-1].op if b.ops else None
            if term not in ("callsub", "retsub"):
                for s in b.succs:
                    # stay within the routine
                    if self._bb_to_sub.get(s) is self._bb_to_sub.get(b):
                        targets.append((s, d))
            for t, dt in targets:
                if t.key not in ed:
                    ed[t.key] = dt
                    wl.append(t)
                elif ed[t.key] != dt:
                    conflicted.append(t)

        # HAZARD — height-ambiguous joins. The AVM has NO static verifier: a
        # join whose paths arrive at different depths is legal (later ops just
        # find whatever operands are there), and then this block has no single
        # frame anchor — a fat expansion anchored to either path's depth reads
        # or buries a NEIGHBOURING slot on the other path, a silent wrong
        # value. Compilers never emit this; hand-written TEAL can. Poison the
        # conflicted blocks and everything depth-reachable from them (their
        # stored first-reach values are one path's truth at best): a missing
        # depth makes every consumer refuse — narrow frame ops, no demand, and
        # the band-unsafe scan flags the sub (unknown height reaching retsub),
        # withdrawing its callers' deep-slot reroutes.
        if conflicted:
            amb: set = set()
            wl2 = list(conflicted)
            while wl2:
                b = wl2.pop()
                if b.key in amb:
                    continue
                amb.add(b.key)
                pair = self._pair_by_cs.get(b)
                if pair is not None and pair[0].key not in amb:
                    wl2.append(pair[0])
                term = b.ops[-1].op if b.ops else None
                if term not in ("callsub", "retsub"):
                    wl2.extend(
                        s for s in b.succs
                        if (self._bb_to_sub.get(s) is self._bb_to_sub.get(b)
                            and s.key not in amb))
            for key in amb:
                ed.pop(key, None)
        return ed

    def _compute_entry_depths(self) -> dict:
        """``bb_key -> entry stack depth`` (top-first slot count) via forward BFS
        from the no-pred blocks, ``exit = entry + L - C`` along each edge.

        HAZARD: on disagreement KEEP THE FIRST (forward) value. A loop header is
        reached from its preheader before its latch, so it keeps the true
        loop-invariant depth ``D``; the latch's differing proposal is the
        slot-model artifact that drives the spiral. The resulting cap
        (``_read_entry(b, k>D) -> None``) is what stops the deep phi climb.

        Verified call pairings cross like the values do: a paired continuation
        gets ``ex - A + R`` from its callsub block (the physical stack after
        the callee consumed the args and left its results), and the callee's
        ``retsub`` edge into it proposes nothing — that edge would carry the
        CALLEE-relative depth, a different frame whose junk cap either culled
        real reads to None or let artifact chains through uncapped."""
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
            pair = self._pair_by_cs.get(b)
            if pair is not None:
                cont, a, r = pair
                if ex - a + r >= 0 and cont.key not in depth:
                    depth[cont.key] = ex - a + r
                    wl.append(cont)
            for s in b.succs:
                pair_s = self._call_pairs.get(s.key)
                if pair_s is not None and b.key in pair_s[3]:
                    continue                    # verified return edge: wrong frame
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
        """Value at predecessor ``p``'s EXIT slot ``slot`` (top-first): within
        ``p``'s own locals (``slot <= L``) that is the producing PyVar, deeper is
        an entry value passing through, at entry slot ``slot - L + C`` (the
        inverse of ``L + k - C``).

        HAZARD: blocks containing a ``frame_bury`` are answered from
        :meth:`_build_frame_exit_sim` instead, because the narrow phase-2 model
        treats ``frame_bury`` as a bare pop with no definition — so the buried
        slot would read as an untouched passthrough (collapsing a loop-carried
        slot to its pre-loop value) and the survivor ranks would be shifted."""
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
            # frame ops. The fat and narrow conventions agree on net depth
            # change, so the narrow passthrough arithmetic applies.
            if slot > STACK_MAX:
                return None
            return self._read_entry(p, slot - (len(st) - d))
        L = self._locals[p]
        if slot <= L:
            return self._surv_by_slot[p].get(slot)
        if slot > STACK_MAX:
            # Same guard as ``_phi_node_exit_index``: a net-changing loop maps
            # the value one slot deeper each lap, so without the cap the
            # recursion grows unbounded.
            return None
        return self._read_entry(p, slot - L + self._consumed[p])

    def _build_frame_exit_sim(self, p: PyBlock):
        """Symbolic exit stack for a ``frame_bury``-containing block, or ``None``
        when inapplicable (no parseable bury, block outside a proto'd sub,
        unknown entry depth, or the sim dips below the routine band).

        Simulated bottom-first over the routine's band — entry slot ``k`` at
        index ``d - k``, ``d`` the routine-relative entry depth (args + locals;
        deeper caller stack is unreachable to frame ops). Frame ops use their
        REAL semantics (``frame_dig N`` pushes frame position ``nargs + N``,
        ``frame_bury N`` pops the top INTO it) while every other op keeps its
        narrow phase-1 arity, so the two models agree wherever no bury
        interferes."""
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

    def _read_edge(self, b: PyBlock, p: PyBlock, k: int):
        """Value arriving at ``b``'s entry slot ``k`` along the CFG edge from
        ``p`` — normally ``p``'s exit slot ``k``, except deep across a verified
        call return.

        At a paired continuation, slots ``1..R`` really are what the call left
        on top, so they keep reading the ``retsub`` predecessor's exit. Anything
        deeper never travelled through the callee: the AVM discards the callee's
        frame at ``retsub``, leaving the caller's pre-call stack minus the ``A``
        args, so continuation slot ``k > R`` is the CALLER's pre-call slot
        ``k - R + A`` — read it from the callsub block, whose exit stack IS the
        pre-call stack under the ``(0, 0)`` arity convention (args on top, the
        shape ``frame_param_sources`` and the lift's arg recovery rely on).
        Reading the retsub edge instead threaded the callee's OWN band into the
        caller: merge phis over a callee's every local and every OTHER caller's
        stack (max_args 143 on one mainnet probe), values in slots they never
        physically occupy."""
        pair = self._call_pairs.get(b.key)
        if pair is not None:
            cs, a_in, r_out, ret_pred_keys = pair[:4]
            if k > r_out and p.key in ret_pred_keys:
                if b.key in self._value_unsafe_conts:
                    # Unmodelable below-band effect, so NEITHER candidate is the
                    # runtime value: the pre-call slot may have been rewritten,
                    # and the callee's exit slot is discarded by the truncation.
                    # Refuse — a surfaced unknown, never a wrong value.
                    return None
                return self._read_exit(cs, k - r_out + a_in)
        return self._read_exit(p, k)

    def _read_entry(self, b: PyBlock, k: int):
        """Value at ``b``'s ENTRY slot ``k`` (top-first), creating phis on
        demand (Braun ``readVariableRecursive`` — sealed-block path)."""
        key = (b.key, k)
        memo = self._entry_val.get(key, _MISSING)
        if memo is not _MISSING:
            return memo
        if k > self._depth.get(b.key, STACK_MAX):
            # THE DEPTH CAP: beyond the block's true entry depth no such value
            # exists at runtime, so stop rather than build the deep phi chain a
            # net-changing loop would otherwise climb to.
            self._entry_val[key] = None
            return None
        if key in self._reading:
            # A value-walk cycle re-entered an IN-FLIGHT single-pred
            # resolution. Braun breaks join cycles by memoising the phi before
            # recursing, and every reachable CFG cycle contains a >=2-pred
            # block — but the walk is not the CFG: the call-return reroute
            # reads the CALLSUB block for deep continuation slots, skipping
            # the callee entry that may have been the only join on the cycle.
            # Braun's answer for exactly this is the operandless placeholder
            # phi: hand it out now, and the outer frame completes it when its
            # value arrives — whereupon it trivially collapses to that value,
            # or to None when the cycle defines nothing (joinless passthrough
            # all the way around). Never registered in ``phis``/``entry_phis``:
            # a single-arg phi always collapses.
            P = PyPhi(b.key, k)
            self._entry_val[key] = P
            return P
        if k > self._max_entry.get(b.key, 0):
            self._max_entry[b.key] = k
        preds = b.preds
        if not preds:
            self._entry_val[key] = None          # routine entry / no incoming def
            return None
        self._reading.add(key)
        try:
            if len(preds) == 1:
                v = self._read_edge(b, preds[0], k)
                ph = self._entry_val.get(key, _MISSING)
                if (ph is not _MISSING and isinstance(ph, PyPhi)
                        and ph.key() == key):
                    # A re-entrant read minted the placeholder for THIS
                    # resolution while we recursed; complete and collapse it
                    # so its users get the real value.
                    ph.args.append(v)
                    if isinstance(v, PyPhi):
                        self._phi_users.setdefault(v.key(), set()).add(ph)
                    v = self._try_remove_trivial(ph)
                self._entry_val[key] = v
                return v
            # Join: create the phi, memoise it (breaks back-edge cycles), fill
            # args.
            P = PyPhi(b.key, k)
            self.phis[key] = P
            b.entry_phis.append(P)
            self._entry_val[key] = P
            for p in preds:
                a = self._read_edge(b, p, k)
                P.args.append(a)
                if isinstance(a, PyPhi):
                    self._phi_users.setdefault(a.key(), set()).add(P)
            v = self._try_remove_trivial(P)
            self._entry_val[key] = v
            return v
        finally:
            self._reading.discard(key)

    def _try_remove_trivial(self, P: PyPhi):
        """Braun ``tryRemoveTrivialPhi``: if ``P``'s args (ignoring self-refs) are
        one distinct value ``v``, replace ``P`` with ``v``, cascade into every phi
        that referenced ``P``, and return ``P``'s replacement.

        HAZARD: the cascade is ORDER-SENSITIVE — processing u1 before u2 can
        change u2's triviality, and an unstable order makes SSA construction
        NONDETERMINISTIC. The iterative form (needed because a deep chain would
        overflow the stack) must therefore reproduce the recursion's traversal
        exactly: LIFO with users pushed in reverse pops them in sorted order and
        finishes each user's cascade before the next sibling."""
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
            # Sort by the STABLE (bb_key, slot) identity: `_phi_users` is a set
            # and id() is not seed-stable.
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
        """Populate ``self._bb_to_sub`` (BB -> owning routine entry BB) and
        ``self._proto_io`` (sub entry -> ``(args, returns)`` from its ``proto``);
        depends only on CFG shape and phase-1 immediates, not on the stack sim."""
        # Ownership follows the CONSTRUCTION policy this depth machinery was
        # validated against, which lives verbatim in pyblock_partition.
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

    def _compute_call_pairs(self) -> None:
        """Verified call/return pairings — the ONE map every call-boundary
        crossing (depth or value) keys off, so they cannot disagree.

        A ``callsub`` block CS pairs with continuation K only when ALL of:

        * CS's callee entry declares ``proto A R`` (a legacy callee has no
          declared arity — guessing would be worse than the known gap, and
          ``lift._infer_arities`` handles those separately);
        * the construction partition puts K in CS's own routine (the naive
          return point ``pyblock_partition`` itself uses, so ownership and
          crossing agree about where the call comes back to);
        * K really is reached along the callee's return — it has a ``retsub``
          predecessor OWNED by that callee. ``_pyblock_return_point`` is the
          naive source-next pairing, so a never-returning callee (or a
          mispaired K) fails this check and gets NO crossing: an unresolved
          depth surfaces as None downstream, a wrong one reads a neighbouring
          frame slot as if it were this one.

        The retsub predecessors are recorded per pair because K may ALSO be an
        ordinary branch target; only the return edges get call semantics."""
        from ..subroutines import _pyblock_return_point

        self._call_pairs = {}
        self._pair_by_cs = {}
        for cs, cont in _pyblock_return_point(self.blocks).items():
            if cont is None or cont is cs:
                continue
            callee = next((s for s in cs.succs if s in self._proto_io), None)
            if callee is None:
                continue
            if self._bb_to_sub.get(cont) is not self._bb_to_sub.get(cs):
                continue
            ret_pred_keys = frozenset(
                p.key for p in cont.preds
                if p.ops and p.ops[-1].op == "retsub"
                and self._bb_to_sub.get(p) is callee
            )
            if not ret_pred_keys:
                continue
            a, r = self._proto_io[callee]
            self._call_pairs[cont.key] = (cs, a, r, ret_pred_keys, callee)
            self._pair_by_cs[cs] = (cont, a, r)

    def _classify_call_effects(self) -> None:
        """Sort callees by what they do to the CALLER's residual stack, so each
        continuation gets the strongest answer that is actually true.

        * CLEAN — never touches below its own band, so the residual is exactly
          the pre-call stack and the continuation's deep slots read the
          CALLSUB block.
        * HARD (``_value_unsafe_conts``) — an op consuming past the band, an
          unknowable band height, a nested call needing more args than the
          band holds, or a ``callsub`` that is not its block's terminator.
          Deep slots there REFUSE.

        WHAT THE AVM ACTUALLY ENFORCES (measured on a live node, 2026-08-01 —
        the docs describe the frame as a convention, which misled an earlier
        draft of this into modelling shapes that cannot run):

        * ``frame_dig``/``frame_bury`` outside the frame are rejected at
          RUNTIME, not merely by the assembler ("frame_bury -2 in sub with 1
          args"). A below-band frame op therefore cannot execute at all, so
          the sub is dead and refusing costs nothing.
        * PLAIN stack ops are NOT bounded by the frame: ``cover 3`` reaching
          under a ``proto 1 1`` band runs and permutes the caller's values.
          This is the real below-band case and the reason HARD exists.
        * The bound is re-checked at ``retsub`` ("retsub executed with stack
          below frame"), so a callee may dip below only if it puts the height
          back — the values it took are still gone.

        Depth crossings survive both classes: a permute changes no heights,
        and a returning ``retsub``'s stack shape is VM-enforced, so the band
        stays locatable even where the values do not.

        A block matters only if it CAN REACH a ``retsub`` of its sub (over the
        construction-policy local edges — an internal callsub flows to its
        return point): the claim being protected is about the stack AT retsub,
        so a region that only ever exits the program (a never-returning branch,
        the dead continuation of a call to an assert-fail helper — exactly
        where band heights are legitimately unknowable) cannot compromise it,
        however it writes. Within reaching blocks, an uncomputable height IS
        unsafe — including every live continuation of a legacy no-proto call,
        whose frame ops act directly on the CALLER's frame. Unsafety is
        transitive over ``callsub`` (a clean wrapper inherits its callee's)."""
        def net(op):
            if op.op == "frame_dig":
                return 1
            if op.op == "frame_bury":
                return -1
            return op.n_out - op.n_in

        # Reverse reachability to a retsub over local edges (callsub -> its
        # return point; retsub/return/err terminal), mirroring pyblock_partition.
        from ..subroutines import _pyblock_return_point
        return_point = _pyblock_return_point(self.blocks)
        local_preds: dict = {}
        reach_wl: list = []
        for b in self.blocks:
            if not b.ops:
                continue
            last = b.ops[-1].op
            if last == "retsub":
                reach_wl.append(b)
                continue
            if last in ("return", "err"):
                continue
            succs = ([return_point.get(b)] if last == "callsub"
                     else b.succs)
            for s in succs:
                if s is not None:
                    local_preds.setdefault(s, []).append(b)
        reaches_retsub: set = set(reach_wl)
        while reach_wl:
            b = reach_wl.pop()
            for p in local_preds.get(b, ()):
                if p not in reaches_retsub:
                    reaches_retsub.add(p)
                    reach_wl.append(p)

        _READONLY = frozenset({"dig", "frame_dig", "dup", "dup2", "dupn"})
        unsafe: set = set()
        clobber: set = set()        # unsafe BECAUSE caller values were consumed
        calls: dict = {}
        for b in self.blocks:
            sub = self._bb_to_sub.get(b)
            if sub is None or b not in reaches_retsub:
                continue
            if b.ops and b.ops[-1].op == "callsub":
                for s in b.succs:
                    calls.setdefault(sub, set()).add(self._bb_to_sub.get(s))
            if sub in unsafe:
                continue
            h = self._frame_edepth.get(b.key)
            if h is None:
                unsafe.add(sub)
                continue
            nargs = self._proto_io.get(sub, (0, 0))[0]
            for i, o in enumerate(b.ops):
                if o.op == "frame_bury":
                    n = _frame_imm(o)
                    if n is None or nargs + n < 0:
                        unsafe.add(sub)
                        break
                elif o.op == "callsub":
                    if i != len(b.ops) - 1:
                        unsafe.add(sub)      # sim would have to model a call
                        break
                    a_callee = next(
                        (self._proto_io[s][0] for s in b.succs
                         if s in self._proto_io), 0)
                    if a_callee > h:
                        unsafe.add(sub)
                        clobber.add(sub)
                        break
                elif o.n_in > h and o.op not in _READONLY:
                    # A dip or a cross-band cover/uncover/bury. The AVM does
                    # NOT bound plain stack ops by the frame (verified live:
                    # `cover 3` under a `proto 1 1` band runs and permutes the
                    # caller's values), and the op's arity says how many cells
                    # it consumed, not which caller values they were.
                    unsafe.add(sub)
                    clobber.add(sub)
                    break
                h += net(o)
        changed = True
        while changed:
            changed = False
            for sub, callees in calls.items():
                if sub not in unsafe and (None in callees or callees & unsafe):
                    unsafe.add(sub)
                    changed = True
                if sub not in clobber and callees & clobber:
                    clobber.add(sub)
                    changed = True
        self._value_unsafe_conts = {
            cont_key for cont_key, pair in self._call_pairs.items()
            if pair[4] in unsafe
        }
        self._residual_clobber_conts = {
            cont_key for cont_key, pair in self._call_pairs.items()
            if pair[4] in clobber
        }
        # Keyed by CALLEE ENTRY as well, because the lift pairs calls with the
        # corrected continuation policy while `_call_pairs` uses the
        # construction one — the two can disagree, and a consumer must not
        # miss a clobbering callee because the pairing differs.
        # PROTO'D subs only. "Reached below its own band" presupposes a band:
        # a legacy sub has no ``proto``, so ``nargs`` is 0 and its band starts
        # empty — consuming caller values is simply how it takes arguments, and
        # every such sub would otherwise be flagged (97 of 97 flagged callees
        # over a 60-probe sample were this false positive). The lift then wiped
        # the caller's stack at every legacy call, losing real values.
        self._clobber_callee_keys = {sub.key for sub in clobber
                                     if sub in self._proto_io}

    def _try_expand_frame_op(
        self, op: PyOp, local_stack: list, sub: PyBlock, proto: tuple,
        missing_below: Optional[int] = None,
    ) -> bool:
        """Rewrite ``frame_dig N`` / ``frame_bury N`` (either sign of ``N``) to
        the fat-stack convention; ``False`` falls back to the narrow path.

        The target is an ABSOLUTE frame position: ``nargs + N``, counted from the
        BOTTOM of the routine band (``N < 0`` are args below the base, ``N >= 0``
        locals above it). So the index is bottom-anchored — but ``local_stack``
        is only the TOP of that band, because Braun materialises just the entry
        slots something demanded. ``missing_below`` is how many band slots sit
        below ``local_stack[0]`` (``edepth(bb) - len(seed)``, constant for the
        whole block since both sides move by the same net per op), and the index
        is ``nargs + N - missing_below``.

        HAZARD: neither half of that is optional. Dropping the correction (as the
        original ``len(sub.entry_stack) + N`` did) slides the index whenever the
        seed is short — ``len(sub.entry_stack)`` is not ``nargs``, being shorter
        for 90 of 202 proto'd subs in the probe corpus. But converting a TOP-first
        slot against ``len(local_stack)`` instead is just as wrong: an entry-depth
        slot only matches the current length at the block's first op, so a
        ``frame_bury`` after a few pushes (``label39``'s ``dupn 4`` … ``frame_bury
        1``) computed an out-of-range index, fell back to the narrow path — where
        ``frame_bury`` is a bare pop with NO definition — and silently lost the
        buried value.

        The consumed band is everything at and above the target; ``frame_dig``
        emits ``n_consumed + 1`` outputs (band + dug copy on top, per
        :func:`_shuffle_mapping`) and ``frame_bury`` ``n_consumed - 1``."""
        try:
            n = int(op.immediates.strip().split()[0])
        except (ValueError, IndexError, AttributeError):
            return False
        if missing_below is None:
            return False              # no routine-relative depth -> narrow path
        target_idx = proto[0] + n - missing_below
        if target_idx < 0 or target_idx >= len(local_stack):
            return False
        n_consumed = len(local_stack) - target_idx      # top to target inclusive
        band_topfirst = list(reversed(local_stack[target_idx:]))

        if op.op == "frame_dig":
            n_out_new = n_consumed + 1
        else:  # frame_bury needs a slot above the target to pop
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
        # new_outs is top-first per the shuffle convention; push back bottom-first.
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
        # Cacheable because `self.blocks` is fixed before first use. Keep the
        # single-underscore cache name: a `__` attribute is name-mangled, so the
        # hasattr check misses and the dict is rebuilt on every call.
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


# Lazy-import wrappers: ssa.py stays free of even sibling-module imports at
# load time.

def _fold_spec_fixed(a):
    from .const_fold import fold_spec_fixed
    return fold_spec_fixed(a)


def _compute_inner_txn_fields(prog: SSAProgram) -> list:
    from .inner_txn_fields import compute_inner_txn_fields
    return compute_inner_txn_fields(prog)


def _compute_scratch_influence(prog: SSAProgram) -> dict:
    from .scratch_influence import compute_scratch_influence
    return compute_scratch_influence(prog)


def _to_ssaprogram(py: PySSA, source: SSAProgram) -> SSAProgram:
    """Translate a built :class:`PySSA` into a new ``SSAProgram`` shell, with
    ``source`` as the read-only graph backend."""
    prog = SSAProgram.__new__(SSAProgram)
    _apply_pyssa_to(prog, py, source=source)
    return prog


def _collapse_phi_args_to_leaves(py: PySSA, phi_map: dict, var_map: dict) -> None:
    """Collapse each ``Phi``'s args to the transitive ``SSAVar`` leaves reachable
    through the ``PyPhi.args`` graph (SCC condensation, memoized per SCC)."""
    import networkx as nx
    # Nodes are integer indices, not PyPhis, purely to avoid millions of
    # `(bb_key, slot)` rehashes. networkx iterates in INSERTION order, so
    # inserting 0..N-1 and the edges in phi order gives the identical
    # condensation and leaf order.
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

    # Resolve each SCC's leaves ONCE — phis in an SCC share a leaf set, so the
    # per-phi lookup was ~33M calls. Same SSAVars, same order.
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
                # Seed spec-fixed AVM ops whose value is a known literal
                # (e.g. `global ZeroAddress`).
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
    """Seed ``const_value`` through value-identity edges (shuffle pass-through +
    scratch reads, to a fixed point) and stash the identity-step relation on
    ``prog._graph.graph["identity_steps"]``; iterating lets identity-of-identity
    chains flow (const -> swap -> load -> swap -> consumer)."""
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
                    # AVM scratch zero-init is a precisely-known int 0, and must
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

    # (c) scratch bridge -- HAZARD: single reaching store ONLY. An identity step
    # asserts snk IS src, so a multi-store load would get one identity per store
    # and const-prop would fold it to whichever is constant first -- unsound when
    # another reaching store is a runtime value. A multi-store load is a merge,
    # handled with must-semantics by propagate_scratch_constants.
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
    """Drop phis not consumed by any op input, so ``prog.phis`` is the consumer
    set rather than the full builder output.

    A DIRECT filter, valid only because ``_collapse_phi_args_to_leaves`` has run:
    a public ``Phi.args`` then holds only ``SSAVar``s, so no phi is reachable
    THROUGH another phi. The assert below pins that precondition.

    ``bb.exit_stack`` counts as a consumer. It is not decoration — block-arg
    lowering, the lift's phi rebuild and the frame bridges all read
    ``pred.exit_stack[-k]`` for the per-edge value ``Phi.args`` no longer
    carries. Filtering on op inputs alone left those slots pointing at phis
    absent from ``prog.phis`` (288 of 1225 such references over a 40-probe
    sample): const/range propagation iterates ``prog.phis``, so it never visited
    them and their ``const_value``/``range`` stayed None forever, making a
    perfectly live value read as unresolvable. Nulling the slots instead would
    DELETE the value the rebuild needs, so keep the phi."""
    _reached: set = set()
    for _a in prog.assignments:
        for _inp in _a.inputs:
            if isinstance(_inp, Phi):
                _reached.add(id(_inp))
    for _bb in prog.blocks.values():
        for _e in _bb.exit_stack:
            if isinstance(_e, Phi):
                _reached.add(id(_e))
    assert not any(isinstance(_arg, Phi)
                   for _p in prog.phis.values() for _arg in _p.args), \
        "phi args must be leaf-collapsed before _drop_unconsumed_phis"
    prog.phis = {k: p for k, p in prog.phis.items() if id(p) in _reached}
    for bb in prog.blocks.values():
        bb.phis = [p for p in bb.phis if id(p) in _reached]


def _apply_pyssa_to(
    prog: SSAProgram, py: PySSA, *, source: Optional[SSAProgram] = None,
) -> None:
    """Mutate ``prog`` to use ``py``-built SSA, rebuilding ``vars`` / ``phis`` /
    ``assignments`` / ``blocks`` and discarding whatever was there before.

    ``source`` is a separately-loaded program (:meth:`PySSA.build`) or ``None``
    for the in-place case (:meth:`SSAProgram.__init__`), where annotations are
    read back out of ``prog`` itself. Chain structure survives off the hot path
    on ``prog._pyssa`` / ``_phi_to_pyphi`` / ``_pyphi_to_phi``, which
    :meth:`SSAProgram.chain_predecessors` and friends query."""
    # HAZARD: snapshot everything re-read from `src` BEFORE wiping `prog` — in
    # the in-place case `src.vars` IS `prog.vars`, so the wipe would clobber the
    # const/range/type annotations being copied over.
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
    # Match the state flags `SSAProgram.__init__` sets, so every pass that gates
    # on one of them finds it.
    prog._consts_propagated = False
    prog._scratch_propagated = False
    prog._ranges_propagated = False
    prog._shuffles_propagated = False
    prog._inputs_propagated = False

    # 1) SSAVars, seeding const_value / range / type from the source prog's
    # already-populated var table.
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

    # 2) Phis: one per (bb_key, slot), registered under DirectPhi only since the
    # Direct/Indirect distinction is collapsed here. `SSAProgram.phi` lookups are
    # kind-agnostic, so a consumer holding an "IndirectPhi" kind still resolves.
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

    # 4.5) Surface each BB's exit stack, translated to public operands, in
    # VERBATIM bottom-first order with dead slots left None. Out-of-SSA /
    # block-arg lowering reads `pred.exit_stack[k]` for the value a successor's
    # slot-k phi gets on that edge — which `Phi.args` (dedup'd) no longer has.
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

    # 5) Collapse each Phi's args to the transitive SSAVar leaves.
    _collapse_phi_args_to_leaves(py, phi_map, var_map)

    # 6) Build Assignments (+ bb back-refs, def/use links, spec-fixed seeds).
    _build_assignments(prog, py, var_map, phi_map, bb_map)

    # NB inner-txn field grouping, scratch reaching-definitions and const/
    # identity-step seeding are deliberately NOT run here — they were ~58% of
    # build time for callers that never read them. They now live behind
    # SSAProgram._ensure_inner_txn_fields / _ensure_scratch_influence /
    # _ensure_identity_steps, each reproducing what the eager block produced.

    # 7) Drop phis not transitively consumed by any op input.
    _drop_unconsumed_phis(prog)

    for bb in prog.blocks.values():
        bb.assignments.sort(key=lambda a: a.location.line)
        bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    # 8) Chain-structure refs (chain root, propagation graph), off the hot path.
    prog._pyssa = py
    prog._phi_to_pyphi = {p: pp for pp, p in phi_map.items()}
    prog._pyphi_to_phi = dict(phi_map)

    return prog


def _demo(source: str) -> None:
    """Render the PySSA-built SSA for a TEAL source (CLI diagnostic dump)."""
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
