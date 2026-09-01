"""The pure-Python SSA builder behind :class:`SSAProgram`.

Pipeline (:meth:`PySSA._construct`): instantiate PyVars per opcode output ->
routine metadata + call pairing + callee effect classification -> ONE per-routine
stack simulation (:mod:`.stacksim`) filling ``op.inputs`` / ``b.exit_stack`` ->
liveness filter.

ONE SIMULATOR. There used to be two here — Braun on-demand phi placement reading
values back through ``_read_exit``, and a phase-6c block simulation over a
"fat band" rewrite of the frame ops — plus the lift's private scheduler making three.
Every PAIR of them produced a silent wrong-value bug (Braun vs 6c in the callsub
work, SSA vs lift in ``(itob 0x151f7c75)``), each invisible until a bespoke
metric went looking. The duplicate SSA models are gone, and the lift now shares
:func:`stacksim.walk_routine`: real ``callsub`` arities and join alignment have
one owner. A ``frame_dig`` is one input and one output, not a band; there is no
depth cap, because a per-routine stack cannot spiral the way a whole-program
slot model could.

HAZARD — slot model. Stack slots are 1-based TOP-FIRST, both for phi identity
``(bb_key, slot)`` and for indexing an ``exit_stack`` (``exit_stack[-k]``).

HAZARD — the ``PyPhi.args`` graph can be CYCLIC (constant-stack CFG loops), so
every traversal needs a ``seen`` set. ``PyPhi`` is unified: the public
Direct/Indirect kind distinction is collapsed here.

CLI: ``python -m tealql.tealtools.ssa.ssa <teal-source>`` renders the build.
"""
from __future__ import annotations

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
from ..language.avm import op_arity


#: The AVM's stack limit. No longer a construction bound — the old whole-program
#: slot model could climb to it and had to be capped; a per-routine simulation
#: cannot. Kept because it is a real property of the machine and is exported.
STACK_MAX = 1000


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

    __slots__ = ("bb_key", "slot", "args", "partial")

    def __init__(self, bb_key: tuple, slot: int):
        self.bb_key = bb_key
        self.slot = slot
        self.args: list[Optional[Operand]] = []
        # The cell is absent on >=1 incoming path (max-window join arm too
        # shallow, or a net-popping loop's later laps). Mirrored onto the
        # public Phi — see models.Phi.partial for the consumption contract.
        self.partial: bool = False

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
    ``inputs`` / ``outputs`` filled by the per-BB simulator.

    ``source_assignment`` carries annotations across the preliminary
    graph-backed SSA and is cleared after rebuilding so it does not retain the
    discarded preliminary CFG. ``public_assignment`` is the durable identity
    bridge from this model to public SSA. Source coordinates remain public
    value keys, but must never join two representation layers internally.
    """

    op: str
    immediates: str
    file: str
    line: int
    n_in: int
    n_out: int
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    source_assignment: object = field(default=None, repr=False)
    public_assignment: object = field(default=None, repr=False)


class PyBlock:
    """Ordered opcodes plus CFG neighbours — ``preds`` / ``succs`` are the RAW
    CFG, callsub and retsub edges included."""

    __slots__ = (
        "key", "ops", "preds", "succs", "entry_phis", "exit_stack",
    )

    def __init__(self, key: tuple):
        self.key = key  # (file, first_line, last_line)
        self.ops: list[PyOp] = []
        self.preds: list["PyBlock"] = []
        self.succs: list["PyBlock"] = []
        self.entry_phis: list[PyPhi] = []
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
    # Subroutine metadata.
    _bb_to_sub: dict = field(default_factory=dict)
    _proto_io: dict = field(default_factory=dict)
    # Sub entry -> (A, R): its ``proto`` verbatim, else the shared legacy
    # inference (see _compute_call_pairs). Depth crossing and call-effect
    # classification read THIS map so the two cannot disagree about a callee.
    _callsub_arities: dict = field(default_factory=dict)
    # Verified call/return pairings (see _compute_call_pairs):
    #   cont.key -> (callsub PyBlock, A, R, frozenset of verified retsub pred keys)
    #   callsub PyBlock -> (cont PyBlock, A, R)
    _call_pairs: dict = field(default_factory=dict)
    _pair_by_cs: dict = field(default_factory=dict)
    # Callees that may have rewritten the caller's residual stack (see
    # _classify_call_effects). Keyed two ways for two consumers: BLOCKS for the
    # simulator, which withdraws the residual at the `callsub`, and KEYS for the
    # lift, which fills those slots with `Undefined`.
    _unsafe_callee_blocks: set = field(default_factory=set)
    _clobber_callee_keys: set = field(default_factory=set)
    # bb_key -> entry stack depth INCLUDING the sub's args; see
    # stacksim.entry_heights. Absent = unreachable or height-ambiguous.
    _frame_edepth: dict = field(default_factory=dict)
    # Owned blocks without an exact bottom anchor. The height result also keeps
    # its narrower conflict set for diagnostics.
    _height_poisoned: set = field(default_factory=set)
    _height_conflicted: set = field(default_factory=set)
    # Entry bb_keys of DIVERGENT legacy subs (retsub sites at different
    # depths — not function-shaped; see stacksim's `shifted` merge). Surfaced
    # so SSA-level consumers can see the shape the lift reports as
    # `not_function_shaped` without re-running the fixpoint.
    _divergent_legacy: set = field(default_factory=set)
    # Callee entry PyBlock -> callee_effects.Summary, for the UNSAFE callees
    # whose below-band effect is exactly computable (tree-shaped, callsub-free
    # bodies). The simulation rewrites the caller residual through these
    # instead of blanking it; the lift still Undefines (`_clobber_callee_keys`
    # unchanged) until per-call-site inlining lands there.
    _effect_summaries: dict = field(default_factory=dict)
    # Canonical semantic products retained for downstream adapters and
    # diagnostics; neither mutates the public SSA objects.
    _frame_analysis: object = None
    _stack_result: object = None
    # callsub bb_key -> continuation bb_key (corrected policy), see
    # subroutines.corrected_return_points.
    _corrected_rp: dict = field(default_factory=dict)

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
        # ONE continuation policy for the whole pipeline. `prog.blocks` and
        # `prog.labels` are already populated here (`_build_from_graph` fills
        # them before calling us), which is all `identify_subroutines` reads —
        # so the construction path can use the CORRECTED answer instead of the
        # naive source-next guess it used to re-derive.
        from ..cfg.subroutines import corrected_return_points
        self._corrected_rp = corrected_return_points(prog)
        self._compute_subs_and_protos()
        # Routine metadata, then the two analyses the operand build and the LIFT
        # both key off. `_clobber_callee_keys` is what tells the lift to fill a
        # clobbered caller slot with `Undefined` rather than the stale pre-call
        # value, and `_unsafe_callee_blocks` is what makes the simulation itself
        # withdraw that residual — a per-routine walk cannot otherwise see a
        # callee dipping under its own band, because the dip happens on the
        # callee's own stack.
        self._compute_call_pairs()
        from . import stacksim
        heights = stacksim.entry_heights(
            self.blocks, self._bb_to_sub, self._proto_io, self._pair_by_cs)
        self._frame_edepth = heights.entry
        self._height_poisoned = heights.poisoned
        self._height_conflicted = heights.conflicted
        self._classify_call_effects()
        from . import callee_effects
        self._effect_summaries = callee_effects.build_summaries(
            self.blocks, self._bb_to_sub, self._proto_io,
            self._unsafe_callee_blocks)
        self._phase_stacksim()
        self._phase8_live_filter()
        return self

    # ----- Phase 1: instantiate PyVars -----------------------------------

    def _phase1_instantiate(self, prog: SSAProgram) -> None:
        by_ql: dict[object, PyBlock] = {}
        for qbb in prog.blocks.values():
            b = PyBlock((qbb.file, qbb.first_line, qbb.last_line))
            for a in qbb.assignments:
                # The op's CANONICAL arity. `callsub`/`retsub` read (0, 0) here
                # and `frame_dig` (0, 1); the simulation supplies what a call
                # really consumes and where a frame op really reads, and records
                # the operands itself — it never rewrites these.
                n_in, n_out = op_arity(a.op, a.immediates)
                op = PyOp(
                    op=a.op, immediates=a.immediates,
                    file=a.location.file, line=a.location.line,
                    n_in=n_in, n_out=n_out,
                    source_assignment=a,
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

    def _phase_stacksim(self) -> None:
        """Fill operands from the single clean simulation.

        One forward per-routine walk with real ``callsub`` arities and frame
        slots read and written in place — see the module docstring for what this
        replaced and why."""
        from . import stacksim

        def mint(block, slot):
            # Identity is (bb_key, slot) and the public Phi mirrors it, so a
            # block's phis must not share a slot — a call-result phi can collide
            # with a join phi in the same block.
            s = slot
            while (block.key, s) in self.phis:
                s += 1
            p = PyPhi(block.key, s)
            self.phis[(block.key, s)] = p
            block.entry_phis.append(p)
            return p

        # The partition, return-point map and arity fixpoint were computed
        # once in `_compute_subs_and_protos` / `_compute_call_pairs` from
        # exactly these inputs — reuse them instead of a 2nd and 3rd run.
        part = self._bb_to_sub
        rp = self._return_point
        # Bottom-anchored answers for frame ops in depth-poisoned blocks —
        # where the working list is not bottom-anchored and ``stack[pos]``
        # would read a neighbouring cell on the shallower paths.
        from . import frame_slots
        frame_analysis = frame_slots.analyze(
            self.blocks, part, self._proto_io, rp, self._frame_edepth,
            self._unsafe_callee_blocks,
            self._callsub_arities,
            poisoned=self._height_poisoned)
        self._frame_analysis = frame_analysis
        res = stacksim.simulate(self.blocks, part, self._proto_io, rp, mint,
                                unsafe_callees=self._unsafe_callee_blocks,
                                frame_analysis=frame_analysis,
                                effect_summaries=self._effect_summaries,
                                arity=self._callsub_arities,
                                divergent_subs=self._arity_divergent)
        self._stack_result = res
        self._divergent_legacy = {b.key for b in res.divergent}
        for b in self.blocks:
            for o in b.ops:
                o.inputs = list(res.args.get(id(o), []))
            b.exit_stack = list(res.exit.get(b, []))

    def _compute_subs_and_protos(self) -> None:
        """Populate ``self._bb_to_sub`` (BB -> owning routine entry BB) and
        ``self._proto_io`` (sub entry -> ``(args, returns)`` from its ``proto``);
        depends only on CFG shape and phase-1 immediates, not on the stack sim."""
        # Ownership follows the CONSTRUCTION policy this depth machinery was
        # validated against, which lives verbatim in pyblock_partition.
        from ..cfg.subroutines import pyblock_partition
        self._bb_to_sub = pyblock_partition(self.blocks, self._corrected_rp)

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

        * CS's callee has ONE ``(A, R)``: declared by ``proto``, or inferred
          by the shared legacy fixpoint (``infer_legacy_arities`` — the same
          arities the simulation executes, so crossing and execution cannot
          disagree). A DIVERGENT legacy callee — retsub sites at different
          depths — has no single crossing and pairs with NOTHING: one path's
          height would be wrong on the others, so its live continuation stays
          depth-poisoned. Pairing used to require an explicit ``proto``,
          which left every legacy call's continuation without an entry depth
          and poisoned the caller's whole local suffix: in a proto'd caller,
          frame params read AFTER such a call lifted to ``undefined`` (the
          shape puya-ts emits for auth helpers, called first in nearly every
          method);
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
        from ..cfg.subroutines import _pyblock_return_point
        from . import stacksim

        return_point = _pyblock_return_point(self.blocks, self._corrected_rp)
        # Cache both for the later phases: `_classify_call_effects` and
        # `_phase_stacksim` used to recompute this return-point map (×3) and
        # re-run the whole-program arity FIXPOINT (×3) with identical inputs.
        self._return_point = return_point
        divergent: set = set()
        self._callsub_arities = stacksim.infer_arities(
            self.blocks, self._bb_to_sub, self._proto_io, return_point,
            divergent=divergent)
        self._arity_divergent = divergent
        self._call_pairs = {}
        self._pair_by_cs = {}
        for cs, cont in return_point.items():
            if cont is None or cont is cs:
                continue
            callee = next((s for s in cs.succs if s in self._proto_io), None)
            if callee is None:
                # Legacy: the partition-root successor, crossed with its
                # INFERRED (A, R). A divergent callee gets no pair — no
                # single depth is true on every return path.
                callee = next((s for s in cs.succs
                               if self._bb_to_sub.get(s) is s), None)
                if callee is None or callee in divergent:
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
            a, r = (self._proto_io.get(callee)
                    or self._callsub_arities[callee])
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
        unsafe — the live continuation of a call whose crossing could not be
        verified (a DIVERGENT legacy callee leaves no single depth), or a
        height-conflicted join. Unsafety is
        transitive over ``callsub`` (a clean wrapper inherits its callee's)."""
        def net(op):
            if op.op == "frame_dig":
                return 1
            if op.op == "frame_bury":
                return -1
            return op.n_out - op.n_in

        # Reverse reachability to a retsub over local edges (callsub -> its
        # return point; retsub/return/err terminal), mirroring pyblock_partition.
        return_point = self._return_point
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
                    # Proto'd or legacy alike: `_callsub_arities` carries the
                    # inferred (A, R) for proto-less callees, so a legacy
                    # callee dipping below THIS sub's band still flags it —
                    # the blanket unsafety its unpaired continuation used to
                    # provide is gone now that legacy calls cross.
                    a_callee = next(
                        ((self._proto_io.get(s)
                          or self._callsub_arities[s])[0]
                         for s in b.succs
                         if s in self._proto_io
                         or s in self._callsub_arities), 0)
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
        # Keyed by CALLEE ENTRY, not by continuation: the lift pairs calls with
        # the corrected continuation policy while `_call_pairs` uses the
        # construction one — the two can disagree, and a consumer must not
        # miss a clobbering callee because the pairing differs. (The
        # continuation-keyed views this used to publish had no consumer left
        # once Braun's `_read_edge`/`_read_exit` went.)
        # PROTO'D subs only. "Reached below its own band" presupposes a band:
        # a legacy sub has no ``proto``, so ``nargs`` is 0 and its band starts
        # empty — consuming caller values is simply how it takes arguments, and
        # every such sub would otherwise be flagged (97 of 97 flagged callees
        # over a 60-probe sample were this false positive). The lift then wiped
        # the caller's stack at every legacy call, losing real values.
        self._clobber_callee_keys = {sub.key for sub in clobber
                                     if sub in self._proto_io}
        # The UNSAFE set as ENTRY BLOCKS, for a simulator that withdraws at the
        # `callsub` rather than at a paired continuation. Same proto'd
        # restriction, same reason; keyed by block because a per-routine
        # simulation identifies a callee by the block it enters.
        self._unsafe_callee_blocks = {sub for sub in unsafe
                                      if sub in self._proto_io}

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
                       phi_map: dict, bb_map: dict) -> tuple[dict, dict]:
    """Build ``prog.assignments`` (+ ``bb.assignments``, def/use back-refs,
    and spec-fixed const seeds) from the PySSA ops.

    Returns the two identity maps forming the supported private/public bridge:
    ``id(PyOp) -> Assignment`` and its reverse. PyOp keeps its exported
    structural equality contract, so the forward map explicitly keys on
    identity. The old implementation looked the preliminary assignment back
    up by ``(file, line)`` here; that made a representation boundary depend on
    a reporting coordinate and silently selected the last value on collision.
    """
    def _xlate(o):
        if o is None:
            return None
        if isinstance(o, PyVar):
            return var_map.get(o)
        if isinstance(o, PyPhi):
            return phi_map.get(o)
        return o

    pyop_to_assignment: dict = {}
    assignment_to_pyop: dict = {}
    for py_b in py.blocks:
        bb = bb_map[py_b]
        for py_op in py_b.ops:
            source_a = py_op.source_assignment
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
                ast_code=(source_a.ast_code if source_a is not None
                          else f"{py_op.op} {py_op.immediates}".strip()),
                # Const-block and inline-push literals are resolved on the
                # graph-loaded preliminary Assignment.  Private SSA replaces
                # that object; preserve the assignment-level seed as well as
                # the output SSAVar's const_value.  Byte-length/bytemath passes
                # intentionally consume this field.
                const=source_a.const if source_a is not None else None,
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
            py_op.public_assignment = a
            py_op.source_assignment = None       # release the preliminary CFG
            pyop_to_assignment[id(py_op)] = a
            assignment_to_pyop[a] = py_op
            prog.assignments.append(a)
            bb.assignments.append(a)

    prog.assignments.sort(key=lambda a: (a.location.file, a.location.line))
    return pyop_to_assignment, assignment_to_pyop


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
            return ("phi", o.file, o.line, o.stack_index)
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
            _snk = ("phi", _p.file, _p.line, _p.stack_index)
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
    src_sources_snapshot = getattr(src, "sources", None)
    src_off_end_snapshot = set(getattr(src, "off_end_exits", ()))
    src_polarity_snapshot = dict(getattr(src, "edge_polarity", {}))
    src_unknown_snapshot = frozenset(getattr(src, "unknown_ops", ()))
    src_strict_snapshot = bool(getattr(src, "_strict", False))

    prog.vars = {}
    prog.phis = {}
    prog.assignments = []
    prog.blocks = {}
    prog.labels = src_labels_snapshot
    prog._graph = src_graph_snapshot
    prog.source_path = src_source_path_snapshot
    prog.sources = src_sources_snapshot
    # These live beside, rather than inside, the rebuilt BB objects.  The
    # in-place constructor retained them by accident; the exported
    # ``PySSA.build`` fresh-shell path used to lose them entirely.
    prog.off_end_exits = src_off_end_snapshot
    prog.edge_polarity = src_polarity_snapshot
    prog.unknown_ops = src_unknown_snapshot
    prog._strict = src_strict_snapshot
    prog._revision = 0
    # Match the state flags `SSAProgram.__init__` sets, so every pass that gates
    # on one of them finds it.
    prog._consts_propagated = False
    prog._scratch_propagated = False
    prog._ranges_propagated = False
    prog._byte_lengths_propagated = False
    prog._bytemath_ranges_propagated = False

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
    # PyVar equality is source-key based for compatibility, so the supported
    # cross-representation bridge keys on object id to reject a same-location
    # value from another build.
    prog._pyvar_id_to_var = {id(pv): v for pv, v in var_map.items()}
    prog._var_id_to_pyvar = {id(v): pv for pv, v in var_map.items()}

    # 2) Phis: one per (bb_key, slot).
    phi_map: dict = {}  # PyPhi -> Phi
    for (bb_key, slot), py_p in py.phis.items():
        p = Phi(bb_key[0], bb_key[1], slot)
        p.partial = py_p.partial
        phi_map[py_p] = p
        prog.phis[(bb_key[0], bb_key[1], slot)] = p
    prog._pyphi_id_to_phi = {id(pp): p for pp, p in phi_map.items()}
    prog._phi_id_to_pyphi = {id(p): pp for pp, p in phi_map.items()}

    # 3) BasicBlocks.
    bb_map: dict = {}
    for py_b in py.blocks:
        bb = BasicBlock(*py_b.key)
        bb_map[py_b] = bb
        prog.blocks[py_b.key] = bb
    for py_b, bb in bb_map.items():
        bb.predecessors = [bb_map[p] for p in py_b.preds if p in bb_map]
        bb.successors = [bb_map[s] for s in py_b.succs if s in bb_map]
    prog._pyblock_to_block = dict(bb_map)
    prog._block_id_to_pyblock = {id(bb): py_b for py_b, bb in bb_map.items()}

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
    (prog._pyop_id_to_assignment,
     prog._assignment_to_pyop) = _build_assignments(
        prog, py, var_map, phi_map, bb_map,
    )

    # NB inner-txn field grouping, scratch reaching-definitions and const/
    # identity-step seeding are deliberately NOT run here — they were ~58% of
    # build time for callers that never read them. They now live behind
    # SSAProgram._ensure_inner_txn_fields / _ensure_scratch_influence /
    # _ensure_identity_steps, each reproducing what the eager block produced.

    # 7) Drop phis not transitively consumed by any op input.
    _drop_unconsumed_phis(prog)

    for bb in prog.blocks.values():
        bb.assignments.sort(key=lambda a: a.location.line)
        bb.phis.sort(key=lambda p: p.stack_index)

    # Preserve the canonical AVM instruction stream independently of the
    # functional live-assignment view. Copy/input/scratch cleanup is allowed to
    # remove redundant definitions from ``prog.assignments`` and
    # ``bb.assignments``; stack-semantic consumers must still execute these
    # opcodes in source order. The Assignment objects stay shared so sound
    # annotations and equivalent-value rewrites remain visible in both views.
    prog._stack_assignments = tuple(prog.assignments)
    prog._stack_vars = dict(prog.vars)
    for bb in prog.blocks.values():
        bb.stack_assignments = tuple(bb.assignments)

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
