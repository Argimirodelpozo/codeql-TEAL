"""Lift an :class:`~tealql.tealtools.ssa.SSAProgram` into the Puya-shaped IR: TEAL's
stack machine (frame slots, scratch, shuffles) becomes value-based, typed IR,
partitioned into ``main`` plus one subroutine per ``callsub`` target.

The public SSA carries both a functional live-assignment view and the canonical
AVM opcode stream. Analysis passes may rewrite or clean the former; lifting
always simulates the latter, so pass order cannot change program semantics.
"""
from __future__ import annotations

import logging

from ..avm import _STACK_SHUFFLE_OPS, _TERMINATOR_OPS, op_arity
from ..ssa import (
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _canon_shuffle,
    _shuffle_mapping,
)
from ..ssa import stacksim as stack_engine
from ..ssa.frame_slots import ReturnSlots, SlotMerge
from ..ssa.models import Assignment as _SSAAssignment, BasicBlock as _SSABasicBlock
from ..structure import analyze_structure
from . import pre_ir, transforms, type_recovery
from ..avm import (
    BIGUINT_RESULT_OPS,
    _BOOL_OPS,
    _BYTES_OPS,
    _NAME_PREFIX,
    _POLY_FIRST_OPERAND_OPS,
    _U64_OPS,
    COND_BRANCH_OPS,
    _field_type,
    _multi_out_type,
)
from ..ssa.operands import imm0 as _imm0
from .teal_const import _load_src
from ..ast.literals import tokenize_operands as _tokenize_operands

logger = logging.getLogger("tealql.tealtools.lift")

_FRAME_OPS = frozenset({"frame_dig", "frame_bury"})


def _ops(bb):
    """Canonical AVM instructions for ``bb`` (clones fall back to live ops)."""
    return getattr(bb, "stack_assignments", ()) or bb.assignments


def _infer_arities(struct, callsite, *, divergent: "set | None" = None) -> dict:
    """``Subroutine -> (nargs, nret)``: read off ``proto``, or inferred.

    A thin binding of :func:`..subroutines.infer_legacy_arities` to the
    ``structure.Subroutine`` model. The fixpoint itself is shared with the SSA's
    `stacksim.infer_arities` — it was implemented twice, the copies drifted, and
    the SSA's under-counted a sub branching into a shared tail while this one
    got it right.

    ``divergent`` (out-param) collects the legacy subs that are NOT
    FUNCTION-SHAPED: their ``retsub`` sites leave different stack depths, so the
    callee's net effect depends on the path it took. A pre-``proto`` ``retsub``
    does not truncate — it is a jump — so such a sub is perfectly legal TEAL and
    simply is not a function: NO single ``(nargs, nret)`` describes it, and the
    fixpoint's ``max`` over return sites necessarily over-declares the shallow
    paths, which the stack adapter then pads with ``Undefined`` (an explicit
    unknown — imprecise, never a wrong value).

    Making those calls faithful means INLINING the callee per call site, which
    the IR can express (its block ids are synthetic, unlike the SSA layer's
    source-position identities) but this lift does not yet do.
    """
    from ..subroutines import infer_legacy_arities

    by_name = {s.name: s for s in struct.subroutines}

    def _proto_of(s):
        return (_proto_io(s.entry_bb)
                if any(a.op == "proto" for a in _ops(s.entry_bb)) else None)

    def _callee_of(b):
        cs = callsite.get(b)
        return by_name.get(cs.target_name) if cs else None

    def _succs_of(b, body):
        cs = callsite.get(b)
        if cs is not None and cs.continuation_bb is not None:
            return [cs.continuation_bb] if cs.continuation_bb in body else []
        return [s for s in b.successors if s in body]

    return infer_legacy_arities(
        struct.subroutines,
        entry_of=lambda s: s.entry_bb,
        proto_of=_proto_of,
        body_of=lambda s: s.body,
        ops_of=_ops,
        succs_of=_succs_of,
        callee_of=_callee_of,
        op_arity=lambda o: op_arity(o.op, o.immediates),
        divergent=divergent,
    )


def _const(cv: Const):
    # SSA integer consts carry kind "int", not "uint64"; without this they fall
    # through to BytesConstant(decimal-string) -- renders right, but is a uint64
    # stored as bytes.
    if cv.kind == "int":
        try:
            return pre_ir.UInt64Constant(int(cv.value))
        except ValueError:
            return pre_ir.UInt64Constant(0)
    return pre_ir.BytesConstant(cv.value)


_UINT64_MAX = (1 << 64) - 1


def _range_note(local_id: str, rng) -> str | None:
    """A compact ``// `` annotation for an :class:`IntRange`, or ``None`` for the
    (uninformative) full uint64 domain."""
    lo, hi = rng.lo, rng.hi
    if lo <= 0 and hi >= _UINT64_MAX:
        return None
    if lo == hi:
        return f"{local_id} = {lo}"
    if hi >= _UINT64_MAX:
        return f"{local_id} >= {lo}"
    if lo <= 0:
        return f"{local_id} <= {hi}"
    return f"{lo} <= {local_id} <= {hi}"


def _len_note(local_id: str, t) -> str | None:
    """``len(x) = 8`` / ``2 <= len(x) <= 4096`` from a bytes type's ``byte_length``
    or ``byte_length_range``."""
    bl = getattr(t, "byte_length", None)
    if bl is not None:
        return f"len({local_id}) = {bl}"
    r = getattr(t, "byte_length_range", None)
    if r is None:
        return None
    if r.lo == r.hi:
        return f"len({local_id}) = {r.lo}"
    if r.lo <= 0:
        return f"len({local_id}) <= {r.hi}"
    return f"{r.lo} <= len({local_id}) <= {r.hi}"


def _val_note(local_id: str, t, cap: int = 40) -> str | None:
    """``x = N`` / ``lo <= x <= hi`` from a bytes type's bigint ``int_value_range``
    (bytemath), with multi-hundred-digit bounds collapsed to ``<N-bit>``."""
    r = getattr(t, "int_value_range", None)
    if r is None:
        return None

    def _s(n: int) -> str:
        s = str(n)
        return s if len(s) <= cap else f"<{n.bit_length()}-bit>"

    if r.lo == r.hi:
        return f"{local_id} = {_s(r.lo)}"
    return f"{_s(r.lo)} <= {local_id} <= {_s(r.hi)}"


def lift(prog: SSAProgram) -> pre_ir.Program:
    """Lift ``prog`` into the Puya-shaped IR model.

    The input comes back STRUCTURALLY UNTOUCHED: the dead-assert-edge prune the
    typed lift needs (:func:`_prune_dead_assert_edges`) is applied for the
    duration of the build and inverted on exit, success or failure — so a caller
    may lift the very program its SSA-level analyses read (``build_lifter`` /
    ``security.common.ir_lifter`` do; no fresh re-parse). Annotation passes the
    build triggers (const/scratch caches) do land on ``prog`` — they are the
    shared annotation layer, not mutations."""
    return _Lifter(prog).build()


def _prune_dead_assert_edges(prog: SSAProgram):
    """Drop the dead fall-through edges of always-failing ``assert 0`` blocks and
    rebuild the affected join phis from the surviving predecessors, returning an
    undo record for :func:`_restore_pruned_edges`.

    HAZARD: the edge is runtime-dead but STRUCTURAL, so the failing block stays a
    phi predecessor at a join, where it can contribute a value of a different AVM
    type than the live preds — the typed lift then drops the phi, loses the live
    survivor, and emits an operand-less intrinsic the MIR backend rejects. Prune
    only MULTI-predecessor successors: a single-pred successor has no phi to
    pollute, and dropping its only edge would orphan still-live code."""
    from ..ssa import const_int

    undo_edges: list = []              # (block, succ_idx, succ, pred_idx|None)
    undo_phis: list = []               # (phi, original args list), first-seen
    seen_phis: set = set()
    dead = [b for b in prog.blocks.values()
            if any(a.op == "assert" and a.inputs and const_int(a.inputs[0]) == 0
                   for a in _ops(b))]
    for b in dead:
        for s in list(b.successors):
            if len(s.predecessors) <= 1:
                continue                       # not a join -> no phi to de-pollute
            si = b.successors.index(s)
            pi = s.predecessors.index(b) if b in s.predecessors else None
            b.successors.remove(s)
            if pi is not None:
                s.predecessors.remove(b)
            undo_edges.append((b, si, s, pi))
            for phi in s.phis:
                k = phi.stack_index
                newargs = [p.exit_stack[-k] for p in s.predecessors
                           if len(p.exit_stack) >= k and p.exit_stack[-k] is not None]
                if newargs:
                    if id(phi) not in seen_phis:
                        seen_phis.add(id(phi))
                        undo_phis.append((phi, phi.args))
                    phi.args = newargs
    return undo_edges, undo_phis


def _restore_pruned_edges(undo) -> None:
    """Invert :func:`_prune_dead_assert_edges` exactly — edges re-inserted at
    their original list positions (successor ORDER can be semantic), original
    ``phi.args`` lists re-bound."""
    undo_edges, undo_phis = undo
    for b, si, s, pi in reversed(undo_edges):
        b.successors.insert(si, s)
        if pi is not None:
            s.predecessors.insert(pi, b)
    for phi, args in undo_phis:
        phi.args = args


class _Lifter:
    """Stateful builder behind :func:`lift` — one instance per program."""

    def __init__(self, prog: SSAProgram) -> None:
        self.prog = prog

    def build(self) -> pre_ir.Program:
        """Lift to the pre-IR, surfacing any failure as a typed
        :class:`tealql.tealtools.errors.LiftError` (stage ``"build"``). The
        input program's CFG is restored on the way out, success or failure."""
        from ..errors import LiftError
        # Scratch influence is consumed by the build (load_stores) but CACHED on
        # prog and shared with the SSA layer — force it BEFORE the prune so the
        # cache always holds the un-pruned result. (Entry points that pre-run
        # propagate_constants computed it pre-prune already; this pins the bare
        # lift() path to the same semantics.)
        self.prog._ensure_scratch_influence()
        undo = _prune_dead_assert_edges(self.prog)
        try:
            return self._build_impl()
        except LiftError:
            raise
        except Exception as e:
            raise LiftError(f"{type(e).__name__}: {e}", stage="build") from e
        finally:
            _restore_pruned_edges(undo)

    def _build_impl(self) -> pre_ir.Program:
        from ..errors import LiftError
        files = self.prog.source_files
        if len(files) != 1:
            raise LiftError(
                "lift requires exactly one AVM program; project a directory-backed "
                "SSAProgram with prog.for_file(file) first "
                f"(found {len(files)} files)", stage="build")
        self.label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in self.prog.labels}
        struct = analyze_structure(self.prog)
        self.sub_of = {bb: s for s in struct.subroutines for bb in s.body}
        self.callsite = {cs.callsub_bb: cs for cs in struct.call_sites}
        self.cont_site = {cs.continuation_bb: cs for cs in struct.call_sites
                          if cs.continuation_bb is not None}
        self._clobber_callees: set = set(
            getattr(getattr(self.prog, "_pyssa", None), "_clobber_callee_keys", ()) or ())
        self.not_function_shaped: set = set()
        _arity = _infer_arities(struct, self.callsite,
                                divergent=self.not_function_shaped)
        # Legal TEAL that is not a function: a pre-`proto` `retsub` is a jump,
        # so a sub whose return sites leave different depths has no single
        # signature. `_splice_divergent_legacy` (below, after the producer maps
        # exist) gives each CALL SITE its own copy of the body — the call
        # becomes the jump it really is, and the divergence becomes ordinary
        # depth-divergent joins at the continuation. Subs its guards refuse
        # keep the arity-model recovery and are warned about there.
        self._io_by_entry = {s.entry_bb: a for s, a in _arity.items()}
        self._proto_entries = {s.entry_bb for s in struct.subroutines
                               if any(a.op == "proto" for a in _ops(s.entry_bb))}
        # Representation-specific outputs of the canonical `ssa.stacksim`
        # routine walk. Opcode execution translates into PRE-IR values here;
        # traversal, loop discovery and join alignment live in one engine.
        self.stack_args: dict = {}                # id(assignment) -> [pre-IR operand]
        self.stack_phis: dict = {}                # BasicBlock -> [pre_ir.Phi]
        self.stack_exit: dict = {}                # BasicBlock -> PRE-IR value stack
        self._phi_by_register: dict = {}          # id(Register) -> live pre-IR Phi
        self._param_phis: set = set()             # non-proto entry arg phis -> params (skip)
        # Producer map + scratch reaching-def (per `load N`, the SSAVars its
        # influencing `store N`s wrote) -- call args are passed via scratch here,
        # not as callsub operands, so typing them needs the reaching-def.
        self.producer = {o: a for a in self.prog.stack_assignments
                         for o in a.outputs if isinstance(o, SSAVar)}
        self.load_stores: dict = {}
        self.prog._ensure_scratch_influence()
        g = getattr(self.prog, "_graph", None)
        if g is not None:
            for n in g.nodes:
                stores = g.nodes[n].get("scratch_stores")
                if not stores:
                    continue
                lv = self.prog.stack_var(n.location.file, n.location.start_line, 1)
                if lv is not None:
                    self.load_stores[lv] = [self.prog.stack_var(*k) for k in stores]
        # Per-call-site duplication of divergent legacy subroutines. Runs after
        # `producer` exists (clone outputs register there) and before groups /
        # `bid` form (clones join their caller's group and need block ids).
        self._splice_entry: dict = {}     # callsub_bb -> that site's clone of the entry
        self._splice_retsub: dict = {}    # clone retsub block -> the site's continuation
        self._clone_map_of: dict = {}     # clone block -> {original -> clone} for its site
        self._clones_of_group: dict = {}  # struct.Subroutine | None (main) -> [clone blocks]
        self._spliced_subs: set = set()   # subs spliced at EVERY site: no group is built
        self.doomed_edges: set = set()    # (pred, join): shallow-arm entry dies in join
        self._doom_profile: dict = {}     # block -> [(dip, impure_before)] | None
        self._splice_divergent_legacy(struct)
        all_blocks = sorted(self.prog.blocks.values(), key=self._key)
        main_blocks = [bb for bb in all_blocks if bb not in self.sub_of]
        groups = [("main", None,
                   sorted(main_blocks + self._clones_of_group.get(None, []),
                          key=self._key))]
        for s in sorted(struct.subroutines, key=lambda s: self._key(s.entry_bb)):
            if s in self._spliced_subs:
                continue                  # every site got its own copy: no group
            # Drop blocks this body cannot actually REACH. Bodies overlap, and
            # for two different reasons that must not be conflated:
            #
            #  * legitimately — a tail reachable from two entries is in both
            #    bodies, and each context simulates it from its own
            #    predecessor. Simulation is per-group precisely so that works.
            #  * spuriously — a helper called from several places fans its
            #    `retsub` out to EVERY caller's continuation, so the
            #    continuation heuristic pulls other callers' blocks in
            #    (app_1850858495: one block landed in five bodies, four of them
            #    unreachable there).
            #
            # Only the second kind is a bug, and it is the one that produces
            # wrong VALUES: with no predecessor in the group simulation starts
            # on an empty stack, and `frame_dig N` — which resolves by absolute
            # index — reads whatever was pushed next. `callsub; frame_bury 0;
            # pushbytes 0x151f7c75; frame_dig 0; itob` lifted to
            # `(itob 0x151f7c75)`, the puya "incompatible argument types"
            # reports on the probe corpus.
            #
            # Reachable = the entry, or holding a CFG predecessor, or the
            # continuation of a `callsub` in this body (a continuation's CFG
            # predecessor is the CALLEE's retsub, so the call edge must be
            # consulted or every continuation reads as unreachable).
            body = [bb for bb in s.body
                    if bb is s.entry_bb
                    or any(q in s.body for q in bb.predecessors)
                    or self.cont_site.get(bb) is not None
                    and self.cont_site[bb].callsub_bb in s.body]
            groups.append((s.name or f"sub@L{s.entry_bb.first_line}", s,
                           sorted(body + self._clones_of_group.get(s, []),
                                  key=self._key)))
        # Global block ids, though Puya restarts block@0 per subroutine: the
        # partition leaves cross-routine branch edges (tail-calls / shared
        # epilogues), which a per-subroutine-local id would silently mis-target.
        # Splice clones id AFTER the originals; they never enter `line2block`
        # (they share their original's lines — label targets resolve to the
        # original and `_site_target` maps them into the copy).
        self.bid = {bb: i for i, bb in enumerate(all_blocks)}
        for _cb in (cb for lst in self._clones_of_group.values() for cb in lst):
            self.bid[_cb] = len(self.bid)
        self.line2block = {bb.first_line: bb for bb in all_blocks}
        self.regs: dict = {}
        self.ctr: dict = {}
        # Non-stack aliases: legacy entry phis -> params and call-result phis ->
        # caller-local result registers. Frame reads themselves now resolve from
        # the canonical live stack instead of a second versioned-local model.
        self.frame_map: dict = {}
        # SSA operand -> exact pre-IR value, including Undefined. ``frame_map``
        # remains the Register-only annotation API; this total map is what
        # value/scratch consumers use so an unresolved frame value never turns
        # into a freshly-minted clean register.
        self.ssa_values: dict = {}
        self.shuffle_src: dict = {}           # SSAVar (shuffle output) -> source operand
        # Bottom-position frame reads in a depth-poisoned region are described
        # once by SSA's canonical FrameAnalysis.  Translate that typed plan to
        # edge-correlated pre-IR phis; do not reconstruct a second, versioned
        # ``l%slot.version`` frame model here.
        pyssa = getattr(self.prog, "_pyssa", None)
        frame_analysis = getattr(pyssa, "_frame_analysis", None)
        self._height_poisoned = set(
            getattr(frame_analysis, "poisoned", ()) or ())
        frame_instructions = getattr(frame_analysis, "instructions", {}) or {}
        self._frame_reads_by_assignment: dict = {}
        self._frame_returns_by_assignment: dict = {}
        for py_block in getattr(pyssa, "blocks", ()) or ():
            for py_op in py_block.ops:
                instruction = frame_instructions.get(id(py_op))
                assignment = self.prog.assignment_for_pyop(py_op)
                if assignment is None:
                    continue
                if isinstance(instruction, SlotMerge):
                    self._frame_reads_by_assignment[assignment] = instruction
                elif isinstance(instruction, ReturnSlots):
                    self._frame_returns_by_assignment[assignment] = instruction
        self.frame_phis: dict = {}          # BasicBlock -> [position-keyed Phi]
        self._frame_phi_cache: dict = {}    # SlotMerge signature -> Register
        self._frame_phi_read_ids: dict = {} # signature -> poisoned read ids
        self._frame_phi_pending: list = []  # (PhiArgument, known values, writes)
        self._frame_refusals: set = set()   # poisoned frame_dig Assignment ids
        self._frame_return_values: dict = {}# retsub Assignment -> [pre-IR value]
        self.cur_gname = "main"
        self.cur_nret = 0                     # proto return count of the group being built
        # Inter-procedural return wiring: alias the continuation's return phi(s) to
        # a caller-local result register. In the raw CFG that phi's only predecessor
        # is the callee's retsub block, so it would resolve into the callee's
        # register space -- a different Puya subroutine, hence "undefined" here.
        self.call_results: dict = {}          # callsub_bb -> [result Register], declared order
        for cs in struct.call_sites:
            if cs.callsub_bb in self._splice_entry:
                # A spliced site has no call: the continuation's values arrive
                # on the simulated stack through the copy, and aliasing its
                # phis to `cr%` registers no InvokeSubroutine defines would
                # leave orphans.
                continue
            cont, entry = cs.continuation_bb, cs.target_entry
            if cont is None or entry is None:
                continue
            nret = self._sub_io(entry)[1]
            if nret <= 0:
                continue
            by_idx = {ph.stack_index: ph for ph in cont.phis}
            outs = []
            for j in range(nret):                # j: declared order; stack_index 1 = top
                ph = by_idx.get(nret - j)
                # A `cr` prefix, not reg()'s `v`: this pre-pass runs before the
                # per-group `_name_group`, so these must not share its counter.
                if ph is not None:
                    r = self.regs.get(ph) or self._new_reg("cr", self.type_of(ph))
                    self.regs[ph] = r
                    self.frame_map[ph] = r            # consumers resolve to the result reg
                else:
                    r = self._new_reg("cr", "?")
                outs.append(r)
            self.call_results[cs.callsub_bb] = outs
        self.subs = []
        sub_pairs = []                                # (pre_ir.Subroutine, struct.Subroutine)
        for gname, s, gb in groups:
            self.cur_gname = gname
            self.cur_is_main = s is None
            if s is None:
                params, nrets = [], 0
            else:
                nargs, nrets = self._sub_io(s.entry_bb)
                params = [pre_ir.Parameter(pre_ir.Register(f"p%{i}", 0, "?"))
                          for i in range(nargs)]
                # Legacy non-proto subs have no `frame_dig`: their args are the entry
                # block's stack-index phis. Map those to params -- entry stack_index
                # k = k-th from TOP = param[nargs-k] -- and skip building them.
                if s.entry_bb not in self._proto_entries:
                    for ph in s.entry_bb.phis:
                        if 1 <= ph.stack_index <= nargs:
                            self.frame_map[ph] = params[nargs - ph.stack_index].register
                            self._param_phis.add(ph)
            self.cur_nret = nrets
            self.cur_nargs = len(params)
            # `_control_retsub` picks its return-slot rule off this: proto subs read
            # returns off frame slots, non-proto subs leave them on the value stack.
            self.cur_is_proto = (s is not None and s.entry_bb in self._proto_entries)
            self._setup_shuffles(gb)
            self._name_group(gb)
            # Main-group entry = the block holding the first instruction, NOT "a
            # block with no predecessors": when the first block is a branch target
            # that set is empty, or holds only a dead-code block further down.
            entry = (s.entry_bb if s is not None
                     else min(gb, key=lambda b: (b.file, b.first_line)))
            self._current_group = set(gb)
            self._simulate_group(gb, entry, params)
            self._prepare_frame_returns(gb)
            self._finish_frame_phis()
            body = [self._build_block(bb) for bb in gb]
            if s is None:
                file = all_blocks[0].file.split("/")[-1] if all_blocks else "program"
                self.subs.append(pre_ir.Subroutine(id=file, parameters=[], returns=[],
                                               body=body, is_main=True))
            else:
                sub_ir = pre_ir.Subroutine(id=gname, parameters=params,
                                       returns=["?"] * nrets, body=body)
                self.subs.append(sub_ir)
                sub_pairs.append((sub_ir, s))
        # Each guarded pass records how often it FIRED. Every one of them
        # refuses silently when its guards fail -- by design, since each falls
        # back to a total, honest representation -- so a rotted guard changes
        # nothing observable and no gate goes red. These counts are what
        # `tests/test_pass_firing_ratchet.py` pins.
        stats: dict = {
            "splice_subs": len(self._spliced_subs),
            "splice_sites": len(self._splice_entry),
            "doomed_edges": len(self.doomed_edges),
            "frame_position_phis": sum(map(len, self.frame_phis.values())),
            "frame_slot_refusals": len(self._frame_refusals),
        }
        self._apply_doomed_edges()
        transforms.prune_dead_phis(self.subs)
        # Loop: a cross-group passthrough value can itself be another passthrough.
        while transforms.isolate_cross_group_phis(self.subs):
            pass
        transforms.prune_dead_phis(self.subs)
        self.name2sub = {s.id: s for s in self.subs if not s.is_main}
        type_recovery.recover_types(self, sub_pairs)
        # Sink mixed-type phis that only feed scratch stores into per-predecessor
        # stores (runs after recovery, so "mixed" is observable). HAZARD: this
        # PRESERVES the write -- scratch is gload-readable across the group, so a
        # store with no local load is NOT dead and must never be dropped.
        stats["sink_mixed_scratch"] = transforms.sink_mixed_phi_scratch_stores(self.subs)
        main = next(sub for sub in self.subs if sub.is_main)
        prog_ir = pre_ir.Program(main=main, subroutines=[s for s in self.subs if not s.is_main],
                                 pass_stats=stats)
        type_recovery.finalize_types(prog_ir)
        # A sub called with conflicting result AVM types can't have one Puya return
        # type; clone it per type (after finalize, so caller result types settled).
        stats["specialize_returns"] = transforms.specialize_polymorphic_returns(prog_ir)
        # A still-`?` phi whose arms cross the AVM divide is a dynamically-typed
        # stack cell no single typed register can carry. Faithfulness ladder:
        # tail-duplicate the join when every guard holds (each pred gets its own
        # copy — EXACT, no merge exists); else split into one phi per demanded
        # FAMILY, each use picking its own — before materialize, which stamps
        # the split's Undefined arms.
        stats["tail_dup_joins"] = transforms.tail_duplicate_mixed_joins(prog_ir)
        stats["split_mixed_phis"] = transforms.split_mixed_phis(prog_ir)
        stats["phi_arms_given_up"] = transforms.materialize_phi_consts(prog_ir)
        # Puya requires per-sub block ownership, so a block reached from more than
        # one subroutine is cloned into each consuming sub.
        stats["dup_cross_sub_blocks"] = transforms.duplicate_cross_subroutine_blocks(prog_ir)
        stats["dup_cross_sub_blocks"] += transforms.duplicate_pure_shared_sinks(prog_ir)
        # Transforms may append representation-level subroutine clones.  The
        # detector-facing views MUST be the same objects as Program exposes;
        # keeping the pre-transform list made every analysis skip specialized
        # bodies and fail to resolve their InvokeSubroutine targets.
        self.subs = [prog_ir.main, *prog_ir.subroutines]
        self.name2sub = {s.id: s for s in prog_ir.subroutines}
        self._build_register_sources(prog_ir)
        pre_ir.assert_well_formed(prog_ir)
        return prog_ir

    def _build_register_sources(self, prog_ir: pre_ir.Program) -> None:
        """Build the many-to-many SSA -> pre-IR annotation bridge.

        ``regs`` remains the established public primary map.  This companion
        view includes frame parameters/locals, aliased registers, and cloned
        registers while preserving every SSA source that maps to one IR value.
        """
        objects = {id(r): r for r in pre_ir.registers(prog_ir)}
        sources: dict[int, list] = {}
        seen: dict[int, set[int]] = {}
        for mapping in (self.regs, self.frame_map):
            for ssa_value, reg in mapping.items():
                rid = id(reg)
                if rid not in objects:
                    continue
                ids = seen.setdefault(rid, set())
                if id(ssa_value) not in ids:
                    ids.add(id(ssa_value))
                    sources.setdefault(rid, []).append(ssa_value)
        for clone_id, original in prog_ir.register_origins.items():
            if clone_id not in objects:
                continue
            # Cloning passes can compose (for example a specialized subroutine
            # can then have a shared region duplicated). Resolve to the oldest
            # surviving origin instead of relying on transform insertion order.
            seen_origins: set[int] = set()
            while (id(original) in prog_ir.register_origins
                   and id(original) not in seen_origins):
                seen_origins.add(id(original))
                original = prog_ir.register_origins[id(original)]
            for ssa_value in sources.get(id(original), ()):
                ids = seen.setdefault(clone_id, set())
                if id(ssa_value) not in ids:
                    ids.add(id(ssa_value))
                    sources.setdefault(clone_id, []).append(ssa_value)
        self.register_objects = objects
        self.register_sources = {rid: tuple(vals) for rid, vals in sources.items()}

    def _sub_io(self, entry_bb):
        return self._io_by_entry.get(entry_bb) or _proto_io(entry_bb)

    def _key(self, bb):
        return (bb.file, bb.first_line)

    def _splice_divergent_legacy(self, struct) -> None:
        """Give every call site of a divergent legacy subroutine its OWN COPY of
        the body — the faithful model: a pre-`proto` `callsub`/`retsub` is a
        jump, so per-site the call becomes `Goto(copy entry)`, the copy's
        `retsub` becomes `Goto(that site's continuation)`, and the caller's
        stack flows through VERBATIM. The divergence then joins at the
        continuation as an ordinary depth-divergent merge, which the max-window
        join represents cell-for-cell — no signature, no `Undefined` padding.

        Duplication is what makes `retsub` lowerable at all with >1 caller: the
        return target is correlated with the entry edge (the return-address
        stack), which a flat CFG cannot express — but each COPY has exactly one
        continuation, so its retsub is a direct jump. The 2026-08-04 in-place
        splice attempt lacked this and was reverted; per-site copies also
        dissolve its identity problem, because every cloned block, assignment
        and output is a FRESH object (block/var keys get an `@l<site-line>`
        file suffix — both classes hash by value, so reused keys would conflate
        clone with original in every map keyed on them).

        GUARDS — any failure refuses the whole sub (all sites or none, so the
        call interface stays consistent) and keeps the arity-model recovery:

        * every site has a callsub block and a continuation;
        * the body contains a `retsub` (so continuations keep a simulated
          predecessor) and no nested `callsub` (recursion / callsite-map
          nesting) and no `frame_dig`/`frame_bury`/`proto`;
        * every edge into the body comes from the body or a call site, and
          every non-retsub edge out stays inside it — a stray jump either way
          would dangle once the original body stops being built;
        * sites x blocks <= 512.

        Measured 2026-08-05: every affected corpus contract is the same
        TEALScript-era shape — 2 sites x 9 blocks, no nested calls, no frame
        ops — so the guards cover the entire real population."""
        refused = []
        for d in sorted(self.not_function_shaped,
                        key=lambda s_: self._key(s_.entry_bb)):
            sites = [cs for cs in struct.call_sites
                     if cs.target_entry is d.entry_bb]
            body = sorted(d.body, key=self._key)
            body_set = set(body)
            callsub_bbs = {cs.callsub_bb for cs in sites}
            ops = [a.op for bb in body for a in _ops(bb)]

            def _is_retsub(bb):
                instructions = _ops(bb)
                return bool(instructions) and instructions[-1].op == "retsub"

            ok = (bool(sites)
                  and all(cs.callsub_bb is not None
                          and cs.continuation_bb is not None for cs in sites)
                  and "retsub" in ops
                  and "callsub" not in ops
                  and not any(o in ("frame_dig", "frame_bury", "proto")
                              for o in ops)
                  and len(sites) * len(body) <= 512
                  and all(p in body_set or p in callsub_bbs
                          for bb in body for p in bb.predecessors)
                  and all(s_ in body_set
                          for bb in body if not _is_retsub(bb)
                          for s_ in bb.successors))
            if not ok:
                refused.append(d)
                continue
            for cs in sites:
                cmap = self._clone_site(body, d, cs)
                self._splice_entry[cs.callsub_bb] = cmap[d.entry_bb]
                caller = self.sub_of.get(cs.callsub_bb)
                self._clones_of_group.setdefault(caller, []).extend(
                    cmap[bb] for bb in body)
            self._spliced_subs.add(d)
        if refused:
            logger.warning(
                "%d legacy subroutine(s) are NOT function-shaped (their retsub "
                "sites leave different stack depths) and failed the per-site "
                "splice guards, so the lifted signature over-declares the "
                "shallow paths and values below the call read as Undefined: %s",
                len(refused),
                ", ".join(sorted(str(getattr(s_, "name", s_))
                                 for s_ in refused)[:5]))

    def _clone_site(self, body, d, cs):
        """Clone ``body`` for call site ``cs``; returns {original -> clone}.

        Shallow beyond the copy's own defs: cloned assignments keep their
        original `location` (provenance) and any operand defined OUTSIDE the
        body (a caller value) stays the original object. Only body-DEFINED
        outputs are re-minted, and inputs are remapped onto those, so
        `_shuffle_mapping`-style def/use correspondence survives inside the
        copy. Clone phis are dropped: stack simulation supplies every mainline
        value, and the site's single entry edge means the caller's stack flows
        in verbatim."""
        tag = f"@l{cs.line}"
        cmap = {bb: _SSABasicBlock(bb.file + tag, bb.first_line, bb.last_line)
                for bb in body}
        var_map: dict = {}
        for bb in body:                       # pass 1: mint every body def
            for a in _ops(bb):
                for o in a.outputs:
                    if isinstance(o, SSAVar) and o not in var_map:
                        nv = SSAVar(o.file + tag, o.line, o.index)
                        nv.const_value, nv.range, nv.type = \
                            o.const_value, o.range, o.type
                        var_map[o] = nv
        for bb in body:                       # pass 2: clone ops over the map
            cb = cmap[bb]
            for a in _ops(bb):
                ca = _SSAAssignment(
                    outputs=[var_map.get(o, o) for o in a.outputs],
                    op=a.op, immediates=a.immediates,
                    inputs=[var_map.get(i, i) for i in a.inputs],
                    location=a.location, ast_code=a.ast_code,
                    const=a.const, basic_block=cb, shuffled=a.shuffled)
                for o in ca.outputs:
                    if isinstance(o, SSAVar):
                        o.defined_by = ca
                        self.producer[o] = ca
                cb.assignments.append(ca)
            cb.stack_assignments = tuple(cb.assignments)
            if cb.assignments and cb.assignments[-1].op == "retsub":
                cb.successors = [cs.continuation_bb]
                self._splice_retsub[cb] = cs.continuation_bb
            else:
                cb.successors = [cmap.get(s_, s_) for s_ in bb.successors]
            self._clone_map_of[cb] = cmap
        return cmap

    def _apply_doomed_edges(self) -> None:
        """Retarget every recorded doomed ``(pred, join)`` edge to an explicit
        ``Fail`` block in the pred's pre-IR subroutine, and drop the join's phi
        arms for that edge (an arm whose edge no longer exists fails Puya's
        phi-vs-predecessors check). Runs after the groups are built — the
        terminators being rewritten are the emitted pre-IR ones — and before
        ``prune_dead_phis``. Both reject: the original by stack underflow, the
        recompiled program by ``err`` — and a rejecting transaction discards
        everything it did first (group-atomic), so rejecting earlier is
        observationally identical."""
        if not self.doomed_edges:
            return
        blk_of: dict = {}                  # pre-IR block id -> (subroutine, block)
        for sub in self.subs:
            for blk in sub.body:
                blk_of[blk.id] = (sub, blk)
        next_id = max(blk_of, default=-1) + 1
        for P, J in sorted(self.doomed_edges,
                           key=lambda e: (self.bid.get(e[0], -1),
                                          self.bid.get(e[1], -1))):
            pid, jid = self.bid.get(P), self.bid.get(J)
            if pid not in blk_of or jid not in blk_of:
                continue
            psub, pblk = blk_of[pid]
            jblk = blk_of[jid][1]
            fail = pre_ir.BasicBlock(
                id=next_id, phis=[], ops=[],
                terminator=pre_ir.Fail("stack underflow on this path"))
            next_id += 1
            psub.body.append(fail)
            blk_of[fail.id] = (psub, fail)
            pre_ir.map_succ_ids(pblk.terminator,
                                lambda b, _j=jid, _f=fail.id: _f if b == _j else b)
            for ph in jblk.phis:
                ph.args = [a for a in ph.args if a.through != pid]

    def _site_target(self, bb, blk):
        """A label-resolved block as seen from ``bb``: label targets resolve via
        ``line2block`` to ORIGINALS, so inside a spliced copy they must map to
        that copy's clone (identity everywhere else)."""
        if blk is None:
            return None
        m = self._clone_map_of.get(bb)
        return m.get(blk, blk) if m else blk

    def type_of(self, o, op=None, imm=None) -> str:
        if op in _BOOL_OPS:
            return "bool"
        if op in BIGUINT_RESULT_OPS:
            return "biguint"
        ft = _field_type(op, imm)
        if ft:
            return ft
        t = getattr(o, "type", None)
        if t is not None and getattr(t, "kind", None):
            return t.kind
        if getattr(o, "range", None) is not None:
            return "uint64"
        if op in _U64_OPS:
            return "uint64"
        if op in _BYTES_OPS:
            return "bytes"
        if op == "load":
            # The slot itself carries no type (hence `?` above); type the load by
            # what was stored, via the reaching-def in `_ssa_type`.
            rt = self._ssa_type(o)
            if rt != "?":
                return rt
        return "?"

    def _new_reg(self, prefix: str, ir_type: str) -> pre_ir.Register:
        n = self.ctr.get(prefix, 0)
        self.ctr[prefix] = n + 1
        return pre_ir.Register(f"{prefix}%{n}", 0, ir_type)

    def _is_real_phi(self, ph: Phi) -> bool:
        bb = ph.basic_block
        return bb is not None and len(bb.predecessors) > 1

    def reg(self, o) -> pre_ir.Register:
        if o in self.frame_map:
            return self.frame_map[o]
        if o not in self.regs:
            self.regs[o] = self._new_reg("v", self.type_of(o))
        return self.regs[o]

    def _range_comment(self, outs) -> str | None:
        """``// v0 = 1, len(v1) = 8`` style note for an assignment's ranged outputs,
        or ``None`` when nothing informative is annotated."""
        parts = []
        for o in outs:
            lid = self.reg(o).local_id
            rng = getattr(o, "range", None)
            if rng is not None:
                note = _range_note(lid, rng)
                if note:
                    parts.append(note)
            t = getattr(o, "type", None)
            if t is not None and getattr(t, "kind", None) == "bytes":
                for note in (_len_note(lid, t), _val_note(lid, t)):
                    if note:
                        parts.append(note)
        return ", ".join(parts) if parts else None

    def _frame_value_root(self, value, seen=None):
        """Collapse ``phi(seed, self)`` for bottom-position equality checks."""
        if not isinstance(value, pre_ir.Register):
            return value
        visited = set() if seen is None else seen
        if id(value) in visited:
            return value
        phi = self._phi_by_register.get(id(value))
        if phi is None:
            return value
        visited.add(id(value))
        args = [arg.value for arg in phi.args if arg.value is not value]
        if not args:
            return value
        roots = [self._frame_value_root(arg, set(visited)) for arg in args]
        return (roots[0] if all(root == roots[0] for root in roots[1:])
                else value)

    def _single_value(self, values):
        """Return the one semantic value in ``values``, else ``None``.

        Constants can be reconstructed independently on two paths, so value
        equality is intentional. Register names are globally injective in this
        lift, making equality just as strict as identity for registers.
        """
        if not values:
            return None
        roots = [self._frame_value_root(value) for value in values]
        first = roots[0]
        return first if all(value == first for value in roots[1:]) else None

    @staticmethod
    def _frame_signature(instruction: SlotMerge) -> tuple:
        return (
            id(instruction.home),
            instruction.position,
            tuple(id(pred) for pred in instruction.entry_predecessors),
            tuple(id(op) for op in instruction.writes),
        )

    def _frame_read_value(self, assignment, instruction: SlotMerge):
        """Translate one canonical bottom-position merge to a pre-IR value.

        Entry cells come from the already-walked predecessor exit stacks;
        frame writes come from their already-recorded operands. Distinct values
        become one phi at the region entry, correlated with the concrete entry
        or backedge that carries each value. A write-after-read backedge is
        filled after the routine walk, exactly like SSA's deferred frame arm.
        """
        home = self.prog.block_for_pyblock(instruction.home)
        if home is None:
            self._frame_refusals.add(id(assignment))
            return pre_ir.Undefined()

        signature = self._frame_signature(instruction)
        self._frame_phi_read_ids.setdefault(signature, set()).add(id(assignment))
        cached = self._frame_phi_cache.get(signature)
        if cached is not None:
            return cached

        semantic: list = []
        semantic_pending: list = []
        edge_values: dict = {}
        edge_pending: dict = {}

        for py_pred in instruction.entry_predecessors:
            pred = self.prog.block_for_pyblock(py_pred)
            stack = self.stack_exit.get(pred)
            if (pred is None or stack is None
                    or not 0 <= instruction.position < len(stack)):
                self._frame_refusals.add(id(assignment))
                continue
            value = stack[instruction.position]
            semantic.append(value)
            edge_values.setdefault(pred, []).append(value)

        write_edges = {
            id(write): predecessors
            for write, predecessors in instruction.write_predecessors
        }
        for py_write in instruction.writes:
            write = self.prog.assignment_for_pyop(py_write)
            if write is None:
                self._frame_refusals.add(id(assignment))
                continue
            args = self.stack_args.get(id(write))
            if args:
                semantic.append(args[0])
            else:
                semantic_pending.append(write)

            py_predecessors = write_edges.get(id(py_write), ())
            predecessors = [self.prog.block_for_pyblock(pred)
                            for pred in py_predecessors]
            predecessors = [pred for pred in predecessors if pred is not None]
            # Compatibility with a FrameAnalysis produced by an older caller:
            # a write in the immediate backedge block has an unambiguous edge
            # even without the new correlation field.
            if not predecessors and write.basic_block in home.predecessors:
                predecessors = [write.basic_block]
            for pred in predecessors:
                if args:
                    edge_values.setdefault(pred, []).append(args[0])
                else:
                    edge_pending.setdefault(pred, []).append(write)

        one = self._single_value(semantic)
        if one is not None and not semantic_pending:
            if isinstance(one, pre_ir.Undefined):
                self._frame_refusals.add(id(assignment))
            return one
        if not semantic and not semantic_pending:
            self._frame_refusals.add(id(assignment))
            return pre_ir.Undefined()
        if not instruction.allow_phi:
            self._frame_refusals.add(id(assignment))
            return pre_ir.Undefined()

        register = self._new_reg("tmp", "?")
        phi = pre_ir.Phi(register, [])
        self._phi_by_register[id(register)] = phi
        self._frame_phi_cache[signature] = register
        self.frame_phis.setdefault(home, []).append(phi)

        predecessors = [pred for pred in home.predecessors
                        if pred in self._current_group]
        if not predecessors:
            self._frame_refusals.add(id(assignment))
        for pred in predecessors:
            known = edge_values.get(pred, [])
            pending = edge_pending.get(pred, [])
            value = self._single_value(known)
            if pending:
                arg = pre_ir.PhiArgument(pre_ir.Undefined(), self.bid[pred])
                self._frame_phi_pending.append(
                    (signature, arg, tuple(known), tuple(pending)))
            elif value is not None:
                arg = pre_ir.PhiArgument(value, self.bid[pred])
            else:
                arg = pre_ir.PhiArgument(pre_ir.Undefined(), self.bid[pred])
                self._frame_refusals.add(id(assignment))
            phi.args.append(arg)
        return register

    def _prepare_frame_returns(self, blocks) -> None:
        """Resolve poisoned proto return slots before pre-IR blocks are built.

        ``retsub`` truncates a proto frame and returns its bottom-position
        slots. It is therefore the same operation as a group of frame_digs,
        and must use FrameAnalysis when the working stack is top-aligned.
        """
        if not self.cur_is_proto or not self.cur_nret:
            return
        for block in blocks:
            key = (block.file, block.first_line, block.last_line)
            if key not in self._height_poisoned:
                continue
            retsub = self.term_assign(block)
            if retsub is None or retsub.op != "retsub":
                continue
            instruction = self._frame_returns_by_assignment.get(retsub)
            values = []
            for index in range(self.cur_nret):
                slot = instruction.slots.get(index) if instruction else None
                if slot is None:
                    self._frame_refusals.add(id(retsub))
                    values.append(pre_ir.Undefined())
                else:
                    values.append(self._frame_read_value(retsub, slot))
            self._frame_return_values[id(retsub)] = values

    def _finish_frame_phis(self) -> None:
        """Fill loop-carried frame arms whose writes ran after their reads."""
        pending, self._frame_phi_pending = self._frame_phi_pending, []
        for signature, arg, known, writes in pending:
            values = list(known)
            missing = False
            for write in writes:
                args = self.stack_args.get(id(write))
                if args:
                    values.append(args[0])
                else:
                    missing = True
            value = self._single_value(values)
            if not missing and value is not None:
                arg.value = value
            else:
                self._frame_refusals.update(
                    self._frame_phi_read_ids.get(signature, ()))

    def _setup_shuffles(self, gb):
        # Puya is value-based, so a pure stack shuffle drops out: map each output
        # to its source operand and let consumers reference the value directly.
        # The mapping is exact (out[i] = in[m[i]]), hence value-preserving.
        for bb in gb:
            for a in _ops(bb):
                if a.op not in _STACK_SHUFFLE_OPS:
                    continue
                m = _shuffle_mapping(a)
                if m is None:
                    continue
                for i, src_idx in enumerate(m):
                    if i < len(a.outputs) and 0 <= src_idx < len(a.inputs):
                        out = a.outputs[i]
                        if isinstance(out, SSAVar):
                            self.shuffle_src[out] = a.inputs[src_idx]

    def _is_routed_shuffle(self, a) -> bool:
        if a.op not in _STACK_SHUFFLE_OPS:
            return False
        outs = [o for o in a.outputs if isinstance(o, SSAVar)]
        return bool(outs) and all(o in self.shuffle_src for o in outs)

    def _name_group(self, gb):
        # HAZARD: do NOT clear `self.ctr` per group. Generated register names must be
        # GLOBALLY UNIQUE because consumers bridge to them by (name, version), which
        # has to stay INJECTIVE; per-group reuse of tmp%0 collapses distinct values
        # onto one name. The counter feeds naming only, so this changes no behaviour.
        for bb in gb:
            if len(bb.predecessors) > 1:
                for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                    if ph not in self.regs:
                        self.regs[ph] = self._new_reg("tmp", self.type_of(ph))
            for a in _ops(bb):
                if a.op in _FRAME_OPS:
                    continue                       # frame outputs map to params/locals
                if self._is_routed_shuffle(a):
                    continue                       # const shuffle outputs route to sources
                if a.op in _TERMINATOR_OPS and a.op != "callsub":
                    continue
                if a.op in ("intcblock", "bytecblock", "proto"):
                    continue
                if (len(a.outputs) == 1 and not a.inputs
                        and getattr(a.outputs[0], "const_value", None) is not None):
                    continue
                pfx = "tmp" if a.op == "callsub" else _NAME_PREFIX.get(a.op, "tmp")
                nssa = sum(isinstance(o, SSAVar) for o in a.outputs)
                for idx, o in enumerate(a.outputs):
                    if not isinstance(o, SSAVar):
                        continue
                    # idx is the TOP-FIRST output slot; multi-result ops (get_ex /
                    # params / box / addw…) type their slots individually.
                    mt = _multi_out_type(a.op, a.immediates, idx) if nssa > 1 else None
                    if a.op in _POLY_FIRST_OPERAND_OPS and a.inputs:
                        # setbit: result type == its VALUE operand -- the deepest
                        # stack input, i.e. the LAST top-first SSA input.
                        vt = self._ssa_type(a.inputs[-1])
                        rt = vt if vt != "?" else self.type_of(o, a.op, a.immediates)
                    else:
                        rt = mt or self.type_of(o, a.op, a.immediates)
                    if o not in self.regs:
                        self.regs[o] = self._new_reg(pfx, rt)
                    elif self.regs[o].ir_type == "?" and rt != "?":
                        # Registered untyped by an earlier cross-group reference (a
                        # tail-call / shared-epilogue edge reaching value() before the
                        # defining group is named); its op is known now, so fix it.
                        self.regs[o].ir_type = rt

    def value(self, o, _seen=None):
        seen = _seen if _seen is not None else set()
        while True:
            if isinstance(o, (SSAVar, Phi)) and o in self.ssa_values:
                return self.ssa_values[o]
            if isinstance(o, (SSAVar, Phi)) and o in self.frame_map:
                break                            # param / local / callsub-return reg
            if isinstance(o, SSAVar) and o in self.shuffle_src and id(o) not in seen:
                seen.add(id(o))
                o = self.shuffle_src[o]               # route through stack shuffles
                continue
            if isinstance(o, Phi) and not self._is_real_phi(o) and id(o) not in seen:
                b = o.basic_block
                if b is not None and len(b.predecessors) == 1:
                    seen.add(id(o))
                    es = b.predecessors[0].exit_stack
                    k = o.stack_index
                    nxt = es[-k] if 0 < k <= len(es) else None
                    if nxt is not None:
                        o = nxt                  # inline trivial single-pred phi
                        continue
            break
        cv = getattr(o, "const_value", None)
        if cv is not None:
            return _const(cv)
        if o is None:
            return pre_ir.Undefined()
        if isinstance(o, Const):
            return _const(o)
        return self.reg(o)

    def term_assign(self, bb):
        last = None
        for a in _ops(bb):
            if a.op in _TERMINATOR_OPS:
                last = a
        return last

    def _asserts_false(self, bb) -> bool:
        """``bb`` asserts a compile-time zero, so it aborts unconditionally and (like
        ``err``) lifts to ``Fail``, not a ``ProgramExit`` of a maybe-non-uint64 top."""
        from ..ssa import const_int
        return any(a.op == "assert" and a.inputs and const_int(a.inputs[0]) == 0
                   for a in _ops(bb))

    def _recover_match_keys(self, bb, labels):
        """Recover a `match`'s case keys, in label order, from the source line of a
        multi-push whose operands the parser stripped (leaving a phantom push)."""
        src = _load_src(self.prog)
        if len(src) != 1:
            return None, set()
        lines = next(iter(src.values()))
        push = next((a for a in reversed(_ops(bb))
                     if a.op in ("pushbytess", "pushints")), None)
        ln = push.location.line if push is not None else 0
        if not (1 <= ln <= len(lines)):
            return None, set()
        parts = lines[ln - 1].strip().split(None, 1)
        ops_ = _tokenize_operands(parts[1]) if len(parts) == 2 else []
        if len(ops_) < len(labels):
            return None, set()
        cases, targets = [], set()
        for i, lbl in enumerate(labels):
            blk = self._site_target(bb, self.line2block.get(self.label2line.get(lbl)))
            if blk is None or blk not in self.bid:
                return None, set()
            cases.append((ops_[i], self.bid[blk]))
            targets.add(blk)
        return cases, targets

    def control(self, bb):
        t = self.term_assign(bb)
        op = t.op if t is not None else None

        if op == "callsub":
            ce = self._splice_entry.get(bb)
            if ce is not None:
                return pre_ir.Goto(self.bid[ce])   # spliced: the call IS a jump
            cs = self.callsite.get(bb)
            cont = cs.continuation_bb if cs else None
            if cont is not None and cont in self.bid:
                return pre_ir.Goto(self.bid[cont])
            # No continuation (a non-returning callee): in a sub that is a value-less
            # return, but in main there is no caller, so it must be a program exit --
            # a value-less SubroutineReturn is invalid for the main program.
            if self.cur_is_main:
                return pre_ir.ProgramExit(pre_ir.UInt64Constant(0))
            return pre_ir.SubroutineReturn([])
        if op == "retsub":
            sc = self._splice_retsub.get(bb)
            if sc is not None:                     # spliced copy: direct jump
                return pre_ir.Goto(self.bid[sc])
            return self._control_retsub(bb)
        succ = [s for s in bb.successors if s in self.bid]
        if not succ:
            if op == "err" or self._asserts_false(bb):
                return pre_ir.Fail()
            if op == "return" and t is not None:
                return pre_ir.ProgramExit(self._sel_value(t))
            # HAZARD: `return`, and a block that falls off the end with no explicit
            # terminator, both exit with the STACK TOP (the approval result), never a
            # hardcoded 0 -- that would turn an approve-if-X program into an
            # unconditional reject. Read it off the simulated stack, which is
            # already in this lift's register space.
            rsx = self.stack_exit.get(bb, [])
            v = rsx[-1] if rsx else pre_ir.UInt64Constant(0)
            return pre_ir.ProgramExit(v)
        if len(succ) == 1:
            return pre_ir.Goto(self.bid[succ[0]])
        if len(succ) == 2 and op in COND_BRANCH_OPS and t is not None:
            cond = self._sel_value(t)
            taken = self._site_target(bb, self.line2block.get(
                self.label2line.get((t.immediates or "").strip())))
            if taken in succ:
                other = succ[0] if succ[1] is taken else succ[1]
            else:
                taken, other = succ[0], succ[1]
            if op == "bnz":
                return pre_ir.ConditionalBranch(cond, self.bid[taken], self.bid[other])
            return pre_ir.ConditionalBranch(cond, self.bid[other], self.bid[taken])  # bz
        if op == "match" and t is not None:
            term = self._control_match(bb, t, succ)
            if term is not None:
                return term
        if op == "switch" and t is not None:
            term = self._control_switch(bb, t, succ)
            if term is not None:
                return term
        # `match` is KEYED, so a POSITIONAL GotoNth over CFG-successor order
        # mis-targets its arms. Reaching here means neither key recovery nor the
        # source fallback worked, so emit Undefined rather than a confident wrong
        # route.
        return pre_ir.GotoNth(pre_ir.Undefined(),
                              [self.bid[s] for s in succ[:-1]], self.bid[succ[-1]])

    def _sel_value(self, t):                  # branch/switch selector value
        if t is not None and self.stack_args.get(id(t)):
            return self.stack_args[id(t)][0]
        return self.value(t.inputs[0]) if (t and t.inputs) else pre_ir.Undefined()

    def _control_retsub(self, bb):
        """Build the ``SubroutineReturn`` for a ``retsub`` block.

        HAZARD: a retsub's raw-CFG successors are the CALLERS' continuations
        (interprocedural return edges), not internal flow — model it as a value
        return, never a goto into them (with >1 caller that has no selector and
        renders as `goto_nth undefined`). The return VALUES differ by convention:
        a `proto A R` sub returns frame slots A..A+R-1, a legacy sub the TOP R of
        the stack; applying the proto rule to a short non-proto stack reads past
        the end, yields Undefined, and DCEs the whole body."""
        rsx = self.stack_exit.get(bb, [])              # canonical simulated stack
        if not self.cur_nret:
            return pre_ir.SubroutineReturn([])
        np = self.cur_nargs
        if self.cur_is_proto:
            term = self.term_assign(bb)
            planned = (self._frame_return_values.get(id(term))
                       if term is not None else None)
            if planned is not None:
                return pre_ir.SubroutineReturn(planned)
            # Frame slots A..A+R-1: simulation seeds the stack with params, then
            # frame_bury deep-writes each slot at rsx[A+j]. NOT the top R -- a sub
            # keeping working locals past its returns has something else on top.
            rets = [rsx[np + j] if np + j < len(rsx) else pre_ir.Undefined()
                    for j in range(self.cur_nret)]
        else:
            # Legacy sub: no frame slots, so the R returns are the TOP R.
            base = len(rsx) - self.cur_nret
            rets = [rsx[base + j] if 0 <= base + j < len(rsx) else pre_ir.Undefined()
                    for j in range(self.cur_nret)]
        return pre_ir.SubroutineReturn(rets)

    def _control_match(self, bb, t, succ):
        """Build a keyed ``Switch`` for a ``match`` block, or ``None`` to fall through
        to the generic positional GotoNth.

        HAZARD: `match t0..t_{n-1}` takes the matched value on top and the n keys
        below; AVM pairs label[i] with the i-th key counting from the DEEPEST
        (first-pushed) one. SSA inputs are TOP-FIRST, so keys arrive deepest-LAST
        and the mapping is uniformly label[i] -> ins[n - i] (matched value = ins[0]),
        whether the keys come from one multi-push op or separate pushes. Getting
        this wrong silently SWAPS sibling arms — an OnCompletion / ABI selector
        routed to the wrong body."""
        labels = (t.immediates or "").split()
        n = len(labels)
        ins = (self.stack_args.get(id(t)) if id(t) in self.stack_args
               else [self.value(x) for x in t.inputs])
        order = list(range(n))[::-1]           # label[i] -> ins[n - i]
        cases, targets = [], set()
        for i, lbl in enumerate(labels):
            blk = self._site_target(bb, self.line2block.get(self.label2line.get(lbl)))
            ki = 1 + order[i]
            ci = ins[ki] if 0 <= ki < len(ins) else None
            if isinstance(ci, pre_ir.BytesConstant):
                key = ci.value                       # bytes-keyed match
            elif isinstance(ci, pre_ir.UInt64Constant):
                key = str(ci.value)                  # uint64-keyed match
            else:
                key = None
            if blk is None or blk not in self.bid or key is None:
                cases = None
                break
            cases.append((key, self.bid[blk]))
            targets.add(blk)
        if cases is None:                 # parser dropped the case keys
            cases, targets = self._recover_match_keys(bb, labels)  # (from source)
        default = next((s for s in succ if s not in targets), None)
        if cases and default is not None:
            val = ins[0] if ins else pre_ir.Undefined()
            return pre_ir.Switch(val, cases, self.bid[default])
        return None

    def _control_switch(self, bb, t, succ):
        """Build the POSITIONAL ``GotoNth`` for a ``switch`` block, or ``None`` to
        fall through to the generic GotoNth.

        HAZARD: `switch L0..L_{n-1}` is POSITIONAL (popped index i jumps to L_i) and
        DUPLICATE labels are significant, so arms must be built by position — from
        the distinct successor SET, as the generic GotoNth does, the index->target
        map scrambles and every arm can mis-route. Out-of-range falls through to the
        next instruction, which may COINCIDE with a labeled target, so resolve the
        default by source line, not by set-difference like `match`."""
        labels = (t.immediates or "").split()
        arms, ok = [], True
        for lbl in labels:
            blk = self._site_target(bb, self.line2block.get(self.label2line.get(lbl)))
            if blk is None or blk not in self.bid:
                ok = False
                break
            arms.append(self.bid[blk])
        sl = t.location.line if getattr(t, "location", None) else None
        after = [fl for fl in self.line2block if sl is not None and fl > sl]
        ft = self._site_target(bb, self.line2block[min(after)] if after else None)
        if ok and ft is not None and ft in self.bid:
            return pre_ir.GotoNth(self._sel_value(t), arms, self.bid[ft])
        if ok and succ:                       # robustness: best-effort default
            labeled = {self._site_target(bb, self.line2block.get(self.label2line.get(lbl)))
                       for lbl in labels}
            dft = next((s for s in succ if s not in labeled), succ[-1])
            return pre_ir.GotoNth(self._sel_value(t), arms, self.bid[dft])
        return None

    def _simulate_group(self, body_list, entry_bb, params):
        """Adapt the canonical stack walk to PRE-IR values for one group."""
        body = set(body_list)

        def isucc(b):
            # retsub/return/err LEAVE the sub: their raw successors are the callers'
            # continuations, not internal flow. A callsub flows to its own
            # continuation, not into the callee. SPLICED sites invert both rules:
            # the callsub jumps INTO its own copy of the callee, and the copy's
            # retsub jumps to this site's continuation — checked FIRST, before
            # the terminator-op rules that would misread them.
            ce = self._splice_entry.get(b)
            if ce is not None:
                return [ce] if ce in body else []
            sc = self._splice_retsub.get(b)
            if sc is not None:
                return [sc] if sc in body else []
            instructions = _ops(b)
            if instructions and instructions[-1].op in ("retsub", "return", "err"):
                return []
            cs = self.callsite.get(b)
            if cs is not None and cs.continuation_bb in body:
                return [cs.continuation_bb]
            return [s for s in b.successors if s in body]

        def merge_value(block, _top_slot, _bottom_index, incoming, _is_loop):
            reg = self._new_reg("tmp", "?")
            args = [
                pre_ir.PhiArgument(
                    value if present else pre_ir.Undefined(), self.bid[pred])
                for pred, present, value in incoming
            ]
            phi = pre_ir.Phi(reg, args)
            self._phi_by_register[id(reg)] = phi
            self.stack_phis.setdefault(block, []).append(phi)
            return reg, phi

        def extend_backedge(phi, pred, present, value):
            phi.args.append(pre_ir.PhiArgument(
                value if present else pre_ir.Undefined(), self.bid[pred]))

        def before_merge(block, preds, depth, is_loop):
            if not is_loop:
                self._mark_doomed_merge(block, preds, depth)

        def execute_block(block, stack, _npred):
            for assignment in _ops(block):
                self._simulate_op(assignment, block, stack, params)

        stack_engine.walk_routine(
            body_list,
            entry_bb,
            successors=isucc,
            initial_stack=[param.register for param in params],
            # Preserve the old totality policy for disconnected lift blocks:
            # they lower against symbolic params instead of crashing.
            orphan_stack=lambda _block: [param.register for param in params],
            exit_stacks=self.stack_exit,
            execute_block=execute_block,
            merge_value=merge_value,
            extend_backedge=extend_backedge,
            before_merge=before_merge,
        )

    def _stack_value(self, o):                # SSA operand -> pre-IR value
        cv = getattr(o, "const_value", None)
        if cv is not None:
            return _const(cv)
        if isinstance(o, Const):
            return _const(o)
        if isinstance(o, SSAVar):
            return self.reg(o)
        return self.value(o)

    def _block_doom_profile(self, b):
        """``(dips, net)`` for ``b``'s straight line, or None to refuse: each
        dip is the level RELATIVE TO BLOCK ENTRY right after an op's pops —
        the underflow-relevant low point — and ``net`` the level after the
        last op, which offsets the NEXT block's dips when a doom walk follows
        an unconditional chain. Arity accounting mirrors ``_simulate_op``
        exactly — canonical shuffle arities (a ``cover n`` transiently needs
        n+1 cells), const pushes, terminators pushing nothing. Frame ops,
        ``callsub`` and ``retsub`` refuse: their depth behaviour is
        contextual, and a wrong profile here turns a LIVE path into a reject.

        No purity tracking: a transaction that underflows DISCARDS everything
        it did (state writes, inner txns, logs — group-atomic), so an
        execution that will underflow in this straight line is
        observationally a reject from its first instruction. Ops before the
        crossing can only reject SOONER (a failing ``assert``, a pure panic)
        — the same outcome."""
        if b in self._doom_profile:
            return self._doom_profile[b]
        run, dips, out = 0, [], None
        for a in _ops(b):
            if a.op in _FRAME_OPS or a.op in ("callsub", "retsub"):
                break
            if a.op in ("intcblock", "bytecblock", "proto"):
                continue
            if a.op in _STACK_SHUFFLE_OPS:
                n_in, m = _canon_shuffle(a.op, a.immediates)
                if m is None:
                    m, n_in = _shuffle_mapping(a), len(a.inputs)
                if m is None:
                    break
                run -= n_in
                dips.append(run)
                run += n_in
                continue
            if (not a.inputs and a.outputs and all(
                    getattr(o, "const_value", None) is not None for o in a.outputs)):
                run += len(a.outputs)
                continue
            ni, _ = op_arity(a.op, a.immediates)
            run -= ni
            dips.append(run)
            if a.op not in _TERMINATOR_OPS:
                run += sum(1 for o in a.outputs if isinstance(o, SSAVar))
        else:
            out = (dips, run)
        self._doom_profile[b] = out
        return out

    def _mark_doomed_merge(self, b, preds, depth):
        """Record shallow incoming edges that inevitably underflow after ``b``.

        Stack width and top alignment are owned by :func:`stacksim.walk_routine`;
        this is the lift-only behavioural repair layered on that shared join.
        """
        # DEAD-ARM FAITHFULNESS: an execution entering via a pred SHALLOWER
        # than the merge window dies the moment the ORIGINAL program consumes
        # below what that pred actually holds — an AVM stack underflow, a
        # deterministic reject that (group-atomically) discards everything the
        # transaction did first. When the dip below the pred's depth happens
        # in THIS very block (straight line, so inevitable), the recompiled
        # program must reject there too — otherwise the padded unknown lowers
        # to a zero and the dead arm APPROVES where the original panics
        # (measured live: 5/10 dryrun inputs diverged on a two-arm join whose
        # shallow arm popped past its depth). Record the edge;
        # `_apply_doomed_edges` retargets it to a `Fail` in the pre-IR. NOT a
        # join-rule change: window, alignment and arms are untouched, so the
        # two stack simulations still agree.
        # The dip may sit past the join block itself: walk the UNCONDITIONAL
        # chain (each step a single distinct raw-CFG successor), offsetting
        # each block's dips by the accumulated net effect — a dip below the
        # arm's depth anywhere along it is just as inevitable as one in the
        # join block. A branch stops the walk: past it the dip is conditional,
        # and killing the edge would reject the arm's LIVE paths too.
        for p in preds:
            d = len(self.stack_exit[p])
            if d >= depth:
                continue
            off, cur, seen_chain = 0, b, set()
            for _ in range(64):
                prof = self._block_doom_profile(cur)
                if prof is None:
                    break
                dips, net = prof
                if any(off + dip < -d for dip in dips):
                    self.doomed_edges.add((p, b))
                    break
                seen_chain.add(cur)
                succ = set(cur.successors)
                if len(succ) != 1:
                    break
                cur = next(iter(succ))
                if cur in seen_chain:
                    break
                off += net

    def _simulate_op(self, a, b, stack, params):
        """Execute one SSA assignment against the PRE-IR value stack."""
        # Frame ops address a bottom-anchored position. At an exact-height block
        # the canonical live stack is that frame state. At an unavailable anchor
        # a resolved SSA input is safe to copy (the frame-slot analysis supplied
        # it); otherwise use an explicit Undefined, never a neighbouring cell.
        if a.op == "frame_dig":
            output = a.outputs[0] if a.outputs else None
            slot = _imm0(a)
            pos = len(params) + slot if slot is not None else -1
            key = (b.file, b.first_line, b.last_line)
            if key in self._height_poisoned:
                instruction = self._frame_reads_by_assignment.get(a)
                if instruction is None:
                    self._frame_refusals.add(id(a))
                    source = pre_ir.Undefined()
                else:
                    source = self._frame_read_value(a, instruction)
            elif 0 <= pos < len(stack):
                source = stack[pos]
            else:
                source = pre_ir.Undefined()
            stack.append(source)
            # Provenance-only alias: this does not drive simulation. It lets
            # SSA->IR annotation consumers associate a frame_dig output with
            # the canonical register the shared stack state selected.
            if output is not None and isinstance(source, pre_ir.Register):
                self.frame_map[output] = source
                if a.inputs and isinstance(a.inputs[0], Phi):
                    # SSA and pre-IR position phis are the same semantic merge;
                    # make that boundary agreement visible to annotation users.
                    self.frame_map[a.inputs[0]] = source
            if output is not None:
                self.ssa_values[output] = source
                if a.inputs and isinstance(a.inputs[0], Phi):
                    self.ssa_values[a.inputs[0]] = source
            return
        if a.op == "frame_bury":
            if stack:
                v = stack.pop()
                self.stack_args[id(a)] = [v]
                slot = _imm0(a)
                pos = len(params) + slot if slot is not None else -1
                key = (b.file, b.first_line, b.last_line)
                # A poisoned block has no usable bottom coordinate in this
                # top-aligned list. FrameAnalysis routes later reads straight
                # to this recorded operand, so withdraw the physical cell
                # rather than writing a neighbouring position on shallow arms.
                stored = (pre_ir.Undefined()
                          if key in self._height_poisoned else v)
                if 0 <= pos < len(stack):
                    stack[pos] = stored
                elif pos == len(stack):
                    stack.append(stored)       # target is the vacated top cell
            return
        if a.op in _STACK_SHUFFLE_OPS:
            # Use the op's CANONICAL arity, not a.inputs: the SSA's fat-band sim can
            # under-count a shuffle's inputs on a shallow model stack (dup2 with 1
            # input), making _shuffle_mapping bail and simulation drop the op --
            # which starves a downstream callsub's args.
            n_in, m = _canon_shuffle(a.op, a.immediates)
            if m is None:                       # frame_* / unrecognised
                m, n_in = _shuffle_mapping(a), len(a.inputs)
            if m is None or len(stack) < n_in:
                return
            ins = [stack.pop() for _ in range(n_in)]            # top-first
            for v in reversed([ins[k] for k in m]):
                stack.append(v)
            return
        if a.op == "callsub":
            if b in self._splice_entry:
                # Spliced divergent-legacy site: the call is a JUMP — no args
                # popped, no results pushed; the stack flows into the copy.
                self.stack_args[id(a)] = []
                return
            cs = self.callsite.get(b)
            nargs = self._sub_io(cs.target_entry)[0] if (cs and cs.target_entry) else 0
            nargs = min(nargs, len(stack))
            self.stack_args[id(a)] = stack[len(stack) - nargs:]      # param order
            if nargs:
                del stack[len(stack) - nargs:]
            if (cs is not None and cs.target_entry is not None
                    and getattr(cs.target_entry, "_key", None) is not None
                    and cs.target_entry._key() in self._clobber_callees):
                # This callee reaches under its own frame with a plain stack op
                # (`cover`/`uncover`/a dip), which the AVM permits — it bounds
                # only `frame_dig`/`frame_bury` — so it may have permuted or
                # eaten the caller's OWN values. This stack adapter otherwise
                # assumes everything below the args survives a call, and on a
                # live-AVM differential that assumption emitted the STALE
                # pre-call value and INVERTED the program's outcome.
                #
                # `ssa.callee_effects` computes what the callee really leaves
                # there (every AVM stack op's effect is static). MOST of what
                # it names needs no ABI at all: a moved caller cell and a
                # passed argument are values THIS CALLER ALREADY HOLDS, and a
                # callee-produced constant re-materialises anywhere. Only a
                # callee-produced RUNTIME value has nowhere to travel — no
                # `(nargs, nret)` can carry it, so that cell alone stays
                # Undefined (expressing it needs per-call-site inlining).
                self._apply_clobber_effect(cs, a, stack)
            for r in self.call_results.get(b, []):
                stack.append(r)
            return
        if (not a.inputs and a.outputs and all(           # const push(es)
                getattr(o, "const_value", None) is not None for o in a.outputs)):
            for o in reversed(a.outputs):                 # pushints/pushbytess
                stack.append(_const(o.const_value))
            return
        if a.op in ("intcblock", "bytecblock", "proto"):
            return
        ni, _ = op_arity(a.op, a.immediates)
        ni = min(ni, len(stack))
        self.stack_args[id(a)] = [stack.pop() for _ in range(ni)]    # top-first
        if a.op not in _TERMINATOR_OPS:
            for o in reversed([o for o in a.outputs if isinstance(o, SSAVar)]):
                stack.append(self._stack_value(o))

    def _apply_clobber_effect(self, cs, a, stack) -> None:
        """Rewrite the caller residual through the callee's below-band effect
        summary, falling back to ``Undefined`` per CELL (never wholesale).

        ``stack`` is the simulated stack with the call's arguments already
        popped, so depth ``d`` is ``stack[-d]`` — the same coordinates
        :mod:`ssa.callee_effects` speaks. Cells the summary does not mention
        are untouched by the callee and keep their pre-call value."""
        from ..ssa.callee_effects import _Below, _CalleeParam

        py = getattr(self.prog, "_pyssa", None)
        entry = cs.target_entry
        py_entry = self.prog.pyblock_for_block(entry)
        summ = (getattr(py, "_effect_summaries", {}) or {}).get(py_entry)
        if summ is None or summ.reach > len(stack):
            for _i in range(len(stack)):
                stack[_i] = pre_ir.Undefined()
            return
        args = self.stack_args.get(id(a), [])         # param order (0 = deepest)
        base = list(stack)

        def one(cell):
            """The lift-space value for one summary cell, or None if it has
            no public SSA identity to carry across the boundary."""
            if isinstance(cell, _Below):
                return base[-cell.j] if 0 < cell.j <= len(base) else None
            if isinstance(cell, _CalleeParam):
                return (args[cell.p] if 0 <= cell.p < len(args) else None)
            v = self.prog.var_for_pyvar(cell)
            cv = getattr(v, "const_value", None) if v is not None else None
            # A callee-produced RUNTIME value has no ABI to travel on; only a
            # constant re-materialises in the caller. Retain the explicit TOP
            # against its exact public SSA identity: scratch reaching-defs name
            # the stored SSA leaf later, and resolving it as a fresh Register
            # would silently turn this unknown into clean.
            if cv is not None:
                return _const(cv)
            if v is None:
                return None
            unknown = pre_ir.Undefined(self._ssa_type(v))
            self.ssa_values[v] = unknown
            return unknown

        for d in range(1, summ.reach + 1):
            vals = []
            for _rb, m in summ.paths:
                c = m.get(d)
                vals.append(base[-d] if c is None else one(c))
            if not vals or any(v is None for v in vals) or \
                    not all(v == vals[0] for v in vals):
                # Unknowable, or genuinely path-dependent with no phi home at
                # a call boundary — this CELL alone is undefined.
                stack[-d] = pre_ir.Undefined()
            else:
                stack[-d] = vals[0]

    def _build_block(self, bb):
        phis = self._block_phis(bb)
        ops = []
        for a in _ops(bb):
            self._block_emit_op(a, bb, ops)
        return pre_ir.BasicBlock(id=self.bid[bb], phis=phis, ops=ops,
                             terminator=self.control(bb), comment=f"L{bb.first_line}")

    def _block_phis(self, bb):
        """Entry phis from stack slots plus bottom-position frame slots."""
        return [*self.frame_phis.get(bb, ()), *self.stack_phis.get(bb, ())]

    def _block_emit_op(self, a, bb, ops):
        """Lower one assignment; value-only frame/shuffle ops emit nothing."""
        if a.op == "frame_dig":
            return
        if a.op == "frame_bury":
            return
        if a.op in _STACK_SHUFFLE_OPS:
            return                              # simulation reorders the stack itself
        if self._is_routed_shuffle(a):
            return                              # const shuffle routed to source
        if a.op == "callsub":
            if bb in self._splice_entry:
                return                        # spliced: control() emits the jump
            cs = self.callsite.get(bb)
            target = (cs.target_name if cs and cs.target_name
                      else (a.immediates or "?"))
            # The args are the callsub's OWN operands, TOP-FIRST, so PARAM order
            # (0 = deepest) reverses them. They used to be read off the caller's
            # `exit_stack` top, which held them only while a callsub was modelled
            # as consuming nothing — that slot is now the call's RESULT.
            call_args = self.stack_args.get(id(a), [])
            invoke = pre_ir.InvokeSubroutine(target, call_args, origin=a)
            outs = self.call_results.get(bb)      # caller-local return registers
            if outs:
                ops.append(pre_ir.Assignment(list(outs), invoke))
            else:
                ops.append(pre_ir.IntrinsicOp(invoke))
            return
        if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock",
                                               "proto"):
            return
        if (not a.inputs and a.outputs and all(       # const push(es): inlined
                getattr(o, "const_value", None) is not None for o in a.outputs)):
            return
        args = self.stack_args[id(a)] if id(a) in self.stack_args \
            else [self.value(i) for i in a.inputs]
        intr = pre_ir.Intrinsic(a.op, a.immediates.split() if a.immediates else [],
                            args, line=a.location.line, origin=a)
        shown = [o for o in a.outputs if isinstance(o, SSAVar)]
        if a.op == "assert" and not shown:
            ops.append(pre_ir.Assert(args[0] if args else pre_ir.Undefined()))
        elif shown:
            ops.append(pre_ir.Assignment([self.reg(o) for o in shown], intr,
                                     comment=self._range_comment(shown)))
        else:
            ops.append(pre_ir.IntrinsicOp(intr))

    def _ssa_type(self, o, depth=0):
        """Type an SSA operand by its producing op, tracing scratch loads through the
        reaching-def and frame reads through to their param/local register."""
        if isinstance(o, Const):
            return o.kind
        if not isinstance(o, SSAVar) or depth > 6:
            return "?"
        if o in self.ssa_values:
            return self.ssa_values[o].ir_type
        if o in self.frame_map:                       # a param/local read
            return self.frame_map[o].ir_type
        a = self.producer.get(o)
        op = a.op if a else None
        imm = a.immediates if a else None
        if op in _BOOL_OPS:
            return "bool"
        if op in BIGUINT_RESULT_OPS:
            return "biguint"
        ft = _field_type(op, imm)
        if ft:
            return ft
        t = getattr(o, "type", None)
        if t is not None and getattr(t, "kind", None):
            return t.kind
        if getattr(o, "range", None) is not None:
            return "uint64"
        if op in _POLY_FIRST_OPERAND_OPS and a is not None:   # setbit: result == value operand
            ins = getattr(a, "inputs", None)
            if ins:                               # SSA inputs are top-first; value is deepest
                vt = self._ssa_type(ins[-1], depth + 1)
                if vt != "?":
                    return vt
            return "?"
        if op in _U64_OPS:
            return "uint64"
        if op in _BYTES_OPS:
            return "bytes"
        if o in self.load_stores:
            ts = {self._ssa_type(s, depth + 1) for s in self.load_stores[o] if s is not None}
            ts.discard("?")
            if len(ts) == 1:
                return next(iter(ts))
        return "?"


def _proto_io(entry_bb):
    for a in _ops(entry_bb):
        if a.op == "proto":
            toks = (a.immediates or "").split()
            if len(toks) >= 2:
                try:
                    return int(toks[0]), int(toks[1])
                except ValueError:
                    break
    return 0, 0
