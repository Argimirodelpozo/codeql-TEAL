"""Lift an :class:`~tealql.tealtools.ssa.SSAProgram` into the Puya-shaped IR: TEAL's
stack machine (frame slots, scratch, shuffles) becomes value-based, typed IR,
partitioned into ``main`` plus one subroutine per ``callsub`` target.

HAZARD: analysis passes do NOT compose with the lift — running ``run_all_passes``
before :func:`lift` yields INVALID IR. Only annotations ride up; mutations break
the builder.
"""
from __future__ import annotations

import logging

from ..ssa.block_args import to_block_args
from ..avm import _STACK_SHUFFLE_OPS, _TERMINATOR_OPS, op_arity
from ..passes.frame_resolution import resolve_sub
from ..ssa import (
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _canon_shuffle,
    _shuffle_mapping,
)
from ..structure import analyze_structure
from . import pre_ir, transforms, type_recovery
from ..avm import (
    _BOOL_OPS,
    _BYTES_OPS,
    _COND_BRANCH,
    _NAME_PREFIX,
    _POLY_FIRST_OPERAND_OPS,
    _U64_OPS,
    _field_type,
    _imm0,
    _multi_out_type,
)
from .teal_const import _load_src
from ..ast.literals import tokenize_operands as _tokenize_operands

logger = logging.getLogger("tealql.tealtools.lift")

_FRAME_OPS = frozenset({"frame_dig", "frame_bury"})


def _infer_arities(struct, callsite, *, divergent: "set | None" = None) -> dict:
    """``Subroutine -> (nargs, nret)``: read off ``proto``, or — for legacy subs that
    pass args / returns on the stack — inferred by a cross-procedural depth fixpoint.

    ``divergent`` (out-param) collects the legacy subs that are NOT FUNCTION-SHAPED:
    their ``retsub`` sites leave different stack depths, so the callee's net effect
    depends on the path it took. A pre-``proto`` ``retsub`` does not truncate — it
    is a jump — so such a sub is perfectly legal TEAL and simply is not a function:
    NO single ``(nargs, nret)`` describes it, and this fixpoint's ``max`` over
    return sites necessarily over-declares the shallow paths, which the re-simulator
    then pads with ``Undefined`` (an explicit unknown — imprecise, never a wrong
    value; the caller's own pre-call value is what physically sits there).

    Making those calls faithful means INLINING the callee per call site, which the
    IR can express (its block ids are synthetic, unlike the SSA layer's
    source-position identities) but this lift does not yet do. Until it does, the
    set is surfaced so a consumer can tell "not function-shaped, values below the
    call are unknown" from "this value happens to be unknown"."""
    by_name = {s.name: s for s in struct.subroutines}
    proto = {s: _proto_io(s.entry_bb) if any(a.op == "proto" for a in s.entry_bb.assignments)
             else None for s in struct.subroutines}
    arity = {s: (p if p is not None else (0, 0)) for s, p in proto.items()}

    def block_io(b, depth_in):
        d = mn = depth_in
        for a in b.assignments:
            if a.op == "retsub":
                break
            if a.op == "callsub":
                cs = callsite.get(b)
                ce = by_name.get(cs.target_name) if cs else None
                pop, push = arity.get(ce, (0, 0)) if ce else (0, 0)
            else:
                pop, push = op_arity(a.op, a.immediates)
            d -= pop
            mn = min(mn, d)
            d += push
        return d, mn

    def internal_succ(b, body):
        cs = callsite.get(b)
        if cs is not None and cs.continuation_bb is not None:
            return [cs.continuation_bb] if cs.continuation_bb in body else []
        return [s for s in b.successors if s in body]

    for _ in range(len(struct.subroutines) + 4):
        changed = False
        for s in struct.subroutines:
            if proto[s] is not None:
                continue
            depth = {s.entry_bb: 0}
            order = [s.entry_bb]
            floor = 0
            ret_ds: list[int] = []
            i = 0
            while i < len(order):
                b = order[i]
                i += 1
                d_out, mn = block_io(b, depth[b])
                floor = min(floor, mn)
                if b.assignments and b.assignments[-1].op == "retsub":
                    ret_ds.append(d_out)
                for su in internal_succ(b, s.body):
                    if su not in depth:
                        depth[su] = d_out
                        order.append(su)
            # MAX over ALL retsub sites, not the first reached: a sub whose paths
            # diverge would otherwise silently truncate a deeper path's returns.
            ret_d = max(ret_ds) if ret_ds else None
            # HAZARD: reflect the CONVERGED iteration, so discard as well as add.
            # Early iterations assume (0, 0) for every legacy callee, which makes
            # a path THROUGH one look shallower than its siblings — accumulating
            # the mark would report a sub that is perfectly function-shaped once
            # its callee's arity is known.
            if divergent is not None:
                if len(set(ret_ds)) > 1:
                    divergent.add(s)
                else:
                    divergent.discard(s)
            na, nr = -floor, (ret_d - floor if ret_d is not None else 0)
            if arity[s] != (na, nr):
                arity[s] = (na, nr)
                changed = True
        if not changed:
            break
    return arity


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
                   for a in b.assignments)]
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
                if phi.kind != "DirectPhi":
                    continue
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
        self.form = to_block_args(self.prog)
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
        if self.not_function_shaped:
            # Legal TEAL that is not a function: a pre-`proto` `retsub` is a jump,
            # so a sub whose return sites leave different depths has no single
            # signature. The inferred one over-declares its shallow paths and the
            # re-simulator pads them with `Undefined` — an explicit unknown, but
            # the caller's own value is what physically sits there, so say so
            # rather than let a silent `Undefined` read as an ordinary gap.
            logger.warning(
                "%d legacy subroutine(s) are NOT function-shaped (their retsub "
                "sites leave different stack depths), so the lifted signature "
                "over-declares the shallow paths and values below the call read "
                "as Undefined: %s. Faithful lifting of these needs per-call-site "
                "inlining.",
                len(self.not_function_shaped),
                ", ".join(sorted(str(getattr(s_, "name", s_))
                                 for s_ in self.not_function_shaped)[:5]))
        self._io_by_entry = {s.entry_bb: a for s, a in _arity.items()}
        self._proto_entries = {s.entry_bb for s in struct.subroutines
                               if any(a.op == "proto" for a in s.entry_bb.assignments)}
        # `resim_*`: every group's value stack re-simulated with correct callsub
        # arities (`_resim`), replacing the fat SSA wiring in `_build_block`. PySSA
        # threads the whole-program stack through subs, caps it at STACK_MAX and
        # loses cross-call survivors -- which surface as used-but-never-defined
        # operands Puya's destructure_ssa rejects. HAZARD: all-or-nothing --
        # re-simulating only some subs mismatches the shared call interface and
        # corrupts the others.
        self.resim_args: dict = {}                # id(assignment) -> [pre-IR operand]
        self.resim_phis: dict = {}                # PyBlock -> [pre_ir.Phi]
        self.resim_exit: dict = {}                # PyBlock -> re-simulated exit stack
        self.resim_blocks: set = set()            # blocks whose ops use re-simulated args
        self._param_phis: set = set()             # non-proto entry arg phis -> params (skip)
        # Producer map + scratch reaching-def (per `load N`, the SSAVars its
        # influencing `store N`s wrote) -- call args are passed via scratch here,
        # not as callsub operands, so typing them needs the reaching-def.
        self.producer = {o: a for a in self.prog.assignments
                         for o in a.outputs if isinstance(o, SSAVar)}
        self.load_stores: dict = {}
        self.prog._ensure_scratch_influence()
        g = getattr(self.prog, "_graph", None)
        if g is not None:
            for n in g.nodes:
                stores = g.nodes[n].get("scratch_stores")
                if not stores:
                    continue
                lv = self.prog.var(n.location.file, n.location.start_line, 1)
                if lv is not None:
                    self.load_stores[lv] = [self.prog.var(*k) for k in stores]
        all_blocks = sorted(self.prog.blocks.values(), key=self._key)
        main_blocks = [bb for bb in all_blocks if bb not in self.sub_of]
        groups = [("main", None, main_blocks)]
        for s in sorted(struct.subroutines, key=lambda s: self._key(s.entry_bb)):
            groups.append((s.name or f"sub@L{s.entry_bb.first_line}", s,
                           sorted(s.body, key=self._key)))
        # Global block ids, though Puya restarts block@0 per subroutine: the
        # partition leaves cross-routine branch edges (tail-calls / shared
        # epilogues), which a per-subroutine-local id would silently mis-target.
        self.bid = {bb: i for i, bb in enumerate(all_blocks)}
        self.line2block = {bb.first_line: bb for bb in all_blocks}
        self.regs: dict = {}
        self.ctr: dict = {}
        self.frame_map: dict = {}              # SSAVar (frame_dig out[0]) -> Register
        self.local_regs: dict = {}            # (gname, slot) -> Register (k<0 bury fallback)
        self._fr_regs: dict = {}              # (gname, slot, version) -> local Register
        self.bury_target: dict = {}           # id(frame_bury assignment) -> versioned Register
        self.final_locals: dict = {}          # gname -> {slot: final versioned Register}
        self.shuffle_src: dict = {}           # SSAVar (shuffle output) -> source operand
        # The frame reads below resolve off the LIVE re-sim stack, not frame_map;
        # only param / negative reads take the plain frame_map path (see
        # `_resim_exec_op`).
        self.frame_passthrough: set = set()   # frame_dig out0 of k>=0 pushed locals
        self.pushed_slot: dict = {}           # pushed frame_dig out0 -> slot k
        self.frame_local_slot: dict = {}      # frame_bury-d local's frame_dig out0 -> slot k
        self.cur_gname = "main"
        self.cur_nret = 0                     # proto return count of the group being built
        # Inter-procedural return wiring: alias the continuation's return phi(s) to
        # a caller-local result register. In the raw CFG that phi's only predecessor
        # is the callee's retsub block, so it would resolve into the callee's
        # register space -- a different Puya subroutine, hence "undefined" here.
        self.call_results: dict = {}          # callsub_bb -> [result Register], declared order
        for cs in struct.call_sites:
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
            self._setup_frame(gb, params)
            self._setup_shuffles(gb)
            self._name_group(gb)
            # Main-group entry = the block holding the first instruction, NOT "a
            # block with no predecessors": when the first block is a branch target
            # that set is empty, or holds only a dead-code block further down.
            entry = (s.entry_bb if s is not None
                     else min(gb, key=lambda b: (b.file, b.first_line)))
            self._resim(gb, entry, params)
            self.resim_blocks.update(gb)
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
        transforms.sink_mixed_phi_scratch_stores(self.subs)
        main = next(sub for sub in self.subs if sub.is_main)
        prog_ir = pre_ir.Program(main=main, subroutines=[s for s in self.subs if not s.is_main])
        type_recovery.finalize_types(prog_ir)
        # A sub called with conflicting result AVM types can't have one Puya return
        # type; clone it per type (after finalize, so caller result types settled).
        transforms.specialize_polymorphic_returns(prog_ir)
        transforms.materialize_phi_consts(prog_ir)
        # Puya requires per-sub block ownership, so a block reached from more than
        # one subroutine is cloned into each consuming sub.
        transforms.duplicate_cross_subroutine_blocks(prog_ir)
        return prog_ir

    def _sub_io(self, entry_bb):
        return self._io_by_entry.get(entry_bb) or _proto_io(entry_bb)

    def _key(self, bb):
        return (bb.file, bb.first_line)

    def type_of(self, o, op=None, imm=None) -> str:
        if op in _BOOL_OPS:
            return "bool"
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

    def _local(self, slot: int) -> pre_ir.Register:
        key = (self.cur_gname, slot)
        if key not in self.local_regs:
            self.local_regs[key] = pre_ir.Register(f"l%{slot}", 0, "?")
        return self.local_regs[key]

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

    def _setup_frame(self, gb, params):
        # Bind frame_resolution's slot model (frame_dig / frame_bury -> params /
        # versioned locals) onto this group's registers. The k<0 `frame_bury`
        # fallback stays in `_build_block` via `_local`.
        res = resolve_sub(gb, len(params))
        for out0, i in res.dig_param.items():
            self.frame_map[out0] = params[i].register
        for out0, (slot, ver) in res.dig_local.items():
            self.frame_map[out0] = self._local_reg(slot, ver)
            self.frame_local_slot[out0] = slot
        for aid, (slot, ver) in res.bury.items():
            self.bury_target[aid] = self._local_reg(slot, ver)
        self.shuffle_src.update(res.passthrough)
        self.frame_passthrough |= res.pushed
        self.pushed_slot.update(res.pushed_slot)
        self.final_locals[self.cur_gname] = {
            slot: self._local_reg(slot, ver) for slot, ver in res.final.items()}

    def _local_reg(self, slot: int, ver: int) -> pre_ir.Register:
        """The (cached, identity-stable) versioned local register for a slot."""
        key = (self.cur_gname, slot, ver)
        r = self._fr_regs.get(key)
        if r is None:
            r = self._fr_regs[key] = pre_ir.Register(f"l%{slot}", ver, "?")
        return r

    def _setup_shuffles(self, gb):
        # Puya is value-based, so a pure stack shuffle drops out: map each output
        # to its source operand and let consumers reference the value directly.
        # The mapping is exact (out[i] = in[m[i]]), hence value-preserving.
        for bb in gb:
            for a in bb.assignments:
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
            for a in bb.assignments:
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
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS:
                last = a
        return last

    def _asserts_false(self, bb) -> bool:
        """``bb`` asserts a compile-time zero, so it aborts unconditionally and (like
        ``err``) lifts to ``Fail``, not a ``ProgramExit`` of a maybe-non-uint64 top."""
        from ..ssa import const_int
        return any(a.op == "assert" and a.inputs and const_int(a.inputs[0]) == 0
                   for a in bb.assignments)

    def _recover_match_keys(self, bb, labels):
        """Recover a `match`'s case keys, in label order, from the source line of a
        multi-push whose operands the parser stripped (leaving a phantom push)."""
        src = _load_src(getattr(self.prog, "source_path", ""))
        if len(src) != 1:
            return None, set()
        lines = next(iter(src.values()))
        push = next((a for a in reversed(bb.assignments)
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
            blk = self.line2block.get(self.label2line.get(lbl))
            if blk is None or blk not in self.bid:
                return None, set()
            cases.append((ops_[i], self.bid[blk]))
            targets.add(blk)
        return cases, targets

    def control(self, bb):
        t = self.term_assign(bb)
        op = t.op if t is not None else None

        if op == "callsub":
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
            return self._control_retsub(bb)
        succ = [s for s in bb.successors if s in self.bid]
        if not succ:
            if op == "err" or self._asserts_false(bb):
                return pre_ir.Fail()
            # HAZARD: `return`, and a block that falls off the end with no explicit
            # terminator, both exit with the STACK TOP (the approval result), never a
            # hardcoded 0 -- that would turn an approve-if-X program into an
            # unconditional reject. Read it off the clean re-simulated stack;
            # bb.exit_stack is fat STACK_MAX garbage and yields an undefined operand.
            rsx = self.resim_exit.get(bb, [])
            v = rsx[-1] if rsx else pre_ir.UInt64Constant(0)
            return pre_ir.ProgramExit(v)
        if len(succ) == 1:
            return pre_ir.Goto(self.bid[succ[0]])
        if len(succ) == 2 and op in _COND_BRANCH and t is not None:
            cond = self._sel_value(t)
            taken = self.line2block.get(self.label2line.get((t.immediates or "").strip()))
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
            term = self._control_switch(t, succ)
            if term is not None:
                return term
        # `match` is KEYED, so a POSITIONAL GotoNth over CFG-successor order
        # mis-targets its arms. Reaching here means neither key recovery nor the
        # source fallback worked, so emit Undefined rather than a confident wrong
        # route.
        return pre_ir.GotoNth(pre_ir.Undefined(),
                              [self.bid[s] for s in succ[:-1]], self.bid[succ[-1]])

    def _sel_value(self, t):                  # branch/switch selector value
        if t is not None and self.resim_args.get(id(t)):
            return self.resim_args[id(t)][0]
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
        rsx = self.resim_exit.get(bb, [])              # clean re-simulated stack
        if not self.cur_nret:
            return pre_ir.SubroutineReturn([])
        np = self.cur_nargs
        if self.cur_is_proto:
            # Frame slots A..A+R-1: resim seeds the stack with the params, then
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
        ins = (self.resim_args.get(id(t)) if id(t) in self.resim_args
               else [self.value(x) for x in t.inputs])
        order = list(range(n))[::-1]           # label[i] -> ins[n - i]
        cases, targets = [], set()
        for i, lbl in enumerate(labels):
            blk = self.line2block.get(self.label2line.get(lbl))
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

    def _control_switch(self, t, succ):
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
            blk = self.line2block.get(self.label2line.get(lbl))
            if blk is None or blk not in self.bid:
                ok = False
                break
            arms.append(self.bid[blk])
        sl = t.location.line if getattr(t, "location", None) else None
        after = [fl for fl in self.line2block if sl is not None and fl > sl]
        ft = self.line2block[min(after)] if after else None
        if ok and ft is not None and ft in self.bid:
            return pre_ir.GotoNth(self._sel_value(t), arms, self.bid[ft])
        if ok and succ:                       # robustness: best-effort default
            labeled = {self.line2block.get(self.label2line.get(lbl)) for lbl in labels}
            dft = next((s for s in succ if s not in labeled), succ[-1])
            return pre_ir.GotoNth(self._sel_value(t), arms, self.bid[dft])
        return None

    def _resim(self, body_list, entry_bb, params):
        """Re-simulate a routine's value-stack with correct callsub arities, filling
        `resim_args` (per-op operands), `resim_phis` (merge phis) and `resim_exit`
        (per-block stacks)."""
        body = set(body_list)

        def isucc(b):
            # retsub/return/err LEAVE the sub: their raw successors are the callers'
            # continuations, not internal flow. A callsub flows to its own
            # continuation, not into the callee.
            if b.assignments and b.assignments[-1].op in ("retsub", "return", "err"):
                return []
            cs = self.callsite.get(b)
            if cs is not None and cs.continuation_bb in body:
                return [cs.continuation_bb]
            return [s for s in b.successors if s in body]

        # Back-edge detection, so a loop header's phis can be created up-front from
        # the forward edge and closed once the body has been simulated.
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict = {b: WHITE for b in body_list}
        back: set = set()

        def dfs(b):
            color[b] = GRAY
            for su in isucc(b):
                if color.get(su) == GRAY:
                    back.add((b, su))
                elif color.get(su) == WHITE:
                    dfs(su)
            color[b] = BLACK

        dfs(entry_bb)
        back_targets = {dst for _, dst in back}
        fpred: dict = {b: [] for b in body_list}
        bpred: dict = {b: [] for b in body_list}
        for b in body_list:
            for su in isucc(b):
                (bpred if (b, su) in back else fpred)[su].append(b)
        order, seen = [], set()

        def visit(b):
            if b in seen:
                return
            seen.add(b)
            for s in isucc(b):
                if (b, s) not in back:
                    visit(s)
            order.append(b)

        visit(entry_bb)
        order.reverse()                       # topological over forward edges
        order += [b for b in body_list if b not in seen]   # blocks the forward DAG
        #            missed still need clean resim_args

        pending: list = []                    # (phi, slot, back-pred) to close
        for b in order:
            preds = [p for p in fpred[b] if p in self.resim_exit]
            stack = self._resim_entry_stack(b, entry_bb, params, preds,
                                            back_targets, bpred[b], pending)
            for a in b.assignments:
                self._resim_exec_op(a, b, stack, params)
            self.resim_exit[b] = stack
        for ph, slot, bp in pending:          # close loop back-edges
            if bp in self.resim_exit and slot < len(self.resim_exit[bp]):
                ph.args.append(pre_ir.PhiArgument(self.resim_exit[bp][slot], self.bid[bp]))

    def _resim_value(self, o):                # SSA operand -> pre-IR value
        cv = getattr(o, "const_value", None)
        if cv is not None:
            return _const(cv)
        if isinstance(o, Const):
            return _const(o)
        if isinstance(o, SSAVar):
            return self.reg(o)
        return self.value(o)

    def _resim_entry_stack(self, b, entry_bb, params, preds,
                           back_targets, bpred_b, pending):
        """Block `b`'s entry value-stack: the sub's args, a loop-header phi set
        (back-edge args deferred into `pending`), a copy of the single predecessor's
        exit, or a slot-wise merge that builds `resim_phis`."""
        if b is entry_bb or not preds:
            return [pp.register for pp in params]          # entry: the args
        if b in back_targets:                              # loop header
            depth = min(len(self.resim_exit[p]) for p in preds)
            stack, phis = [], []
            for slot in range(depth):
                r = self._new_reg("tmp", "?")
                ph = pre_ir.Phi(r, [pre_ir.PhiArgument(self.resim_exit[p][slot], self.bid[p])
                                for p in preds])
                phis.append(ph)
                stack.append(r)
                for bp in bpred_b:
                    pending.append((ph, slot, bp))
            self.resim_phis[b] = phis
            return stack
        if len(preds) == 1:
            return list(self.resim_exit[preds[0]])
        # Plain merge, slot-wise. HAZARD: align predecessors by their STACK TOP (the
        # common top `depth` values), never the bottom -- consumers read the top, and
        # a pred carrying extra DEEP values (an unconsumed `..._get_ex` value left
        # under the result) keeps its live values there. Bottom-first indexing merges
        # such a pred's leftover instead of its computed value. For uniform-depth
        # joins `len-depth+slot == slot`, so this is a no-op.
        depth = min(len(self.resim_exit[p]) for p in preds)
        tops = {p: self.resim_exit[p][len(self.resim_exit[p]) - depth:]
                for p in preds}
        stack, phis = [], []
        for slot in range(depth):
            vals = [tops[p][slot] for p in preds]
            if all(v is vals[0] for v in vals):
                stack.append(vals[0])
            else:
                r = self._new_reg("tmp", "?")
                phis.append(pre_ir.Phi(r, [pre_ir.PhiArgument(tops[p][slot],
                                                      self.bid[p]) for p in preds]))
                stack.append(r)
        if phis:
            self.resim_phis[b] = phis
        return stack

    def _resim_exec_op(self, a, b, stack, params):
        """Simulate one assignment `a` of block `b` against the clean re-sim `stack`
        (mutated in place), recording per-op operands into `resim_args`."""
        # Frame ops FIRST: PySSA models them as fat [1..STACK_MAX] band ops (and they
        # are in _STACK_SHUFFLE_OPS), so the generic / shuffle paths below would pop
        # the whole stack. On the clean stack frame_dig pushes one value, bury pops one.
        if a.op == "frame_dig":
            out0 = a.outputs[0] if a.outputs else None
            if out0 is not None and out0 in self.frame_passthrough:
                # A pushed local: read its LIVE value off the re-sim stack at slot
                # position len(params)+k. The band input value() resolves to is
                # polluted by a loop's band phis, so it returns the loop's mutated
                # register for a pre-loop local. Fall back to value() only when the
                # slot isn't on the stack.
                slot = self.pushed_slot.get(out0)
                pos = len(params) + slot if slot is not None else -1
                if 0 <= pos < len(stack):
                    stack.append(stack[pos])
                else:
                    stack.append(self.value(out0))
            elif out0 is not None and out0 in self.frame_local_slot:
                # A frame_bury-d local: read its live value off the re-sim stack at
                # len(params)+k, which carries the deep-writes AND the merge phi for
                # a slot written on >1 path into a join. frame_map's version is
                # picked by a CFG-blind walk, drops that merge, and leaves the
                # post-join read undominated (an entry-orphan).
                pos = len(params) + self.frame_local_slot[out0]
                if 0 <= pos < len(stack):
                    stack.append(stack[pos])
                else:
                    stack.append(self.frame_map.get(out0) or pre_ir.Undefined())
            else:
                # param / negative below-frame read: the plain frame_map path.
                # Widening value() to these re-resolves them and diverges from the
                # IR construction path -- a bytes value into a u64 op.
                stack.append(self.frame_map.get(out0) or pre_ir.Undefined())
            return
        if a.op == "frame_bury":
            if stack:
                v = stack.pop()
                self.resim_args[id(a)] = [v]
                # frame_bury N also DEEP-WRITES frame slot N -- an absolute stack
                # position (len(params)+N: args at 0..nargs-1, locals above).
                # Modelling only the pop leaves a later read of that slot seeing
                # the stale frame-init instead of the buried value.
                toks = (a.immediates or "").split()
                if toks:
                    try:
                        pos = len(params) + int(toks[0])
                    except ValueError:
                        pos = -1
                    if 0 <= pos < len(stack):
                        stack[pos] = v
            return
        if a.op in _STACK_SHUFFLE_OPS:
            # Use the op's CANONICAL arity, not a.inputs: the SSA's fat-band sim can
            # under-count a shuffle's inputs on a shallow model stack (dup2 with 1
            # input), making _shuffle_mapping bail and the resim drop the op --
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
            cs = self.callsite.get(b)
            nargs = self._sub_io(cs.target_entry)[0] if (cs and cs.target_entry) else 0
            nargs = min(nargs, len(stack))
            self.resim_args[id(a)] = stack[len(stack) - nargs:]      # param order
            if nargs:
                del stack[len(stack) - nargs:]
            if (cs is not None and cs.target_entry is not None
                    and getattr(cs.target_entry, "_key", None) is not None
                    and cs.target_entry._key() in self._clobber_callees):
                # This callee reaches under its own frame with a plain stack op
                # (`cover`/`uncover`/a dip), which the AVM permits — it bounds
                # only `frame_dig`/`frame_bury` — so it may have permuted or
                # eaten the caller's OWN values. This re-simulation otherwise
                # assumes everything below the args survives a call, and on a
                # live-AVM differential that assumption emitted the STALE
                # pre-call value and INVERTED the program's outcome. Nothing
                # below the args is knowable here, and no `(nargs, nret)` can
                # say what became of it (expressing it needs per-call-site
                # inlining), so mark those slots explicitly undefined: still a
                # lift, never a false value.
                for _i in range(len(stack)):
                    stack[_i] = pre_ir.Undefined()
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
        self.resim_args[id(a)] = [stack.pop() for _ in range(ni)]    # top-first
        if a.op not in _TERMINATOR_OPS:
            for o in reversed([o for o in a.outputs if isinstance(o, SSAVar)]):
                stack.append(self._resim_value(o))

    def _build_block(self, bb):
        # Always True (every group is re-simulated); the per-op `resim_args`
        # lookups below still take it as a flag.
        resim = bb in self.resim_blocks
        phis = self._block_phis(bb)
        ops = []
        for a in bb.assignments:
            self._block_emit_op(a, bb, resim, ops)
        return pre_ir.BasicBlock(id=self.bid[bb], phis=phis, ops=ops,
                             terminator=self.control(bb), comment=f"L{bb.first_line}")

    def _block_phis(self, bb):
        """Entry phis for block `bb`, taken from the re-simulation."""
        return self.resim_phis.get(bb, [])

    def _block_emit_op(self, a, bb, resim, ops):
        """Lower one assignment `a` of block `bb` into `ops` (frame reads, re-sim
        shuffles and inlined consts emit nothing)."""
        if a.op == "frame_dig":
            return                              # a param/local read (no op)
        if a.op == "frame_bury":
            # frame_bury DEFINES its slot (l%slot = buried value), and must be
            # emitted BEFORE the shuffle / resim skips below: PySSA models the bury
            # as a fat-band op, so it would otherwise be dropped and the slot's
            # later frame_dig reads go undefined.
            slot = _imm0(a)
            if slot is not None:
                src = (self.resim_args[id(a)][0]
                       if resim and id(a) in self.resim_args
                       else self.value(a.inputs[0]) if a.inputs else None)
                if src is not None:
                    tgt = self.bury_target.get(id(a)) or self._local(slot)
                    ops.append(pre_ir.Assignment([tgt], src))
            return
        if resim and a.op in _STACK_SHUFFLE_OPS:
            return                              # re-sim reorders the stack itself
        if self._is_routed_shuffle(a):
            return                              # const shuffle routed to source
        if a.op == "callsub":
            cs = self.callsite.get(bb)
            target = (cs.target_name if cs and cs.target_name
                      else (a.immediates or "?"))
            # Args are passed via scratch, not callsub operands: take the caller's
            # exit_stack top nargs in PARAM order (es[-nargs+i]).
            nargs = self._sub_io(cs.target_entry)[0] if (cs and cs.target_entry) else 0
            es = bb.exit_stack
            if resim:
                call_args = self.resim_args.get(id(a), [])
            elif nargs and len(es) >= nargs:
                call_args = [self.value(es[-nargs + i]) for i in range(nargs)]
            else:
                call_args = [self.value(i) for i in a.inputs]
            invoke = pre_ir.InvokeSubroutine(target, call_args)
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
        args = self.resim_args[id(a)] if resim and id(a) in self.resim_args \
            else [self.value(i) for i in a.inputs]
        intr = pre_ir.Intrinsic(a.op, a.immediates.split() if a.immediates else [],
                            args, line=a.location.line)
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
        if o in self.frame_map:                       # a param/local read
            return self.frame_map[o].ir_type
        a = self.producer.get(o)
        op = a.op if a else None
        imm = a.immediates if a else None
        if op in _BOOL_OPS:
            return "bool"
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
    for a in entry_bb.assignments:
        if a.op == "proto":
            toks = (a.immediates or "").split()
            if len(toks) >= 2:
                try:
                    return int(toks[0]), int(toks[1])
                except ValueError:
                    break
    return 0, 0
