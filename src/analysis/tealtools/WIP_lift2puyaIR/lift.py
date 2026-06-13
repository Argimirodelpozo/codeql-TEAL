"""Lift a :class:`~tealtools.ssa.SSAProgram` into the Puya-shaped IR
(``lift(prog) -> pre_ir.Program``) — the decompiler direction: stack-machine TEAL
SSA (frame slots, scratch, shuffles) becomes value-based, typed, subroutine IR.

Two structural rewrites (both contained, no substrate change):

- **Subroutine partitioning** (via :func:`tealtools.structure.analyze_structure`):
  routing/handler BBs become ``main``; each ``callsub``-reachable routine becomes
  a ``pre_ir.Subroutine``; ``callsub``/``retsub`` -> Invoke / Return.
- **Frame modeling** de-noises PySSA's ``_try_expand_frame_op``, which models
  ``frame_dig``/``frame_bury`` as ~1000-wide stack ops over the ``[1..STACK_MAX]``
  unroll. Here ``frame_dig -k`` reads param ``nargs-k`` and other slots read/write
  a local (single values), the fat frame ops drop, and the now-dead stack-model
  phis are pruned by liveness. Heuristic, but removes essentially all the noise.

Constants and trivial single-pred phis are inlined; types come from :mod:`optypes`.
"""
from __future__ import annotations

from ..block_args import to_block_args
from ..opcode_sigs import op_arity
from ..passes.frame_resolution import resolve_sub
from ..ssa import (
    _STACK_SHUFFLE_OPS,
    _TERMINATOR_OPS,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _shuffle_mapping,
)
from ..structure import analyze_structure
from . import pre_ir, transforms, type_recovery
from .optypes import (
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
from .teal_const import _load_src, _tokenize_operands

_FRAME_OPS = frozenset({"frame_dig", "frame_bury"})


def _infer_arities(struct, callsite) -> dict:
    """``Subroutine -> (nargs, nret)`` for every routine. Proto subs read it off
    their ``proto``; legacy subs pass args / return on the stack, so infer it from
    a cross-procedural stack-depth fixpoint: propagate depth over each sub's
    internal CFG (a ``callsub`` flows to its continuation with the callee's current
    arity), where the deepest point below entry is ``nargs`` and a ``retsub``'s
    depth above that floor is ``nret``."""
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
            ret_d = None
            i = 0
            while i < len(order):
                b = order[i]
                i += 1
                d_out, mn = block_io(b, depth[b])
                floor = min(floor, mn)
                if b.assignments and b.assignments[-1].op == "retsub" and ret_d is None:
                    ret_d = d_out
                for su in internal_succ(b, s.body):
                    if su not in depth:
                        depth[su] = d_out
                        order.append(su)
            na, nr = -floor, (ret_d - floor if ret_d is not None else 0)
            if arity[s] != (na, nr):
                arity[s] = (na, nr)
                changed = True
        if not changed:
            break
    return arity


def _const(cv: Const):
    # SSA integer consts carry kind "int" (not "uint64"); without this they all
    # fell through to BytesConstant(decimal-string) -- rendered verbatim so it
    # looked right, but semantically a uint64 stored as bytes (Puya wants `Nu`).
    if cv.kind == "int":
        try:
            return pre_ir.UInt64Constant(int(cv.value))
        except ValueError:
            return pre_ir.UInt64Constant(0)
    return pre_ir.BytesConstant(cv.value)


_UINT64_MAX = (1 << 64) - 1


def _range_note(local_id: str, rng) -> str | None:
    """A compact ``// `` annotation for an :class:`IntRange`, or ``None`` when
    the range is the full uint64 domain (uninformative). The uint64 ceiling is
    rendered as an open ``>=`` floor rather than the 20-digit max."""
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
    """``len(x) = 8`` / ``len(x) <= 20`` / ``2 <= len(x) <= 4096`` from a bytes
    type's exact ``byte_length`` or its ``byte_length_range``."""
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
    """``x = N`` / ``lo <= x <= hi`` from a bytes type's bigint
    ``int_value_range`` (bytemath). Multi-hundred-digit bounds collapse to
    ``<N-bit>`` so the line stays readable."""
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
    """Lift ``prog`` into the Puya-shaped IR model (see module docstring)."""
    return _Lifter(prog).build()


class _Lifter:
    """Stateful builder behind :func:`lift` (one instance per program). ``build``
    drives the pipeline; the methods share working state -- register maps, the
    block-id table, frame / local / shuffle routing -- as instance attributes."""

    def __init__(self, prog: SSAProgram) -> None:
        self.prog = prog

    def build(self) -> pre_ir.Program:
        self.form = to_block_args(self.prog)
        self.label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in self.prog.labels}
        struct = analyze_structure(self.prog)
        self.sub_of = {bb: s for s in struct.subroutines for bb in s.body}
        self.callsite = {cs.callsub_bb: cs for cs in struct.call_sites}
        self.cont_site = {cs.continuation_bb: cs for cs in struct.call_sites
                          if cs.continuation_bb is not None}
        # Subroutine (nargs, nret): proto subs declare it; legacy non-proto subs pass
        # args / return on the stack, so it is inferred (see `_infer_arities`).
        _arity = _infer_arities(struct, self.callsite)
        self._io_by_entry = {s.entry_bb: a for s, a in _arity.items()}
        # Every legacy non-proto sub needs its value-stack re-simulated with correct
        # callsub arities (see `_resim`): PySSA threads the whole-program stack
        # through them (proto subs escape via frame ops + dead-phi pruning), so it
        # caps at STACK_MAX and corrupts their args / survivors / returns. `resim_*`
        # carry that re-simulation into `_build_block`, replacing the fat SSA wiring.
        self._proto_entries = {s.entry_bb for s in struct.subroutines
                               if any(a.op == "proto" for a in s.entry_bb.assignments)}
        # Re-simulate EVERY sub's value stack. A proto sub that calls another can
        # leave a stack survivor that PySSA's fat [1..STACK_MAX] band conflates and
        # loses across the interprocedural return edge (it surfaces as a
        # used-but-never-defined operand that Puya's destructure_ssa rejects);
        # re-simulation reconstructs the clean stack so the survivor is real. It
        # has to be all-or-nothing -- re-simulating only some subs mismatches the
        # shared call interface and corrupts others. The added cost is negligible
        # (folks-v3 lift+lower ~3s either way; SSA *construction* dominates, ~17-40s).
        # Frame ops are handled on the clean stack inside `_resim` (frame_dig pushes
        # its param/local, frame_bury pops).
        _resim_subs = set(struct.subroutines)
        self.resim_args: dict = {}                # id(assignment) -> [pre-IR operand]
        self.resim_phis: dict = {}                # PyBlock -> [pre_ir.Phi]
        self.resim_exit: dict = {}                # PyBlock -> re-simulated exit stack
        self.resim_blocks: set = set()            # blocks whose ops use re-simulated args
        self._param_phis: set = set()             # non-proto entry arg phis -> params (skip)
        # SSA-level producer map + scratch reaching-def (per `load N`, the value
        # SSAVars its influencing `store N`s wrote) -- used to type call args,
        # which are passed via scratch (load/store) here, not as callsub operands.
        self.producer = {o: a for a in self.prog.assignments
                         for o in a.outputs if isinstance(o, SSAVar)}
        self.load_stores: dict = {}
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
        # Global block ids. Puya restarts block@0 per subroutine, but that's not
        # safe here: structure.py's partition has ~28 cross-routine branch edges
        # (tail-calls / compiler-shared epilogues that don't belong to one
        # routine), so a per-subroutine-local id would silently mis-target those
        # gotos. Global ids keep control flow correct; per-sub numbering needs the
        # routines to be closed CFG regions, which is a structure.py concern.
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
        self.frame_passthrough: set = set()   # frame_dig out0 of k>=0 pushed locals
        #   (frame_resolution.SubFrames.pushed) — the resim path resolves THESE via
        #   value() (their value lives cross-block), but leaves every other frame_dig
        #   on the plain frame_map path so negative/param reads don't diverge.
        self.cur_gname = "main"
        self.cur_nret = 0                     # proto return count of the group being built
        # Inter-procedural return wiring. A callsub's continuation receives the
        # callee's return value(s). In the raw CFG that value is a phi whose only
        # predecessor is the callee's retsub block, so it would resolve into the
        # callee's register space -- a different Puya subroutine, hence "undefined"
        # in the caller. Bind it to the InvokeSubroutine's result instead: alias the
        # continuation's top-of-stack return phi(s) to a caller-local result reg.
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
                # Use a `cr` prefix (not reg()'s `v`): this pre-pass runs before the
                # per-group `_name_group`, whose `ctr.clear()` would otherwise restart
                # the `v` counter and collide these with a group's own `v%N`.
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
                # block's stack-index phis (merged from the call sites). The pre-IR
                # sub entry has no predecessors, so map those phis to params (entry
                # stack_index k = k-th from top = param[nargs-k]) and skip building
                # them -- matching how proto subs read args off the frame.
                if s.entry_bb not in self._proto_entries:
                    for ph in s.entry_bb.phis:
                        if 1 <= ph.stack_index <= nargs:
                            self.frame_map[ph] = params[nargs - ph.stack_index].register
                            self._param_phis.add(ph)
            self.cur_nret = nrets
            self._setup_frame(gb, params)
            self._setup_shuffles(gb)
            self._name_group(gb)
            # `main` and every non-proto sub thread the whole-program stack (which
            # PySSA fattens), so re-simulate their value-stacks for clean operands.
            if s is None or s in _resim_subs:
                entry = (s.entry_bb if s is not None
                         else next((b for b in gb if not b.predecessors), gb[0]))
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
        # Replace cross-group passthrough phis with each caller's own value (loop:
        # a passthrough value can itself be another passthrough), then re-prune the
        # phis they orphaned.
        while transforms.isolate_cross_group_phis(self.subs):
            pass
        transforms.prune_dead_phis(self.subs)
        self.name2sub = {s.id: s for s in self.subs if not s.is_main}
        # Recover the register / return / phi AVM types to a fixpoint (see
        # :mod:`type_recovery`), then assemble the program and reconcile the
        # placeholder-seeded mixed-type phi webs on its final shape.
        type_recovery.recover_types(self, sub_pairs)
        # Now that the phi-arg AVM types are known, sink any mixed-type phi that
        # only feeds scratch stores into per-predecessor stores (the reused-slot
        # artifact). This PRESERVES the scratch write -- it is gload-readable
        # across the group, so it must not be dropped -- while removing the merge
        # Puya would reject. (Runs after recovery so "mixed" is observable.)
        transforms.sink_mixed_phi_scratch_stores(self.subs)
        main = next(sub for sub in self.subs if sub.is_main)
        prog_ir = pre_ir.Program(main=main, subroutines=[s for s in self.subs if not s.is_main])
        type_recovery.finalize_types(prog_ir)
        transforms.materialize_phi_consts(prog_ir)
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
            # A scratch load is typed by what was stored into the slot, via
            # the reaching-def (``_ssa_type`` resolves it through
            # ``load_stores`` with a depth guard); the slot itself carries no
            # type, which is why the plain checks above leave it ``?``.
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
        """``// v0 = 1, len(v1) = 8`` style note for the ranged outputs of an
        assignment / phi. uint64 vars carry an ``IntRange`` (range_arith /
        range_assert); bytes vars carry a byte length and/or a bigint value
        range on their type (byte_lengths / bytemath). ``None`` when nothing
        informative is annotated."""
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
        # frame_dig / frame_bury are resolved to params / versioned locals by
        # passes.frame_resolution (precise for proto subs -- the sound case, and
        # the only place frame ops occur); bind that substrate slot model onto
        # this group's registers. The k<0 `frame_bury` fallback stays in
        # `_build_block` via `_local`.
        res = resolve_sub(gb, len(params))
        for out0, i in res.dig_param.items():
            self.frame_map[out0] = params[i].register
        for out0, (slot, ver) in res.dig_local.items():
            self.frame_map[out0] = self._local_reg(slot, ver)
        for aid, (slot, ver) in res.bury.items():
            self.bury_target[aid] = self._local_reg(slot, ver)
        self.shuffle_src.update(res.passthrough)
        self.frame_passthrough |= res.pushed
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
        # A pure stack shuffle (dup/dupn/swap/cover/uncover) just reorders or
        # duplicates values; map each output to its source operand so consumers
        # reference the value directly and the op drops out (Puya is value-based,
        # no shuffles). The mapping is exact (out[i] = in[m[i]]), so this is
        # always value-preserving; fat-frame stack vars a routed source lands on
        # resolve through the frame-op passthrough routing in `_setup_frame`.
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
        self.ctr.clear()
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
                    # idx is the top-first output slot; multi-result ops
                    # (get_ex / params / box / addw…) type their slots
                    # individually -- type_of can't tell them apart.
                    mt = _multi_out_type(a.op, a.immediates, idx) if nssa > 1 else None
                    if a.op in _POLY_FIRST_OPERAND_OPS and a.inputs:
                        # setbit: result type == its VALUE operand (the deepest
                        # stack input == last top-first SSA input), uint64 or bytes.
                        vt = self._ssa_type(a.inputs[-1])
                        rt = vt if vt != "?" else self.type_of(o, a.op, a.immediates)
                    else:
                        rt = mt or self.type_of(o, a.op, a.immediates)
                    if o not in self.regs:
                        self.regs[o] = self._new_reg(pfx, rt)
                    elif self.regs[o].ir_type == "?" and rt != "?":
                        # already registered untyped by an earlier cross-group
                        # reference (a tail-call / shared-epilogue edge reaches
                        # value() before this, the defining, group is named);
                        # now that we know its op, fix the type in place.
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

    def _recover_match_keys(self, bb, labels):
        """Recover a `match`'s case keys from source when the extractor dropped
        them (a `pushbytess base32(..) ..` whose operands it stripped, leaving a
        phantom 0-output push). The keys are the push's operands, in label order;
        stored as their source literal (`teal_const._const_bytes` parses them)."""
        src = _load_src(getattr(self.prog, "db_path", ""))
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
        resim = bb in self.resim_blocks

        def _cond():                          # branch/switch selector value
            if resim and t is not None and self.resim_args.get(id(t)):
                return self.resim_args[id(t)][0]
            return self.value(t.inputs[0]) if (t and t.inputs) else pre_ir.Undefined()

        if op == "callsub":
            cs = self.callsite.get(bb)
            cont = cs.continuation_bb if cs else None
            if cont is not None and cont in self.bid:
                return pre_ir.Goto(self.bid[cont])
            # No continuation: the callee doesn't return here (non-returning). In
            # a sub, model that as a value-less return; in main there is no caller
            # to return to, so the post-call flow is an unreachable program exit
            # (a value-less SubroutineReturn would be invalid for the main program).
            if self.cur_is_main:
                return pre_ir.ProgramExit(pre_ir.UInt64Constant(0))
            return pre_ir.SubroutineReturn([])
        if op == "retsub":
            # A retsub returns to its caller. Its raw-CFG successors are the
            # callers' continuations (interprocedural return edges), but each
            # caller already reaches its own continuation via its callsub ->
            # Goto(continuation). So model retsub as a value return, NOT a
            # goto / goto_nth into the callers — the latter, with >1 caller,
            # had no selector and rendered as `goto_nth undefined`.
            #
            # The N returns are frame slots 0..N-1. A sub that *buries* its
            # return into the slot (frame_bury 0) leaves the slot's current
            # value there, not on the exit stack — so prefer the final slot
            # local; only fall back to the (bottom-first) exit-stack slice for
            # returns that were left on the stack.
            if resim:                                      # clean re-simulated stack
                rsx = self.resim_exit.get(bb, [])
                return pre_ir.SubroutineReturn(rsx[-self.cur_nret:] if self.cur_nret else [])
            slots = self.final_locals.get(self.cur_gname, {})
            es = bb.exit_stack or []
            rets = []
            for j in range(self.cur_nret):
                if j in slots:
                    rets.append(slots[j])                  # buried into the slot
                elif len(es) >= self.cur_nret - j:
                    rets.append(self.value(es[-self.cur_nret + j]))  # left on the stack
            return pre_ir.SubroutineReturn(rets)
        succ = [s for s in bb.successors if s in self.bid]
        if not succ:
            if op == "err":
                return pre_ir.Fail()
            # `return` (arity 0/0) returns the stack top; a block that falls off
            # the end with NO explicit terminator (op is None -- a bare-expression
            # program, e.g. a v6 `txn Sender; global CreatorAddress; ==`) returns
            # its stack top implicitly too. Both ProgramExit the top value (the
            # approval result), NOT a hardcoded 0 -- else the lift turns an
            # approve-if-X program into an unconditional reject. For a re-simulated
            # block use its clean local stack; bb.exit_stack is the fat STACK_MAX
            # garbage and would yield an undefined operand.
            if resim:
                rsx = self.resim_exit.get(bb, [])
                v = rsx[-1] if rsx else pre_ir.UInt64Constant(0)
            else:
                v = (self.value(bb.exit_stack[-1]) if bb.exit_stack
                     else pre_ir.UInt64Constant(0))
            return pre_ir.ProgramExit(v)
        if len(succ) == 1:
            return pre_ir.Goto(self.bid[succ[0]])
        if len(succ) == 2 and op in _COND_BRANCH and t is not None:
            cond = _cond()
            taken = self.line2block.get(self.label2line.get((t.immediates or "").strip()))
            if taken in succ:
                other = succ[0] if succ[1] is taken else succ[1]
            else:
                taken, other = succ[0], succ[1]
            if op == "bnz":
                return pre_ir.ConditionalBranch(cond, self.bid[taken], self.bid[other])
            return pre_ir.ConditionalBranch(cond, self.bid[other], self.bid[taken])  # bz
        if op == "match" and t is not None:
            # `match t0..t_{n-1}`: matched value on top, the n case values below.
            # go-algorand pairs label[i] with the i-th case counting from the
            # DEEPEST (label[0] <-> C_0, the first-pushed/deepest constant). The
            # recovered `inputs` are [value, C_0, C_1, …, C_{n-1}] (value first,
            # then the constants in push/deepest-first order), so C_i is at index
            # i+1. (Pairing label[i] with ins[n-i] silently SWAPS sibling methods
            # -- e.g. routes one ABI selector to another's body; oracle-confirmed.)
            labels = (t.immediates or "").split()
            n = len(labels)
            ins = (self.resim_args.get(id(t)) if (resim and id(t) in self.resim_args)
                   else [self.value(x) for x in t.inputs])
            cases, targets = [], set()
            for i, lbl in enumerate(labels):
                blk = self.line2block.get(self.label2line.get(lbl))
                ci = ins[i + 1] if (i + 1) < len(ins) else None
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
            if cases is None:                 # extractor dropped the case keys
                cases, targets = self._recover_match_keys(bb, labels)  # (from source)
            default = next((s for s in succ if s not in targets), None)
            if cases and default is not None:
                val = ins[0] if ins else pre_ir.Undefined()
                return pre_ir.Switch(val, cases, self.bid[default])
        if op in ("switch", "match"):
            return pre_ir.GotoNth(_cond(),
                              [self.bid[s] for s in succ[:-1]], self.bid[succ[-1]])
        return pre_ir.GotoNth(pre_ir.Undefined(),
                              [self.bid[s] for s in succ[:-1]], self.bid[succ[-1]])

    def _resim(self, body_list, entry_bb, params):
        """Re-simulate a non-proto sub's value-stack with correct callsub arities.
        PySSA caps such a sub's stack at STACK_MAX, so its post-call survivors come
        back as fat-phi garbage; here operands come from a clean local stack
        instead. Fills `resim_args` (per-op operands), `resim_phis` (merge phis),
        `resim_exit` (per-block stacks)."""
        body = set(body_list)

        def isucc(b):
            # retsub/return/err leave the sub -- their raw successors are the
            # callers' continuations (interprocedural return edges), NOT internal
            # flow. A callsub flows to its continuation, not into the callee.
            if b.assignments and b.assignments[-1].op in ("retsub", "return", "err"):
                return []
            cs = self.callsite.get(b)
            if cs is not None and cs.continuation_bb in body:
                return [cs.continuation_bb]
            return [s for s in b.successors if s in body]

        # Back-edge detection (DFS), so loops work: a loop header's phis are
        # created up-front from the forward edge, and their back-edge args are
        # filled once the body has been simulated.
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
        order += [b for b in body_list if b not in seen]   # cover any block the
        #            forward DAG missed, so every op still gets clean resim_args

        def rv(o):                            # SSA operand -> pre-IR value
            cv = getattr(o, "const_value", None)
            if cv is not None:
                return _const(cv)
            if isinstance(o, Const):
                return _const(o)
            if isinstance(o, SSAVar):
                return self.reg(o)
            return self.value(o)

        pending: list = []                    # (phi, slot, back-pred) to close
        for b in order:
            preds = [p for p in fpred[b] if p in self.resim_exit]
            if b is entry_bb or not preds:
                stack = [pp.register for pp in params]      # entry: the args
            elif b in back_targets:                         # loop header
                depth = min(len(self.resim_exit[p]) for p in preds)
                stack, phis = [], []
                for slot in range(depth):
                    r = self._new_reg("tmp", "?")
                    ph = pre_ir.Phi(r, [pre_ir.PhiArgument(self.resim_exit[p][slot], self.bid[p])
                                    for p in preds])
                    phis.append(ph)
                    stack.append(r)
                    for bp in bpred[b]:
                        pending.append((ph, slot, bp))
                self.resim_phis[b] = phis
            elif len(preds) == 1:
                stack = list(self.resim_exit[preds[0]])
            else:                                           # plain merge: phi/slot
                depth = min(len(self.resim_exit[p]) for p in preds)
                stack, phis = [], []
                for slot in range(depth):
                    vals = [self.resim_exit[p][slot] for p in preds]
                    if all(v is vals[0] for v in vals):
                        stack.append(vals[0])
                    else:
                        r = self._new_reg("tmp", "?")
                        phis.append(pre_ir.Phi(r, [pre_ir.PhiArgument(self.resim_exit[p][slot],
                                                              self.bid[p]) for p in preds]))
                        stack.append(r)
                if phis:
                    self.resim_phis[b] = phis
            for a in b.assignments:
                # Frame ops first: PySSA models them as fat [1..STACK_MAX] band ops
                # (also in _STACK_SHUFFLE_OPS), so the generic / shuffle paths below
                # would pop the whole stack. On the clean stack a `frame_dig` pushes
                # its resolved param/local (one value) and a `frame_bury` pops one.
                if a.op == "frame_dig":
                    out0 = a.outputs[0] if a.outputs else None
                    # A k>=0 pushed local read cross-block (frame_resolution routed
                    # it through shuffle_src): resolve via value() so the value
                    # carried from the defining block reaches here. Every other
                    # frame_dig keeps the plain frame_map path — widening value()
                    # to all of them re-resolves param/negative reads and diverges
                    # from the IR construction path (a bytes value into a u64 op).
                    if out0 is not None and out0 in self.frame_passthrough:
                        stack.append(self.value(out0))
                    else:
                        stack.append(self.frame_map.get(out0) or pre_ir.Undefined())
                    continue
                if a.op == "frame_bury":
                    if stack:
                        v = stack.pop()
                        self.resim_args[id(a)] = [v]
                        # frame_bury N writes the popped value INTO frame slot N —
                        # an absolute stack position (len(params)+N on the clean
                        # proto frame: args at 0..nargs-1, locals above). The pop
                        # alone modelled only the stack-top removal, not the deep
                        # write, so a later working-stack read of that slot saw the
                        # stale frame-init. Concretely a sub that arranges its
                        # return via `frame_dig k; frame_bury 0; popn …; retsub`
                        # returned the init "" instead of the computed value. Model
                        # the deep write so the slot carries the buried value.
                        toks = (a.immediates or "").split()
                        if toks:
                            try:
                                pos = len(params) + int(toks[0])
                            except ValueError:
                                pos = -1
                            if 0 <= pos < len(stack):
                                stack[pos] = v
                    continue
                if a.op in _STACK_SHUFFLE_OPS:
                    m = _shuffle_mapping(a)
                    if m is None or len(stack) < len(a.inputs):
                        continue
                    ins = [stack.pop() for _ in range(len(a.inputs))]   # top-first
                    for v in reversed([ins[k] for k in m]):
                        stack.append(v)
                    continue
                if a.op == "callsub":
                    cs = self.callsite.get(b)
                    nargs = self._sub_io(cs.target_entry)[0] if (cs and cs.target_entry) else 0
                    nargs = min(nargs, len(stack))
                    self.resim_args[id(a)] = stack[len(stack) - nargs:]      # param order
                    if nargs:
                        del stack[len(stack) - nargs:]
                    for r in self.call_results.get(b, []):
                        stack.append(r)
                    continue
                if (not a.inputs and a.outputs and all(           # const push(es)
                        getattr(o, "const_value", None) is not None for o in a.outputs)):
                    for o in reversed(a.outputs):                 # pushints/pushbytess
                        stack.append(_const(o.const_value))
                    continue
                if a.op in ("intcblock", "bytecblock", "proto"):
                    continue
                ni, _ = op_arity(a.op, a.immediates)
                ni = min(ni, len(stack))
                self.resim_args[id(a)] = [stack.pop() for _ in range(ni)]    # top-first
                if a.op not in _TERMINATOR_OPS:
                    for o in reversed([o for o in a.outputs if isinstance(o, SSAVar)]):
                        stack.append(rv(o))
            self.resim_exit[b] = stack
        for ph, slot, bp in pending:          # close loop back-edges
            if bp in self.resim_exit and slot < len(self.resim_exit[bp]):
                ph.args.append(pre_ir.PhiArgument(self.resim_exit[bp][slot], self.bid[bp]))

    def _build_block(self, bb):
        resim = bb in self.resim_blocks               # re-simulated (non-proto / main)
        phis = []
        if resim:
            phis = self.resim_phis.get(bb, [])
        elif len(bb.predecessors) > 1:
            params = list(self.form.params.get(bb, []))
            cs = self.cont_site.get(bb)
            callee_sub = self.sub_of.get(cs.target_entry) if cs else None
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                if ph in self._param_phis:
                    continue                        # non-proto arg -> param
                i = params.index(ph) if ph in params else None
                args = []
                for pred in bb.predecessors:
                    if pred not in self.bid:
                        continue
                    # A continuation's predecessor that lies *inside the callee*
                    # is the interprocedural return edge: in the pre-IR, bb is
                    # reached from the callsub block (Goto), carrying the invoke
                    # result, not from the callee. Relabel the arg to the callsub
                    # block and supply the result (or, for a value below the
                    # returns, the caller's own surviving stack value).
                    if callee_sub is not None and self.sub_of.get(pred) is callee_sub \
                            and cs.callsub_bb in self.bid:
                        res = self.call_results.get(cs.callsub_bb, [])
                        nret = len(res)
                        si = ph.stack_index
                        if 1 <= si <= nret:
                            args.append(pre_ir.PhiArgument(res[nret - si],
                                                       self.bid[cs.callsub_bb]))
                            continue
                        es = cs.callsub_bb.exit_stack or []
                        nargs = self._sub_io(cs.target_entry)[0]
                        depth = nargs + (si - nret)
                        if depth <= len(es):
                            args.append(pre_ir.PhiArgument(self.value(es[-depth]),
                                                       self.bid[cs.callsub_bb]))
                            continue
                    e = self.form.edge(pred, bb)
                    val = (e.args[i] if (e is not None and i is not None
                                         and i < len(e.args)) else None)
                    args.append(pre_ir.PhiArgument(self.value(val), self.bid[pred]))
                phis.append(pre_ir.Phi(self.reg(ph), args, comment=self._range_comment([ph])))
        ops = []
        for a in bb.assignments:
            if a.op == "frame_dig":
                continue                            # a param/local read (no op)
            if a.op == "frame_bury":
                # frame_bury DEFINES its slot (l%slot = buried value). Emit that
                # before any shuffle / resim skip below: PySSA models the bury as
                # a fat-band op, so it would otherwise be dropped and the slot's
                # later frame_dig reads go undefined. On a re-simulated block the
                # buried value is the clean resim-stack top; else the SSA operand.
                slot = _imm0(a)
                if slot is not None:
                    src = (self.resim_args[id(a)][0]
                           if resim and id(a) in self.resim_args
                           else self.value(a.inputs[0]) if a.inputs else None)
                    if src is not None:
                        tgt = self.bury_target.get(id(a)) or self._local(slot)
                        ops.append(pre_ir.Assignment([tgt], src))
                continue
            if resim and a.op in _STACK_SHUFFLE_OPS:
                continue                            # re-sim reorders the stack itself
            if self._is_routed_shuffle(a):
                continue                            # const shuffle routed to source
            if a.op == "callsub":
                cs = self.callsite.get(bb)
                target = (cs.target_name if cs and cs.target_name
                          else (a.immediates or "?"))
                # Args are passed via scratch, not callsub operands, so take the
                # caller's exit_stack top nargs in param order (es[-nargs+i]).
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
                continue
            if a.op in _TERMINATOR_OPS or a.op in ("intcblock", "bytecblock",
                                                   "proto"):
                continue
            if (not a.inputs and a.outputs and all(       # const push(es): inlined
                    getattr(o, "const_value", None) is not None for o in a.outputs)):
                continue
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
        return pre_ir.BasicBlock(id=self.bid[bb], phis=phis, ops=ops,
                             terminator=self.control(bb), comment=f"L{bb.first_line}")

    def _ssa_type(self, o, depth=0):
        """Type an SSA operand by its producing op, tracing scratch loads
        through the reaching-def to the stored value's type, and frame reads
        through to the param/local register they map to."""
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
