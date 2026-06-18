"""In-place structural rewrites over the pre-IR (:mod:`pre_ir`) — phi / block
cleanup and out-of-SSA prep, as distinct from :mod:`type_recovery` (types only).

:func:`prune_dead_phis`, :func:`isolate_cross_group_phis` and
:func:`materialize_phi_consts` run during :class:`lift._Lifter` build;
:func:`simplify_trivial_phis` runs in :func:`to_puya_ir.to_puya` before lowering.
See each function for details.
"""
from __future__ import annotations

import copy as _copy

from . import pre_ir
from .optypes import avm


def _intr(o):
    """The :class:`pre_ir.Intrinsic` an op wraps (IntrinsicOp.intrinsic or an
    Assignment whose source is one), else None."""
    if isinstance(o, pre_ir.IntrinsicOp):
        return o.intrinsic
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
        return o.source
    return None


def _succ_ids(t) -> list:
    """Successor block ids of a terminator."""
    if isinstance(t, pre_ir.Goto):
        return [t.target]
    if isinstance(t, pre_ir.ConditionalBranch):
        return [t.non_zero, t.zero]
    if isinstance(t, pre_ir.Switch):
        return [b for _, b in t.cases] + [t.default]
    if isinstance(t, pre_ir.GotoNth):
        return list(t.blocks) + [t.default]
    return []


def sink_mixed_phi_scratch_stores(subs) -> int:
    """Eliminate a mixed-AVM-type phi (the reused-slot artifact: a slot the source
    register-allocator packed two disjoint-live variables into, merged at a CFG
    join) by SINKING the scratch store it feeds into its predecessors, rather than
    dropping the store. Scratch is gload-readable across the atomic group, so a
    store with no in-program load is NOT dead -- a sibling transaction may read it
    -- and must be preserved; only the typing of the merge value is the problem.

    For a phi ``p = φ(v_i @ P_i)`` whose ONLY uses are scratch ``store N <p>`` ops,
    replace each with per-predecessor ``store N <v_i>`` appended to P_i (each v_i is
    the value on that edge, single-typed), then drop the phi. The mixed-type merge
    never forms. Returns the number of phis sunk.

    Guards (else the phi is left to fail loudly, never silently mis-stored):
      * every use of p is a scratch store (no copy / op / terminator / phi use);
      * every predecessor of p's block branches ONLY to it (no critical edge), so
        appending to the predecessor runs exactly on the edge into the merge;
      * each store is reachable from the phi block by a UNIQUE single-predecessor
        chain with no load/store of that slot before it -- so moving the write to
        the edge changes neither an in-program read nor the slot's final value
        (the only thing a cross-group gload observes).
    """
    blocks = list(pre_ir.blocks(subs))
    by_id = {b.id: b for b in blocks}
    preds: dict = {b.id: [] for b in blocks}
    for b in blocks:
        for tgt in _succ_ids(b.terminator):
            preds.setdefault(tgt, []).append(b.id)

    def chain_to(sb_id, b_id):
        """Block ids [b_id .. sb_id] if a unique single-pred chain links them."""
        chain = [sb_id]
        cur = sb_id
        while cur != b_id:
            ps = preds.get(cur, [])
            if len(ps) != 1 or len(chain) > 4096:
                return None
            cur = ps[0]
            chain.append(cur)
        return chain                          # sb .. b (order doesn't matter here)

    def slot_touched(chain, sb, store_idx, slot):
        """A static load/store of ``slot``, or ANY dynamic scratch op, on the chain
        before the store (dynamic loads/stores could touch any slot)."""
        for bid in chain:
            b = by_id[bid]
            ops = b.ops[:store_idx] if b is sb else b.ops
            for o in ops:
                s = _intr(o)
                if not isinstance(s, pre_ir.Intrinsic):
                    continue
                if s.op in ("loads", "stores"):
                    return True               # dynamic slot -- can't prove safe
                if s.op in ("load", "store") and s.immediates and str(s.immediates[0]) == slot:
                    return True
        return False

    n = 0
    for B in blocks:
        for ph in list(B.phis):
            tys = {avm(a.value.ir_type) for a in ph.args
                   if isinstance(a.value, pre_ir.Register)} - {"?"}
            if len(tys) < 2:
                continue                      # not mixed-AVM
            # collect p's stores; bail on any non-store use
            stores = []                        # (block, op_index, slot, intrinsic)
            other = False
            for bb in blocks:
                for i, o in enumerate(bb.ops):
                    s = _intr(o)
                    if (isinstance(s, pre_ir.Intrinsic) and s.op == "store"
                            and s.args and s.args[0] is ph.register):
                        stores.append((bb, i, str(s.immediates[0]), s))
                    elif s is not None and any(a is ph.register for a in s.args):
                        other = True
                    elif isinstance(o, pre_ir.Assignment) and o.source is ph.register:
                        other = True
                for ph2 in bb.phis:
                    if any(a.value is ph.register for a in ph2.args):
                        other = True
                for v in pre_ir.operands(bb.terminator):
                    if v is ph.register:
                        other = True
            if other or not stores:
                continue
            if not all(set(_succ_ids(by_id[p].terminator)) == {B.id}
                       for p in preds.get(B.id, [])):
                continue                      # a predecessor has a critical edge
            chains = []
            ok = True
            for (sb, idx, slot, s) in stores:
                ch = chain_to(sb.id, B.id)
                if ch is None or slot_touched(ch, sb, idx, slot):
                    ok = False
                    break
                chains.append(ch)
            if not ok:
                continue
            # SINK: per predecessor, store that edge's value to each slot.
            arg_of = {a.through: a.value for a in ph.args}
            for p in preds.get(B.id, []):
                vi = arg_of.get(p)
                if vi is None:
                    ok = False
                    break
                for (sb, idx, slot, s) in stores:
                    by_id[p].ops.append(pre_ir.IntrinsicOp(
                        pre_ir.Intrinsic("store", [slot], [vi])))
            if not ok:
                continue
            for (sb, idx, slot, s) in stores:
                sb.ops = [o for o in sb.ops if _intr(o) is not s]
            B.phis = [x for x in B.phis if x is not ph]
            n += 1
    return n


def _vkey(v):
    """Value-identity key: registers by object identity, constants by value."""
    if isinstance(v, pre_ir.Register):
        return ("r", id(v))
    if isinstance(v, pre_ir.UInt64Constant):
        return ("u", v.value)
    if isinstance(v, pre_ir.BytesConstant):
        return ("b", v.value)
    return ("o", id(v))


def simplify_trivial_phis(program: pre_ir.Program) -> int:
    """Collapse trivial phis to a fixpoint. A phi is trivial when, ignoring
    arguments that reference its own register (loop self-edges), all remaining
    arguments are the same value -- then the phi *is* that value. Returns the
    number removed."""
    repl: dict = {}

    def resolve(v, _seen=None):
        seen = _seen if _seen is not None else set()
        while isinstance(v, pre_ir.Register) and id(v) in repl and id(v) not in seen:
            seen.add(id(v))
            v = repl[id(v)]
        return v

    changed = True
    while changed:                       # fixpoint: a collapse can expose more
        changed = False
        for b in pre_ir.blocks(program):
            for phi in b.phis:
                if id(phi.register) in repl:
                    continue
                distinct = {}
                for a in phi.args:
                    v = resolve(a.value)
                    if isinstance(v, pre_ir.Register) and v is phi.register:
                        continue          # self-reference
                    distinct[_vkey(v)] = v
                if len(distinct) <= 1:
                    repl[id(phi.register)] = (next(iter(distinct.values()))
                                              if distinct else pre_ir.Undefined())
                    changed = True
    if not repl:
        return 0

    for b in pre_ir.blocks(program):
        b.phis = [phi for phi in b.phis if id(phi.register) not in repl]

    for b in pre_ir.blocks(program):           # copy_source=False: don't forward a
        for node in (*b.phis, *b.ops, b.terminator):   # copy's source into a
            pre_ir.map_operands(node, resolve, copy_source=False)  # removed phi reg
    return len(repl)



def prune_dead_phis(subs) -> None:
    """Drop phis not reachable (through phi args) from a real use — i.e. the
    frame stack-model phis, now that frame ops no longer consume them. Forward
    liveness: seed from ops / control / returns (NOT phi args, and NOT ``pop`` /
    ``popn`` operands), then propagate backward through phi arguments; keep only
    live phis.

    ``pop`` / ``popn`` are stack-discipline drops — in value-based IR a discard is
    not a real use, so a phi feeding ONLY a ``popn`` is dead (the value is thrown
    away). Counting the discard as a use keeps such phis artificially live; for a
    frame's dead locals (``popn``-d before ``retsub``) that revives a genuinely
    mixed-AVM-type merge Puya's typed IR then rejects. Operands a pruned phi left
    dangling in a ``pop`` / ``popn`` are trimmed so no operand references a removed
    register (the discard itself is dropped at lowering)."""
    live: set = set()
    phi_by_reg: dict = {}
    for b in pre_ir.blocks(subs):
        for phi in b.phis:
            phi_by_reg[id(phi.register)] = phi

    def is_discard(node):
        intr = _intr(node)
        return isinstance(intr, pre_ir.Intrinsic) and intr.op in ("pop", "popn")

    for b in pre_ir.blocks(subs):            # seed from ops / terminator, NOT phis
        for node in (*b.ops, b.terminator):
            if is_discard(node):
                continue                     # a discard is not a real use
            for v in pre_ir.operands(node):
                if isinstance(v, pre_ir.Register):
                    live.add(id(v))
    work = list(live)
    while work:
        phi = phi_by_reg.get(work.pop())
        if phi is None:
            continue
        for pa in phi.args:
            if isinstance(pa.value, pre_ir.Register) and id(pa.value) not in live:
                live.add(id(pa.value))
                work.append(id(pa.value))
    removed = {rid for rid in phi_by_reg if rid not in live}
    for b in pre_ir.blocks(subs):
        b.phis = [phi for phi in b.phis if id(phi.register) in live]
        for node in b.ops:                   # trim pruned regs out of pop / popn
            intr = _intr(node) if is_discard(node) else None
            if intr is not None:
                intr.args = [a for a in intr.args
                             if not (isinstance(a, pre_ir.Register) and id(a) in removed)]


def _subst_value(v, m: dict):
    """Replace a Register operand per the id -> Value map (else unchanged)."""
    return m.get(id(v), v) if isinstance(v, pre_ir.Register) else v


def _subst_block(bb, m: dict) -> None:
    """Apply the substitution map to every operand position in a block."""
    def sub(v):
        return _subst_value(v, m)
    for node in (*bb.phis, *bb.ops, bb.terminator):
        pre_ir.map_operands(node, sub)


def isolate_cross_group_phis(subs) -> int:
    """Resolve passthrough values PySSA shares across subroutine groups; returns
    the phis dropped (loop: a passthrough can chain to another).

    Caller stack surviving a call (below the args, untouched by the callee,
    re-emerging in the continuation) becomes ONE phi at the callee entry merged
    across all callers -- so its register is used in a different group than it's
    defined in, invalid for Puya and the source of cross-family phi conflicts.
    Each caller already supplies its own value as the arg from its callsub block;
    resolve every cross-group use to that arg and drop the orphaned phi."""
    phi_by_reg: dict = {}                # id(register) -> (group, phi)
    blocks_of: dict = {}                 # id(group) -> {pre-IR block ids}
    for g in subs:
        blocks_of[id(g)] = {bb.id for bb in g.body}
        for bb in g.body:
            for ph in bb.phis:
                phi_by_reg[id(ph.register)] = (g, ph)
    removed: set = set()
    for b_group in subs:
        used: set = set()
        for bb in b_group.body:              # uses in ops / terminator, NOT phis
            for node in (*bb.ops, bb.terminator):
                for v in pre_ir.operands(node):
                    if isinstance(v, pre_ir.Register):
                        used.add(id(v))
        sub_map: dict = {}
        for rid in used:
            entry = phi_by_reg.get(rid)
            if entry is None or entry[0] is b_group:
                continue                     # not a phi, or same group -- fine
            ph = entry[1]
            # the value this group itself supplied: the phi arg flowing in from
            # one of its own (callsub) blocks. Exactly one => unambiguous.
            mine = [a.value for a in ph.args if a.through in blocks_of[id(b_group)]]
            if len(mine) == 1:
                sub_map[rid] = mine[0]
                removed.add(rid)
        if sub_map:
            for bb in b_group.body:
                _subst_block(bb, sub_map)
    if removed:
        for bb in pre_ir.blocks(subs):
            bb.phis = [ph for ph in bb.phis
                       if id(ph.register) not in removed]
    return len(removed)


def materialize_phi_consts(prog) -> None:
    """Puya requires phi arguments to be registers, so a phi merging a constant
    on some edge (a path-dependent literal) needs that constant materialized: a
    ``let r = <const>`` at the end of the through block, with the phi arg pointing
    at ``r``. (Without this the translator silently drops the const arg, leaving
    the phi short an operand vs its predecessors.)

    The materialized register takes the phi's AVM type, so a const whose family
    DISAGREES with it (a dead coarse-SSA placeholder -- e.g. an empty ``""`` on an
    edge of a uint64-resolved phi) is coerced to that type first; otherwise
    ``let pc: uint64 = <bytes>`` fails Puya's assignment check (same cross-family
    fix `_reconcile_mixed_phis` applies to phi-arg registers)."""
    from .type_recovery import _itob_const, _to_u64_const
    block_by_id: dict = {}
    for bb in pre_ir.blocks(prog):
        block_by_id[bb.id] = bb
    n = 0
    for bb in pre_ir.blocks(prog):
        for ph in bb.phis:
            for arg in ph.args:
                if isinstance(arg.value, pre_ir.Register):
                    continue
                through = block_by_id.get(arg.through)
                if through is None:
                    continue
                ty = ph.register.ir_type
                if ty == "?":
                    ty = ("uint64" if isinstance(arg.value, pre_ir.UInt64Constant)
                          else "bytes")
                val = arg.value
                if avm(ty) == "u" and isinstance(val, pre_ir.BytesConstant):
                    val = _to_u64_const(val)
                elif avm(ty) == "b" and isinstance(val, pre_ir.UInt64Constant):
                    val = _itob_const(val.value)
                r = pre_ir.Register(f"pc%{n}", 0, ty)
                n += 1
                through.ops.append(pre_ir.Assignment([r], val))
                arg.value = r


def _remap_succ_ids(t, idmap: dict) -> None:
    """Rewrite a terminator's successor block ids in place via ``idmap``."""
    if isinstance(t, pre_ir.Goto):
        t.target = idmap.get(t.target, t.target)
    elif isinstance(t, pre_ir.ConditionalBranch):
        t.non_zero = idmap.get(t.non_zero, t.non_zero)
        t.zero = idmap.get(t.zero, t.zero)
    elif isinstance(t, pre_ir.Switch):
        t.cases = [(k, idmap.get(b, b)) for k, b in t.cases]
        t.default = idmap.get(t.default, t.default)
    elif isinstance(t, pre_ir.GotoNth):
        t.blocks = [idmap.get(b, b) for b in t.blocks]
        t.default = idmap.get(t.default, t.default)


def _clone_subroutine(callee, new_id: str, rets: list, base_bid: int):
    """Deep-copy ``callee`` as a new subroutine ``new_id`` returning ``rets``.

    Body block ids are renumbered from ``base_bid`` (global-unique, like the
    lift's own ids) and every terminator / phi-arg predecessor reference is
    remapped; the return value registers are retyped and the retype propagated
    over the clone's copies / phis. The clone's registers are FRESH (deep copy),
    so the original subroutine is untouched."""
    body = _copy.deepcopy(callee.body)
    params = _copy.deepcopy(callee.parameters)
    idmap = {bb.id: base_bid + i for i, bb in enumerate(body)}
    for bb in body:
        bb.id = idmap[bb.id]
        _remap_succ_ids(bb.terminator, idmap)
        for ph in bb.phis:
            for a in ph.args:
                a.through = idmap.get(a.through, a.through)
    for bb in body:
        t = bb.terminator
        if isinstance(t, pre_ir.SubroutineReturn):
            for i, v in enumerate(t.result):
                if (i < len(rets) and isinstance(v, pre_ir.Register)
                        and avm(rets[i]) in ("u", "b")):
                    v.ir_type = rets[i]
    clone = pre_ir.Subroutine(id=new_id, parameters=params,
                              returns=list(rets), body=body)
    from . import type_recovery               # settle the retype within the clone
    type_recovery._propagate_copy_types([clone])
    type_recovery._unify_phi_types([clone])
    return clone


def specialize_polymorphic_returns(prog) -> int:
    """Clone a subroutine called with conflicting result AVM types.

    Hand-written / non-Puya contracts often have ONE generic state accessor --
    ``get(app, key) = app_global_get_ex; …; retsub`` -- called for keys of
    different types: ``position`` / ``side`` hold uint64, ``escrow_cancel_address``
    holds a bytes address. The sub passes the raw (untyped) state value through,
    so its single Puya return type can't be both: ``_unify_call_returns`` pins one
    and the other callsite's ``cr = invoke(...)`` fails Puya's assignment type
    check (uint64 source into a bytes target). Specialize -- for each callsite
    whose result type clashes (a concrete uint64/bytes family disagreement) with
    the callee's declared return, route it to a per-return-type CLONE of the
    callee. Behaviour-preserving: a pass-through value lowers identically whether
    the register is typed bytes or uint64; only the type annotation differs.
    Returns the number of clones created."""
    sub_by_id = {s.id: s for s in prog.subroutines}
    next_bid = max((b.id for b in pre_ir.blocks(prog)), default=0) + 1
    clones: dict = {}                          # (callee_id, want-tuple) -> clone_id
    made = 0
    for bb in pre_ir.blocks(prog):
        for o in bb.ops:
            if not (isinstance(o, pre_ir.Assignment)
                    and isinstance(o.source, pre_ir.InvokeSubroutine)):
                continue
            callee = sub_by_id.get(o.source.target)
            if callee is None or len(o.targets) != len(callee.returns):
                continue
            want = tuple(t.ir_type for t in o.targets)
            clash = any(avm(w) in ("u", "b") and avm(h) in ("u", "b")
                        and avm(w) != avm(h)
                        for w, h in zip(want, callee.returns))
            if not clash:
                continue
            key = (callee.id, want)
            cid = clones.get(key)
            if cid is None:
                rets = [w if avm(w) in ("u", "b") else h
                        for w, h in zip(want, callee.returns)]
                sig = "".join(avm(r) if avm(r) in ("u", "b") else "x" for r in rets)
                cid = f"{callee.id}__{sig}"
                while cid in sub_by_id:        # avoid an id collision
                    cid += "_"
                clone = _clone_subroutine(callee, cid, rets, next_bid)
                next_bid += len(callee.body)
                prog.subroutines.append(clone)
                sub_by_id[cid] = clone
                clones[key] = cid
                made += 1
            o.source.target = cid
    return made


def _block_registers(b):
    """Every Register that appears anywhere in a block (phi reg / args, op
    targets / operands, terminator operands)."""
    for ph in b.phis:
        yield ph.register
        for a in ph.args:
            if isinstance(a.value, pre_ir.Register):
                yield a.value
    for o in b.ops:
        for t in getattr(o, "targets", None) or []:
            yield t
        for v in pre_ir.operands(o):
            if isinstance(v, pre_ir.Register):
                yield v
    for v in pre_ir.operands(b.terminator):
        if isinstance(v, pre_ir.Register):
            yield v


def _region_defined(region_blocks) -> set:
    """ids of registers DEFINED inside a region (op targets + phi registers)."""
    defs: set = set()
    for b in region_blocks:
        for ph in b.phis:
            defs.add(id(ph.register))
        for o in b.ops:
            for t in getattr(o, "targets", None) or []:
                defs.add(id(t))
    return defs


def _fix_phi_predecessors(groups) -> None:
    """Drop phi args whose ``through`` is no longer an actual CFG predecessor of
    the block (after edges were redirected by duplication)."""
    preds: dict = {}
    for g in groups:
        for b in g.body:
            for t in _succ_ids(b.terminator):
                preds.setdefault(t, set()).add(b.id)
    for g in groups:
        for b in g.body:
            pp = preds.get(b.id, set())
            for ph in b.phis:
                kept = [a for a in ph.args if a.through in pp]
                if kept:
                    ph.args = kept


def duplicate_cross_subroutine_blocks(prog, _max_rounds: int = 12) -> int:
    """Give every subroutine a PRIVATE, self-contained body by cloning blocks it
    shares with another subroutine.

    The structure partition can leave a block reachable from / present in more
    than one subroutine -- a hand-written contract ``b``-ing into a shared
    epilogue (`retsub`) from several subs, or two subs whose bodies OVERLAP a
    common region (the same block object in both ``.body`` lists). Puya requires
    each block to belong to exactly one subroutine with all its predecessors
    there ("block@N of subroutine X has predecessor block(s) outside of list";
    and a shared object collides in ``to_puya``'s id-keyed block map). For each
    subroutine S, the blocks reachable from its entry that are OWNED by another
    sub (first sub, in [main, …] order, whose reachable set contains the block)
    are cloned PRIVATELY into S: fresh global-unique block ids (edges + phi
    predecessors remapped), and region-DEFINED registers get fresh, uniquely
    renamed copies while registers defined OUTSIDE the region stay shared (a
    deepcopy ``memo`` pre-seeded with them). S's own blocks then have their edges
    redirected to the clones and their USES of region-defined registers remapped
    to the renamed copies. Re-run to a fixpoint. Returns the region copies made."""
    made = 0
    renames = [0]                                  # global rename counter for clones
    for _ in range(_max_rounds):
        groups = [prog.main] + prog.subroutines
        bid2blk = {b.id: b for g in groups for b in g.body}

        def succ(bid):
            return [t for t in _succ_ids(bid2blk[bid].terminator) if t in bid2blk]

        reach: dict = {}
        for g in groups:
            seen, stack = set(), ([g.body[0].id] if g.body else [])
            while stack:
                x = stack.pop()
                if x in seen:
                    continue
                seen.add(x)
                stack += succ(x)
            reach[g.id] = seen
        owner: dict = {}                          # block id -> first sub whose BODY holds it
        for g in groups:                          # (physical membership, NOT mere reach, so
            for b in g.body:                      #  the kept original always physically exists)
                owner.setdefault(b.id, g.id)

        next_bid = max(bid2blk) + 1
        changed = False
        for g in groups:
            # main as a CONSUMER (it `b`s into a subroutine's body) is a different,
            # rarer pattern: the shared region ends in `retsub`, which is invalid in
            # main (it exits via ProgramExit, and a void retsub has no exit value to
            # synthesize). Don't clone into main -- leave it a clean lift-failure
            # rather than emit an invalid main. (main as an OWNER is fine: subs that
            # share main's blocks still clone them privately.)
            if g is prog.main:
                continue
            foreign = sorted(bid for bid in reach[g.id] if owner[bid] != g.id)
            if not foreign:
                continue
            changed = True
            region_blocks = [bid2blk[f] for f in foreign]
            defined = _region_defined(region_blocks)
            memo: dict = {}                       # share registers defined OUTSIDE the region
            for b in region_blocks:
                for r in _block_registers(b):
                    if id(r) not in defined:
                        memo[id(r)] = r           # external reg -> itself (not copied)
            clones = _copy.deepcopy(region_blocks, memo)
            # original region-defined reg -> its fresh clone; rename each uniquely
            # (the owner's names may already be used by S -> SSA "assigned multiple
            # times"). Object identity carries the rename through the clone.
            regmap = {rid: memo[rid] for rid in defined if rid in memo}
            for r in regmap.values():
                renames[0] += 1
                r.name = f"{r.name}~d{renames[0]}"
            idmap = {old: next_bid + i for i, old in enumerate(foreign)}
            next_bid += len(foreign)
            for nb, old in zip(clones, foreign):
                nb.id = idmap[old]
                _remap_succ_ids(nb.terminator, idmap)
                for ph in nb.phis:
                    for a in ph.args:
                        a.through = idmap.get(a.through, a.through)
            owned = [b for b in g.body if b.id not in idmap]   # drop shared originals
            g.body = owned + clones

            def _rm(v):
                return regmap.get(id(v), v) if isinstance(v, pre_ir.Register) else v

            for b in owned:                       # redirect edges + remap foreign reg uses
                _remap_succ_ids(b.terminator, idmap)
                for node in (*b.phis, *b.ops, b.terminator):
                    pre_ir.map_operands(node, _rm)
            made += 1
        if not changed:
            break
        _fix_phi_predecessors([prog.main] + prog.subroutines)
    return made
