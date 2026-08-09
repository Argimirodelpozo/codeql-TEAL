"""In-place structural rewrites over the pre-IR (:mod:`pre_ir`) — phi / block
cleanup and out-of-SSA prep (types live in :mod:`type_recovery`)."""
from __future__ import annotations

import copy as _copy
import logging

from . import pre_ir
from ..language.avm import avm

logger = logging.getLogger("tealql.tealtools.lift")


def _intr(o):
    """The :class:`pre_ir.Intrinsic` an op wraps, else None."""
    if isinstance(o, pre_ir.IntrinsicOp):
        return o.intrinsic
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
        return o.source
    return None


_succ_ids = pre_ir.succ_ids              # kept: an established import for callers


def _phi_only_scratch_stores(blocks, ph):
    """The `(block, op_index, slot, intrinsic)` scratch stores of `ph.register`, or
    `None` if it has ANY other use (the value must keep flowing through the phi)."""
    stores = []                            # (block, op_index, slot, intrinsic)
    for bb in blocks:
        for i, o in enumerate(bb.ops):
            s = _intr(o)
            if (isinstance(s, pre_ir.Intrinsic) and s.op == "store"
                    and s.args and s.args[0] is ph.register):
                stores.append((bb, i, str(s.immediates[0]), s))
                continue
            # ANY other use — op arg, copy source, INVOKE arg, ValueTuple element
            # — makes sinking unsafe, so scan via pre_ir.operands: a use it misses
            # leaves a dangling ref that lowers to a typed zero.
            if any(v is ph.register for v in pre_ir.operands(o)):
                return None
        for ph2 in bb.phis:
            if any(a.value is ph.register for a in ph2.args):
                return None
        for v in pre_ir.operands(bb.terminator):
            if v is ph.register:
                return None
    return stores or None


def _stores_sinkable(stores, B, by_id, preds, chain_to, slot_touched) -> bool:
    """The sink guards: no critical edge into merge block `B`, and each store sits on
    a unique single-predecessor chain `B` UNCONDITIONALLY reaches, slot untouched."""
    if not all(set(_succ_ids(by_id[p].terminator)) == {B.id}
               for p in preds.get(B.id, [])):
        return False                      # a predecessor has a critical edge
    for (sb, idx, slot, s) in stores:
        ch = chain_to(sb.id, B.id)        # [sb, .., B] — single-predecessor chain
        if ch is None or slot_touched(ch, sb, idx, slot):
            return False
        # POST-DOMINANCE: every chain block from B down to (not including) sb needs a
        # single successor. If one could branch, the sunk store — appended to `B`'s
        # predecessors — would run on the arm that skips sb too, writing the slot on a
        # path the original never did and changing what a cross-group `gload` reads.
        if any(len(set(_succ_ids(by_id[bid].terminator))) != 1 for bid in ch[1:]):
            return False
    return True


def _apply_phi_sink(stores, B, ph, by_id, preds) -> bool:
    """Append a per-predecessor ``store slot <edge-value>`` to `B`, drop the originals
    and the phi; False with NO mutation if an edge lacks a phi arg.

    HAZARD: the no-mutation bail is what keeps it atomic — half-sinking would
    double-store the slot on the edges it did cover."""
    arg_of = {a.through: a.value for a in ph.args}
    edge_preds = preds.get(B.id, [])
    if any(arg_of.get(p) is None for p in edge_preds):
        return False                      # incomplete coverage -> atomic no-op
    for p in edge_preds:
        vi = arg_of[p]
        for (sb, idx, slot, s) in stores:
            by_id[p].ops.append(pre_ir.IntrinsicOp(
                pre_ir.Intrinsic("store", [slot], [vi])))
    for (sb, idx, slot, s) in stores:
        sb.ops = [o for o in sb.ops if _intr(o) is not s]
    B.phis = [x for x in B.phis if x is not ph]
    return True


def sink_mixed_phi_scratch_stores(subs) -> int:
    """Kill a mixed-AVM-type phi (a reused scratch slot merged at a join) by SINKING
    the scratch store it feeds into the predecessors, one single-typed store per edge.

    HAZARD: never delete the store instead. Scratch is ``gload``-readable across the
    atomic group, so a store with no in-program load is NOT dead — a sibling
    transaction may read it. A phi failing the guards is left alone, never
    mis-stored."""
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
        """A static load/store of ``slot``, or ANY dynamic scratch op (which could
        touch any slot), on the chain before the store."""
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
            # EVERY arg votes, not just Registers: this runs BEFORE
            # `materialize_phi_consts`, so a merge of raw stack cells still
            # carries its per-edge CONSTANTS (`byte "aa"` vs `int 8`), and a
            # Register-only scan sees no types at all — the mixed phi then
            # survives to materialisation, which cannot give one register two
            # types, and the lower stage rejects it.
            tys = {avm(getattr(a.value, "ir_type", "?"))
                   for a in ph.args} - {"?"}
            if len(tys) < 2:
                continue                      # not mixed-AVM
            stores = _phi_only_scratch_stores(blocks, ph)
            if stores is None:
                continue
            if not _stores_sinkable(stores, B, by_id, preds, chain_to, slot_touched):
                continue
            if _apply_phi_sink(stores, B, ph, by_id, preds):
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
    """Collapse trivial phis (all args the same value once self-edges are ignored) to
    a fixpoint; returns the number removed."""
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

    # copy_source=False: don't forward a copy's source into a removed phi register.
    for b in pre_ir.blocks(program):
        for node in (*b.phis, *b.ops, b.terminator):
            pre_ir.map_operands(node, resolve, copy_source=False)
    return len(repl)



def prune_dead_phis(subs) -> None:
    """Drop phis no real use reaches, seeding liveness from ops / terminators and
    propagating backward through phi args.

    HAZARD: ``pop`` / ``popn`` operands must NOT seed — a discard is not a use in a
    value-based IR, and counting it keeps a frame's dead locals alive, reviving
    mixed-AVM-type merges Puya's typed IR rejects. Pruned registers are trimmed back
    out of those discards so no operand references a removed register."""
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
    """Resolve a cross-group use of a callee-entry passthrough phi (invalid for Puya:
    the register is defined in another subroutine) to the caller's own arg and drop
    the orphaned phi; returns the count, so callers loop until it reaches 0."""
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
            # the phi arg flowing in from one of this group's own (callsub) blocks;
            # resolve only when there is exactly one, i.e. unambiguous.
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


def _mapped(v, m: dict):
    """``v`` mapped through ``m`` (an ``id(value) -> value`` substitution)."""
    return m.get(id(v), v)


def _clone_vp(vp, m: dict):
    """A NEW ValueProvider with every leaf Value mapped through ``m``. New
    objects, never mutation — the original block must survive verbatim for the
    next clone. Bare values map directly (frozen constants are shared)."""
    if isinstance(vp, pre_ir.Intrinsic):
        return pre_ir.Intrinsic(vp.op, list(vp.immediates),
                                [_mapped(a, m) for a in vp.args], vp.line,
                                vp.origin)
    if isinstance(vp, pre_ir.InvokeSubroutine):
        return pre_ir.InvokeSubroutine(
            vp.target, [_mapped(a, m) for a in vp.args], vp.origin)
    if isinstance(vp, pre_ir.ValueTuple):
        return pre_ir.ValueTuple([_mapped(v, m) for v in vp.values])
    return _mapped(vp, m)


def _clone_terminator(t, m: dict):
    """A NEW terminator with mapped operand values and the SAME successor ids."""
    if isinstance(t, pre_ir.Goto):
        return pre_ir.Goto(t.target)
    if isinstance(t, pre_ir.ConditionalBranch):
        return pre_ir.ConditionalBranch(_mapped(t.condition, m), t.non_zero, t.zero)
    if isinstance(t, pre_ir.GotoNth):
        return pre_ir.GotoNth(_mapped(t.value, m), list(t.blocks), t.default)
    if isinstance(t, pre_ir.Switch):
        return pre_ir.Switch(_mapped(t.value, m), list(t.cases), t.default)
    if isinstance(t, pre_ir.SubroutineReturn):
        return pre_ir.SubroutineReturn([_mapped(r, m) for r in t.result])
    if isinstance(t, pre_ir.ProgramExit):
        return pre_ir.ProgramExit(_mapped(t.result, m))
    if isinstance(t, pre_ir.Fail):
        return pre_ir.Fail(t.error_message)
    return None


def _tail_dup_preds(prog, sub, B):
    """The predecessor blocks to clone ``B`` for, or None when any guard of
    :func:`tail_duplicate_mixed_joins` fails. Guards, in order:

    * ``B`` is a real join in THIS sub (>= 2 preds, none in another sub, not
      the sub's entry, has a terminator), small enough to copy;
    * every phi arm is a value defined OUTSIDE ``B`` — no self/sibling phi
      arms (a loop header), no arm produced by ``B``'s own ops, and no
      ``Undefined`` missing-cell arms (a depth-divergent join: the phi + pc%
      representation already carries those honestly, and cloning would turn
      the marker into a nonsense computation);
    * every phi covers every pred edge;
    * nothing defined in ``B`` (phi registers or op targets) is used outside
      it — the moment a value escapes, deleting the join would need real phi
      splitting downstream, which is exactly what this pass refuses to do."""
    if B.terminator is None or not sub.body or B is sub.body[0]:
        return None
    preds = [b for b in sub.body if B.id in pre_ir.succ_ids(b.terminator)]
    if B in preds:
        # A self-loop: the clone's terminator would still target the deleted
        # join — dangling. (Usually also caught as a self-arm / escape, but
        # that relies on the phi shape; this does not.)
        return None
    if len(preds) < 2 or len(preds) > 8 or len(preds) * max(1, len(B.ops)) > 256:
        return None
    for s2 in (prog.main, *prog.subroutines):
        if s2 is sub:
            continue
        for b2 in s2.body:
            if B.id in pre_ir.succ_ids(b2.terminator):
                return None                    # shared across subs: refuse
    defined = {id(ph.register) for ph in B.phis}
    for o in B.ops:
        if isinstance(o, pre_ir.Assignment):
            defined.update(id(t) for t in o.targets)
    pred_ids = {p.id for p in preds}
    for ph in B.phis:
        covered = set()
        for a in ph.args:
            if isinstance(a.value, pre_ir.Undefined) or id(a.value) in defined:
                return None
            covered.add(a.through)
        if not pred_ids <= covered:
            return None                        # an edge with no arm: refuse
    for s2 in (prog.main, *prog.subroutines):
        for b2 in s2.body:
            if b2 is B:
                continue
            for node in (*b2.phis, *b2.ops, b2.terminator):
                if any(id(v) in defined for v in pre_ir.operands(node)):
                    return None                # a B-defined value escapes
    return preds


def tail_duplicate_mixed_joins(prog) -> int:
    """Delete a join whose ``?``-typed phi mixes AVM families by giving each
    predecessor its OWN COPY of the join block — real tail duplication, the one
    fully faithful representation of a dynamically-typed stack cell: each copy
    consumes its path's single-typed value directly, so no merge register ever
    exists and NOTHING becomes an unknown.

    Cloning is shallow for values defined outside the block (pre-IR registers
    are identity-keyed — a deep copy would sever every external reference) and
    fresh only for the block's own defs (``td%N``). Every guard failure falls
    through to :func:`split_mixed_phis`, whose per-use pick is total — so this
    pass has no completeness obligation, only a correctness one. Inert on
    compiler output: a mixed-family merge is hand-written-TEAL-only (0 of the
    231-probe corpus)."""
    n_dup = 0
    ctr = 0
    for _round in range(64):
        found = None
        for sub in (prog.main, *prog.subroutines):
            for bb in sub.body:
                if any(ph.register.ir_type == "?"
                       and len({avm(getattr(a.value, "ir_type", "?"))
                                for a in ph.args} - {"?"}) >= 2
                       for ph in bb.phis):
                    preds = _tail_dup_preds(prog, sub, bb)
                    if preds is not None:
                        found = (sub, bb, preds)
                        break
            if found:
                break
        if found is None:
            return n_dup
        sub, B, preds = found
        next_id = max(b.id for s in (prog.main, *prog.subroutines)
                      for b in s.body) + 1
        arm_of = [{a.through: a.value for a in ph.args} for ph in B.phis]
        clone_ids = []
        for P in preds:
            m: dict = {}
            for ph, arms in zip(B.phis, arm_of):
                m[id(ph.register)] = arms[P.id]
            ops = []
            for o in B.ops:
                if isinstance(o, pre_ir.Assignment):
                    tgts = []
                    for t in o.targets:
                        nt = pre_ir.Register(f"td%{ctr}", 0, t.ir_type)
                        ctr += 1
                        m[id(t)] = nt
                        prog.register_origins[id(nt)] = t
                        tgts.append(nt)
                    ops.append(pre_ir.Assignment(tgts, _clone_vp(o.source, m),
                                                 o.comment))
                elif isinstance(o, pre_ir.IntrinsicOp):
                    ops.append(pre_ir.IntrinsicOp(_clone_vp(o.intrinsic, m)))
                elif isinstance(o, pre_ir.Assert):
                    ops.append(pre_ir.Assert(_mapped(o.condition, m), o.message))
            clone = pre_ir.BasicBlock(
                id=next_id, phis=[], ops=ops,
                terminator=_clone_terminator(B.terminator, m), comment=B.comment)
            next_id += 1
            sub.body.append(clone)
            pre_ir.map_succ_ids(
                P.terminator, lambda b, _c=clone.id: _c if b == B.id else b)
            clone_ids.append(clone.id)
        # A successor phi's `through=B` arm becomes one arm per clone — its
        # value is defined ABOVE B (the escape guard), so every clone
        # contributes the same object along its own edge.
        for s2 in (prog.main, *prog.subroutines):
            for b2 in s2.body:
                for ph in b2.phis:
                    if any(a.through == B.id for a in ph.args):
                        ph.args = [
                            na for a in ph.args
                            for na in (
                                [pre_ir.PhiArgument(a.value, cid)
                                 for cid in clone_ids]
                                if a.through == B.id else [a])]
        sub.body.remove(B)
        n_dup += 1
    logger.warning("tail_duplicate_mixed_joins hit its round cap; "
                   "remaining mixed joins fall back to the per-use pick")
    return n_dup


def _use_family(node, reg, sub_returns, sub_by_id):
    """Concrete AVM families (`{"u","b"}` subset) that ``node``'s uses of ``reg``
    DEMAND, per the langspec position tables. Empty set = every position is
    any-typed (a discard, a scratch/state VALUE, a copy into an untyped
    register)."""
    from .type_recovery import _expected_type

    out: set = set()

    def _intrinsic(intr):
        for i, a in enumerate(intr.args):
            if a is reg:
                et = _expected_type(intr.op, i, intr.args, intr.immediates)
                if et is not None and avm(et) in ("u", "b"):
                    out.add(avm(et))

    if isinstance(node, pre_ir.Phi):
        if any(a.value is reg for a in node.args):
            f = avm(node.register.ir_type)
            if f in ("u", "b"):
                out.add(f)
    elif isinstance(node, pre_ir.Assignment):
        s = node.source
        if isinstance(s, pre_ir.Intrinsic):
            _intrinsic(s)
        elif isinstance(s, pre_ir.InvokeSubroutine):
            callee = sub_by_id.get(s.target)
            for i, a in enumerate(s.args):
                if a is reg and callee and i < len(callee.parameters):
                    f = avm(callee.parameters[i].register.ir_type)
                    if f in ("u", "b"):
                        out.add(f)
        elif isinstance(s, pre_ir.ValueTuple):
            for i, v in enumerate(s.values):
                if v is reg and i < len(node.targets):
                    f = avm(node.targets[i].ir_type)
                    if f in ("u", "b"):
                        out.add(f)
        elif s is reg:                        # bare copy: the target's family
            f = avm(node.targets[0].ir_type) if node.targets else "?"
            if f in ("u", "b"):
                out.add(f)
    elif isinstance(node, pre_ir.IntrinsicOp):
        _intrinsic(node.intrinsic)
    elif isinstance(node, pre_ir.Assert):
        if node.condition is reg:
            out.add("u")
    elif isinstance(node, (pre_ir.ConditionalBranch,)):
        if node.condition is reg:
            out.add("u")
    elif isinstance(node, (pre_ir.Switch, pre_ir.GotoNth)):
        if node.value is reg:
            out.add("u")
    elif isinstance(node, pre_ir.SubroutineReturn):
        for i, v in enumerate(node.result):
            if v is reg:
                f = avm(sub_returns[i]) if i < len(sub_returns) else "?"
                if f in ("u", "b"):
                    out.add(f)
    elif isinstance(node, pre_ir.ProgramExit):
        if node.result is reg:
            out.add("u")
    return out


def split_mixed_phis(prog) -> int:
    """Split a ``?``-typed phi whose args cross the AVM uint64/bytes divide into
    ONE PHI PER DEMANDED FAMILY, then point each use at the family it demands —
    the "per-use pick" for a genuinely dynamically-typed stack cell, which a
    single typed register cannot represent.

    Each family's phi keeps that family's arms VERBATIM and carries an explicit
    ``Undefined`` on the others. For a TYPED use this is EXACT under
    panic-pruning: reaching a bytes consumer along the uint64 arm is an AVM
    runtime type panic, so every execution past that use took a same-family arm
    (the shared stack walk already makes this argument for depth divergence).
    An any-typed use (``stores``, a state-put value) has no family to pick, so
    it takes the phi of the MAJORITY family and the minority arms are logged as
    explicit unknowns — the honest floor; only real tail duplication could keep
    both families' values there.

    Runs AFTER type recovery (only consumer-untypable phis are still ``?``) and
    BEFORE ``materialize_phi_consts`` (which turns the ``Undefined`` arms into
    per-edge stamped registers). Consumer-TYPED mixed phis never reach here —
    recovery already replaces their dead cross-family arms."""
    sub_by_id = {s.id: s for s in prog.subroutines}
    n_split = 0
    ctr = 0
    # A rewrite can newly MIX a downstream `?` phi (its formerly-untyped arm
    # became a typed pf% register), so iterate rounds; each round splits EVERY
    # phi that is mixed at its own split time, and a split phi is concretely
    # typed, so the `?` population shrinks monotonically — the cap is a
    # backstop, not a budget.
    for _round in range(64):
        mixed = [(sub, bb, ph)
                 for sub in (prog.main, *prog.subroutines)
                 for bb in sub.body for ph in bb.phis
                 if ph.register.ir_type == "?"
                 and len({avm(getattr(a.value, "ir_type", "?"))
                          for a in ph.args} - {"?"}) >= 2]
        if not mixed:
            return n_split
        for sub, bb, ph in mixed:
            ctr = _split_one_mixed_phi(prog, sub_by_id, sub, bb, ph, ctr)
            n_split += 1
    logger.warning("split_mixed_phis did not converge; a mixed phi may remain")
    return n_split


def _split_one_mixed_phi(prog, sub_by_id, sub, bb, ph, ctr) -> int:
    """Split ONE mixed phi (see :func:`split_mixed_phis`); returns the advanced
    ``pf%`` name counter. Arm families are recomputed here because an earlier
    split in the same round may have retyped this phi's arguments."""
    reg = ph.register
    arm_fams = [avm(getattr(a.value, "ir_type", "?")) for a in ph.args]
    maj = ("u" if arm_fams.count("u") > arm_fams.count("b")
           else "b" if arm_fams.count("b") > arm_fams.count("u")
           else next(f for f in arm_fams if f != "?"))
    # Resolve every use NODE to one family: its demanded family when it is
    # unanimous, else the majority (a node demanding BOTH families panics on
    # every path — dead; an any-typed node has nothing to pick by).
    uses = []                                 # (node, family)
    for s2 in (prog.main, *prog.subroutines):
        for b2 in s2.body:
            for node in (*b2.phis, *b2.ops, b2.terminator):
                if node is ph or not any(
                        v is reg for v in pre_ir.operands(node)):
                    continue
                dem = _use_family(node, reg, s2.returns, sub_by_id)
                if len(dem) == 1:
                    uses.append((node, next(iter(dem))))
                else:
                    _i = _intr(node)
                    discard = (isinstance(_i, pre_ir.Intrinsic)
                               and _i.op in ("pop", "popn"))
                    if (not dem and not discard
                            and any(f not in ("?", maj) for f in arm_fams)):
                        logger.warning(
                            "mixed-type merge: an any-typed use takes the "
                            "majority (%s) phi — the minority arm(s) become "
                            "explicit unknowns; recompiled TEAL may compute "
                            "with 0 on those paths", maj)
                    elif len(dem) == 2:
                        logger.warning(
                            "mixed-type merge: one op demands BOTH AVM "
                            "families of the same value — dead on every "
                            "path; majority (%s) arm kept", maj)
                    uses.append((node, maj))
    needed = {f for _, f in uses}
    fam_reg: dict = {}
    for fam in sorted(needed):                # deterministic order
        ty = "uint64" if fam == "u" else "bytes"
        nr = pre_ir.Register(f"pf%{ctr}", 0, ty)
        ctr += 1
        args = []
        for a, af in zip(ph.args, arm_fams):
            v = a.value
            if v is reg:                      # self-loop arm follows its phi
                v = nr
            elif af == fam:
                pass                          # this family's arm, verbatim
            elif af == "?":
                # An untyped arm can serve ONE family only; give it to the
                # majority phi (stamping a `?` register is the same
                # monotonic refinement `_unify_phi_types` performs).
                if fam == maj:
                    if isinstance(v, pre_ir.Register) and v.ir_type == "?":
                        v.ir_type = ty
                else:
                    v = pre_ir.Undefined()
            else:
                v = pre_ir.Undefined()        # cross-family: explicit unknown
            args.append(pre_ir.PhiArgument(v, a.through))
        nph = pre_ir.Phi(nr, args)
        bb.phis.append(nph)
        fam_reg[fam] = nr
    for node, fam in uses:
        pre_ir.map_operands(
            node, lambda v, _r=fam_reg[fam]: _r if v is reg else v,
            copy_source=True)
    bb.phis = [p for p in bb.phis if p is not ph]
    return ctr


def materialize_phi_consts(prog) -> int:
    """Materialize a constant phi argument as a ``let r = <const>`` at the end of its
    through block, coerced to the phi's AVM type; returns the number of arms GIVEN UP
    (kept as an explicit unknown because no single register can hold them).

    HAZARD: Puya requires phi args to be registers and SILENTLY DROPS a constant one,
    leaving the phi short an operand vs its predecessors. The coercion is equally
    required: ``let pc: uint64 = <bytes>`` fails Puya's assignment check.

    The return value is a PRECISION metric, not a health one: every count is a real
    value the model stopped tracking, so it should only ever fall. It is the last
    rung of the mixed-cell ladder — whatever tail duplication and the per-use split
    could not keep lands here."""
    from .type_recovery import _itob_const, _to_u64_const
    block_by_id: dict = {}
    for bb in pre_ir.blocks(prog):
        block_by_id[bb.id] = bb
    n = given_up = 0
    for bb in pre_ir.blocks(prog):
        for ph in bb.phis:
            if all(isinstance(a.value, pre_ir.Register) for a in ph.args):
                continue
            ty = ph.register.ir_type
            undecided = ty == "?"
            if undecided:
                # No consumer typed this phi, so decide ONCE for the whole
                # phi — majority AVM family of the args, tie to the first
                # concrete one — and STAMP it on the register. The old per-arg
                # guess gave one phi differently-typed args (`byte "aa"` vs
                # `int 8` at a join both stores to scratch), which no register
                # can carry, and Puya's phi check rejected the lift.
                fams = [avm(getattr(a.value, "ir_type", "?")) for a in ph.args]
                conc = [f for f in fams if f != "?"]
                fam = (("u" if conc.count("u") > conc.count("b") else
                        "b" if conc.count("b") > conc.count("u") else conc[0])
                       if conc else "u")   # residual unknown: translation's default
                ty = "uint64" if fam == "u" else "bytes"
                ph.register.ir_type = ty
            for arg in ph.args:
                if isinstance(arg.value, pre_ir.Register):
                    # A register arm is normally already the right type and needs no
                    # materialising — but skipping it UNCONDITIONALLY also skipped the
                    # cross-family ones, which are the only arms that cannot work. The
                    # vote above has already SEEN the disagreement (it is what made the
                    # count a tie, then broke it arbitrarily with `conc[0]`), so a
                    # genuinely two-typed cell became a phi declaring one family with an
                    # arm from the other. Puya rejects that outright —
                    #   InternalError: Phi node received arguments with unexpected type(s)
                    # — and the whole lift dies.
                    if avm(getattr(arg.value, "ir_type", "?")) in ("?", avm(ty)):
                        continue
                    # Same policy as the undecided case below: an explicit unknown of the
                    # phi's own type. Coercing (itob/btoi) would assert a plausible WRONG
                    # value on a path that may be live, and failing the lift costs every
                    # analysis downstream. The warning is the point — a real loss of
                    # precision on that arm, announced rather than silently repaired.
                    through = block_by_id.get(arg.through)
                    if through is None:
                        continue
                    logger.warning(
                        "mixed-type merge: arm %s of a %s phi is cross-family — kept as an "
                        "explicit unknown; that path's value is not modelled",
                        arg.value, ty)
                    given_up += 1
                    r = pre_ir.Register(f"pc%{n}", 0, ty)
                    n += 1
                    through.ops.append(pre_ir.Assignment([r], pre_ir.Undefined(ir_type=ty)))
                    arg.value = r
                    continue
                through = block_by_id.get(arg.through)
                if through is None:
                    continue
                val = arg.value
                if undecided and avm(getattr(val, "ir_type", "?")) not in ("?", avm(ty)):
                    # A COIN-FLIP type with a cross-family arm: the register
                    # cannot hold that arm's value, and coercing it (itob /
                    # btoi of the constant) asserts a plausible wrong value on
                    # a path that may be live. An explicit unknown never lies.
                    logger.warning(
                        "mixed-type merge: arm %s of an untyped phi cannot be a "
                        "%s — kept as an explicit unknown; recompiled TEAL may "
                        "compute with 0 on that path", val, ty)
                    given_up += 1
                    val = pre_ir.Undefined(ir_type=ty)
                elif avm(ty) == "u" and isinstance(val, pre_ir.BytesConstant):
                    val = _to_u64_const(val)
                elif avm(ty) == "b" and isinstance(val, pre_ir.UInt64Constant):
                    val = _itob_const(val.value)
                elif isinstance(val, pre_ir.Undefined) and val.ir_type != ty:
                    # A merge arm with no value (a predecessor that arrives too
                    # shallow). Stamp the phi's settled type on it — Undefined is
                    # frozen, so replace the instance — or `let pc%N: bytes =
                    # undefined` renders as consistent while the untyped source
                    # still lowers as uint64 and fails Puya's assignment check.
                    val = pre_ir.Undefined(ir_type=ty)
                r = pre_ir.Register(f"pc%{n}", 0, ty)
                n += 1
                through.ops.append(pre_ir.Assignment([r], val))
                arg.value = r
    return given_up


def _remap_succ_ids(t, idmap: dict) -> None:
    """Rewrite a terminator's successor block ids in place via ``idmap``."""
    pre_ir.map_succ_ids(t, lambda b: idmap.get(b, b))


def _clone_subroutine(callee, new_id: str, rets: list, base_bid: int):
    """Deep-copy ``callee`` as a new subroutine ``new_id`` returning ``rets``, with
    body block ids renumbered from the global-unique ``base_bid`` and every
    terminator / phi-arg predecessor reference remapped."""
    # ONE deepcopy operation is load-bearing.  Copying ``body`` and
    # ``parameters`` separately creates two copies of every parameter register:
    # the declared parameter and an undefined look-alike consumed by the body.
    # Puya accepts their equal textual ids, but id()-keyed taint sees the body
    # value as clean.
    memo: dict = {}
    clone = _copy.deepcopy(callee, memo)
    body = clone.body
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
    clone.id = new_id
    clone.returns = list(rets)
    from . import type_recovery               # settle the retype within the clone
    type_recovery._propagate_copy_types([clone])
    type_recovery._unify_phi_types([clone])
    original_regs = [p.register for p in callee.parameters]
    original_regs.extend(r for b in callee.body for r in _block_registers(b))
    origins = {
        id(memo[id(r)]): r for r in original_regs
        if id(r) in memo and isinstance(memo[id(r)], pre_ir.Register)
    }
    return clone, origins


def specialize_polymorphic_returns(prog) -> int:
    """Route a callsite whose result AVM type clashes with the callee's declared
    return to a per-return-type CLONE of it; returns the number of clones created.

    HAZARD: legal only because the clone differs by type ANNOTATION — a value the
    callee passes through (a generic state accessor returning a raw state value)
    lowers identically whether its register is typed uint64 or bytes. Without it one
    callsite's ``cr = invoke(...)`` fails Puya's assignment type check."""
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
                clone, origins = _clone_subroutine(callee, cid, rets, next_bid)
                next_bid += len(callee.body)
                prog.subroutines.append(clone)
                prog.register_origins.update(origins)
                sub_by_id[cid] = clone
                clones[key] = cid
                made += 1
            o.source.target = cid
    return made


def _block_registers(b):
    """Every Register appearing anywhere in a block, defs and uses alike."""
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
    """Drop phi args whose ``through`` is no longer a CFG predecessor of the block."""
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
    """Give every subroutine a PRIVATE body, to a fixpoint, by cloning the blocks it
    shares with another (a hand-written contract ``b``-ing into a shared ``retsub``
    epilogue); returns the region copies made.

    HAZARD: Puya requires each block to belong to exactly one subroutine with all its
    predecessors there, and a shared block object also collides in ``to_puya``'s
    id-keyed block map. The clone is correct only under the register split the
    pre-seeded deepcopy ``memo`` enforces: region-DEFINED registers get fresh
    uniquely-renamed copies (else SSA "assigned multiple times"), while registers
    defined OUTSIDE stay SHARED."""
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
        # block id -> first sub whose BODY holds it: physical membership, NOT mere
        # reach, so the kept original always physically exists somewhere.
        owner: dict = {}
        for g in groups:
            for b in g.body:
                owner.setdefault(b.id, g.id)

        next_bid = max(bid2blk) + 1
        changed = False
        for g in groups:
            # Never clone INTO main: the shared region ends in `retsub`, invalid in a
            # main that exits via ProgramExit, so a clean lift-failure beats an
            # invalid main. (main as an OWNER is fine — subs still clone its blocks.)
            if g is prog.main:
                continue
            foreign = sorted(bid for bid in reach[g.id] if owner[bid] != g.id)
            if not foreign:
                continue
            changed = True
            region_blocks = [bid2blk[f] for f in foreign]
            defined = _region_defined(region_blocks)
            memo: dict = {}
            for b in region_blocks:
                for r in _block_registers(b):
                    if id(r) not in defined:
                        memo[id(r)] = r           # external reg -> itself, not copied
            clones = _copy.deepcopy(region_blocks, memo)
            regmap = {rid: memo[rid] for rid in defined if rid in memo}
            original_regs = {
                id(r): r for b in region_blocks for r in _block_registers(b)
            }
            prog.register_origins.update({
                id(clone): original_regs[rid]
                for rid, clone in regmap.items()
                if rid in original_regs
            })
            # `defined` is a set of id()s whose iteration order varies run-to-run, so
            # sort by stable SSA identity before numbering (keeps rendered IR diffable).
            for r in sorted(regmap.values(), key=lambda r: (r.name, r.version)):
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


def duplicate_pure_shared_sinks(prog) -> int:
    """Give every caller its own copy of a cross-routine pure control sink.

    ``duplicate_cross_subroutine_blocks`` deliberately refuses to clone a
    foreign region into main because an arbitrary region ending in ``retsub``
    would make main invalid. A compiler-shared terminal ``exit 0``/``err``
    block is different: it carries no data and can be copied exactly. Keeping
    that repair here means detector-facing pre-IR already has honest per-routine
    ownership instead of relying on Puya lowering to repair the graph later.

    A value-carrying sink needs phi/register splitting and is left alone for
    the structural validator to reject.
    """
    groups = [prog.main, *prog.subroutines]
    block_by_id = {bb.id: bb for group in groups for bb in group.body}
    if not block_by_id:
        return 0
    next_id = max(block_by_id) + 1

    def is_pure_sink(bb) -> bool:
        return (not bb.phis and not bb.ops
                and not _succ_ids(bb.terminator)
                and not any(isinstance(value, pre_ir.Register)
                            for value in pre_ir.operands(bb.terminator)))

    callers: dict[int, list] = {}
    for group in groups:
        for bb in group.body:
            for target in _succ_ids(bb.terminator):
                reached_by = callers.setdefault(target, [])
                if not any(caller is group for caller in reached_by):
                    reached_by.append(group)

    copies = 0
    for bid, caller_groups in list(callers.items()):
        bb = block_by_id.get(bid)
        if bb is None or len(caller_groups) <= 1 or not is_pure_sink(bb):
            continue
        for group in groups:
            if bb in group.body:
                group.body.remove(bb)
        for group in caller_groups:
            clone = pre_ir.BasicBlock(
                id=next_id,
                phis=[],
                ops=[],
                terminator=_copy.copy(bb.terminator),
                comment=bb.comment,
            )
            next_id += 1
            group.body.append(clone)
            for source in group.body:
                _remap_succ_ids(source.terminator, {bid: clone.id})
            copies += 1
    return copies
