"""Structural rewrites over the Puya-shaped pre-IR (:mod:`pre_ir`).

Each pass rewrites the ``pre_ir.*`` model in place (phi / block cleanup, out-of-SSA
prep), as distinct from :mod:`type_recovery` (which only assigns AVM types). The
:class:`lift._Lifter` build calls the first three; :func:`to_puya_ir.to_puya`
calls :func:`simplify_trivial_phis` just before lowering to ``puya.ir.models``.

- :func:`prune_dead_phis` — drop phis not reachable through phi args from a real
  use (the frame stack-model phis, once frame ops no longer consume them).
- :func:`isolate_cross_group_phis` — resolve a passthrough value PySSA shares
  across subroutine groups to each caller's own arg, then drop the orphaned phi.
- :func:`materialize_phi_consts` — give a phi merging a constant on some edge a
  ``let r = <const>`` in the through block (Puya requires phi args be registers).
- :func:`simplify_trivial_phis` — drop phis whose arguments are all the same
  value (ignoring self-references) and forward that value to every use. Puya's
  own ``copy_propagation`` asserts on a register replaced by itself, so these
  must be collapsed before lowering.
"""
from __future__ import annotations

from . import pre_ir


def _vkey(v):
    """Value-identity key: registers by object identity, constants by value."""
    if isinstance(v, pre_ir.Register):
        return ("r", id(v))
    if isinstance(v, pre_ir.UInt64Constant):
        return ("u", v.value)
    if isinstance(v, pre_ir.BytesConstant):
        return ("b", v.value)
    return ("o", id(v))


def _all_blocks(program):
    for sub in (program.main, *program.subroutines):
        for b in sub.body:
            yield b


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
        for b in _all_blocks(program):
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

    for b in _all_blocks(program):
        b.phis = [phi for phi in b.phis if id(phi.register) not in repl]

    for b in _all_blocks(program):           # copy_source=False: don't forward a
        for node in (*b.phis, *b.ops, b.terminator):   # copy's source into a
            pre_ir.map_operands(node, resolve, copy_source=False)  # removed phi reg
    return len(repl)



def prune_dead_phis(subs) -> None:
    """Drop phis not reachable (through phi args) from a real use — i.e. the
    frame stack-model phis, now that frame ops no longer consume them. Forward
    liveness: seed from ops / control / returns (NOT phi args), then propagate
    backward through phi arguments; keep only live phis."""
    live: set = set()
    phi_by_reg: dict = {}
    for sub in subs:
        for b in sub.body:
            for phi in b.phis:
                phi_by_reg[id(phi.register)] = phi
    for sub in subs:
        for b in sub.body:                   # seed from ops / terminator, NOT phis
            for node in (*b.ops, b.terminator):
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
    for sub in subs:
        for b in sub.body:
            b.phis = [phi for phi in b.phis if id(phi.register) in live]


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
    """Resolve passthrough values that PySSA shares across subroutine groups.

    A callee's entry block can carry *passthrough* phis -- caller stack that
    survives the call (it sits below the call args, is untouched by the callee,
    and re-emerges in the continuation). PySSA's whole-program stack model puts
    ONE such phi at the callee entry, merged across every caller, so its register
    ends up *used in a different subroutine group than it is defined in*. That is
    invalid for Puya (registers are per-subroutine) and the source of the
    cross-family phi conflicts (one phi merging two callers' bytes + uint64).

    Each caller already supplies its own value as the phi arg flowing in from its
    callsub block, so resolve every cross-group use to that arg and drop the now
    -unreferenced phi from the callee. Returns the number of phis dropped (so the
    caller can loop -- a passthrough value can itself be another passthrough)."""
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
        for g in subs:
            for bb in g.body:
                bb.phis = [ph for ph in bb.phis
                           if id(ph.register) not in removed]
    return len(removed)


def materialize_phi_consts(prog) -> None:
    """Puya requires phi arguments to be registers, so a phi merging a constant
    on some edge (a path-dependent literal) needs that constant materialized: a
    ``let r = <const>`` at the end of the through block, with the phi arg pointing
    at ``r``. (Without this the translator silently drops the const arg, leaving
    the phi short an operand vs its predecessors.)"""
    block_by_id: dict = {}
    for sub in [prog.main, *prog.subroutines]:
        for bb in sub.body:
            block_by_id[bb.id] = bb
    n = 0
    for sub in [prog.main, *prog.subroutines]:
        for bb in sub.body:
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
                    r = pre_ir.Register(f"pc%{n}", 0, ty)
                    n += 1
                    through.ops.append(pre_ir.Assignment([r], arg.value))
                    arg.value = r
