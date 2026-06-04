"""Model-level transforms over the Puya-shaped (mirror) IR (:mod:`ir`).

Rewrite the ``ir.*`` model in place. Run by :func:`to_puya_ir.to_puya` between
:func:`lift.lift` and lowering to the real ``puya.ir.models``.

- :func:`simplify_trivial_phis` — drop phis whose arguments are all the same
  value (ignoring self-references) and forward that value to every use. Puya's
  own ``copy_propagation`` asserts on a register replaced by itself, so these
  must be collapsed before lowering.
"""
from __future__ import annotations

from . import ir


def _vkey(v):
    """Value-identity key: registers by object identity, constants by value."""
    if isinstance(v, ir.Register):
        return ("r", id(v))
    if isinstance(v, ir.UInt64Constant):
        return ("u", v.value)
    if isinstance(v, ir.BytesConstant):
        return ("b", v.value)
    return ("o", id(v))


def _all_blocks(program):
    for sub in (program.main, *program.subroutines):
        for b in sub.body:
            yield b


# AVM ops with side effects (or that may trap) — never droppable even if their
# result is unused. Everything else (arithmetic, comparisons, byte ops, txn /
# state *reads*, loads, …) is pure and droppable when dead.
_SIDE_EFFECT = frozenset({
    "store", "stores", "log",
    "app_global_put", "app_local_put", "app_global_del", "app_local_del",
    "box_put", "box_del", "box_create", "box_replace", "box_resize",
    "box_splice", "itxn_begin", "itxn_next", "itxn_field", "itxn_submit",
    "gitxn_field", "assert", "return", "err", "callsub", "retsub",
})


def simplify_trivial_phis(program: ir.Program) -> int:
    """Collapse trivial phis to a fixpoint. A phi is trivial when, ignoring
    arguments that reference its own register (loop self-edges), all remaining
    arguments are the same value -- then the phi *is* that value. Returns the
    number removed."""
    repl: dict = {}

    def resolve(v, _seen=None):
        seen = _seen if _seen is not None else set()
        while isinstance(v, ir.Register) and id(v) in repl and id(v) not in seen:
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
                    if isinstance(v, ir.Register) and v is phi.register:
                        continue          # self-reference
                    distinct[_vkey(v)] = v
                if len(distinct) <= 1:
                    repl[id(phi.register)] = (next(iter(distinct.values()))
                                              if distinct else ir.Undefined())
                    changed = True
    if not repl:
        return 0

    for b in _all_blocks(program):
        b.phis = [phi for phi in b.phis if id(phi.register) not in repl]

    def fix_vp(vp):
        if isinstance(vp, (ir.Intrinsic, ir.InvokeSubroutine)):
            vp.args = [resolve(a) for a in vp.args]
        elif isinstance(vp, ir.ValueTuple):
            vp.values = [resolve(a) for a in vp.values]

    for b in _all_blocks(program):
        for phi in b.phis:
            for a in phi.args:
                a.value = resolve(a.value)
        for op in b.ops:
            if isinstance(op, ir.Assignment):
                fix_vp(op.source)
            elif isinstance(op, ir.Assert):
                op.condition = resolve(op.condition)
            elif isinstance(op, ir.IntrinsicOp):
                fix_vp(op.intrinsic)
        t = b.terminator
        if isinstance(t, ir.ConditionalBranch):
            t.condition = resolve(t.condition)
        elif isinstance(t, (ir.Switch, ir.GotoNth)):
            t.value = resolve(t.value)
        elif isinstance(t, ir.SubroutineReturn):
            t.result = [resolve(r) for r in t.result]
        elif isinstance(t, ir.ProgramExit):
            t.result = resolve(t.result)
    return len(repl)


