"""Model-level transforms over the Puya-shaped IR (:mod:`ir`).

These are the "Puya way" tiers: they rewrite the ``ir.*`` model in place, not
the text. Run between :func:`tealtools.experimental_3.lower.lower` and
``ir.Program.render()``.

- :func:`collapse_dispatch` — fold an ABI method-selector ``==``/branch chain
  into one :class:`ir.Switch` (Puya's ``switch sel {0x… => block@N, …}``).
- :func:`simplify_trivial_phis` — drop phis whose arguments are all the same
  value (ignoring self-references) and forward that value to every use.
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


def _collect_used(x, into: set) -> None:
    if isinstance(x, ir.Register):
        into.add(id(x))
    elif isinstance(x, (ir.Intrinsic, ir.InvokeSubroutine)):
        for a in x.args:
            _collect_used(a, into)
    elif isinstance(x, ir.ValueTuple):
        for v in x.values:
            _collect_used(v, into)


def _used_registers(program) -> set:
    used: set = set()
    for b in _all_blocks(program):
        for phi in b.phis:
            for pa in phi.args:
                _collect_used(pa.value, used)
        for op in b.ops:
            if isinstance(op, ir.Assignment):
                _collect_used(op.source, used)      # source args are uses
            elif isinstance(op, ir.Assert):
                _collect_used(op.condition, used)
            elif isinstance(op, ir.IntrinsicOp):
                _collect_used(op.intrinsic, used)
        t = b.terminator
        if isinstance(t, ir.ConditionalBranch):
            _collect_used(t.condition, used)
        elif isinstance(t, (ir.Switch, ir.GotoNth)):
            _collect_used(t.value, used)
        elif isinstance(t, ir.SubroutineReturn):
            for r in t.result:
                _collect_used(r, used)
        elif isinstance(t, ir.ProgramExit):
            _collect_used(t.result, used)
    return used


def eliminate_dead_ops(program: ir.Program) -> int:
    """Drop ``let``-bindings whose source is pure and whose every target is
    unused, to a fixpoint (dropping one can orphan its inputs). Side-effecting
    statements (``ir.Assert``, ``ir.IntrinsicOp``, calls) are always kept."""
    removed = 0
    changed = True
    while changed:
        changed = False
        used = _used_registers(program)
        for b in _all_blocks(program):
            kept = []
            for op in b.ops:
                if (isinstance(op, ir.Assignment)
                        and isinstance(op.source, ir.Intrinsic)
                        and op.source.op not in _SIDE_EFFECT
                        and all(id(t) not in used for t in op.targets)):
                    removed += 1
                    changed = True
                else:
                    kept.append(op)
            b.ops = kept
    return removed


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


def _is_selector(hexval: str) -> bool:
    """A 4-byte bytes literal — the shape of an ARC4 method selector."""
    return hexval.startswith("0x") and len(hexval) == 10  # 0x + 8 hex = 4 bytes


def _selector_eq(block: ir.BasicBlock):
    """If ``block`` ends in ``goto (== <selector> <v>) ? nz : zero``, return
    ``(selector_hex, v, nz, zero, eq_op)``; else ``None``."""
    term = block.terminator
    if not isinstance(term, ir.ConditionalBranch):
        return None
    cond = term.condition
    if not isinstance(cond, ir.Register):
        return None
    for op in block.ops:
        if isinstance(op, ir.Assignment) and cond in op.targets:
            src = op.source
            if (isinstance(src, ir.Intrinsic) and src.op == "=="
                    and len(src.args) == 2):
                a, b = src.args
                if isinstance(a, ir.BytesConstant) and _is_selector(a.value):
                    return (a.value, b, term.non_zero, term.zero, op)
                if isinstance(b, ir.BytesConstant) and _is_selector(b.value):
                    return (b.value, a, term.non_zero, term.zero, op)
    return None


def collapse_dispatch(program: ir.Program) -> int:
    """Fold ABI selector ``==``/branch chains into ``ir.Switch``. Returns the
    number of chains collapsed."""
    n = 0
    for sub in (program.main, *program.subroutines):
        n += _collapse_in(sub)
    return n


def _collapse_in(sub: ir.Subroutine) -> int:
    by_id = {b.id: b for b in sub.body}
    absorbed: set = set()
    collapsed = 0
    for head in sub.body:
        if head.id in absorbed:
            continue
        info = _selector_eq(head)
        if info is None:
            continue
        head_val = info[1]
        head_eq = info[4]
        cases: list = []
        default = None
        cur = head
        while True:
            ci = _selector_eq(cur)
            if ci is None:
                default = cur.id
                break
            sel_hex, _v, nz, zero, _eq = ci
            cases.append((sel_hex, nz))
            if cur is not head:
                absorbed.add(cur.id)
            nxt = by_id.get(zero)
            if nxt is None:
                default = zero
                break
            cur = nxt
        if len(cases) < 2:           # a lone `== selector` isn't a dispatch
            continue
        head.ops = [o for o in head.ops if o is not head_eq]
        head.terminator = ir.Switch(head_val, cases, default)
        collapsed += 1
    if absorbed:
        sub.body = [b for b in sub.body if b.id not in absorbed]
    return collapsed
