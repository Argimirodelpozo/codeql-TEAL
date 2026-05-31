"""Model-level transforms over the Puya-shaped IR (:mod:`ir`).

These are the "Puya way" tiers: they rewrite the ``ir.*`` model in place, not
the text. Run between :func:`tealtools.experimental_3.lower.lower` and
``ir.Program.render()``.

- :func:`collapse_dispatch` — fold an ABI method-selector ``==``/branch chain
  into one :class:`ir.Switch` (Puya's ``switch sel {0x… => block@N, …}``).
"""
from __future__ import annotations

from . import ir


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
