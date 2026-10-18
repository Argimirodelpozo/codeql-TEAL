"""Order-preserving walks over a lifted Puya IR program's ops.

One home for the ``for s in subs: for bb in s.body: for o in bb.ops`` loop the
encoded-type, storage and IR-type recoveries all repeat. Each generator yields
in exactly that nested order, so a converted loop visits the same ops in the same
sequence. Walks that interleave phis or per-sub parameters stay hand-written.
"""
from __future__ import annotations

import puya.ir.models as M


def walk_ops(subs):
    """Yield ``(sub, op)`` for every op of every block of each sub in ``subs``."""
    for s in subs:
        for bb in s.body:
            for o in bb.ops:
                yield s, o


def walk_sources(subs):
    """Yield ``(sub, op, src)`` where ``src`` is an ``Assignment``'s source and
    the op itself otherwise."""
    for s, o in walk_ops(subs):
        yield s, o, (o.source if isinstance(o, M.Assignment) else o)


def reg_defs(subs) -> dict:
    """``id(target register) -> defining Assignment`` over ``subs`` (a later
    definition of the same object overwrites, as the hand-rolled loops did)."""
    reg_def: dict = {}
    for _, o in walk_ops(subs):
        if isinstance(o, M.Assignment):
            for t in o.targets:
                reg_def[id(t)] = o
    return reg_def
