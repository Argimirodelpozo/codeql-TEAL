"""Static integer-range + type seeding for SSAProgram.

Tags SSAVars / Phis with an :class:`IntRange` + uint64 type from four seed
tables — ``_OP_RANGE_SEEDS`` (op alone bounds the single output, e.g.
bool-shaped comparisons / ``getbyte`` / ``len``), ``_OP_OUTPUT_SEEDS``
(positional bounds on a *multi*-output op: the 0/1 exists-flag the
``*_get`` / ``*_ex`` family pushes, plus ``box_len``'s length),
``_TXN_FIELD_RANGES`` (enum / count-valued txn/gtxn/itxn fields) and
``_GLOBAL_FIELD_RANGES`` (``global FIELD``) — then unions arg ranges
through phis to a fixed point.

Bridged from ``SSAProgram.propagate_ranges`` (which keeps the idempotency
guard + state flag).
"""
from __future__ import annotations

from typing import Optional

from ..ssa import IntRange, SSAProgram, SSAVar, TealType, _OP_RANGE_SEEDS
from ..ssa.models import (
    _GLOBAL_FIELD_RANGES,
    _OP_OUTPUT_SEEDS,
    _TXN_FIELD_RANGES,
)


def propagate_ranges(prog: SSAProgram) -> None:
    UINT64 = TealType("uint64")

    def _seed(o, lo: int, hi: int) -> None:
        if isinstance(o, SSAVar) and o.range is None:
            o.range = IntRange(lo, hi)
            o.type = UINT64

    # Pass 1: seed from per-op rules.
    for a in prog.assignments:
        # Multi-output / positional seeds first (exists-flags on the
        # ``*_get`` / ``*_ex`` family, box_len's length) — these have >1
        # output, so they precede the single-output rules below.
        out_seeds = _OP_OUTPUT_SEEDS.get(a.op)
        if out_seeds is not None:
            for idx, lo, hi in out_seeds:
                if idx < len(a.outputs):
                    _seed(a.outputs[idx], lo, hi)
            continue

        # The remaining rules each yield exactly one stack output.
        if len(a.outputs) != 1:
            continue
        o = a.outputs[0]

        seed = _OP_RANGE_SEEDS.get(a.op)
        if seed is not None:
            _, lo, hi = seed
            _seed(o, lo, hi)
            continue

        if not a.immediates:
            continue
        toks = a.immediates.split()

        # txn-family field reads where the field carries the range.
        field: Optional[str] = None
        if a.op in ("txn", "gtxns", "itxn") and toks:
            field = toks[0]
        elif a.op in ("gtxn", "gtxna", "gtxnas") and len(toks) >= 2:
            field = toks[1]
        if field is not None:
            rng = _TXN_FIELD_RANGES.get(field)
            if rng is not None:
                _seed(o, *rng)
                continue

        # global FIELD (only enum-valued fields seed).
        if a.op == "global" and toks:
            rng = _GLOBAL_FIELD_RANGES.get(toks[0])
            if rng is not None:
                _seed(o, *rng)
                continue

    # Pass 2: union ranges through phis to fixed point. A phi gets a range
    # only if every arg has one; type unifies to uint64 only when all agree.
    changed = True
    while changed:
        changed = False
        for ph in prog.phis.values():
            if ph.range is not None or not ph.args:
                continue
            arg_ranges: list[IntRange] = []
            ok = True
            for arg in ph.args:
                r = getattr(arg, "range", None)
                if r is None:
                    ok = False
                    break
                arg_ranges.append(r)
            if not ok:
                continue
            lo = min(r.lo for r in arg_ranges)
            hi = max(r.hi for r in arg_ranges)
            ph.range = IntRange(lo, hi)
            arg_types = [getattr(arg, "type", None) for arg in ph.args]
            if all(t is not None and t.kind == "uint64" for t in arg_types):
                ph.type = UINT64
            changed = True
