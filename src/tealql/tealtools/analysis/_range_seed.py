"""Seed SSAVars / Phis with an :class:`IntRange` from the static AVM seed tables."""
from __future__ import annotations

from ..ssa import IntRange, SSAProgram, SSAVar, TealType, _OP_RANGE_SEEDS
from ..avm import (
    _GLOBAL_FIELD_RANGES,
    _OP_OUTPUT_SEEDS,
    _PARAMS_OPS,
    _PARAMS_VALUE_RANGES,
    _TXN_FIELD_RANGES,
    _field_type,
    _txn_field_name,
)


def propagate_ranges(prog: SSAProgram) -> None:
    UINT64 = TealType("uint64")

    def _seed(o, lo: int, hi: int) -> None:
        if isinstance(o, SSAVar) and o.range is None:
            o.range = IntRange(lo, hi)
            o.type = UINT64

    for a in prog.assignments:
        # Positional seeds bind by output INDEX, so multi-output ops must be
        # matched before the single-output rules below.
        out_seeds = _OP_OUTPUT_SEEDS.get(a.op)
        if out_seeds is not None:
            for idx, lo, hi in out_seeds:
                if idx < len(a.outputs):
                    _seed(a.outputs[idx], lo, hi)
            # *_params_get: outputs[1] is the VALUE, outputs[0] the exists-flag.
            if a.op in _PARAMS_OPS and a.immediates and len(a.outputs) > 1:
                rng = _PARAMS_VALUE_RANGES.get(a.immediates.split()[0])
                if rng is not None:
                    _seed(a.outputs[1], *rng)
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
        field = _txn_field_name(a.op, toks)
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

        # Any field DECLARED `bool` is 0 or 1. Derived from the type tables
        # rather than listed, because the bound is what the type MEANS, not a
        # spec value that a consensus upgrade could move -- unlike `MinTxnFee`
        # or `MinBalance`, which are deliberately absent from the range tables
        # for exactly that reason. Covers `global PayoutsEnabled` plus the txn
        # side (`ConfigAssetDefaultFrozen`, `FreezeAssetFrozen`,
        # `Nonparticipation`, ...), none of which were ranged before.
        if _field_type(a.op, a.immediates) == "bool":
            _seed(o, 0, 1)
            continue

    # Union arg ranges through phis to a fixed point. A phi needs EVERY arg
    # ranged — one unknown arg means the phi is unbounded, not partially bounded.
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
