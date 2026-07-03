"""Stack-side constant propagation for SSAProgram.

Resolves SSAVars / Phis to compile-time literals: (1) seed each SSAVar from
its defining Assignment's resolved ``const``; (2) iterate to a fixed point
over phi-arg unification, the value-identity step relation
(``g.graph["identity_steps"]``), and op-level folding (``const_fold``) so
fold→propagate→fold chains converge.

Bridged from ``SSAProgram.propagate_constants`` (which keeps the idempotency
guard + state flag).
"""
from __future__ import annotations

from ..ssa import Const, Phi, SSAProgram, SSAVar
from ..ssa.const_fold import try_fold_assignment


def propagate_constants(prog: SSAProgram) -> None:
    # Pass 1: SSAVars from their defining Assignment's resolved constant.
    for v in prog.vars.values():
        if v.defined_by is not None and v.defined_by.const is not None:
            v.const_value = v.defined_by.const

    # Pass 2: fixed point over (a) phi-arg unification, (b) the value-identity
    # step relation, and (c) op-level folding.
    steps = prog._graph.graph.get("identity_steps", []) or []

    def _resolve_endpoint(key):
        if key[0] == "var":
            _, f, l, i = key
            return prog.vars.get((f, l, i))
        _, f, l, kind, idx = key
        return prog.phis.get((f, l, kind, idx))

    # Pre-resolve endpoints once; skip steps where either side is missing.
    resolved_steps: list[tuple] = []
    for src_key, snk_key in steps:
        src = _resolve_endpoint(src_key)
        snk = _resolve_endpoint(snk_key)
        if src is not None and snk is not None and src is not snk:
            resolved_steps.append((src, snk))

    changed = True
    while changed:
        changed = False
        for phi in prog.phis.values():
            if phi.const_value is not None:
                continue
            arg_consts: list[Const] = []
            ok = True
            for arg in phi.args:
                if isinstance(arg, SSAVar):
                    cv = arg.const_value
                elif isinstance(arg, Phi):
                    cv = arg.const_value
                else:
                    cv = None
                if cv is None:
                    ok = False
                    break
                arg_consts.append(cv)
            if ok and arg_consts and all(c == arg_consts[0] for c in arg_consts):
                phi.const_value = arg_consts[0]
                changed = True
        for src, snk in resolved_steps:
            if src.const_value is not None and snk.const_value is None:
                snk.const_value = src.const_value
                changed = True
        for a in prog.assignments:
            if len(a.outputs) != 1:
                continue
            out = a.outputs[0]
            if not isinstance(out, SSAVar) or out.const_value is not None:
                continue
            folded = try_fold_assignment(a)
            if folded is not None:
                out.const_value = folded
                changed = True
