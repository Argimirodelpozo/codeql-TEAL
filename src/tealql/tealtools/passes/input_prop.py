"""Unify reads of *execution-stable* inputs onto one canonical SSAVar per
``(op, immediates [, stack-key])``.

HAZARD: unifying a read that is NOT execution-stable merges two genuinely
different values and every downstream verdict inherits the error. Excluded for
that reason: ``itxn``-family (a read after ``itxn_submit`` sees a new inner
txn), application state and ``balance`` / ``min_balance`` / asset-holding (all
mutable mid-execution), and ``global OpcodeBudget`` (decreases as it runs).
Runs after the constant passes so const-folded stack indices are in the key."""
from __future__ import annotations

from typing import Optional

from ..ssa import Assignment, Const, Phi, SSAProgram, SSAVar


# Ops whose result is execution-stable, keyed by (op, immediates) ALONE — every
# operand that selects the value is an IMMEDIATE (txn/array index).
_STABLE_INPUT_OPS_IMM_ONLY = frozenset({
    "txn", "txna",
    "gtxn", "gtxna",
    "global",
    "arg",
})

# Execution-stable, but at least one selecting operand is POPPED off the stack —
# the key must include every popped input, or reads returning different values
# unify. ``args`` pops the arg index; ``gtxnas`` pops the array index (txn index
# is immediate); ``gtxnsas`` pops BOTH the txn index and the array index.
_STABLE_INPUT_OPS_STACK = frozenset({
    "gtxns", "gtxnsa", "gtxnsas", "gtxnas", "txnas", "args",
})

# ``global`` fields that are NOT execution-stable; one home in ``avm``.
from ..avm import UNSTABLE_GLOBAL_FIELDS as _UNSTABLE_GLOBAL_FIELDS


def _operand_key(operand) -> Optional[tuple]:
    """Stable hashable identifier for a popped operand, or ``None`` if unresolvable."""
    if isinstance(operand, Const):
        return ("const", operand.kind, operand.value)
    cv = getattr(operand, "const_value", None)
    if cv is not None:
        return ("const", cv.kind, cv.value)
    if isinstance(operand, SSAVar):
        return ("var", operand.file, operand.line, operand.index)
    if isinstance(operand, Phi):
        return ("phi", operand.file, operand.line, operand.kind, operand.stack_index)
    return None


def _input_key(a: Assignment) -> Optional[tuple]:
    """Canonical key for an input-read Assignment, or ``None`` if it isn't one.

    HAZARD: same key must mean *provably* the same value. Errs toward keeping
    reads distinct — any unresolved immediate or stack operand yields ``None``
    rather than a key that might over-unify."""
    op = a.op
    if op in _STABLE_INPUT_OPS_IMM_ONLY:
        if op == "global" and a.immediates.strip() in _UNSTABLE_GLOBAL_FIELDS:
            return None
        return (op, a.immediates)
    if op in _STABLE_INPUT_OPS_STACK:
        if not a.inputs:
            return None
        # Key on EVERY popped operand — an op may pop more than one selector
        # (gtxnsas pops both the txn index and the array index), and a key
        # missing one unifies reads of different transactions.
        idx_keys = tuple(_operand_key(x) for x in a.inputs)
        if any(k is None for k in idx_keys):
            return None
        return (op, a.immediates, idx_keys)
    return None


def propagate_inputs(prog: SSAProgram) -> None:
    """Rewire every duplicate input read's consumers onto the first reader's output."""
    canonical: dict[tuple, SSAVar] = {}
    redirects: dict[SSAVar, SSAVar] = {}
    for a in prog.assignments:
        if not a.outputs:
            continue
        out = a.outputs[0]
        if not isinstance(out, SSAVar):
            continue
        key = _input_key(a)
        if key is None:
            continue
        rep = canonical.get(key)
        if rep is None:
            canonical[key] = out
        elif rep is not out:
            redirects[out] = rep
    if not redirects:
        return
    # Clearing the dead duplicate's uses keeps later analyses from walking it.
    for a in prog.assignments:
        for i, inp in enumerate(a.inputs):
            new = redirects.get(inp)
            if new is not None:
                a.inputs[i] = new
                new.uses.append(a)
    for phi in prog.phis.values():
        for i, arg in enumerate(phi.args):
            new = redirects.get(arg)
            if new is not None:
                phi.args[i] = new
    for old in redirects:
        old.uses = []
