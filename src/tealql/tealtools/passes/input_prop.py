"""Input propagation — unify equivalent input reads within a single
execution.

The AVM guarantees that every read of an *execution-stable* input
returns the same value within one transaction:

  - ``txn FIELD`` / ``txna FIELD i`` — current transaction's fields.
  - ``gtxn N FIELD`` / ``gtxna N FIELD i`` / ``gtxnas N FIELD`` —
    immediate-indexed group transaction.
  - ``gtxns FIELD`` / ``gtxnsa FIELD i`` / ``gtxnsas FIELD`` /
    ``gtxnas N FIELD`` / ``args`` — at least one selecting index is
    POPPED off the stack, so every popped operand is part of the key
    (``gtxnsas`` pops both the txn and the array index; ``gtxnas``
    pops the array index; ``args`` pops the arg index).
  - ``global FIELD`` — constant per execution (GroupSize, Round,
    LatestTimestamp, ...) EXCEPT ``OpcodeBudget``, which decreases as
    the program runs and so is never unified.
  - ``arg i`` — LogicSig program argument (immediate index).

Yet the SSA model treats each *syntactic* read as a fresh SSAVar.
Multiple ``txn NumAppArgs`` reads at different source lines all end
up as distinct SSAVars even though they always carry the same value.
That clutters downstream analyses — predicate sets list the same fact
once per syntactic read, must / may diff at the BB level fails to
dedupe equivalent predicates, etc.

This pass canonicalises by ``(op, immediates [, stack-key])``. The
first reader's output SSAVar becomes canonical; every subsequent
reader's output is rewired in all consumers (assignment inputs and
phi args) to point at the canonical one. The duplicate Assignment
stays in the IR but its output now has empty ``uses`` — it's
effectively dead from a value-flow perspective. Idempotent.

Mutates the SSA in place, mirroring the shape of other
``propagate_*`` passes on :class:`tealql.tealtools.ssa.SSAProgram`. Runs as
Phase A step 3 of :func:`tealql.tealtools.passes.run_all_passes` (after the
constant passes, so const-folded immediates / stack indices are
already in place when the canonical keys are composed), and is also
opt-in for analyses that want the unification without the full
pipeline (path predicates, sec-guide field-flow checks).

What is *not* propagated, deliberately, is anything that can change
within one execution:

  - ``itxn``-family reads observe the most-recently-submitted inner
    transaction, so two reads separated by ``itxn_submit`` can see
    different values.
  - application state (``app_global_get`` / ``app_local_get``) and
    ``balance`` / ``min_balance`` / asset-holding reads can be mutated
    mid-execution (``app_*_put``, inner-txn effects), so they are not
    execution-stable and never unified here.
"""
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
    "gtxns", "gtxnsa", "gtxnsas", "gtxnas", "args",
})

# ``global`` fields that are NOT execution-stable — they change as the program
# runs, so two reads can differ and must never unify.
_UNSTABLE_GLOBAL_FIELDS = frozenset({"OpcodeBudget"})


def _operand_key(operand) -> Optional[tuple]:
    """Stable hashable identifier for ``operand`` — used to compose
    the canonical key when an input op takes a popped index off the
    stack (``gtxns FIELD`` pops the index)."""
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
    """Canonical key for an input-read Assignment, or ``None`` if
    the op isn't an execution-stable input read.

    Same key ⇒ the two reads provably return the same value. Key
    composition is conservative: only literal-equal immediates and
    fully-resolved stack inputs unify; an unresolved phi-of-something
    on the stack makes the key vary and the two reads stay distinct.
    """
    op = a.op
    if op in _STABLE_INPUT_OPS_IMM_ONLY:
        if op == "global" and a.immediates.strip() in _UNSTABLE_GLOBAL_FIELDS:
            return None
        return (op, a.immediates)
    if op in _STABLE_INPUT_OPS_STACK:
        if not a.inputs:
            return None
        # Key on EVERY popped operand (an op may pop more than one index, e.g.
        # gtxnsas pops both the txn index and the array index); if any is
        # unresolved the reads stay distinct (conservative — never over-unify).
        idx_keys = tuple(_operand_key(x) for x in a.inputs)
        if any(k is None for k in idx_keys):
            return None
        return (op, a.immediates, idx_keys)
    return None


def propagate_inputs(prog: SSAProgram) -> None:
    """Walk ``prog`` once, group input reads by canonical key, and
    rewire every duplicate reader's output to the first reader's
    output in all consumer references.

    Idempotent: second call is a no-op (every duplicate output already
    has empty uses; the first-reader chain is unchanged).
    """
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
    # Rewire every consumer reference: assignment inputs first, then
    # phi args. The dead duplicate SSAVar's uses list is cleared so
    # later analyses don't accidentally walk it.
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
