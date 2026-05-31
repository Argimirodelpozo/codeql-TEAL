"""Transitive execution-stable expression propagation (+ CSE).

:mod:`tealtools.passes.input_prop` unifies the execution-stable *leaf*
reads — ``txn`` / ``txna`` / ``gtxn``-family / ``global`` / ``arg``.
This pass takes the next step: a **pure** op whose every input is
execution-stable (or a literal) computes the same value on every
execution, so it is itself execution-stable. Two syntactically-equal
stable expressions therefore always carry the same value and are
unified — common-subexpression elimination over the stable sub-DAG.

Example: once ``txn Sender`` is one canonical leaf ``V``, both
``sha256(V)`` sites collapse to a single value, as do two
``btoi(txna ApplicationArgs 0)`` reads — downstream analyses then see
one derived stable value instead of N syntactic copies.

Soundness. Stability is *seeded* only from the leaf reads
:func:`input_prop._input_key` recognises, and *grows* only through an
allowlist of pure, deterministic, state-free opcodes (arithmetic /
bitwise / comparison / logical / bytes / hash / bytemath). Everything
that can change within one execution is excluded: application-state
reads (``app_*_get``), ``balance`` / ``min_balance`` / asset-app-acct
``*_params_get``, ``itxn``-family results, and scratch ``load`` — none
are pure functions of stable leaves. Phis are excluded too: a join's
value is control-dependent, not a single stable value. An op not on the
allowlist simply doesn't propagate stability (conservative — less CSE,
never a wrong merge), and an expression with any non-stable operand
keeps its own identity (it can only ever match itself).

Run after :meth:`SSAProgram.propagate_inputs` (leaves unified) and
:meth:`SSAProgram.propagate_stack_shuffles` (so a compute op consumes
its stable operands directly rather than through ``dup`` / ``swap``
copies). Idempotent; mutates in place like the other ``propagate_*``
passes.
"""
from __future__ import annotations

from ..ssa import Const, SSAProgram, SSAVar
from .input_prop import _input_key


# Pure, deterministic, state-free, single-output opcodes: a stable input
# set yields a stable output. Conservative allowlist — omissions cost CSE
# coverage, never soundness. Stack shuffles are excluded (the shuffle pass
# copy-propagates them); so are all state / balance / param reads, the
# itxn family, scratch loads, and wide multi-output ops.
_PURE_OPS = frozenset({
    # integer arithmetic
    "+", "-", "*", "/", "%", "exp", "sqrt", "divw",
    # bitwise / shift
    "&", "|", "^", "~", "<<", ">>", "bitlen",
    # comparison
    "==", "!=", "<", ">", "<=", ">=",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
    # logical
    "&&", "||", "!",
    # byte arithmetic
    "b+", "b-", "b*", "b/", "b%", "b&", "b|", "b^", "b~", "bsqrt",
    # byte manipulation
    "concat", "substring", "substring3",
    "extract", "extract3",
    "extract_uint16", "extract_uint32", "extract_uint64",
    "replace2", "replace3", "getbyte", "setbyte", "getbit", "setbit",
    "len", "itob", "btoi", "bzero",
    # hashes (deterministic)
    "sha256", "keccak256", "sha512_256", "sha3_256",
    # selection
    "select",
})


def _is_stable_operand(op, stable: set) -> bool:
    if isinstance(op, Const):
        return True
    if getattr(op, "const_value", None) is not None:
        return True
    return isinstance(op, SSAVar) and op in stable


def _compute_stable(prog: SSAProgram) -> set:
    """Set of SSAVars that are execution-stable: the leaf reads plus the
    pure-op closure over them."""
    stable: set = set()
    for a in prog.assignments:
        if a.outputs and isinstance(a.outputs[0], SSAVar) and _input_key(a) is not None:
            stable.add(a.outputs[0])
    changed = True
    while changed:
        changed = False
        for a in prog.assignments:
            if a.op not in _PURE_OPS or len(a.outputs) != 1:
                continue
            out = a.outputs[0]
            if not isinstance(out, SSAVar) or out in stable:
                continue
            if a.inputs and all(_is_stable_operand(i, stable) for i in a.inputs):
                stable.add(out)
                changed = True
    return stable


def _signature(operand, stable: set, cache: dict, seen: set) -> tuple:
    """Value signature of a stable operand: equal signatures ⇒ provably
    the same runtime value. Non-stable operands get an identity tag so
    they only ever match themselves."""
    if isinstance(operand, Const):
        return ("c", operand.kind, operand.value)
    cv = getattr(operand, "const_value", None)
    if isinstance(cv, Const):
        return ("c", cv.kind, cv.value)
    if isinstance(operand, SSAVar) and operand in stable:
        if operand in cache:
            return cache[operand]
        if operand in seen:  # defensive: pure stable DAG shouldn't cycle
            return ("cycle", id(operand))
        seen.add(operand)
        a = operand.defined_by
        leaf = _input_key(a) if a is not None else None
        if leaf is not None:
            sig = ("leaf",) + leaf
        elif a is not None:
            sig = (a.op, a.immediates) + tuple(
                _signature(i, stable, cache, seen) for i in a.inputs
            )
        else:
            sig = ("opaque", id(operand))
        seen.discard(operand)
        cache[operand] = sig
        return sig
    return ("opaque", id(operand))


def propagate_stable_expressions(prog: SSAProgram) -> None:
    """Unify syntactically-equal execution-stable expressions to one
    canonical SSAVar (CSE over the stable sub-DAG). Idempotent; mutates
    in place. See the module docstring for the soundness argument."""
    stable = _compute_stable(prog)
    if not stable:
        return
    cache: dict = {}
    by_sig: dict[tuple, list] = {}
    for v in stable:
        by_sig.setdefault(_signature(v, stable, cache, set()), []).append(v)

    redirects: dict = {}
    for group in by_sig.values():
        if len(group) < 2:
            continue
        canon = min(group, key=lambda v: (v.file, v.line, v.index))
        for v in group:
            if v is not canon:
                redirects[v] = canon
    if not redirects:
        return

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
