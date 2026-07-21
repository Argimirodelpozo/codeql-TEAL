"""SSA cleanup — drop side-effect-free Assignments whose every output
has zero remaining consumers.

Mostly motivated by :meth:`SSAProgram.propagate_inputs`, which unifies
duplicate input reads (``txn`` / ``global`` / ``gtxn``-family) onto a
canonical SSAVar and leaves the non-canonical reader Assignments with
empty ``uses`` lists. They clutter the assignment listing without
contributing any value-flow information. This pass removes them
safely — the IR retains the canonical reader, and the SSA invariants
hold because nothing references the removed assignments.

Also catches dead pure-computation ops left behind by other passes:
``len(V)`` whose result is unused, ``concat`` whose result is unused,
arithmetic on dead values, etc.

What is *not* dropped:

  - Anything with side effects: state writes
    (``app_global_put``/``del``, ``box_*`` writes, ``store``),
    inner-txn building (``itxn_begin`` / ``field`` / ``submit``),
    ``log``, ``assert``.
  - State *reads* whose absence would lose information for analyses
    that count where state is touched (``app_global_get`` / ``box_get``
    / ``balance`` / ``app_params_get`` / ``asset_*_get`` / etc.).
    These stay in the IR even when their output goes unused.
  - Control-flow ops — terminators and branches are preserved
    independently by :meth:`SSAProgram.eliminate_dead_constants`.
  - ``load`` — scratch loads might be informative for downstream
    sec-guide passes that reason about scratch flow.

Idempotent: a second invocation finds nothing further to drop.
"""
from __future__ import annotations

from ..ssa import SSAProgram, SSAVar


# Side-effect-free ops whose dead instances can be safely removed.
# Each one computes a deterministic function of its inputs with no
# external observability beyond the result SSAVar. State reads and
# control-flow ops are deliberately absent (see module docstring).
#
# CAVEAT — several members can HALT the program: `/` and `%` on a zero divisor,
# `-` on underflow, `+` / `*` on overflow, `btoi` above 8 bytes, the
# extract / getbyte / setbyte family out of range, and the shifts above 63.
# Deleting a dead instance therefore removes a halt condition, so path
# reasoning may see executions surviving a point where the AVM would have
# panicked — notably the `x / y` divide-by-zero GUARD idiom, whose only
# purpose is the panic. That is an over-approximation (more paths considered,
# so findings are at worst false POSITIVE, never suppressed), and this pass
# exists to make rendered IR readable rather than to feed path reasoning —
# but it is a real semantic difference, not a no-op.
_PURE_OPS: frozenset[str] = frozenset({
    # Input / context reads (the canonical readers stay live by
    # construction; only duplicate post-propagate_inputs reads end
    # up matching here).
    "txn", "txna", "txnas",
    "gtxn", "gtxna", "gtxnas",
    "gtxns", "gtxnsa", "gtxnsas",
    "global",
    "arg", "args",
    "itxn", "itxna", "itxnas",
    "gitxn", "gitxna", "gitxnas",
    # Constant pushes (almost always handled earlier by
    # eliminate_dead_constants; include for completeness).
    "intc_0", "intc_1", "intc_2", "intc_3", "intc",
    "bytec_0", "bytec_1", "bytec_2", "bytec_3", "bytec",
    "pushint", "pushbytes", "pushints", "pushbytess",
    "int", "bytes",
    # Pure arithmetic and comparisons.
    "+", "-", "*", "/", "%",
    "b+", "b-", "b*", "b/", "b%",
    "==", "!=", "<", "<=", ">", ">=",
    "b==", "b!=", "b<", "b<=", "b>", "b>=",
    # Logical and bitwise.
    "!", "&&", "||",
    "&", "|", "^", "~",
    "b&", "b|", "b^", "b~",
    "<<", ">>",
    # Byte / int conversions and slicing.
    "len", "bitlen", "concat",
    "extract", "extract3",
    "substring", "substring3",
    "extract_uint16", "extract_uint32", "extract_uint64",
    "replace2", "replace3",
    "getbit", "setbit", "getbyte", "setbyte",
    "bzero",
    "itob", "btoi",
    # Math extras.
    "min", "max", "sqrt", "exp", "expw",
    "divw", "divmodw", "mulw", "addw",
    # Hashing.
    "sha256", "keccak256", "sha512_256", "sha3_256",
    "ed25519verify", "ed25519verify_bare",
    "ecdsa_verify", "ecdsa_pk_decompress", "ecdsa_pk_recover",
    "vrf_verify",
    # Stack shuffles — already side-effect-free and typically
    # marked ``.shuffled = True``.
    "dup", "dup2", "dupn", "swap", "pop", "popn",
    "uncover", "cover",
    "frame_dig",
    # Scratch loads — pure reads. After
    # :meth:`SSAProgram.propagate_scratch_values` forwards a load's
    # consumers to the unified store-source SSAVar, the load itself
    # has empty uses and can be dropped here. The corresponding
    # ``store`` ops stay live (they're side-effecting on scratch).
    "load",
})


def cleanup_unused_ssavars(prog: SSAProgram) -> int:
    """Drop side-effect-free :class:`Assignment` s whose every output
    has empty ``uses``. Mutates ``prog`` in place. Returns the number
    of assignments removed (so callers can log / verify)."""
    # A var consumed only as a phi argument has an empty ``uses`` list
    # (``uses`` records assignment consumers, not phi-arg references), yet
    # it is *live* — its value flows through the phi. Removing its producer
    # would leave the phi (and, after materialisation, every mat_phi copy)
    # referencing an undefined SSAVar. Treat phi-arg SSAVars as live.
    phi_leaf_vars = {
        arg for ph in prog.phis.values() for arg in ph.args
        if isinstance(arg, SSAVar)
    }
    drop_ids: set[int] = set()
    for a in prog.assignments:
        if not a.outputs:
            continue
        if a.op not in _PURE_OPS:
            continue
        if not all(
            isinstance(o, SSAVar) and not o.uses and o not in phi_leaf_vars
            for o in a.outputs
        ):
            continue
        drop_ids.add(id(a))
    if not drop_ids:
        return 0
    # Remove from prog.assignments + each BB's assignments list.
    prog.assignments = [a for a in prog.assignments if id(a) not in drop_ids]
    for bb in prog.blocks.values():
        bb.assignments = [a for a in bb.assignments if id(a) not in drop_ids]
    # Drop the now-orphan SSAVars from prog.vars so downstream walks
    # stop seeing them.
    prog.vars = {
        k: v for k, v in prog.vars.items()
        if v.defined_by is None or id(v.defined_by) not in drop_ids
    }
    return len(drop_ids)
