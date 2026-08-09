"""Drop side-effect-free Assignments whose every output has zero consumers.

HAZARD: state READS stay even when dead — analyses that count where state is
touched would otherwise see a contract that never reads it. ``store`` is not
pure either: a scratch store with no in-program load is still readable across
the group via ``gload``, so it is never dead."""
from __future__ import annotations

from ..ssa import SSAProgram, SSAVar


# Side-effect-free ops whose dead instances can be removed. State reads and
# control-flow ops are deliberately absent (see module docstring).
#
# HAZARD: several members can HALT the program — `/` and `%` on a zero divisor,
# `-` on underflow, `+` / `*` on overflow, `btoi` above 8 bytes, the extract /
# getbyte / setbyte family out of range, the shifts above 63. Deleting a dead
# instance removes that halt, notably the `x / y` divide-by-zero GUARD idiom
# whose only purpose IS the panic, so path reasoning then sees executions the
# AVM would have killed. Over-approximation: findings are at worst false
# POSITIVE, never suppressed. This pass is for readable IR, not path reasoning.
_PURE_OPS: frozenset[str] = frozenset({
    # Input / context reads (canonical readers stay live by construction;
    # only duplicate post-propagate_inputs reads match here).
    "txn", "txna", "txnas",
    "gtxn", "gtxna", "gtxnas",
    "gtxns", "gtxnsa", "gtxnsas",
    "global",
    "arg", "args",
    "itxn", "itxna", "itxnas",
    "gitxn", "gitxna", "gitxnas",
    # Constant pushes.
    "intc_0", "intc_1", "intc_2", "intc_3", "intc",
    "bytec_0", "bytec_1", "bytec_2", "bytec_3", "bytec",
    "pushint", "pushbytes", "pushints", "pushbytess",
    "int",
    # Pure arithmetic and comparisons.
    "+", "-", "*", "/", "%",
    "b+", "b-", "b*", "b/", "b%",
    "==", "!=", "<", "<=", ">", ">=",
    "b==", "b!=", "b<", "b<=", "b>", "b>=",
    # Logical and bitwise.
    "!", "&&", "||",
    "&", "|", "^", "~",
    "b&", "b|", "b^", "b~",
    "shl", "shr",
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
    "sqrt", "exp", "expw",
    "divw", "divmodw", "mulw", "addw",
    # Hashing.
    "sha256", "keccak256", "sha512_256", "sha3_256",
    "ed25519verify", "ed25519verify_bare",
    "ecdsa_verify", "ecdsa_pk_decompress", "ecdsa_pk_recover",
    "vrf_verify",
    # Stack shuffles.
    "dup", "dup2", "dupn", "swap", "pop", "popn",
    "uncover", "cover",
    "frame_dig",
    # Scratch loads are pure reads; the matching ``store`` ops stay live.
    "load",
})


def cleanup_unused_ssavars(prog: SSAProgram) -> int:
    """Drop dead pure Assignments in place; returns how many were removed."""
    # HAZARD: `uses` records assignment consumers only, NOT phi-arg references,
    # so a var consumed solely by a phi looks unused while being live. Dropping
    # its producer leaves the phi referencing an undefined SSAVar.
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
    prog.assignments = [a for a in prog.assignments if id(a) not in drop_ids]
    for bb in prog.blocks.values():
        bb.assignments = [a for a in bb.assignments if id(a) not in drop_ids]
    # Drop the now-orphan SSAVars from the FUNCTIONAL view so downstream value
    # walks stop seeing them. ``SSAProgram._stack_vars`` and each block's
    # ``stack_assignments`` retain the canonical AVM stream for lifting.
    prog.vars = {
        k: v for k, v in prog.vars.items()
        if v.defined_by is None or id(v.defined_by) not in drop_ids
    }
    return len(drop_ids)
