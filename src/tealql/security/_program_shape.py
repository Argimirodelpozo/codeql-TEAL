"""Program shape: approval/rejection exits, file-scoped iteration and field
reads, seed-set builders, app-vs-logicsig classification, location formatting.

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.avm import APP_ONLY_OPS
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar, const_int

# Exit classification is SUBSTRATE, shared with the group-shape / cross-contract
# layers that also reason over approving exits — re-exported here so detector
# bodies keep reaching it through ``common``.
from tealql.tealtools.cfg.exits import (  # noqa: F401
    is_approval_exit,
    is_rejection_exit,
    returned_zero as _return_likely_zero,
)


def _is_const_zero(operand) -> bool:
    return const_int(operand) == 0




# ---------------------------------------------------------------------------
# File-scoped iteration
#
# Most helpers below accept an optional ``file: Optional[str] = None``
# kwarg. When set, the iteration is restricted to ops/blocks whose
# ``location.file == file``. This is what lets a single
# :class:`SSAProgram` built from a multi-program directory (one program per
# dir, several .teal files inside) be analysed program-by-program by
# threading the filename through every iteration.
# ---------------------------------------------------------------------------


def file_match(loc_file: str, want: Optional[str]) -> bool:
    return want is None or loc_file == want




def has_instructions(prog: SSAProgram, *, file: Optional[str] = None) -> bool:
    """True when the program (scoped to ``file`` if given) parsed to at
    least one instruction. ABSENCE-style detectors ("no X validation
    anywhere → finding") must check this first: a degenerate program —
    empty, or fully dropped by parse diagnostics — trivially "lacks"
    every validation, and reporting a contract-shaped finding about it
    would dress up *we could not analyze this* as *this is vulnerable*."""
    return any(
        file_match(a.location.file, file) for a in prog.assignments
    )




def approving_exits(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[BasicBlock]:
    """Every BB that is an approval exit.

    Stricter than :meth:`PathPredicateAnalysis.approving_exits` — that
    method includes every ``return`` regardless of operand constness;
    here we exclude provably-zero returns.

    ``file``: restrict to BBs in this source file (basename); if None,
    every BB across the loaded program."""
    return [
        bb for bb in prog.blocks.values()
        if file_match(bb.file, file) and is_approval_exit(bb)
    ]




def txn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txn FIELD`` assignment in ``prog``. Includes the bare
    ``txn`` op only — ``gtxn``, ``itxn``, etc. are separate
    predicates."""
    return [
        a for a in prog.assignments
        if a.op == "txn" and a.immediates.strip() == field
        and file_match(a.location.file, file)
    ]




def gtxn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every group-transaction field read of ``field``, across both
    immediate-index and dynamic-index variants:

    - ``gtxn N FIELD`` / ``gtxna N FIELD I`` / ``gtxnas N FIELD``
      — group index in the first immediate, field in the second.
    - ``gtxns FIELD`` / ``gtxnsa FIELD I`` / ``gtxnsas FIELD``
      — group index popped off the stack, field in the first immediate.

    The mapping covers the ``gtxn``/``gtxns`` opcode families."""
    out: list[Assignment] = []
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        toks = a.immediates.split()
        if a.op in ("gtxn", "gtxna", "gtxnas") and len(toks) >= 2 and toks[1] == field:
            out.append(a)
        elif a.op in ("gtxns", "gtxnsa", "gtxnsas") and toks and toks[0] == field:
            out.append(a)
    return out




def global_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``global FIELD`` assignment in ``prog``."""
    return [
        a for a in prog.assignments
        if a.op == "global" and a.immediates.strip() == field
        and file_match(a.location.file, file)
    ]




def ssavar_outputs(assignments) -> set:
    """The set of :class:`SSAVar` outputs across a collection of assignments —
    the canonical "seed set" builder for the value-flow bridge."""
    return {o for a in assignments for o in a.outputs if isinstance(o, SSAVar)}




def op_output_seeds(
    prog: SSAProgram, op: str, *, file: Optional[str] = None,
) -> set:
    """SSAVar outputs of every ``op`` assignment (file-matched) — a seed set the
    flow bridge follows through scratch / phi / proto-frame."""
    return ssavar_outputs(
        a for a in prog.assignments
        if a.op == op and file_match(a.location.file, file)
    )




def _txna_reads(
    prog: SSAProgram, immediates: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txna <immediates>`` array read in ``prog`` (e.g.
    ``txna ApplicationArgs 0`` for the ABI method selector)."""
    return [
        a for a in prog.assignments
        if a.op == "txna" and a.immediates.strip() == immediates
        and file_match(a.location.file, file)
    ]




# ---------------------------------------------------------------------------
# Contract-kind classification (application vs logic signature)
#
# Several detectors validate fields of the SIGNED/authorizing transaction
# (RekeyTo / CloseRemainderTo / Fee / Lease / TypeEnum). A LOGIC SIGNATURE
# authorizes the txn it is attached to, so it must validate those fields; an
# APPLICATION does not — the caller authorizes the outer txn — so those checks
# are meaningless on the app's own call and firing them is a false positive.
# `applies_to` declares each detector's scope; this classifies the program so a
# runner can honor it without the user declaring a mode.
# ---------------------------------------------------------------------------


# The AVM spec's app-mode-only opcode set lives in ``avm.py`` (the single
# metadata home); aliased here for the detector-facing name.
_APP_ONLY_OPS = APP_ONLY_OPS



def classify_program(prog: SSAProgram, *, file: Optional[str] = None) -> str:
    """``"app"`` if the program uses any application-only OPCODE, else
    ``"logicsig"``.

    Keyed strictly on opcodes the AVM rejects in Signature mode — NOT on txn
    fields. A logic signature can be attached to an ApplicationCall txn and so
    may read ``OnCompletion`` / ``ApplicationArgs`` / ``ApplicationID`` (e.g. a
    proof-verifier lsig); those fields therefore do not prove an application and
    keying on them would misclassify that lsig class. App-only opcodes can't run
    in a logic signature, so their presence is sound. (Verified: all 229 real
    mainnet app probes still classify as ``"app"`` opcodes-only — every real app
    touches state / logs / issues inner txns.)"""
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op in _APP_ONLY_OPS:
            return "app"
    return "logicsig"




def loc(a) -> str:
    """``file:line`` formatter — the canonical location format used by
    every existing detector's ``pretty()`` output."""
    if hasattr(a, "location"):
        return f"{a.location.file}:{a.location.line}"
    if hasattr(a, "file") and hasattr(a, "first_line"):
        return f"{a.file}:{a.first_line}"
    return str(a)
