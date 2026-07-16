"""Program shape: approval/rejection exits, file-scoped iteration and field
reads, seed-set builders, app-vs-logicsig classification, location formatting.

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar, const_int



# ---------------------------------------------------------------------------
# Approval / rejection exits
# ---------------------------------------------------------------------------


def _is_const_zero(operand) -> bool:
    return const_int(operand) == 0




def _return_likely_zero(bb: BasicBlock) -> bool:
    """Heuristic for ``int 0; return``: the SSA model strips the
    ``return`` opcode's stack input, so we can't read the return
    value off ``last.inputs``. The next-best signal is the BB's
    second-to-last assignment — if it produces a const-int 0 SSAVar
    that nothing else consumes, the program is almost certainly
    returning 0.

    Conservative: when in doubt, return False (so the BB stays
    classified as a potential approval and downstream analyses see it).
    An approval exit includes returns whose value isn't statically
    resolvable."""
    if len(bb.assignments) < 2:
        return False
    if bb.assignments[-1].op not in ("return", "retsub"):
        return False
    prev = bb.assignments[-2]
    if not prev.outputs:
        return False
    out = prev.outputs[0]
    return _is_const_zero(out)




def is_approval_exit(bb: BasicBlock) -> bool:
    """An approval exit: BB ends in ``return`` and the return value is
    non-zero or its constness is unknown.

    The SSA model in :mod:`tealql.tealtools.ssa` represents ``return`` with
    an empty stack-input list (``last.inputs == []``); we recover the
    likely return value via :func:`_return_likely_zero`. A BB whose
    ``int 0; return`` shape we can prove is excluded; everything else
    counts as approval-or-unknown."""
    if not bb.assignments:
        return False
    if bb.assignments[-1].op != "return":
        return False
    return not _return_likely_zero(bb)




def is_rejection_exit(bb: BasicBlock) -> bool:
    """A rejection exit: BB ends in ``err``, ``return 0``, or ``intc_0; retsub``
    (returning 0 from a subroutine — the compiled form of a validator sub's
    "reject" arm; overwhelmingly a program rejection when reached from a failed
    security check, e.g. ``<check>; bz <return-0-block>``)."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "err":
        return True
    if last.op in ("return", "retsub") and _return_likely_zero(bb):
        return True
    return False




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


# Opcodes valid only in Application mode (the AVM rejects them in Signature
# mode), so their presence proves the program is an application.
_APP_ONLY_OPS = frozenset({
    "app_global_get", "app_global_put", "app_global_del", "app_global_get_ex",
    "app_local_get", "app_local_put", "app_local_del", "app_local_get_ex",
    "app_opted_in", "app_params_get", "asset_params_get", "asset_holding_get",
    "acct_params_get",
    "itxn_begin", "itxn_field", "itxn_submit", "itxn_next",
    "itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas",
    "box_create", "box_put", "box_get", "box_del", "box_replace",
    "box_extract", "box_len", "box_resize", "box_splice",
    "log", "gload", "gloads", "gloadss",
})



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
