"""Program shape, file-scoped iteration, field reads, and source locations."""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.language.avm import APP_ONLY_OPS, txn_field_name
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar

# Exit classification is SUBSTRATE shared with the group-shape / cross-contract
# layers; re-exported so detector bodies still reach it through ``common``.
from tealql.tealtools.cfg.exits import (  # noqa: F401
    is_approval_exit,
    is_rejection_exit,
    returned_zero as _return_likely_zero,
)

# ---------------------------------------------------------------------------
# File-scoped iteration: the optional ``file`` kwarg below restricts iteration to
# ops/blocks whose ``location.file == file``, which is what lets one SSAProgram
# built from a multi-.teal directory be analysed program-by-program.
# ---------------------------------------------------------------------------


def file_match(loc_file: str, want: Optional[str]) -> bool:
    return want is None or loc_file == want




def has_instructions(prog: SSAProgram, *, file: Optional[str] = None) -> bool:
    """The program (scoped to ``file``) parsed to at least one instruction.

    HAZARD: ABSENCE-style detectors ("no X validation anywhere → finding") MUST
    check this first. An empty or fully parse-dropped program trivially "lacks"
    every validation, which would report "we could not analyze this" as
    "this is vulnerable"."""
    return any(
        file_match(a.location.file, file) for a in prog.assignments
    )




def approving_exits(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[BasicBlock]:
    """Every BB that is an approval exit — stricter than
    :meth:`PathPredicateAnalysis.approving_exits`, which counts every ``return``
    regardless of operand constness; provably-zero returns are excluded here."""
    return [
        bb for bb in prog.blocks.values()
        if file_match(bb.file, file) and is_approval_exit(bb)
    ]




def unguarded_entry_path_exists(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    *,
    block_closed,
    edge_closed=None,
) -> bool:
    """Some path from a PROGRAM ENTRY reaches ``exit_bb`` crossing no closed
    block (and, when ``edge_closed`` is given, no closed edge).

    THE shared backward must-cross walk — every "is this exit protected" family
    delegates here rather than re-rolling the traversal.

    HAZARD: entries come from ``prog.entry_blocks()``, never from "has no
    predecessors". TEAL's entry is the FIRST block, and both mis-derivations of
    that fact have shipped guard bugs: a self-loop entry (``main: … bnz main``)
    gives every block a predecessor, so the pred-free spelling saturates and
    reads every exit as protected with an EMPTY gate set; and an exit that IS
    the entry (a one-block always-approve program) has no predecessors at all,
    so a walk that only tests predecessors never runs and falls through to its
    default. A predecessor-less NON-first block, by contrast, is dead code — a
    "path" through it is not a real execution and does not witness anything."""
    if block_closed(exit_bb):
        return False
    entry_ids = {id(b) for b in prog.entry_blocks() if b.file == exit_bb.file}
    if id(exit_bb) in entry_ids:
        return True                # the exit IS the entry: a zero-length path
    visited_edges: set = set()
    stack: list = [exit_bb]
    seen = {id(exit_bb)}
    while stack:
        bb = stack.pop()
        for pred in bb.predecessors:
            k = (id(pred), id(bb))
            if k in visited_edges:
                continue
            visited_edges.add(k)
            if edge_closed is not None and edge_closed(pred, bb):
                continue
            if block_closed(pred):
                continue
            if id(pred) in entry_ids:
                return True
            if id(pred) not in seen:
                seen.add(id(pred))
                stack.append(pred)
    return False


def txn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txn FIELD`` assignment — the bare ``txn`` op only, not ``gtxn``/``itxn``."""
    return [
        a for a in prog.assignments
        if a.op == "txn" and a.immediates.strip() == field
        and file_match(a.location.file, file)
    ]




#: The GROUP-indexed read forms. Deliberately excludes ``txn``/``txna``/
#: ``txnas``: those read THIS program's transaction, not a sibling's.
_GROUP_FIELD_OPS = frozenset({
    "gtxn", "gtxna", "gtxnas", "gtxns", "gtxnsa", "gtxnsas",
})


def gtxn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every group-txn read of ``field``. The immediate-index family (``gtxn``,
    ``gtxna``, ``gtxnas``) carries the index first and the field second; the
    stack-index family (``gtxns``, ``gtxnsa``, ``gtxnsas``) has the field first."""
    out: list[Assignment] = []
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        # Restricted to the GROUP-read forms on purpose — `txn Sender` is this
        # program's own sender, not a sibling's. Which immediate holds the field
        # name still differs across the two families, so that part defers to the
        # one table (`avm.txn_field_name`) instead of being re-derived here.
        if a.op in _GROUP_FIELD_OPS and txn_field_name(a.op, a.immediates) == field:
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
    """:class:`SSAVar` outputs across assignments — the canonical seed-set builder."""
    return {o for a in assignments for o in a.outputs if isinstance(o, SSAVar)}




def op_output_seeds(
    prog: SSAProgram, op: str, *, file: Optional[str] = None,
) -> set:
    """SSAVar outputs of every file-matched ``op`` assignment, as a seed set."""
    return ssavar_outputs(
        a for a in prog.assignments
        if a.op == op and file_match(a.location.file, file)
    )




def _txna_reads(
    prog: SSAProgram, immediates: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txna <immediates>`` array read (e.g. ``txna ApplicationArgs 0``)."""
    return [
        a for a in prog.assignments
        if a.op == "txna" and a.immediates.strip() == immediates
        and file_match(a.location.file, file)
    ]




# ---------------------------------------------------------------------------
# Contract-kind classification. A LOGIC SIGNATURE authorizes the txn it is
# attached to, so it must validate RekeyTo / CloseRemainderTo / Fee / Lease /
# TypeEnum; an APPLICATION does not (the caller authorizes the outer txn), so
# those detectors are false positives on an app. `applies_to` declares each
# detector's scope and this classifies the program so a runner can honor it.
# ---------------------------------------------------------------------------


# Aliased for the detector-facing name; ``avm.py`` is the single metadata home.
_APP_ONLY_OPS = APP_ONLY_OPS



def classify_program(prog: SSAProgram, *, file: Optional[str] = None) -> str:
    """``"app"`` if the program uses any application-only OPCODE, else ``"logicsig"``.

    HAZARD: key on OPCODES the AVM rejects in Signature mode, never on txn FIELDS.
    A logicsig can be attached to an ApplicationCall and so may legitimately read
    ``OnCompletion``/``ApplicationArgs``/``ApplicationID``."""
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op in _APP_ONLY_OPS:
            return "app"
    return "logicsig"




def loc(a) -> str:
    """``file:line`` — the canonical location format for every detector's ``pretty()``."""
    if hasattr(a, "location"):
        return f"{a.location.file}:{a.location.line}"
    if hasattr(a, "file") and hasattr(a, "first_line"):
        return f"{a.file}:{a.first_line}"
    return str(a)
