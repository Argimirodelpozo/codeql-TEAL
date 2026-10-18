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
    """Some REALIZABLE path from a PROGRAM ENTRY reaches ``exit_bb`` crossing no
    closed block (and, when ``edge_closed`` is given, no closed edge).

    THE shared must-cross walk — every "is this exit protected" family
    delegates here rather than re-rolling the traversal. Two phases: the
    backward CFG walk (cheap; "no path" is final), then, only when it finds
    one, a forward walk with a RETURN STACK restricted to the blocks the
    backward walk reached (:func:`realizable_unguarded_path_exists`) — so a
    path entering a shared helper from one call site cannot leave it through
    another call site's continuation.

    HAZARD: entries come from ``prog.entry_blocks()``, never from "has no
    predecessors". TEAL's entry is the FIRST block, and both mis-derivations of
    that fact have shipped guard bugs: a self-loop entry (``main: … bnz main``)
    gives every block a predecessor, so the pred-free spelling saturates and
    reads every exit as protected with an EMPTY gate set; and an exit that IS
    the entry (a one-block always-approve program) has no predecessors at all,
    so a walk that only tests predecessors never runs and falls through to its
    default. A predecessor-less NON-first block, by contrast, is dead code — a
    "path" through it is not a real execution and does not witness anything.

    HAZARD: the CFG's ``retsub`` edges fan out to EVERY caller's continuation;
    the backward phase alone stitches unrealizable paths through them (a
    GroupSize bound asserted before one call of a shared helper read as absent
    on another caller's exit — field class ``groupsize-bounded-on-path``)."""
    found, ancestors = _backward_open_ancestors(
        prog, exit_bb, block_closed=block_closed, edge_closed=edge_closed)
    if not found:
        return False
    return realizable_unguarded_path_exists(
        prog, exit_bb, block_closed=block_closed, edge_closed=edge_closed,
        within=ancestors)


def _backward_open_ancestors(prog, exit_bb, *, block_closed, edge_closed=None):
    """``(an entry reaches exit_bb over open CFG edges, the open ancestor ids)``."""
    if block_closed(exit_bb):
        return False, set()
    entry_ids = {id(b) for b in prog.entry_blocks() if b.file == exit_bb.file}
    seen = {id(exit_bb)}
    found = id(exit_bb) in entry_ids          # the exit IS the entry
    visited_edges: set = set()
    stack: list = [exit_bb]
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
                found = True
            if id(pred) not in seen:
                seen.add(id(pred))
                stack.append(pred)
    return found, seen


#: Return-stack depth kept by :func:`exits_reachable_through`; deeper
#: contexts fall back to every ``retsub`` successor (towards a finding).
RETURN_STACK_CAP = 8


def exits_reachable_through(
    prog: SSAProgram,
    read_bb: BasicBlock,
    exits,
    gates=frozenset(),
    *,
    site_gated=None,
    first: bool = False,
) -> list:
    """Approving ``exits`` reachable by a realizable path THROUGH ``read_bb``
    crossing no block in ``gates`` — a forward walk carrying an explicit
    RETURN STACK. With ``first`` it stops at (and returns) the first exit hit
    in DFS order; otherwise every such exit, in discovery order.

    HAZARD: the CFG's ``retsub`` edges fan out to EVERY caller's continuation.
    A read inside a helper called from two arms then "reaches" the other arm's
    exits — a path no execution takes. So the walk is per CALL SITE of the
    read's enclosing sub: it starts at the sub's entry with that site's
    continuation pushed (skipping a site in ``gates`` or for which
    ``site_gated(cs_bb)`` holds), pushes on ``callsub`` and pops on ``retsub``.
    Only an EMPTY stack (an unknown outer context, or the cap) falls back to
    every ``retsub`` successor — conservative, i.e. towards a finding."""
    from tealql.tealtools.cfg.subroutines import identify_subroutines
    subs = identify_subroutines(prog)
    bodies, conts, targets = (subs["bodies"], subs["continuations"],
                              subs["callsub_target"])
    owner = next((e for e, body in bodies.items() if read_bb in body), None)
    if owner is None:
        starts = [(read_bb, (), True)]
    else:
        starts = []
        for cs_bb, entry in targets.items():
            if entry is not owner or cs_bb in gates:
                continue
            if site_gated is not None and site_gated(cs_bb):
                continue
            starts.append((owner, (conts.get(cs_bb),), False))
    seen: set = set()
    found: list = []
    found_ids: set = set()
    stack = list(starts)
    while stack:
        bb, rstack, passed = stack.pop()
        passed = passed or bb is read_bb
        key = (id(bb), tuple(id(b) for b in rstack), passed)
        if key in seen:
            continue
        seen.add(key)
        if passed and bb in exits and id(bb) not in found_ids:
            if first:
                return [bb]
            found_ids.add(id(bb))
            found.append(bb)
        term = bb.assignments[-1].op if bb.assignments else None
        if term == "callsub" and targets.get(bb) is not None:
            tgt = targets[bb]
            new = (rstack + (conts.get(bb),))[-RETURN_STACK_CAP:]
            if tgt not in gates:
                stack.append((tgt, new, passed))
            continue
        if term == "retsub" and rstack and rstack[-1] is not None:
            if rstack[-1] not in gates:
                stack.append((rstack[-1], rstack[:-1], passed))
            continue
        rest = rstack[:-1] if term == "retsub" and rstack else rstack
        for s in bb.successors:
            if s not in gates:
                stack.append((s, rest, passed))
    return found


def realizable_unguarded_path_exists(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    *,
    block_closed,
    edge_closed=None,
    within=None,
) -> bool:
    """:func:`unguarded_entry_path_exists` over REALIZABLE paths only: a forward
    walk from the program entries carrying an explicit return stack, so a path
    that enters a helper from one call site cannot leave it through another
    call site's continuation.

    HAZARD: the CFG's ``retsub`` edges fan out to EVERY caller's continuation.
    A backward walk over them stitches a method arm that never drains onto the
    Delete arm's continuation and reports a "path" no execution takes. Only an
    EMPTY stack (unknown outer context, or the cap) falls back to every
    ``retsub`` successor — conservative, i.e. towards a finding.

    ``within`` (block ids) prunes the walk to blocks that can still reach the
    exit — :func:`unguarded_entry_path_exists` passes its backward set."""
    from tealql.tealtools.cfg.subroutines import identify_subroutines
    subs = identify_subroutines(prog)
    conts, targets = subs["continuations"], subs["callsub_target"]
    entries = [b for b in prog.entry_blocks() if b.file == exit_bb.file]
    seen: set = set()
    stack = [(b, ()) for b in entries
             if not block_closed(b) and (within is None or id(b) in within)]

    def _push(pred, succ, rstack):
        if succ is None or (within is not None and id(succ) not in within):
            return
        if edge_closed is not None and edge_closed(pred, succ):
            return
        if block_closed(succ):
            return
        stack.append((succ, rstack))

    while stack:
        bb, rstack = stack.pop()
        if bb is exit_bb:
            return True
        key = (id(bb), tuple(id(b) for b in rstack))
        if key in seen:
            continue
        seen.add(key)
        term = bb.assignments[-1].op if bb.assignments else None
        if term == "callsub" and targets.get(bb) is not None:
            new = (rstack + (conts.get(bb),))[-RETURN_STACK_CAP:]
            _push(bb, targets[bb], new)
            continue
        if term == "retsub" and rstack and rstack[-1] is not None:
            _push(bb, rstack[-1], rstack[:-1])
            continue
        rest = rstack[:-1] if term == "retsub" and rstack else rstack
        for s in bb.successors:
            _push(bb, s, rest)
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





def classify_program(prog: SSAProgram, *, file: Optional[str] = None) -> str:
    """``"app"`` if the program uses any application-only OPCODE, else ``"logicsig"``.

    HAZARD: key on OPCODES the AVM rejects in Signature mode, never on txn FIELDS.
    A logicsig can be attached to an ApplicationCall and so may legitimately read
    ``OnCompletion``/``ApplicationArgs``/``ApplicationID``."""
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op in APP_ONLY_OPS:
            return "app"
    return "logicsig"




def loc(a) -> str:
    """``file:line`` — the canonical location format for every detector's ``pretty()``."""
    if hasattr(a, "location"):
        return f"{a.location.file}:{a.location.line}"
    if hasattr(a, "file") and hasattr(a, "first_line"):
        return f"{a.file}:{a.first_line}"
    return str(a)
