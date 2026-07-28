"""Subroutine partitioning — the single home for callsub/retsub boundary
reasoning, kept in one file so the policies stay visible against each other.

HAZARD: three DELIBERATELY different policies, not interchangeable.

  * :func:`identify_subroutines` — CORRECTED: entries (with a label-resolution
    fallback for dangling callsub edges), bodies, and fixpoint-corrected
    continuations handling never-returning callees and linker-interleaved
    bodies. The most precise view; feeds the control tree, ``structure`` (and
    through it the lift's frame resolution), and cost.

  * :func:`sound_return_targets` — SOUND: a callsub's return block only when
    EVERY predecessor is a retsub, the condition under which caller-specific
    facts may be carried across the call. A deliberate SUBSET of the corrected
    policy; where it resolves it never disagrees with it.

  * :func:`pyblock_partition` — CONSTRUCTION: every-block ownership over the
    mid-build PyBlock model, using the NAIVE next-op return point. It runs
    BEFORE the SSAProgram exists, so it cannot reuse the corrected policy, and
    naive vs corrected continuations genuinely diverge in the wild (~1.3% of
    callsubs) — a distinct policy, not a lesser copy. Its exact behavior is
    pinned by the SSA behavioural gates; converging it onto the corrected
    policy is a SEMANTIC change — gate any attempt with the c2 differential
    harness + corpus + behavioural.

Pure leaf: imports only :mod:`tealql.tealtools.avm` metadata at runtime.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING, Optional

from .avm import _TERMINATOR_OPS

if TYPE_CHECKING:  # pragma: no cover
    from .ssa import BasicBlock, SSAProgram


def _terminator_op(bb: "BasicBlock") -> Optional[str]:
    """The control-flow terminator op of ``bb``, or ``None`` if it has none.

    Scans rather than reading ``bb.assignments[-1]``: a pass that appends
    synthetic assignments after the terminator would otherwise misclassify the
    block and break the interprocedural edge cut.
    """
    for a in bb.assignments:
        if a.op in _TERMINATOR_OPS:
            return a.op
    return None


def identify_subroutines(prog: "SSAProgram") -> dict:
    """The CORRECTED ``callsub``/``retsub`` partition of the CFG.

    - ``entries``: BBs that are direct successors of a ``callsub``-ending BB.
    - ``bodies``: ``entry_bb → set[BB]``, intraprocedural reachability from
      each entry — ``retsub`` BBs are terminal (their successors leave the
      body) and other subroutine entries are never crossed.
    - ``continuations``: ``callsub_bb → return BB``, heuristically the nearest
      later BB in the same file that is also a ``retsub`` successor of the
      callee.
    - ``callsub_target``: ``callsub_bb → callee entry BB``.
    """
    entries: set[BasicBlock] = set()
    callsub_target: dict[BasicBlock, BasicBlock] = {}

    # Label line + blocks by line, to recover a callsub whose CFG entry edge is
    # missing: a sub whose entry block is empty and merged into a reentrant
    # loop-header successor leaves `callsub -> entry` dangling, so the callee is
    # never seen via `bb.successors`.
    _label_line = {code.rstrip(":").strip(): ln for _f, ln, code in prog.labels}
    _by_line = sorted(prog.blocks.values(), key=lambda b: b.first_line)

    def _target_by_name(bb: BasicBlock) -> Optional[BasicBlock]:
        imm = next((a.immediates for a in bb.assignments if a.op == "callsub"), None)
        ln = _label_line.get((imm or "").strip())
        if ln is None:
            return None
        return next((b for b in _by_line if b.first_line >= ln), None)

    callsub_bbs: list[BasicBlock] = []
    retsub_bbs: list[BasicBlock] = []
    for bb in prog.blocks.values():
        last = _terminator_op(bb)
        if last == "callsub":
            callsub_bbs.append(bb)
            target = bb.successors[0] if bb.successors else _target_by_name(bb)
            if target is not None:
                callsub_target[bb] = target
                entries.add(target)
        elif last == "retsub":
            retsub_bbs.append(bb)

    # Source-ordered blocks per file, for the continuation heuristic.
    bb_by_file_line: dict[str, list[BasicBlock]] = {}
    for bb in prog.blocks.values():
        if not bb.assignments:
            continue
        loc = bb.assignments[0].location
        bb_by_file_line.setdefault(loc.file, []).append(bb)
    for f in bb_by_file_line:
        bb_by_file_line[f].sort(key=lambda b: b.assignments[0].location.line)

    def _source_next(cs_bb: BasicBlock) -> Optional[BasicBlock]:
        """Heuristic 1: the next BB in source order after the callsub, excluding
        subroutine entries (those are call TARGETS, not return points)."""
        last = cs_bb.assignments[-1].location
        for b in bb_by_file_line.get(last.file, ()):
            if b.assignments[0].location.line <= last.line:
                continue
            if b in entries:
                continue
            return b
        return None

    def _body(entry: BasicBlock, conts: dict, *, follow_callsub: bool = True) -> set[BasicBlock]:
        """A subroutine's body: intraprocedural reachability from ``entry``.

        ``callsub`` is modelled as a side-effecting op flowing to its
        continuation, not as a transfer into the callee — the continuation runs
        in THIS sub's frame, so it belongs to the body rather than leaking to
        the frame-less main flow. ``retsub`` is terminal (its successors are
        caller continuations) and another sub's entry is never crossed.

        ``follow_callsub=False`` makes an internal ``callsub`` terminal too,
        giving the sub's OWN blocks (entry → retsub) without spliced-in caller
        continuations — for "is X inside this callee?" without their false
        overlaps."""
        body: set[BasicBlock] = set()
        stack = [entry]
        while stack:
            bb = stack.pop()
            if bb in body:
                continue
            body.add(bb)
            op = _terminator_op(bb)
            if op == "retsub":
                continue
            if op == "callsub":
                if follow_callsub:
                    cont = conts.get(bb)
                    if cont is not None and not (cont in entries and cont is not entry):
                        stack.append(cont)
                continue
            for s in bb.successors:
                if s in entries and s is not entry:
                    continue
                stack.append(s)
        return body

    # Bodies and continuations refine each other: a body must flow through each
    # internal callsub's continuation, while the heuristic-2 fallback needs the
    # CALLEE's retsubs — which live in a body. Seed with heuristic 1, then
    # iterate to a fixpoint; heuristic 2 fills any callsub whose return point
    # isn't the next source block (interleaved subroutine bodies).
    continuations: dict[BasicBlock, Optional[BasicBlock]] = {
        cs_bb: _source_next(cs_bb) for cs_bb in callsub_bbs
    }
    bodies: dict[BasicBlock, set[BasicBlock]] = {}
    # Bounded: the refinement is monotone, so the cap only guards a pathological
    # invalidate<->refill oscillation.
    for _round in range(len(callsub_bbs) + len(entries) + 8):
        bodies = {entry: _body(entry, continuations) for entry in entries}
        pure = {entry: _body(entry, continuations, follow_callsub=False)
                for entry in entries}
        retsub_targets_per_sub = {
            entry: {
                t for bb in body
                if _terminator_op(bb) == "retsub"
                for t in bb.successors
            }
            for entry, body in bodies.items()
        }
        has_retsub = {
            entry: any(_terminator_op(bb) == "retsub" for bb in body)
            for entry, body in bodies.items()
        }
        # Fix mis-attributed continuations:
        #  (a) a callee that never `retsub`s does not return, so its callsub has
        #      NO continuation -- heuristic 1's guess is spurious and may land in
        #      an unrelated sub's body, leaking a cross-group edge;
        #  (b) a continuation inside the callee's OWN body (entry -> retsub) that
        #      isn't a retsub target means heuristic 1 mis-picked a callee block
        #      as the return point; drop it so heuristic 2 refills.
        # The pure body + the retsub-target exemption keep a block legitimately
        # shared with the callee from being dropped.
        for cs_bb in callsub_bbs:
            callee = callsub_target.get(cs_bb)
            cont = continuations[cs_bb]
            if cont is None or callee is None:
                continue
            if not has_retsub.get(callee, True):
                continuations[cs_bb] = None
            elif (cont in pure.get(callee, ())
                    and cont not in retsub_targets_per_sub.get(callee, ())):
                continuations[cs_bb] = None
        added = False
        for cs_bb in callsub_bbs:
            if continuations[cs_bb] is not None:
                continue
            last = cs_bb.assignments[-1].location
            candidates = [
                c for c in retsub_targets_per_sub.get(callsub_target.get(cs_bb), ())
                if c.assignments
                and c.assignments[0].location.file == last.file
                and c.assignments[0].location.line > last.line
            ]
            if candidates:
                continuations[cs_bb] = min(
                    candidates, key=lambda c: c.assignments[0].location.line)
                added = True
        if not added:
            break

    return {
        "entries": entries,
        "bodies": bodies,
        "continuations": continuations,
        "callsub_target": callsub_target,
    }


def sound_return_targets(prog: "SSAProgram") -> tuple[dict, dict]:
    """``(caller_of, return_target_of)``: per ``callsub`` block C, the block B
    execution returns to — the next block in source order.

    HAZARD: B qualifies only when its predecessors are ALL ``retsub`` blocks, so
    B is reached ONLY via the return and C's caller-specific facts hold there.
    Any non-return predecessor and B is skipped — the facts wouldn't hold on
    that other path."""
    caller_of: dict[BasicBlock, BasicBlock] = {}
    return_target_of: dict[BasicBlock, BasicBlock] = {}
    # Per-file blocks sorted by first_line so "the next block" is a bisect, not
    # an O(callsubs x blocks) scan — this runs inside PathPredicateAnalysis on
    # every program.
    by_file: dict[str, list[BasicBlock]] = {}
    for b in prog.blocks.values():
        by_file.setdefault(b.file, []).append(b)
    for f in by_file:
        by_file[f].sort(key=lambda x: x.first_line)
    firsts = {f: [x.first_line for x in bs] for f, bs in by_file.items()}
    for c in prog.blocks.values():
        if not c.assignments or c.assignments[-1].op != "callsub":
            continue
        siblings = by_file.get(c.file, [])
        i = bisect.bisect_right(firsts[c.file], c.last_line)
        if i >= len(siblings):
            continue
        b = siblings[i]
        if b.predecessors and all(
            p.assignments and p.assignments[-1].op == "retsub"
            for p in b.predecessors
        ):
            caller_of[b] = c
            return_target_of[c] = b
    return caller_of, return_target_of


def _pyblock_return_point(blocks) -> dict:
    """CONSTRUCTION-policy return points: per callsub-terminated block, the block
    holding the next op in ``(file, line)`` order — NAIVE source-next, with no
    entry exclusion and no retsub-predecessor requirement. ``blocks`` follows the
    PyBlock protocol: ``.ops`` (each with ``.op``/``.file``/``.line``),
    ``.succs``, ``.preds``, ``.key``."""
    op_lines: list = sorted(
        (op.file, op.line) for b in blocks for op in b.ops
    )
    line_to_bb: dict = {}
    for b in blocks:
        for op in b.ops:
            line_to_bb[(op.file, op.line)] = b
    rps: dict = {}
    for b in blocks:
        if b.ops and b.ops[-1].op == "callsub":
            last = b.ops[-1]
            i = bisect.bisect_right(op_lines, (last.file, last.line))
            rp = None
            if i < len(op_lines) and op_lines[i][0] == last.file:
                rp = line_to_bb[op_lines[i]]
            rps[b] = rp
    return rps


def pyblock_partition(blocks) -> dict:
    """CONSTRUCTION policy: map every block to its owning routine's entry block.

    Roots = main entries (no preds, not a callsub successor) plus every callsub
    successor; ownership = DFS over intra-routine successors where ``callsub``
    flows to its naive return point (:func:`_pyblock_return_point`) and
    ``retsub``/``return``/``err`` are terminal. First claim wins (mains first,
    then entries in ``.key`` order) — exactly the construction-time semantics
    the SSA depth machinery was validated against."""
    return_points = _pyblock_return_point(blocks)

    sub_entries: set = set()
    for b in blocks:
        if b.ops and b.ops[-1].op == "callsub":
            for s in b.succs:
                sub_entries.add(s)

    loc_succs: dict = {}
    for b in blocks:
        if not b.ops:
            loc_succs[b] = list(b.succs)
            continue
        last_op = b.ops[-1].op
        if last_op == "callsub":
            rp = return_points.get(b)
            loc_succs[b] = [rp] if rp is not None else []
        elif last_op in ("retsub", "return", "err"):
            loc_succs[b] = []
        else:
            loc_succs[b] = list(b.succs)

    mains = [
        b for b in blocks
        if not b.preds and b not in sub_entries
    ]
    bb_to_sub: dict = {}
    for root in mains + sorted(sub_entries, key=lambda x: x.key):
        stack = [root]
        while stack:
            b = stack.pop()
            if b in bb_to_sub:
                continue
            bb_to_sub[b] = root
            for s in loc_succs[b]:
                if s is not None and s not in bb_to_sub:
                    stack.append(s)
    return bb_to_sub
