"""Subroutine partitioning — the single home for callsub/retsub boundary
reasoning.

One program, three questions, three deliberately DIFFERENT policies that
historically lived in three modules (control_tree / path_predicates / the SSA
builder) and could drift apart:

  * :func:`identify_subroutines` — the CORRECTED policy (formerly
    ``control_tree.identify_subroutines``, moved verbatim): entries (with a
    label-resolution fallback for dangling callsub edges), bodies, and
    fixpoint-corrected continuations that handle never-returning callees and
    linker-interleaved bodies. The most precise view; feeds the control tree,
    ``structure`` (and through it the lift's frame resolution), and cost.

  * :func:`sound_return_targets` — the SOUND policy (formerly
    ``PathPredicateAnalysis._callsub_return_maps``, moved verbatim): a
    callsub's return block only when EVERY predecessor is a retsub — the
    condition under which caller-specific facts may be carried across the
    call. Deliberately a subset of the corrected policy: measured over the
    full fixture universe (490 programs, ~25k callsubs) it NEVER disagrees
    with the corrected continuation where it resolves.

  * :func:`pyblock_partition` — the CONSTRUCTION policy (formerly the
    ownership core of ``PySSA._compute_subs_and_protos``, moved verbatim):
    every-block ownership over the mid-build PyBlock model, using the NAIVE
    next-op return point. It runs BEFORE the SSAProgram exists, so it cannot
    reuse the corrected policy — and the naive and corrected continuations
    genuinely diverge in the wild (~1.3%% of callsubs on the fixture
    universe), so this is a distinct policy, not a lesser copy. Its exact
    behavior is pinned by the SSA behavioural gates (the folks-xgov history);
    converging it onto the corrected policy is a SEMANTIC change — gate any
    attempt with the c2 differential harness + corpus + behavioural.

The three functions share this module so the policies are visible against
each other instead of drifting apart in three files. Pure leaf: imports only
:mod:`tealql.tealtools.avm` metadata at runtime.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING, Optional

from .avm import _TERMINATOR_OPS

if TYPE_CHECKING:  # pragma: no cover
    from .ssa import BasicBlock, SSAProgram


def _terminator_op(bb: "BasicBlock") -> Optional[str]:
    """Return the control-flow terminator op of ``bb``, or ``None`` if
    the BB has no terminator (e.g. fall-through end of program).

    Scans instead of reading ``bb.assignments[-1].op`` defensively: any
    pass that appends synthetic assignments after a terminator (the removed
    materialize_phis did exactly that, and broke the interprocedural edge
    cut via naive ``[-1]`` checks) keeps classification correct.
    """
    for a in bb.assignments:
        if a.op in _TERMINATOR_OPS:
            return a.op
    return None


def identify_subroutines(prog: "SSAProgram") -> dict:
    """Inspect the CFG for ``callsub`` / ``retsub`` ops and produce:

    - ``entries``: BBs that are direct successors of any ``callsub``-
      ending BB. These are the subroutine entry points.
    - ``bodies``: ``entry_bb → set[BB]`` — the intraprocedural-reachable
      BBs starting from each entry. We follow successor edges, but
      stop at ``retsub`` BBs (their successors leave the body) and
      don't enter other subroutine entries.
    - ``continuations``: ``callsub_bb → continuation_bb``. Heuristic:
      after ``callsub`` at line L, control returns to the BB whose
      first line is the smallest ``> L`` in the same file *and* is a
      successor of some ``retsub`` in the called subroutine. Captures
      the linear "after the call" code without following the long way
      around through the callee's retsub edges.
    """
    entries: set[BasicBlock] = set()
    callsub_target: dict[BasicBlock, BasicBlock] = {}

    # label name -> source line, and blocks by source line, to resolve a callsub
    # whose CFG entry edge is missing -- a subroutine whose own entry block is
    # empty and merged into a reentrant loop-header successor leaves the
    # `callsub -> entry` edge dangling, so the callee is never seen via
    # `bb.successors`. Resolving the `callsub <label>` immediate to the first
    # block at/after that label recovers it.
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

    # Source-ordered blocks per file, for the source-order continuation
    # heuristic.
    bb_by_file_line: dict[str, list[BasicBlock]] = {}
    for bb in prog.blocks.values():
        if not bb.assignments:
            continue
        loc = bb.assignments[0].location
        bb_by_file_line.setdefault(loc.file, []).append(bb)
    for f in bb_by_file_line:
        bb_by_file_line[f].sort(key=lambda b: b.assignments[0].location.line)

    def _source_next(cs_bb: BasicBlock) -> Optional[BasicBlock]:
        """Heuristic 1: the next BB in source order after the callsub,
        excluding subroutine entries (those are call *targets*, not return
        points). Compiled TEAL emits the continuation right after the callsub
        op, so this resolves almost every call on its own."""
        last = cs_bb.assignments[-1].location
        for b in bb_by_file_line.get(last.file, ()):
            if b.assignments[0].location.line <= last.line:
                continue
            if b in entries:
                continue
            return b
        return None

    def _body(entry: BasicBlock, conts: dict, *, follow_callsub: bool = True) -> set[BasicBlock]:
        """A subroutine's body: intraprocedural reachability from the entry,
        modelling ``callsub`` as a *side-effecting op* that flows to its
        continuation (the return point) — not a control transfer into the
        callee. This is the same cut-callsub / splice-continuation model
        :func:`build_control_tree` uses; doing it here keeps the continuation
        (which runs in this sub's frame, before its own ``retsub``) in the
        body rather than leaking it to the frame-less main flow. ``retsub`` is
        terminal (its successors are caller continuations), and we never cross
        into another subroutine's entry.

        With ``follow_callsub=False`` an internal ``callsub`` is terminal too,
        giving the sub's *own* blocks (entry → retsub) without the spliced-in
        caller continuations — used to test "is X inside this callee?" without
        the false overlaps the spliced continuations create."""
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

    # Bodies and continuations refine each other: a body must flow through
    # each internal callsub's continuation, while the heuristic-2 continuation
    # fallback needs the *callee's* retsubs — which live in a body. Seed the
    # continuations with heuristic 1 (self-contained), then iterate to a
    # fixpoint: heuristic 2 fills any callsub whose return point isn't the next
    # source block (a linker that interleaved subroutine bodies). Converges in
    # a round or two — each pass can only add continuations, never remove them.
    continuations: dict[BasicBlock, Optional[BasicBlock]] = {
        cs_bb: _source_next(cs_bb) for cs_bb in callsub_bbs
    }
    bodies: dict[BasicBlock, set[BasicBlock]] = {}
    # bounded (the body/continuation refinement is monotone; the cap only guards
    # against a pathological invalidate<->refill oscillation).
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
        #  (a) a callee that never `retsub`s (it ends every path in `return` /
        #      `err`) does not return, so its callsub has *no* continuation --
        #      heuristic 1's next-source-block guess is spurious (and may land in
        #      an unrelated subroutine's body, leaking a cross-group edge);
        #  (b) a continuation may not lie inside the callee's *own* body
        #      (entry -> retsub) unless it is a retsub target -- when the linker
        #      placed that body right after the callsub, heuristic 1 mis-picked a
        #      callee block as the return point. Drop it so heuristic 2 refills.
        # The pure body (no spliced continuations) and the retsub-target
        # exemption keep a block legitimately shared with the callee from being
        # dropped.
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
    """``(caller_of, return_target_of)``: for each ``callsub`` block C, the
    block B that execution returns to (the next block in source order, whose
    predecessors are ALL ``retsub`` blocks — i.e. B is reached ONLY via the
    return, making it sound to carry C's caller-specific facts there). B with
    any non-return predecessor is skipped (the facts wouldn't hold on the
    other path)."""
    caller_of: dict[BasicBlock, BasicBlock] = {}
    return_target_of: dict[BasicBlock, BasicBlock] = {}
    for c in prog.blocks.values():
        if not c.assignments or c.assignments[-1].op != "callsub":
            continue
        after = [b for b in prog.blocks.values()
                 if b.file == c.file and b.first_line > c.last_line]
        if not after:
            continue
        b = min(after, key=lambda x: x.first_line)
        if b.predecessors and all(
            p.assignments and p.assignments[-1].op == "retsub"
            for p in b.predecessors
        ):
            caller_of[b] = c
            return_target_of[c] = b
    return caller_of, return_target_of


def _pyblock_return_point(blocks) -> dict:
    """The CONSTRUCTION policy's return points: for each callsub-terminated
    block, the block holding the next op in ``(file, line)`` order — the
    naive source-next heuristic (no entry exclusion, no retsub-predecessor
    requirement). ``blocks`` follows the PyBlock structural protocol:
    ``.ops`` (each with ``.op`` / ``.file`` / ``.line``), ``.succs``,
    ``.preds``, ``.key``."""
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
    """The CONSTRUCTION policy (moved verbatim from
    ``PySSA._compute_subs_and_protos``): map every block to its owning
    routine's entry block. Roots = main entries (no preds, not a callsub
    successor) plus every callsub successor; ownership = DFS over
    intra-routine successors, where a ``callsub`` flows to its naive return
    point (:func:`_pyblock_return_point`) and ``retsub``/``return``/``err``
    are terminal. First claim wins (roots iterate mains first, then entries
    in ``.key`` order) — exactly the construction-time semantics the SSA
    depth machinery was validated against."""
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
