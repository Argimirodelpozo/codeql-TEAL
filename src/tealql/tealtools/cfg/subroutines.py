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

Pure leaf: imports only :mod:`tealql.tealtools.language.avm` metadata at runtime.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING, Optional

from ..language.avm import _TERMINATOR_OPS

if TYPE_CHECKING:  # pragma: no cover
    from ..ssa import BasicBlock, SSAProgram


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

    Revision-cached on the program: construction, `analyze_structure`,
    `frame_slots.resolve_program` and the budget layers each re-ran the whole
    fixpoint (which itself rebuilds every body twice per round) with an
    unchanged program. Callers must treat the result as READ-ONLY.

    HAZARD: the key must carry block INSTANCE identity, not just the revision.
    ``BasicBlock`` hashes/compares by VALUE, and construction (which calls this
    via ``corrected_return_points`` before the final blocks exist) can replace
    the instances — a value-equal cached result full of pre-construction
    objects then feeds consumers that read per-instance state (``exit_stack``),
    which silently reads as thousands of unresolved call results.
    """
    revision = getattr(prog, "revision", 0)
    ids = frozenset(map(id, prog.blocks.values()))
    cached = getattr(prog, "_identify_subroutines_cache", None)
    if cached is not None and cached[0] == (revision, ids):
        return cached[1]
    out = _identify_subroutines_uncached(prog)
    try:
        prog._identify_subroutines_cache = ((revision, ids), out)
    except AttributeError:      # only if SSAProgram ever gains __slots__
        pass
    return out


def _identify_subroutines_uncached(prog: "SSAProgram") -> dict:
    entries: set[BasicBlock] = set()
    callsub_target: dict[BasicBlock, BasicBlock] = {}

    # Label -> block by NAME, to recover a callsub whose CFG entry edge is
    # missing: a sub whose entry block is empty and merged into a reentrant
    # loop-header successor leaves `callsub -> entry` dangling, so the callee is
    # never seen via `bb.successors`. Shared resolver (first definition wins,
    # file-scoped, empty label -> next real block) — see `labels.LabelIndex`.
    from .labels import LabelIndex
    _labels = LabelIndex(prog)

    def _target_by_name(bb: BasicBlock) -> Optional[BasicBlock]:
        imm = next((a.immediates for a in bb.assignments if a.op == "callsub"), None)
        if imm is None:
            return None
        return _labels.block(getattr(bb, "file", None), imm)

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



def infer_legacy_arities(
    subs, *, entry_of, proto_of, body_of, ops_of, succs_of, callee_of, op_arity,
    divergent=None,
):
    """``{sub: (nargs, nret)}`` for legacy (pre-``proto``) subroutines — THE
    cross-procedural depth fixpoint, in one place.

    A pre-``proto`` sub declares nothing: its arguments and results are just
    stack depth. How far below its entry the body dips is how many arguments it
    took; what it leaves at ``retsub`` above that floor is what it returned.
    Interprocedural, because a nested call's own arity moves the dip — hence the
    fixpoint rather than one pass.

    Parameterised over accessors because the same question is asked in two value
    models: the SSA asks it over ``PyBlock``s mid-construction, the lift over
    ``structure.Subroutine`` bodies of a finished ``SSAProgram``. That is the
    same shape :func:`..cfg.dominance.iterative_dominators` already solves by
    taking its edge accessor as an argument, and it had been solved twice here
    instead — the two copies drifted, and the SSA's under-counted a sub whose
    body branches into a SHARED TAIL (`app_1050006430` `label23`: 1 argument
    counted, 4 actually consumed, three values stranded on the caller's stack).

    ``entry_of(s)`` is explicit rather than sniffed off the object: the two
    callers name the entry block differently (a ``PyBlock`` IS its own entry,
    a ``structure.Subroutine`` has ``.entry_bb``), and guessing produced a
    depth map keyed by the wrong type.

    ``succs_of(b, body)`` is the caller's: it decides whether a plain branch out
    of the owned body still counts (it must — a shared tail is this routine
    executing). ``divergent`` (out-param) collects subs whose ``retsub`` sites
    leave DIFFERENT depths: those are not functions at all, no single
    ``(nargs, nret)`` describes them, and the ``max`` below necessarily
    over-declares their shallow paths.
    """
    arity = {}
    for s in subs:
        p = proto_of(s)
        arity[s] = p if p is not None else (0, 0)

    for _ in range(len(arity) + 4):
        changed = False
        for s in subs:
            if proto_of(s) is not None:
                continue
            body = body_of(s)
            entry = entry_of(s)
            depth = {entry: 0}
            order = [entry]
            floor = 0
            ret_ds: list = []
            i = 0
            while i < len(order):
                b = order[i]
                i += 1
                d = mn = depth[b]
                for o in ops_of(b):
                    if o.op == "retsub":
                        break
                    # A legacy sub still has a frame: callsub anchors it at the
                    # caller's current stack height. Negative frame slots are
                    # implicit arguments even though frame_dig does not POP
                    # them. Counting only stack-effect dips inferred nargs=0
                    # and left `frame_dig -1` undefined in SSA and pre-IR. A
                    # below-frame bury has the same fixed-band requirement in
                    # addition to popping its value.
                    if o.op in ("frame_dig", "frame_bury"):
                        try:
                            frame_slot = int((o.immediates or "").split()[0])
                        except (ValueError, IndexError):
                            frame_slot = 0
                        if frame_slot < 0:
                            mn = min(mn, frame_slot)
                    if o.op == "callsub":
                        pop, push = arity.get(callee_of(b), (0, 0))
                    else:
                        pop, push = op_arity(o)
                    d -= pop
                    mn = min(mn, d)
                    d += push
                floor = min(floor, mn)
                ops = list(ops_of(b))
                if ops and ops[-1].op == "retsub":
                    ret_ds.append(d)
                for su in succs_of(b, body):
                    if su not in depth:
                        depth[su] = d
                        order.append(su)
            # MAX over ALL retsub sites, not the first reached: a sub whose
            # paths diverge would otherwise silently truncate a deeper path.
            ret_d = max(ret_ds) if ret_ds else None
            # HAZARD: reflect the CONVERGED iteration, so DISCARD as well as
            # add. Early rounds assume (0, 0) for every legacy callee, which
            # makes a path THROUGH one look shallower than its siblings —
            # accumulating the mark would report a sub that is perfectly
            # function-shaped once its callee's arity is known.
            if divergent is not None:
                if len(set(ret_ds)) > 1:
                    divergent.add(s)
                else:
                    divergent.discard(s)
            na, nr = -floor, (ret_d - floor if ret_d is not None else 0)
            if arity[s] != (na, nr):
                arity[s] = (na, nr)
                changed = True
        if not changed:
            break
    return arity


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



def corrected_return_points(prog) -> dict:
    """``{callsub bb_key: continuation bb_key or None}`` under the CORRECTED
    policy, keyed so a mid-construction PyBlock can look itself up.

    The construction path used to run the NAIVE source-next guess
    (:func:`_pyblock_return_point`) on the grounds that it "runs BEFORE the
    SSAProgram exists, so it cannot reuse the corrected policy". That was
    WRONG: `_build_from_graph` populates `prog.blocks` (with assignments and
    successors) and `prog.labels` before it calls `PySSA._construct(prog)`, and
    those are the only things :func:`identify_subroutines` reads — the operand
    wiring it does NOT read is the only thing missing at that point.

    PyBlock and BasicBlock share the ``(file, first_line, last_line)`` identity,
    so the corrected answer maps straight across.
    """
    conts = identify_subroutines(prog)["continuations"]
    return {
        (cs.file, cs.first_line, cs.last_line):
            (None if c is None else (c.file, c.first_line, c.last_line))
        for cs, c in conts.items()
    }


def _pyblock_return_point(blocks, corrected=None) -> dict:
    """Return points per callsub-terminated block.

    ``corrected`` (from :func:`corrected_return_points`) is the SHARED policy
    and is used when supplied — one answer for the whole pipeline. Without it
    this falls back to the naive source-next guess: the next op in
    ``(file, line)`` order, with no entry exclusion and no retsub-predecessor
    requirement. ``blocks`` follows the PyBlock protocol: ``.ops`` (each with
    ``.op``/``.file``/``.line``), ``.succs``, ``.preds``, ``.key``."""
    op_lines: list = sorted(
        (op.file, op.line) for b in blocks for op in b.ops
    )
    line_to_bb: dict = {}
    for b in blocks:
        for op in b.ops:
            line_to_bb[(op.file, op.line)] = b
    by_key = {b.key: b for b in blocks}
    rps: dict = {}
    for b in blocks:
        if b.ops and b.ops[-1].op == "callsub":
            if corrected is not None and b.key in corrected:
                ck = corrected[b.key]
                rps[b] = by_key.get(ck) if ck is not None else None
                continue
            last = b.ops[-1]
            i = bisect.bisect_right(op_lines, (last.file, last.line))
            rp = None
            if i < len(op_lines) and op_lines[i][0] == last.file:
                rp = line_to_bb[op_lines[i]]
            rps[b] = rp
    return rps


def pyblock_partition(blocks, corrected=None) -> dict:
    """CONSTRUCTION policy: map every block to its owning routine's entry block.

    Roots = main entries (no preds, not a callsub successor) plus every callsub
    successor; ownership = DFS over intra-routine successors where ``callsub``
    flows to its naive return point (:func:`_pyblock_return_point`) and
    ``retsub``/``return``/``err`` are terminal. First claim wins (mains first,
    then entries in ``.key`` order) — exactly the construction-time semantics
    the SSA depth machinery was validated against."""
    return_points = _pyblock_return_point(blocks, corrected)

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
    # THE PROGRAM ENTRY IS ALWAYS A ROOT. The AVM starts at PC 0, so the
    # source-first block executes regardless of what else points at it — and a
    # first block that is also a branch target (`start:` ... `bnz start`, the
    # hand-written retry-loop shape) has itself as a predecessor, so the
    # no-preds filter above missed it. With no root the WHOLE program stayed
    # unowned: never simulated, every op keeping empty inputs — the
    # output-with-no-inputs shape that reads CLEAN to every may-analysis, with
    # no refusal marker anywhere. A first block that is a callsub TARGET is
    # already a root via ``sub_entries`` (claimed as a sub: the recursive-main
    # convention), so only the not-a-sub case is added here.
    firsts: dict = {}
    for b in blocks:
        f = b.key[0]
        if f not in firsts or b.key < firsts[f].key:
            firsts[f] = b
    for b in firsts.values():
        if b not in sub_entries and b not in mains:
            mains.append(b)
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
