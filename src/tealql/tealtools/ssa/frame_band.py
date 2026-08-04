"""Bottom-anchored frame resolution for DEPTH-POISONED regions.

Where `_frame_entry_depths` refuses a block (paths reach it at different
absolute heights), the working list the simulation carries is no longer
bottom-anchored: a top-aligned merge realigns the shallow paths' cells, so
``stack[pos]`` — the bottom index a frame op addresses — reads the RIGHT cell
on the deepest path and a NEIGHBOURING cell on the others. The old behaviour
executed the read anyway, so poisoned-region frame operands were phis with a
wrong-cell arm: a silent may-analysis miss, pinned nowhere.

Frame ops do not care about the top. ``frame_dig N`` addresses
``frame_base + N``, and the base does not move — a position is LAP-INVARIANT
even where the top's height varies per iteration (app_3300088574 leaks one
cell per lap and runs fine on the AVM for exactly this reason). So the right
anchor for these reads is the BOTTOM: what was at that position when the
region was entered, and which region-internal ``frame_bury`` may have
rewritten it since. Both are static questions.

This module answers them as a PLAN, built before the simulation runs:

    id(frame_dig PyOp) -> ("entry", region-entry known preds, position)
                        | ("bury",  the dominating frame_bury PyOp)
    (absent = refuse)

The simulation executes the plan where a block is poisoned: an "entry" read
takes the region-entry predecessor's exit cell at the position (the ground
truth at region entry — the depth-known prefix is exact, so pre-region burys
are already in that snapshot); a "bury" read takes the dominating write's
operand. Everything else refuses, and a poisoned ``frame_bury`` never writes
the working list (it cannot locate its cell; the read side routes around it).

WHAT MAKES AN "entry" ANSWER SOUND across laps of a varying-height loop:

* the region is entered at ONE block whose known predecessors agree on the
  entry height ``H0`` (multi-entry or conflicting-height regions refuse);
* relative heights within the region are consistent per lap — a fixpoint
  from the entry (edges INTO the entry excluded: re-entering is a new lap,
  relative height resets by definition), refusing on conflict;
* the position lies below ``H0 + min(D, 0)`` where ``D`` is the region's
  deepest relative dip — cells beneath every lap's excursion are cells no
  plain op in the region can consume or recreate, on any lap (lap entry
  heights only grow past ``H0`` in a net-pushing loop, and a net-popping
  loop's laps conflict in the fixpoint and refuse);
* no region ``callsub`` reaches an UNSAFE callee (one that may rewrite the
  caller's residual below its band — such a callee can touch the protected
  prefix, so the whole region refuses);
* no ``frame_bury`` of the position REACHES the read (else the value is the
  write's, or a merge). A single reaching bury that DOMINATES the read
  answers with its operand; a reaching-but-not-dominating bury (the
  loop-carried write-after-read shape) is a genuine merge of lap values —
  representing it needs position-keyed phis, so it refuses for now.
"""
from __future__ import annotations

from ..avm import op_arity


def _imm_int(op):
    try:
        return int(op.immediates.strip().split()[0])
    except (ValueError, IndexError, AttributeError):
        return None


def _op_net(o, arity):
    """Net stack effect of one op inside the region walk."""
    if o.op == "callsub":
        a, r = arity
        return r - a
    if o.op == "frame_dig":
        return 1
    if o.op == "frame_bury":
        return -1
    n_in, n_out = op_arity(o.op, o.immediates)
    return n_out - n_in


def _op_dip(o, arity):
    """How far below the running height this op reaches (pops before pushes)."""
    if o.op == "callsub":
        return arity[0]
    if o.op == "frame_dig":
        return 0
    if o.op == "frame_bury":
        return 1
    n_in, _ = op_arity(o.op, o.immediates)
    return n_in


def build_plan(blocks, bb_to_sub, proto_io, return_point, edepth,
               unsafe_callees, arity) -> tuple[dict, set]:
    """``(plan, poisoned_keys)`` for the simulation.

    ``plan``: id(PyOp) -> instruction for frame digs the band can answer.
    ``poisoned_keys``: bb_keys the simulation must treat as bottom-unanchored
    (every frame op there either follows the plan or refuses).
    """
    poisoned = {b.key for b in blocks
                if bb_to_sub.get(b) is not None and b.key not in edepth}
    plan: dict = {}
    if not poisoned:
        return plan, poisoned

    def callee_of(b):
        return next((s for s in b.succs if bb_to_sub.get(s) is s), None)

    def local_succs(b):
        if not b.ops:
            return list(b.succs)
        last = b.ops[-1].op
        if last in ("retsub", "return", "err"):
            return []
        if last == "callsub":
            rp = return_point.get(b)
            return [rp] if rp is not None else []
        return list(b.succs)

    # Group poisoned blocks into per-routine regions (weakly connected over
    # local edges restricted to poisoned blocks of the same routine).
    by_key = {b.key: b for b in blocks}
    visited: set = set()
    for seed in blocks:
        if seed.key not in poisoned or seed.key in visited:
            continue
        sub = bb_to_sub.get(seed)
        region: set = set()
        wl = [seed]
        while wl:
            b = wl.pop()
            if b.key in region:
                continue
            region.add(b.key)
            neigh = [s for s in local_succs(b)
                     if s is not None and s.key in poisoned
                     and bb_to_sub.get(s) is sub]
            neigh += [p for p in b.preds
                      if p.key in poisoned and bb_to_sub.get(p) is sub
                      and any(s is b for s in local_succs(p))]
            wl.extend(n for n in neigh if n.key not in region)
        visited |= region
        _plan_region(region, by_key, sub, bb_to_sub, proto_io, return_point,
                     edepth, unsafe_callees, arity, callee_of, local_succs,
                     plan)
    return plan, poisoned


def _plan_region(region, by_key, sub, bb_to_sub, proto_io, return_point,
                 edepth, unsafe_callees, arity, callee_of, local_succs,
                 plan) -> None:
    blocks = [by_key[k] for k in region]

    # ONE entry, and its depth-known predecessors must agree on the height
    # the region is entered at — that agreement is what makes a snapshot
    # position meaningful. (The conflicted JOIN itself — two known preds at
    # different exit heights, `height_ambiguous_join` — fails here and the
    # whole region refuses: either anchor would read a neighbouring cell on
    # the other path, which is the exact lie this module exists to stop.)
    entries: list = []
    for b in blocks:
        # A callsub-ending predecessor is EXCLUDED even when depth-known: a
        # verified pair would have crossed its depth to the continuation and
        # this block would not be poisoned, so a poisoned continuation behind
        # a callsub is exactly the unverified-pair case `_frame_entry_depths`
        # refused to guess for. Guessing here with the inferred arity would
        # reintroduce the wrongness at precisely the refused spot.
        known = [p for p in b.preds
                 if p.key in edepth and bb_to_sub.get(p) is sub
                 and not (p.ops and p.ops[-1].op == "callsub")
                 and any(s is b for s in local_succs(p))]
        if known:
            entries.append((b, known))
    if len(entries) != 1:
        return
    entry, known_preds = entries[0]

    def exit_height(p):
        h = edepth[p.key]
        for o in p.ops:
            h += _op_net(o, (0, 0))
        return h

    # Per-pred entry heights. They may DIFFER — that is often exactly why the
    # region is poisoned (five paths converging on one retsub at five depths,
    # app_2645463331 L3738) — and differing heights are not ambiguity HERE:
    # each known pred's exit list is exact and bottom-anchored, so a position
    # below every path's excursion has one exact cell PER PATH. A single-cell
    # consumer (a frame_dig, with no phi home in a poisoned block) uses the
    # merge only when all paths agree; the retsub consumer hands the per-path
    # cells to the call site, whose continuation phi is the legitimate home.
    heights = [exit_height(p) for p in known_preds]
    if not heights or min(heights) < 0:
        return
    h0 = min(heights)

    # Relative heights per lap, from the entry. Edges INTO the entry are
    # excluded — re-entering is the next lap, where relative height resets —
    # so a net!=0 loop through the entry stays consistent; any OTHER internal
    # cycle with net!=0 conflicts and the region refuses.
    rel = {entry.key: 0}
    order = [entry]
    dip = 0
    unsafe_call = False
    i = 0
    while i < len(order):
        b = order[i]
        i += 1
        r = rel[b.key]
        for o in b.ops:
            a = arity.get(callee_of(b), (0, 0)) if o.op == "callsub" else (0, 0)
            if o.op == "callsub" and callee_of(b) in unsafe_callees:
                unsafe_call = True
            dip = min(dip, r - _op_dip(o, a))
            r += _op_net(o, a)
        for s in local_succs(b):
            if s is None or s.key not in region or s is entry:
                continue
            if s.key in rel:
                if rel[s.key] != r:
                    return                     # inconsistent lap shape
            else:
                rel[s.key] = r
                order.append(s)
    if unsafe_call:
        return
    safe_below = h0 + min(dip, 0)

    # Region burys per absolute position, with region-internal reachability
    # (back edges included: a later-in-source bury reaches around the lap).
    nargs = arity.get(sub, (0, 0))[0]
    if sub in proto_io:
        nargs = proto_io[sub][0]
    burys: dict = {}                          # position -> [(block, idx, op)]
    for b in blocks:
        for idx, o in enumerate(b.ops):
            if o.op == "frame_bury":
                n = _imm_int(o)
                if n is not None and nargs + n >= 0:
                    burys.setdefault(nargs + n, []).append((b, idx, o))

    succ_cache: dict = {}

    def reachable(src_key):
        seen = succ_cache.get(src_key)
        if seen is None:
            seen = set()
            wl = [src_key]
            while wl:
                k = wl.pop()
                for s in local_succs(by_key[k]):
                    if s is not None and s.key in region and s.key not in seen:
                        seen.add(s.key)
                        wl.append(s.key)
            succ_cache[src_key] = seen
        return seen

    def dominates(wb, widx, rb, ridx):
        """Every region path entry -> read passes the write — checked on the
        graph WITH back edges, so lap-2+ paths count too. Same-block: index
        order (the write-later-around-the-lap shape is reaching-but-not-
        dominating and was already refused)."""
        if wb is rb:
            return widx < ridx
        if rb is entry:
            return False               # lap 1 reaches the entry read write-free
        # Remove the write's block: is the read still reachable from entry?
        seen = {entry.key}
        wl = [entry.key] if entry is not wb else []
        while wl:
            k = wl.pop()
            if k == rb.key:
                return False
            for s in local_succs(by_key[k]):
                if (s is not None and s.key in region and s.key != wb.key
                        and s.key not in seen):
                    seen.add(s.key)
                    wl.append(s.key)
        return True

    def killed(wb, widx, sb, sidx, rb, ridx):
        """Every path from after write ``(wb, widx)`` to read ``(rb, ridx)``
        passes the later write ``(sb, sidx)`` — i.e. ``s`` overwrites ``w``
        before any read. Block-level, back edges included."""
        if wb is sb:
            if widx >= sidx:
                return False
            if rb is wb and widx < ridx <= sidx:
                return False           # in-block read between the two writes
            return True
        if rb is wb and widx < ridx:
            return False               # falls to the read before leaving
        if rb is sb:
            return sidx < ridx         # any path must enter s's block first
        seen = {wb.key, sb.key}
        wl = [s.key for s in local_succs(wb)
              if s is not None and s.key in region and s.key not in seen]
        while wl:
            k = wl.pop()
            if k == rb.key:
                return False
            if k in seen:
                continue
            seen.add(k)
            wl.extend(s.key for s in local_succs(by_key[k])
                      if s is not None and s.key in region
                      and s.key not in seen)
        return True

    def resolve_read(rb, ridx, pos):
        """The MERGE instruction for a bottom-anchored read of ``pos`` at
        ``(rb, ridx)``: the region-entry cells (per known pred, if no write
        dominates the read) plus each surviving write's operand — or None.

        Survival is pairwise-kill: a write survives unless a SINGLE other
        reaching write covers every path to the read. Two writes jointly
        covering would both survive — extra arms, a sound over-approximation
        for a may-merge (and it only blocks const-folding, never invents a
        value). The loop-carried write-after-read shape lands here as
        {entry cell, write operand} — the two lap values."""
        if not (0 <= pos < safe_below):
            return None
        reaching = []
        for wb, widx, wop in burys.get(pos, ()):
            if wb is rb:
                if widx < ridx or rb.key in reachable(rb.key):
                    reaching.append((wb, widx, wop))
            elif rb.key in reachable(wb.key):
                reaching.append((wb, widx, wop))
        if not reaching:
            return ("merge", entry, tuple(known_preds), pos, ())
        entry_live = not any(dominates(wb, widx, rb, ridx)
                             for wb, widx, _w in reaching)
        survivors = tuple(
            w[2] for w in reaching
            if not any(killed(w[0], w[1], s[0], s[1], rb, ridx)
                       for s in reaching if s is not w))
        if not survivors and not entry_live:
            return None
        return ("merge", entry, tuple(known_preds) if entry_live else (),
                pos, survivors)

    for b in blocks:
        for ridx, o in enumerate(b.ops):
            if o.op != "frame_dig":
                continue
            n = _imm_int(o)
            if n is None:
                continue
            instr = resolve_read(b, ridx, nargs + n)
            if instr is not None:
                plan[id(o)] = instr

    # A proto'd RETSUB is a bottom-anchored read too: it returns FRAME SLOTS
    # 0..R-1 (positions nargs..nargs+R-1), which `_return_value` reads by
    # bottom index — the same wrong-cell risk as a frame_dig when the retsub
    # block is poisoned. Plan those reads with the same ladder; the call site
    # consults them per return index. (Legacy retsubs read the TOP verbatim —
    # the alignment the window models correctly — and need no gate.)
    if sub in proto_io:
        r_out = proto_io[sub][1]
        for b in blocks:
            if b.ops and b.ops[-1].op == "retsub" and r_out:
                ridx = len(b.ops) - 1
                rets = {}
                for j in range(r_out):
                    instr = resolve_read(b, ridx, nargs + j)
                    if instr is not None:
                        rets[j] = instr
                plan[id(b.ops[-1])] = ("ret", rets)
