"""First-class frame-slot layout and bottom-anchored provenance.

Where :func:`stacksim.entry_heights` cannot supply one exact depth (paths may
reach a block at different absolute heights), the working list is no longer
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

This module answers them as typed frame-slot state, built before simulation:

    FrameAnalysis.instructions[id(frame_dig)] = SlotMerge(
        home, entry_predecessors, position, writes)

An absent instruction means refusal.

The simulation executes this state where a block is poisoned: an entry read
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
representing it creates a position-keyed phi at the region entry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging

from ..avm import op_arity
from .models import SSAVar

# Compatibility logger name: users may filter this established diagnostic.
logger = logging.getLogger("tealql.tealtools.passes.frame_flow")


@dataclass(frozen=True)
class SlotMerge:
    """Bottom-anchored sources for one logical frame-slot read."""

    home: object
    entry_predecessors: tuple
    position: int
    writes: tuple


@dataclass(frozen=True)
class ReturnSlots:
    """Per-declared-return frame-slot reads for one ``retsub``."""

    slots: dict


@dataclass(frozen=True)
class FrameAnalysis:
    """Frame-slot provenance consumed by the canonical stack simulator."""

    instructions: dict
    poisoned: frozenset

    @property
    def reads(self) -> dict:
        return {key: value for key, value in self.instructions.items()
                if isinstance(value, SlotMerge)}

    @property
    def returns(self) -> dict:
        return {key: value for key, value in self.instructions.items()
                if isinstance(value, ReturnSlots)}


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


def analyze(blocks, bb_to_sub, proto_io, return_point, edepth,
            unsafe_callees, arity, *, poisoned=None) -> FrameAnalysis:
    """Compute first-class frame-slot provenance for the simulation.

    ``instructions`` maps frame reads and proto returns to typed slot merges.
    ``poisoned`` holds bb keys the simulation must treat as bottom-unanchored
    (every frame op there either follows the plan or refuses).
    """
    if poisoned is None:
        # Compatibility for external callers using the original signature.
        poisoned = {b.key for b in blocks
                    if bb_to_sub.get(b) is not None and b.key not in edepth}
    else:
        poisoned = set(poisoned)
    plan: dict = {}
    if not poisoned:
        return FrameAnalysis(plan, frozenset())

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
    return FrameAnalysis(plan, frozenset(poisoned))


def build_plan(blocks, bb_to_sub, proto_io, return_point, edepth,
               unsafe_callees, arity, *, poisoned=None) -> tuple[dict, set]:
    """Compatibility wrapper returning the former tuple instruction format."""
    analysis = analyze(blocks, bb_to_sub, proto_io, return_point, edepth,
                       unsafe_callees, arity, poisoned=poisoned)
    legacy = {}
    for key, instruction in analysis.instructions.items():
        if isinstance(instruction, SlotMerge):
            legacy[key] = (
                "merge", instruction.home, instruction.entry_predecessors,
                instruction.position, instruction.writes)
        else:
            legacy[key] = ("ret", {
                slot: (
                    "merge", merge.home, merge.entry_predecessors,
                    merge.position, merge.writes)
                for slot, merge in instruction.slots.items()
            })
    return legacy, set(analysis.poisoned)


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
        # a callsub is exactly the unverified-pair case ``entry_heights``
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
            return SlotMerge(entry, tuple(known_preds), pos, ())
        entry_live = not any(dominates(wb, widx, rb, ridx)
                             for wb, widx, _w in reaching)
        survivors = tuple(
            w[2] for w in reaching
            if not any(killed(w[0], w[1], s[0], s[1], rb, ridx)
                       for s in reaching if s is not w))
        if not survivors and not entry_live:
            return None
        return SlotMerge(entry, tuple(known_preds) if entry_live else (),
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
                plan[id(b.ops[-1])] = ReturnSlots(rets)


# ---------------------------------------------------------------------------
# Public SSA frame layout
# ---------------------------------------------------------------------------


@dataclass
class FrameLayout:
    """Logical parameters and versioned locals for one routine's frame.

    The canonical stack simulator carries the live values. This layout is the
    stable annotation/API view used by callers that need to classify a read as
    a parameter, a written local, or an ordinary pushed frame cell.
    """

    dig_param: dict = field(default_factory=dict)
    dig_local: dict = field(default_factory=dict)
    bury: dict = field(default_factory=dict)
    passthrough: dict = field(default_factory=dict)
    final: dict = field(default_factory=dict)
    pushed: set = field(default_factory=set)
    pushed_slot: dict = field(default_factory=dict)


def resolve_layout(blocks, nargs: int) -> FrameLayout:
    """Resolve frame operations to logical parameter/local slots.

    This compatibility-facing classification is CFG-aware for writes around a
    loop. Value provenance itself comes from :mod:`.stacksim`; consumers should
    prefer normal SSA inputs and use this layout only to classify the remaining
    gaps or to preserve the established public API.
    """
    result = FrameLayout()
    current: dict = {}
    next_version: dict = {}
    in_sub = {id(block) for block in blocks}
    forward: dict = {}

    def reaches_block(source, target) -> bool:
        seen = forward.get(id(source))
        if seen is None:
            seen, work = set(), [source]
            while work:
                block = work.pop()
                for succ in getattr(block, "successors", ()) or ():
                    if id(succ) in in_sub and id(succ) not in seen:
                        seen.add(id(succ))
                        work.append(succ)
            forward[id(source)] = seen
        return id(target) in seen

    burys: dict = {}
    for block in blocks:
        for index, assignment in enumerate(block.assignments):
            if assignment.op == "frame_bury":
                slot = _imm_int(assignment)
                if slot is not None:
                    burys.setdefault(slot, []).append((block, index))

    def bury_reaches(slot: int, block, index: int) -> bool:
        for write_block, write_index in burys.get(slot, ()):
            if write_block is block:
                if write_index < index or reaches_block(block, block):
                    return True
            elif reaches_block(write_block, block):
                return True
        return False

    def fresh(slot: int) -> int:
        version = next_version.get(slot, 0)
        next_version[slot] = version + 1
        current[slot] = version
        return version

    for block in blocks:
        for op_index, assignment in enumerate(block.assignments):
            if assignment.op == "frame_dig" and assignment.outputs:
                slot = _imm_int(assignment)
                if slot is None:
                    continue
                output = assignment.outputs[0]
                if (-nargs <= slot <= -1 and slot not in current
                        and not bury_reaches(slot, block, op_index)):
                    result.dig_param[output] = nargs + slot
                else:
                    version = current.get(slot)
                    if version is not None:
                        result.dig_local[output] = (slot, version)
                    elif slot >= 0 and assignment.inputs:
                        result.passthrough[output] = assignment.inputs[-1]
                        result.pushed.add(output)
                        result.pushed_slot[output] = slot
                    else:
                        result.dig_local[output] = (
                            slot, version if version is not None else fresh(slot))
                for i in range(1, len(assignment.outputs)):
                    output = assignment.outputs[i]
                    if isinstance(output, SSAVar) and i - 1 < len(assignment.inputs):
                        result.passthrough[output] = assignment.inputs[i - 1]
            elif assignment.op == "frame_bury":
                slot = _imm_int(assignment)
                if slot is not None:
                    result.bury[id(assignment)] = (slot, fresh(slot))
                for i, output in enumerate(assignment.outputs):
                    if isinstance(output, SSAVar) and i + 1 < len(assignment.inputs):
                        result.passthrough[output] = assignment.inputs[i + 1]
    result.final = dict(current)
    return result


def _declared_nargs(entry_block) -> int | None:
    for assignment in entry_block.assignments:
        if assignment.op == "proto":
            tokens = (assignment.immediates or "").split()
            try:
                return int(tokens[0]) if tokens else 0
            except ValueError:
                return 0
    return None


def resolve_program(prog) -> dict:
    """Return ``{Subroutine: FrameLayout}`` for declared-frame routines."""
    from ..structure import analyze_structure

    out: dict = {}
    for sub in analyze_structure(prog).subroutines:
        nargs = _declared_nargs(sub.entry_bb)
        if nargs is not None:
            blocks = sorted(sub.body, key=lambda bb: (bb.file, bb.first_line))
            out[sub] = resolve_layout(blocks, nargs)
    return out


# ---------------------------------------------------------------------------
# Public SSA provenance compatibility
# ---------------------------------------------------------------------------


def _program_layouts(prog) -> dict:
    """Use ``SSAProgram``'s established lazy cache when it is available."""
    frame_resolution = getattr(prog, "frame_resolution", None)
    return (frame_resolution() if callable(frame_resolution)
            else resolve_program(prog))


def parameter_sources(prog) -> dict:
    """Caller arguments for every ``frame_dig`` classified as a parameter."""
    out: dict = {}
    for sub, layout in _program_layouts(prog).items():
        nargs = _declared_nargs(sub.entry_bb)
        if not nargs or not layout.dig_param or not sub.callers:
            continue
        by_param: dict = {index: set() for index in range(nargs)}
        for call_site in sub.callers:
            call = next((assignment for assignment in reversed(
                getattr(call_site.callsub_bb, "assignments", ()))
                if assignment.op == "callsub"), None)
            if call is None or len(call.inputs) != nargs:
                continue
            for index in range(nargs):
                value = call.inputs[nargs - 1 - index]
                if value is not None:
                    by_param[index].add(value)
        for output, index in layout.dig_param.items():
            if by_param.get(index):
                out.setdefault(output, set()).update(by_param[index])
    return out


def local_sources(prog) -> dict:
    """Values written by ``frame_bury`` that can reach each local read."""
    out: dict = {}
    for sub, layout in _program_layouts(prog).items():
        if not layout.dig_local or not layout.bury:
            continue
        buried: dict = {}
        for block in sub.body:
            for assignment in block.assignments:
                key = layout.bury.get(id(assignment))
                if key is not None and assignment.inputs:
                    buried.setdefault(key, set()).add(assignment.inputs[0])
        for output, key in layout.dig_local.items():
            if buried.get(key):
                out.setdefault(output, set()).update(buried[key])
    return out


def _unresolved_reads(prog, covered: set[int]) -> list:
    out = []
    for assignment in prog.assignments:
        if (assignment.op != "frame_dig" or assignment.inputs
                or not assignment.outputs):
            continue
        slot = _imm_int(assignment)
        if slot is not None and slot >= 0 and id(assignment.outputs[0]) not in covered:
            out.append(assignment)
    return out


def unresolved_reads(prog) -> list:
    """Local frame reads with neither an SSA input nor a compatibility source."""
    covered = {
        id(output)
        for mapping in (parameter_sources(prog), local_sources(prog))
        for output in mapping
    }
    return _unresolved_reads(prog, covered)


def value_sources(prog) -> dict:
    """All established compatibility sources for frame reads.

    Normal SSA inputs are authoritative. This map remains complete for external
    consumers and for the small set of unresolved compatibility gaps.
    """
    out = {output: set(values)
           for output, values in parameter_sources(prog).items()}
    for output, values in local_sources(prog).items():
        out.setdefault(output, set()).update(values)
    if not getattr(prog, "_frame_unresolved_warned", False):
        try:
            prog._frame_unresolved_warned = True
        except AttributeError:
            pass
        blind = _unresolved_reads(prog, {id(output) for output in out})
        if blind:
            where = ", ".join(
                f"{assignment.location.file}:{assignment.location.line}"
                for assignment in blind[:5])
            logger.warning(
                "%d frame read(s) of a local could not be sourced, so they "
                "read as CLEAN and remain unknown to SSA may-analysis (%s%s)",
                len(blind), where, " …" if len(blind) > 5 else "")
    return out


def gap_sources(prog) -> dict:
    """Only compatibility edges absent from ordinary SSA def-use reachability.

    MAY analyses already walk assignment inputs and phi arguments. Feeding them
    all reconstructed frame edges duplicated almost every traversal edge; this
    filtered view retains only sources that the canonical SSA graph cannot
    reach on its own. :func:`value_sources` remains unchanged for external API
    compatibility and MUST-style caller-set reasoning.
    """
    cached = getattr(prog, "_frame_gap_sources_cache", None)
    if cached is not None:
        return cached

    from .models import Phi

    def upstream(root):
        seen = {root}
        work = [root]
        while work:
            value = work.pop()
            if isinstance(value, Phi):
                incoming = value.args
            else:
                assignment = getattr(value, "defined_by", None)
                incoming = assignment.inputs if assignment is not None else ()
            for source in incoming:
                if source not in seen:
                    seen.add(source)
                    work.append(source)
        return seen

    out = {}
    for output, sources in value_sources(prog).items():
        missing = set(sources) - upstream(output)
        if missing:
            out[output] = missing
    try:
        prog._frame_gap_sources_cache = out
    except AttributeError:
        pass
    return out
