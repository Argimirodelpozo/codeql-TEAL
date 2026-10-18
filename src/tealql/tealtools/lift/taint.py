"""Cached user-input taint and reports over the shared positional summary service."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from types import MappingProxyType
from ..language.avm import STATE_WRITE_OPS
from ..language.effects import STATE_EFFECTS
from . import pre_ir
from .taint_flow import (
    SINK_OPS, UNKNOWN_SOURCE, value_sources, source_label, transfer_fixpoint, sub_local_scratch,
    _trusted_apparg, _intr, _invoke as _invoke,
    _scratch_unknown_write as _scratch_unknown_write,
)
from .summaries import compute_summaries


def _merge_unresolved(lifter, taint: Mapping | None) -> Mapping:
    """Return ``taint`` with representation TOP preserved."""
    if taint is None:
        return user_input_taint(lifter)
    result = {rid: set(sources) for rid, sources in taint.items()}
    for rid, sources in unresolved_taint(lifter).items():
        result.setdefault(rid, set()).update(sources)
    return result



def _return_summary(lifter, trusted_args=frozenset()) -> dict:
    """Legacy aggregate view. Production call transfers use positional results."""
    return {sid: (summary.internal_sources, summary.passthrough)
            for sid, summary in compute_summaries(lifter, trusted_args).items()}


def user_input_taint(lifter, trusted_args=frozenset()) -> Mapping[int, frozenset[str]]:
    """Forward taint from the user-input sources to a fixpoint over ``lifter``'s IR,
    returning ``{id(Register): frozenset(sources)}``; ``trusted_args`` indices are
    exempted from seeding per :func:`_trusted_apparg`.

    Sources are the static table (:func:`source_label`) PLUS own-state reads
    whose slot an untrusted caller can write (:func:`state_value_writers`).

    The completed lift is shared and read-only during an audit.  Cache by the
    only query input so each sink family consumes the same fixed point instead
    of recomputing it independently.
    """
    return _taint_and_state_notes(lifter, trusted_args)[0]


def state_value_writers(lifter, trusted_args=frozenset()) -> Mapping[str, tuple]:
    """``{StateValue label: (writer TEAL lines, ...)}`` — the untrusted writers
    that made each seeded state read a source (for messages)."""
    return _taint_and_state_notes(lifter, trusted_args)[1]


def state_value_sources(lifter, trusted_args=frozenset()) -> Mapping[tuple, str]:
    """``{(file, TEAL line): StateValue label}`` of every own-state read seeded
    as a source — the query layer's source inventory."""
    return _taint_and_state_notes(lifter, trusted_args)[2]


def _taint_and_state_notes(lifter, trusted_args):
    return _taint_state(lifter, trusted_args)[:3]


def _taint_state(lifter, trusted_args):
    """``(taint, notes, points, state_seeds, unknown_scratch)`` — the cached
    fixed point plus the two inputs a per-call-site re-run needs to reproduce
    it (:func:`call_site_taint`)."""
    key = frozenset(trusted_args)
    frozen = getattr(lifter, '_analysis_frozen', False)
    cache = getattr(lifter, "_user_input_taint_cache", {}) if frozen else {}
    if frozen and key in cache:
        return cache[key]
    # State-value seeds grow monotonically: a seeded read can taint another
    # writer's value (``b = a``), so iterate to the least fixed point. The
    # first round is exactly the static-source taint; programs with no
    # constant-key own-state read never pay a second round.
    candidates = _state_candidates(lifter)
    seeds: dict = {}
    notes: dict = {}
    points: dict = {}
    while True:
        taint, scratch = _input_taint(lifter, trusted_args, seeds)
        if candidates is None:
            break
        new_seeds, notes = candidates.seeds_for(lifter, taint)
        if new_seeds == seeds:
            break
        seeds = new_seeds
    if candidates is not None:
        points = {candidates.points[rid]: label for rid, label in seeds.items()}
    result = (taint, MappingProxyType(notes), MappingProxyType(points),
              MappingProxyType(seeds), scratch)
    if frozen:
        cache[key] = result
        lifter._user_input_taint_cache = cache
    return result


def _transfer_rules(lifter, trusted_args, state_seeds, taint):
    """``(seed_label, invoke_ins)`` of the user-input fixpoint over ``taint``."""
    # interprocedural param->return summary, over the same seed set
    summary = (compute_summaries(lifter, trusted_args, state_seeds) if state_seeds
               else compute_summaries(lifter, trusted_args))

    def _seed(src):
        lbl = source_label(src)
        if lbl:
            return lbl if not _trusted_apparg(src, trusted_args) else None
        return state_seeds.get(id(src))

    def _foreign(sid, index):
        # Another procedure's param the callee reads through scratch (its
        # caller parked it there): that param's taint here, i.e. the union
        # of its call sites', never cleaner than any one of them.
        sub = lifter.name2sub.get(sid)
        if sub is None or index >= len(sub.parameters):
            return {UNKNOWN_SOURCE}
        return set(taint.get(id(sub.parameters[index].register), ()))

    def _inv(o, inv, reg_t):
        outputs = ()
        changed = False
        callee = lifter.name2sub.get(inv.target)
        if callee is not None:
            # result <- the callee's summary: its internal-source returns
            # plus only the params that actually flow through.
            args = [reg_t(a) for a in inv.args]
            outputs = summary[callee.id].output_sources(args, _foreign)
            for i, p in enumerate(callee.parameters):   # arg -> callee param
                if i < len(inv.args):
                    pt = reg_t(inv.args[i])
                    if pt - taint[id(p.register)]:
                        taint[id(p.register)] |= pt
                        changed = True
        else:                           # unknown callee: stay conservative
            unknown = {UNKNOWN_SOURCE}
            for a in inv.args:
                unknown.update(reg_t(a))
            outputs = tuple(unknown for _ in getattr(o, "targets", ()))
        return outputs, changed

    return _seed, _inv


def _input_taint(lifter, trusted_args, state_seeds):
    """``(taint, unknown_scratch)`` — one round of the whole-program fixpoint."""
    taint: dict = defaultdict(set)
    seed, inv = _transfer_rules(lifter, trusted_args, state_seeds, taint)
    scratch = transfer_fixpoint(lifter, taint, seed_label=seed, invoke_ins=inv)
    return MappingProxyType({k: frozenset(v) for k, v in taint.items() if v}), scratch


def _own_registers(sub) -> frozenset:
    """``id`` of every register ``sub`` itself defines: params, phis, targets."""
    own = {id(p.register) for p in sub.parameters}
    for b in sub.body:
        own.update(id(ph.register) for ph in b.phis)
        for o in b.ops:
            own.update(id(t) for t in getattr(o, "targets", ()) or ())
    return frozenset(own)


class _ContextTaint(dict):
    """A taint map answering ``own`` registers from itself (empty until the
    context's fixpoint writes them) and every other register from ``base``,
    copied on first write so ``base`` is never mutated."""

    def __init__(self, base, own):
        super().__init__()
        self._base = base
        self._own = own

    def __missing__(self, rid):
        value = set() if rid in self._own else set(self._base.get(rid, ()))
        self[rid] = value
        return value

    def get(self, rid, default=None):
        if dict.__contains__(self, rid):
            return dict.__getitem__(self, rid) or default
        if rid in self._own:
            return default
        return self._base.get(rid, default)

    def __contains__(self, rid):
        return bool(self.get(rid))


#: Per-lift ceiling on context re-runs (memo misses); past it the caller keeps
#: the whole-program (merged) verdict.
_CONTEXT_BUDGET = 256


def call_site_taint(lifter, sub, arg_sources, base=None, trusted_args=frozenset()):
    """``sub``'s taint when entered from ONE call site — the 1-CFA refinement
    of :func:`user_input_taint` — or ``None`` once the per-lift budget is spent.

    The whole-program fixpoint gives each parameter the UNION of every call
    site's argument: a transfer helper called with a pinned receiver at one
    site and an attacker-chosen one at another is ONE register, so a check
    that only one caller needs is judged against taint another caller supplied
    (`assert(p_receiver == p_owner)` is no pin when `p_owner` is attacker-fed
    SOMEWHERE). Here ``sub``'s parameters carry exactly ``arg_sources`` (one
    set per parameter) and the transfer fixpoint is re-run over ``sub`` alone.

    Soundness: every register ``sub`` does not define — the caller's, another
    sub's scratch store, a callee's param — answers from ``base`` (the
    whole-program taint or an enclosing context), so a context is never
    cleaner than the program around ``sub``; callee calls transfer through the
    same positional summaries; the run starts from the program's unknown-scratch
    state; and a self-recursive call feeds its arguments back into ``sub``'s own
    parameters exactly as the whole-program run does. ``base`` must be
    whole-program taint or a map this function returned. Memoised on ``(sub,
    arg_sources, base)``: sites passing equally-tainted arguments share a run."""
    taint, _, _, seeds, scratch = _taint_state(lifter, trusted_args)
    base = taint if base is None else base
    memo = getattr(lifter, "_call_site_taint_memo", None)
    if memo is None or memo[0] is not taint:
        memo = (taint, {}, {})
        lifter._call_site_taint_memo = memo
    key = (sub.id, tuple(frozenset(a) for a in arg_sources),
           None if base is taint else id(base))
    hit = memo[1].get(key)
    if hit is not None and hit[0] is base:
        return hit[1]
    if len(memo[1]) >= _CONTEXT_BUDGET:
        return None
    local = _ContextTaint(base, _own_registers(sub))
    for p, sources in zip(sub.parameters, arg_sources):
        local[id(p.register)] |= sources
    seed, inv = _transfer_rules(lifter, trusted_args, seeds, local)
    local_defs = memo[2].get(sub.id)
    if local_defs is None:
        local_defs = memo[2][sub.id] = sub_local_scratch(lifter, sub)
    transfer_fixpoint(lifter, local, seed_label=seed, invoke_ins=inv, subs=(sub,),
                      unknown_scratch=scratch, scratch_defs=local_defs)
    memo[1][key] = (base, local)     # strong ref to ``base``: no id() reuse
    return local


class _StateCandidates:
    """Own-state reads with a constant slot, and the lifted writers that may
    write those slots — the static half of the ``StateValue`` seed.

    RULE: a read of own state (``app_global_get``, current-app
    ``app_global_get_ex``, ``app_local_get[_ex]``, ``box_get``/``box_extract``)
    whose key is a CONSTANT slot becomes the source ``StateValue:<key>`` when
    some writer that may write that slot

    * writes an attacker-dependent VALUE (tainted by the current fixed point —
      including another ``StateValue``; ``unresolved`` counts, it is TOP)
      that is an UNGUARDED flow by the engine's own sink verdict (a validated
      or sender-pinned write is not), and
    * is NOT authority-preserving per :func:`analysis.authority.authority_for`
      (no creation-only path, no sender pin to a preserved address, no fixed
      trusted replacement).

    A writer "may write" the slot when its key is that constant, or is
    dynamic in the same storage AND that key is itself an unguarded
    attacker-dependent flow (the attacker can steer it onto the slot).

    HAZARD (tightenings, measured on the mainnet ratchet): a writer storing a
    VALIDATED input (bounded / pinned to a sibling payment) gave every
    lending template's per-user position a "source" — 17 writers of one
    local key, every one checked. An untrusted writer of a CLEAN value (counters, ``total += gtxn 1 Amount``, a flag set to a
    constant) gives the caller timing, not content — seeding those turned every
    pool total into a "source". A DYNAMIC-key writer aliases a constant key
    only when its KEY is an unguarded attacker-dependent flow: the authority
    analysis' "any dynamic writer may alias" is the right conservatism for
    PROVING an authority, but as a taint SOURCE it seeded `aid` from a setter
    whose key is asserted to be "w1" or "w2", and every slot of a contract
    with a `BoxMap`/``Sender``-keyed record — keys no caller can steer onto
    an unrelated constant.

    HAZARD: a read whose key is NOT constant is never seeded. The authority
    analysis cannot name its slot (``_slot``/``read_slot`` is ``None``), so it
    could not tell WHICH writers matter — seeding it would make every
    ``box_get(Sender ‖ …)`` record read a source and drown the families in
    rows about the caller's own record."""

    def __init__(self, auth, reads, writers, points):
        self.auth = auth
        self.reads = reads          # id(read Intrinsic) -> slot
        self.points = points        # id(read Intrinsic) -> (file, line)
        self.writers = writers      # [(Intrinsic, SSA Assignment, (file, storage, key|None))]
        self._preserved: dict = {}

    def _untrusted(self, origin, slot) -> bool:
        k = id(origin)
        if k not in self._preserved:
            self._preserved[k] = self.auth.writer_authority(
                origin, slot if slot[2] is not None else None).preserved
        return not self._preserved[k]

    def _unguarded_writes(self, lifter, taint) -> set:
        """``id`` of every writer whose VALUE is an UNGUARDED tainted flow —
        the engine's own sink verdict (coverage of every tainted leaf, sender
        pins, caller/callee transfer), so a writer storing a VALIDATED input
        (`assert(btoi(arg) == gtxn 0 Amount)`) is no source."""
        from .fund_flow import _tainted_sink_flows
        by_id = {id(intr): intr for intr, _, _ in self.writers}

        def sink_of(s):
            if id(s) not in by_id:
                return ()
            effect = STATE_EFFECTS[s.op]
            out = []
            if effect.value_index is not None and effect.value_index < len(s.args):
                out.append((f"v{id(s)}", "LOW", [s.args[effect.value_index]]))
            if effect.key_index < len(s.args):
                out.append((f"k{id(s)}", "LOW", [s.args[effect.key_index]]))
            return tuple(out)

        # The round's taint already carries `unresolved` and StateValue;
        # merging would re-enter this fixed point.
        return {f.field for f in _tainted_sink_flows(
                    lifter, sink_of, taint, merge_unresolved=False, state_notes=False)
                if not f.guarded and not f.param_derived}

    def seeds_for(self, lifter, taint):
        from ..language.avm import state_value_label
        hit: dict = defaultdict(set)
        read_slots = set(self.reads.values())
        unguarded = None
        for intr, origin, slot in self.writers:
            effect = STATE_EFFECTS[intr.op]
            vi = effect.value_index
            if vi is None or vi >= len(intr.args):
                continue        # delete / create / resize: no caller-chosen content
            if not value_sources(intr.args[vi], taint):
                continue
            file, storage, key = slot
            if key is None:
                prefix = _constant_prefix(lifter, intr.args[effect.key_index]) \
                    if effect.key_index < len(intr.args) else ""
                targets = {r for r in read_slots if r[0] == file and r[1] == storage
                           and r[2][2:].startswith(prefix)}
            else:
                targets = {slot} & read_slots
            if not targets or not self._untrusted(origin, slot):
                continue
            if unguarded is None:
                unguarded = self._unguarded_writes(lifter, taint)
            if f"v{id(intr)}" not in unguarded:
                continue
            if key is None and f"k{id(intr)}" not in unguarded:
                continue        # the dynamic key cannot be steered onto `targets`
            for t in targets:
                hit[t].add(origin.location.line)
        seeds = {rid: state_value_label(slot[2]) for rid, slot in self.reads.items()
                 if slot in hit}
        notes: dict = defaultdict(set)
        for slot, lines in hit.items():
            notes[state_value_label(slot[2])] |= lines
        return seeds, {label: tuple(sorted(lines)) for label, lines in notes.items()}


def _constant_prefix(lifter, value, depth=0) -> str:
    """Hex of the constant bytes every value of ``value`` starts with (``""``
    when unknown): ``concat("o", itob(x))`` can only alias keys starting
    with ``o`` — the ``BoxMap``/``LocalMap`` prefix shape. Follows copies,
    phis and EVERY may-reaching scratch store (common prefix)."""
    from os.path import commonprefix
    from .fund_flow import _def_map
    from .taint_flow import _lift_value
    defs = getattr(lifter, "_state_prefix_defs", None)
    if defs is None:
        defs = _def_map(lifter)
        if getattr(lifter, "_analysis_frozen", False):
            lifter._state_prefix_defs = defs
    if depth > 16:
        return ""
    if isinstance(value, pre_ir.BytesConstant):
        return str(value.value).removeprefix("0x")
    if not isinstance(value, pre_ir.Register):
        return ""
    o = defs.get(id(value))
    src = _intr(o) if o is not None else None
    arms = []
    if src is not None and src.op == "concat" and len(src.args) == 2:
        arms = [src.args[1]]            # TOP-FIRST: args[1] is the left operand
    elif isinstance(o, pre_ir.Assignment) and isinstance(
            o.source, (pre_ir.Register, pre_ir.BytesConstant)):
        arms = [o.source]
    elif isinstance(o, pre_ir.Phi):
        arms = [a.value for a in o.args]
    elif src is not None and src.op == "load":
        for lv in getattr(lifter, "register_sources", {}).get(id(value), ()):
            for sv in lifter.load_stores.get(lv, ()):
                arms.append(_lift_value(lifter, sv))
    if not arms:
        return ""
    prefixes = [_constant_prefix(lifter, a, depth + 1) for a in arms]
    common = commonprefix(prefixes)
    return common[:len(common) - len(common) % 2]       # whole bytes only


def _state_candidates(lifter):
    """:class:`_StateCandidates` for ``lifter``, or ``None`` when no read can
    seed (no constant-key own-state read, or no SSA program to ask)."""
    prog = getattr(lifter, "prog", None)
    if prog is None or not hasattr(prog, "assignments"):
        return None
    from ..analysis.authority import authority_for
    from ..language.avm import STATE_VALUE_READ_OPS
    auth = authority_for(prog)
    reads, writers, points = {}, [], {}
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            src = _intr(o)
            if src is None:
                continue
            origin = getattr(src, "origin", None)
            if origin is None or getattr(origin, "op", None) != src.op:
                continue
            if src.op in STATE_VALUE_READ_OPS:
                slot = auth.read_slot(origin)
                if slot is not None:
                    reads[id(src)] = slot
                    points[id(src)] = (origin.location.file, origin.location.line)
            elif src.op in STATE_EFFECTS:
                slot = auth.write_slot(origin)
                if slot is not None:
                    writers.append((src, origin, slot))
    if not reads:
        return None
    owners = {(f, st) for f, st, _ in reads.values()}
    keys = set(reads.values())
    writers = [w for w in writers
               if (w[2][0], w[2][1]) in owners and (w[2][2] is None or w[2] in keys)]
    return _StateCandidates(auth, reads, writers, points) if writers else None


def unresolved_taint(lifter) -> Mapping[int, frozenset[str]]:
    """Register closure reached from any explicit ``Undefined`` value.

    Custom taint views (notably byte-interval taint) replace the normal input
    seed map, but they must not replace analysis TOP with clean.  Compute this
    once from the production interprocedural fixpoint and retain only the
    ``UNKNOWN_SOURCE`` component so callers can union it into any abstraction.
    """
    cached = getattr(lifter, "_unresolved_ir_taint", None)
    frozen = getattr(lifter, '_analysis_frozen', False)
    if frozen and cached is not None:
        return cached
    result = MappingProxyType({
        rid: frozenset({UNKNOWN_SOURCE})
        for rid, sources in user_input_taint(lifter).items()
        if UNKNOWN_SOURCE in sources
    })
    if frozen:
        lifter._unresolved_ir_taint = result
    return result


_SINKS = SINK_OPS


def _tainted_sink_hits(subs, taint):
    """``(op, intrinsic, hit)`` for every sink op of ``subs`` (in block order) whose
    operands carry taint: a :data:`_SINKS` intrinsic, or an ``assert`` (then
    ``intrinsic`` is None and the condition is the operand)."""
    for b in pre_ir.blocks(subs):
        for o in b.ops:
            s = _intr(o)
            if s is not None and s.op in _SINKS:
                args, op = s.args, s.op
            elif isinstance(o, pre_ir.Assert):
                args, op, s = [o.condition], "assert", None
            else:
                continue
            hit = set()
            for a in args:
                hit |= value_sources(a, taint)
            if hit:
                yield op, s, hit


def tainted_sinks(lifter, taint=None) -> list:
    """``(sources, sink_op, immediates)`` for every sink whose operands include a
    tainted value; pass a precomputed ``taint`` map or one is built."""
    taint = _merge_unresolved(lifter, taint)
    return [(frozenset(hit), op, s.immediates if s is not None else None)
            for op, s, hit in _tainted_sink_hits(lifter.subs, taint)]


# Sink categories, most-to-least security-relevant, for the report.
_CATEGORIES = [
    ("INNER-TRANSACTION FIELDS  (fund flow -- who gets paid, and how much)",
     frozenset({"itxn_field"})),
    ("PERSISTENT STATE WRITES", STATE_WRITE_OPS),
    ("EMITTED LOGS",
     frozenset({"log"})),
    ("ASSERTED CONDITIONS  (user-controlled control flow)",
     frozenset({"assert"})),
]


def taint_report(lifter, name: str = "<program>") -> str:
    """A human-readable taint report: every attacker-controlled value reaching a sink,
    grouped by category and annotated with the original TEAL line(s)."""
    taint = user_input_taint(lifter)
    present = {s for v in taint.values() for s in v}
    groups: dict = defaultdict(lambda: {"lines": set(), "sources": set()})
    cat_of = {op: i for i, (_, ops) in enumerate(_CATEGORIES) for op in ops}
    nflows = 0
    for op, s, hit in _tainted_sink_hits(lifter.subs, taint):
        if s is not None:
            fld = str(s.immediates[0]) if s.immediates else ""
            line = getattr(s, "line", 0)
        else:
            fld, line = "", 0
        present |= hit
        nflows += 1
        g = groups[(cat_of.get(op, 99), op, fld)]
        g["lines"].add(line)
        g["sources"] |= hit

    out = ["=" * 70,
           f"  USER-INPUT TAINT REPORT  --  {name}",
           "=" * 70, "",
           "Every value flowing from attacker-controlled input to a sensitive sink,",
           "traced through the lifted IR -- interprocedurally, with scratch flow",
           "resolved via the low-layer reaching-def. Sources are the inputs an",
           "attacker chooses at call time; line numbers are the original TEAL.", "",
           f"  Sources present   : {', '.join(sorted(present)) or '(none)'}",
           f"  Tainted IR values : {len(taint)}",
           f"  Sink flows        : {nflows}", ""]
    if not nflows:
        out.append("  No user-controlled value reaches a tracked sink.")
    for ci, (title, _) in enumerate(_CATEGORIES):
        keys = sorted((k for k in groups if k[0] == ci), key=lambda k: (k[1], k[2]))
        if not keys:
            continue
        out += ["-" * 70, title, "-" * 70]
        for key in keys:
            g = groups[key]
            label = f"{key[1]} {key[2]}".strip()
            lines = sorted(x for x in g["lines"] if x)
            loc = ("TEAL line " + ", ".join(map(str, lines[:10]))
                   + (" ..." if len(lines) > 10 else "")) if lines \
                else f"{len(g['lines'])} site(s)"
            out.append(f"  {label:28s} <- {'+'.join(sorted(g['sources'])):16s}  {loc}")
        out.append("")
    return "\n".join(out)
