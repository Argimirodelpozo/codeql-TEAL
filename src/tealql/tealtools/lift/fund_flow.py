"""Attacker-controlled inner-transaction FUND-FLOW detector (IR layer).

This is the PRIMARY fund-flow analysis: it backs the first-class
``ir-tainted-fund-flow`` detector (run via the ``tealql.security.common.ir_lifter``
bridge) and SUBSUMES the SSA-layer ``security/detections/tainted-fund-flow``
sibling on every axis -- interprocedural taint (the lift resolves ``proto``
frames into explicit params, a connection the SSA def-use does not carry),
guard dominance across ``callsub`` boundaries (:func:`_entry_guards`), typed
values, and cross-contract caller-pin suppression via ``trusted_args``. The SSA
detector is marked ``superseded_by`` this one and dropped from default scans;
it remains only as the automatic fallback when a contract fails to lift.

Every user-input-tainted value reaching a *fund-flow* inner-transaction field is a
finding: the attacker can influence WHO gets paid, HOW MUCH, or WHO controls the
account.

    CloseRemainderTo / AssetCloseTo              -- sweep the account
    Receiver / AssetReceiver                     -- redirect a payment
    Amount / AssetAmount                         -- control how much moves

    (RekeyTo is intentionally NOT a fund field here -- an app/itxn RekeyTo is
    self-inflicted, not a tainted-field vuln; rekey is an lsig-only check. See
    ``avm.FUND_FIELDS`` and the lsig ``rekey-to`` detector.)

Each finding records the *dominating guards* on the path to the sink -- asserts,
and conditional branches whose outcome is forced on every path that reaches the
sink -- classified by whether they test the tainted input or the transaction
``Sender``. So an UNGUARDED attacker-controlled fund flow (nothing on the path
checks the input or who's calling) stands out from one already gated by a check;
the guard list is reported either way so a human triages, à la the SSA-layer
``auth_domination`` detector.

Built on :func:`taint.user_input_taint` (precise interprocedural IR taint) plus a
dominator computation over the lifted IR CFG. Guards are recognised both
intra-procedurally AND across call boundaries: a value passed into a parameter that
the caller already checked counts as guarded (:func:`_entry_guards`, a monotone
fixpoint that ANDs the guard over every tainted-passing call site, with
transitivity through the caller's own params). ``param-derived`` now means only the
residual UNRESOLVED case -- a param feeds the sink, nothing guards it, and the sub
has no call sites to inspect (e.g. dead / externally-entered).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import pre_ir
from .taint import _intr, _invoke, source_label, user_input_taint
from ..avm import FUND_FIELDS as _FUND_FIELDS
from ..cfg.dominance import iterative_dominators

# Inner-txn fields where attacker control = fund redirection / theft, by severity
# (canonical FUND_FIELDS in tealql.tealtools.avm).
_SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

_TXN_SENDER_FAM = frozenset({"txn", "txna", "gtxn", "gtxna", "gtxns", "gtxnsa"})


# --------------------------------------------------------------------------
# IR CFG + dominators (intra-subroutine)
# --------------------------------------------------------------------------


def _succs(term) -> list:
    if isinstance(term, pre_ir.Goto):
        return [term.target]
    if isinstance(term, pre_ir.ConditionalBranch):
        return [term.non_zero, term.zero]
    if isinstance(term, pre_ir.GotoNth):
        return list(term.blocks) + [term.default]
    if isinstance(term, pre_ir.Switch):
        return [b for _, b in term.cases] + [term.default]
    return []


def _dominators(sub) -> dict:
    """``{block_id: set(block_ids that dominate it)}`` for one subroutine.
    The IR sub has a single entry (``ids[0]``) and all blocks reachable."""
    ids = [b.id for b in sub.body]
    if not ids:
        return {}
    succ = {b.id: _succs(b.terminator) for b in sub.body}
    preds: dict = {i: [] for i in ids}
    for i in ids:
        for s in succ[i]:
            if s in preds:
                preds[s].append(i)
    return iterative_dominators(ids, [ids[0]], lambda i: preds[i])


# --------------------------------------------------------------------------
# Expression walk: registers + their defining ops behind a Value
# --------------------------------------------------------------------------


def _invoke_returns(lifter) -> dict:
    """``{id(call_result_register): [callee return-value registers]}``.

    Lets a guard walk descend into a VALIDATION SUBROUTINE: an
    ``assert (callsub check ...)`` where the actual ``txn Sender == owner`` (or
    value) check lives inside the callee's body and flows out through its
    ``SubroutineReturn``. Maps the i-th result of each ``InvokeSubroutine`` to the
    i-th returned register of every ``SubroutineReturn`` in the callee."""
    name2sub = {s.id: s for s in lifter.subs}
    out: dict = {}
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            inv = _invoke(o)
            if inv is None:
                continue
            callee = name2sub.get(inv.target)
            if callee is None:
                continue
            rets_by_pos: dict = defaultdict(list)
            for cb in callee.body:
                t = cb.terminator
                if isinstance(t, pre_ir.SubroutineReturn):
                    for i, v in enumerate(t.result):
                        if isinstance(v, pre_ir.Register):
                            rets_by_pos[i].append(v)
            for i, tgt in enumerate(getattr(o, "targets", ()) or ()):
                if isinstance(tgt, pre_ir.Register):
                    out[id(tgt)] = rets_by_pos.get(i, [])
    return out


def _walk(value, def_of, depth=0, seen=None, inv_ret=None):
    """Yield ``(register, defining_op_or_None)`` for every register in the
    def-expression tree behind ``value`` (bounded). With ``inv_ret`` (from
    :func:`_invoke_returns`), descend through a call result into the callee's
    returned values -- so a check inside an asserted validation subroutine is
    seen as part of the guard condition."""
    if seen is None:
        seen = set()
    if not isinstance(value, pre_ir.Register) or depth > 8 or id(value) in seen:
        return
    seen.add(id(value))
    o = def_of.get(id(value))
    yield value, o
    if o is not None:
        src = _intr(o)
        if src is not None:
            for a in src.args:
                yield from _walk(a, def_of, depth + 1, seen, inv_ret)
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            yield from _walk(o.source, def_of, depth + 1, seen, inv_ret)
        elif isinstance(o, pre_ir.Phi):
            for pa in o.args:
                yield from _walk(pa.value, def_of, depth + 1, seen, inv_ret)
    if inv_ret:                       # descend into an asserted validation sub
        for rv in inv_ret.get(id(value), ()):
            yield from _walk(rv, def_of, depth + 1, seen, inv_ret)


def _is_sender_op(src) -> bool:
    if not isinstance(src, pre_ir.Intrinsic):
        return False
    imm = " ".join(str(i) for i in (src.immediates or []))
    if src.op in _TXN_SENDER_FAM and "Sender" in imm:
        return True
    return src.op == "global" and ("CreatorAddress" in imm or "Sender" in imm)


def _def_map(lifter) -> dict:
    d: dict = {}
    for b in pre_ir.blocks(lifter.subs):
        for ph in b.phis:
            d[id(ph.register)] = ph
        for o in b.ops:
            for t in getattr(o, "targets", ()) or ():
                d[id(t)] = o
    return d


def _ir_op_str(o) -> str:
    """One-line label for a lifted-IR op: ``op imm @Lline`` / ``callsub NAME`` / ``φ``."""
    s = _intr(o)
    if s is not None:
        imm = " ".join(str(i) for i in (s.immediates or []))
        ln = getattr(s, "line", 0)
        return f"{s.op}{(' ' + imm) if imm else ''}" + (f" @L{ln}" if ln else "")
    inv = _invoke(o)
    if inv is not None:
        return f"callsub {inv.target}"
    if isinstance(o, pre_ir.Phi):
        return "φ"
    return "copy" if isinstance(o, pre_ir.Assignment) else str(o)


def ir_taint_chain(lifter, register, view, *, max_hops: int = 40) -> list:
    """The taint road in LIFTED-IR ops: walk backward from ``register`` following
    the tainted arg (per ``view`` -- a :class:`byte_taint.IrByteTaint`) to the
    source op, SOURCE-first. Natively interprocedural: at a subroutine PARAMETER
    (no defining op in a block) it crosses to the caller's bound arg at each
    ``InvokeSubroutine`` site -- the IR represents the callsub arg-passing
    directly, so no ``frame_dig`` hop like the SSA chain."""
    def_of = _def_map(lifter)
    param_args: dict = {}          # id(param register) -> [caller arg values]
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            inv = _invoke(o)
            if inv is None:
                continue
            callee = lifter.name2sub.get(inv.target)
            if callee is None:
                continue
            for i, p in enumerate(callee.parameters):
                if i < len(inv.args):
                    param_args.setdefault(id(p.register), []).append(inv.args[i])

    def _tainted(v):
        return isinstance(v, pre_ir.Register) and (
            bool(view.tainted_bytes(v)) or view.is_scalar_tainted(v))

    def _pick(values):
        """Follow a covered-tainted operand if there is one; else fall back to an
        UNCOVERED register -- byte_taint_view only covers ~90% of registers (a
        lift-synthesized param / block-arg is uncovered), so the taint road runs
        through those coverage gaps rather than dead-ending at them."""
        values = list(values)
        return (next((v for v in values if _tainted(v)), None)
                or next((v for v in values
                         if isinstance(v, pre_ir.Register) and not view.is_covered(v)), None))

    chain: list = []
    seen: set = set()
    cur = register
    while cur is not None and id(cur) not in seen and len(chain) < max_hops:
        seen.add(id(cur))
        o = def_of.get(id(cur))
        nxt = None
        if o is not None:
            chain.append(o)
            src = _intr(o)
            if src is not None:
                nxt = _pick(src.args)
            elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                nxt = _pick([o.source])
            elif isinstance(o, pre_ir.Phi):
                nxt = _pick([pa.value for pa in o.args])
        if nxt is None:               # a parameter -> cross callsub to the caller arg
            nxt = _pick(param_args.get(id(cur), ()))
        cur = nxt
    chain.reverse()
    return chain


def ir_taint_road(lifter, register, view, *, sep: str = "  →  ") -> str:
    """The taint road for ``register`` as a one-line string of lifted-IR ops,
    source → sink (see :func:`ir_taint_chain`). ``(no tainted road)`` if none."""
    ops = ir_taint_chain(lifter, register, view)
    return sep.join(_ir_op_str(o) for o in ops) if ops else "(no tainted road)"


# --------------------------------------------------------------------------
# Guards + findings
# --------------------------------------------------------------------------


@dataclass
class Guard:
    kind: str                 # "assert" | "branch"
    polarity: str | None      # "true" / "false" for a branch, else None
    checks_input: bool        # the condition tests the (same-source) tainted input
    checks_sender: bool       # the condition tests txn Sender / Global.CreatorAddress

    def describe(self) -> str:
        tags = []
        if self.checks_sender:
            tags.append("sender")
        if self.checks_input:
            tags.append("tainted-input")
        p = f"({self.polarity})" if self.polarity else ""
        return f"{self.kind}{p}:{'+'.join(tags) or 'other'}"


def _input_key(src):
    """Identity of a specific user-input READ, e.g. ``("txn", ("ApplicationArgs",
    "0"))`` -- so two reads of the SAME slot match, but ApplicationArgs[0] vs [1]
    don't. ``None`` if ``src`` isn't a user-input source op."""
    if src is None or source_label(src) is None:
        return None
    # Dynamic-index reads (txnas/gtxnas/gtxnsas/gloadss) carry the array INDEX on
    # the stack, not in immediates -- so two DIFFERENT-index reads share the same
    # (op, immediates) and would wrongly collapse to one key. Fall back to
    # register-identity matching for them (None = no cross-read key).
    if src.op in ("txnas", "gtxnas", "gtxnsas", "gloadss"):
        return None
    return (src.op, tuple(str(i) for i in (src.immediates or [])))


def _classify(kind, polarity, cond, def_of, sink_regs, sink_keys, inv_ret=None) -> Guard:
    # checks_input is VALUE-level, not source-FAMILY-level: the guard must test the
    # SAME value the sink uses -- a shared register in their def-trees, OR a read of
    # the same specific input slot (reconnecting the common "check and use each read
    # ApplicationArgs[i] separately" pattern). Family-level overlap (any
    # ApplicationArgs read) would mark "the contract validates SOME input" as
    # "validates THIS value" and hide real findings.
    ci = cs = False
    for r, o in _walk(cond, def_of, inv_ret=inv_ret):
        if id(r) in sink_regs:
            ci = True
        src = _intr(o) if o is not None else None
        if src is not None:
            if _is_sender_op(src):
                cs = True
            if _input_key(src) in sink_keys:
                ci = True
    return Guard(kind, polarity, ci, cs)


def _dominating_guards(by_id, dom, sink_bid, sink_idx, def_of, sink_regs, sink_keys,
                       inv_ret=None) -> list:
    doms = dom.get(sink_bid, {sink_bid})
    guards = []
    for d in doms:
        blk = by_id.get(d)
        if blk is None:
            continue
        # Asserts that must pass before the sink: all of a strictly-dominating
        # block, or those before the sink op in the sink's own block.
        ops = blk.ops if d != sink_bid else blk.ops[:sink_idx]
        for o in ops:
            if isinstance(o, pre_ir.Assert):
                guards.append(_classify("assert", None, o.condition, def_of,
                                        sink_regs, sink_keys, inv_ret))
        # A conditional branch in a strictly-dominating block whose outcome is
        # forced: exactly one successor dominates the sink => that edge is taken
        # on every path to the sink, so its condition guards it.
        t = blk.terminator
        if isinstance(t, pre_ir.ConditionalBranch) and d != sink_bid:
            nz, z = t.non_zero in doms, t.zero in doms
            if nz != z:
                guards.append(_classify("branch", "true" if nz else "false",
                                        t.condition, def_of, sink_regs, sink_keys,
                                        inv_ret))
    return guards


@dataclass
class FundFlowFinding:
    field: str
    severity: str
    sources: frozenset
    sub_id: str
    line: int
    guards: list             # list[Guard]
    param_derived: bool      # sink value flows from a sub param (guard may be upstream)
    sink_reg: object = None  # the tainted operand register -> ir_taint_road witness

    @property
    def guarded(self) -> bool:
        return any(g.checks_input or g.checks_sender for g in self.guards)

    def pretty(self) -> str:
        gd = (", guarded by " + "; ".join(g.describe() for g in self.guards
                                          if g.checks_input or g.checks_sender)) \
            if self.guarded else \
            ("  [param-derived: guard may be in a caller]" if self.param_derived
             else "  ** UNGUARDED **")
        src = "+".join(sorted(self.sources))
        return (f"[{self.severity}] itxn {self.field} <- {src}  "
                f"({self.sub_id} line {self.line}){gd}")

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "sources": sorted(self.sources),
            "subroutine": self.sub_id,
            "line": self.line,
            "guarded": self.guarded,
            "param_derived": self.param_derived,
            "guards": [g.describe() for g in self.guards],
        }


def _entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret=None):
    """Interprocedural guard summary ``{sub.id: {param_idx: (checks_input,
    checks_sender)}}`` plus the set of subs that are called somewhere.

    Param ``i`` of sub ``S`` is entry-guarded iff at EVERY call site that passes a
    TAINTED value for arg ``i`` the caller dominates that call with a guard testing
    that value (input) or the sender. Transitive: if the caller's arg is itself one
    of the caller's params, it inherits that param's entry guard. Monotone fixpoint
    (guards only grow), AND-across-sites (sound: must hold on every path in). An
    untainted-passing site can't expose the sink, so it doesn't constrain the
    summary."""
    subs = {s.id: s for s in lifter.subs}
    # Precompute each call-site arg's STATIC facts once (only the transitive part
    # changes across iterations): (caller_id, tainted, intra_input, intra_sender,
    # [caller param indices the arg flows from]).
    recs: dict = {sid: [] for sid in subs}
    for s in lifter.subs:
        dom, by_id = dom_by_sub[s.id], {b.id: b for b in s.body}
        cpidx = {id(p.register): i for i, p in enumerate(s.parameters)}
        for b in s.body:
            for idx, o in enumerate(b.ops):
                inv = _invoke(o)
                if inv is None or inv.target not in subs:
                    continue
                facts = []
                for arg in inv.args:
                    walked = list(_walk(arg, def_of))
                    aregs = {id(r) for r, _ in walked}
                    akeys = {k for _, oo in walked
                             if (k := _input_key(_intr(oo) if oo is not None else None)) is not None}
                    guards = _dominating_guards(by_id, dom, b.id, idx, def_of, aregs,
                                                akeys, inv_ret)
                    facts.append((s.id, any(r in taint for r in aregs),
                                  any(g.checks_input for g in guards),
                                  any(g.checks_sender for g in guards),
                                  [cpidx[r] for r in aregs if r in cpidx]))
                recs[inv.target].append(facts)
    eg = {sid: {i: (False, False) for i in range(len(subs[sid].parameters))} for sid in subs}
    called = {tid for tid, sites in recs.items() if sites}
    changed = True
    while changed:
        changed = False
        for tid, sites in recs.items():
            for i in range(len(subs[tid].parameters)):
                all_ci = all_cs = True
                seen = False
                for facts in sites:
                    if i >= len(facts):
                        all_ci = all_cs = False
                        break
                    cid, tainted, ci0, cs0, ks = facts[i]
                    if not tainted:
                        continue                  # safe site: doesn't constrain
                    seen = True
                    all_ci &= ci0 or any(eg[cid][k][0] for k in ks)
                    all_cs &= cs0 or any(eg[cid][k][1] for k in ks)
                new = (seen and all_ci, seen and all_cs)
                if new != eg[tid][i]:
                    eg[tid][i] = new
                    changed = True
    return eg, called


def _tainted_sink_flows(lifter, sink_of, taint=None, trusted_args=frozenset(),
                        sender_only=False) -> list:
    """Core taint-to-sink engine. ``sink_of(intrinsic)`` yields
    ``(label, severity, value_args)`` for each sink the op represents -- where
    ``value_args`` is the operand(s) whose taint makes it a finding. Returns
    UNGUARDED-first findings with the full guard machinery: intra- AND inter-
    procedural dominance, validation-subroutine descent, caller entry-guards, and
    cross-contract ``trusted_args``. Parameterising the sink lets one engine power
    inner-txn fields (fund-flow / appcall / asset / asset-admin) AND persistent
    state writes.

    ``sender_only``: count ONLY sender/creator guards toward ``guarded``, not
    input-value checks. The byte-precise partial-fund-flow detector sets this --
    it drives the engine with a byte-interval taint map that has ALREADY cleared
    validated byte ranges, so an input-slot guard would double-count (and, worse,
    reproduce the slot-granular blind spot: a check of one sub-field spuriously
    guarding a different, unchecked sub-field of the same arg)."""
    if taint is None:
        taint = user_input_taint(lifter, trusted_args)
    def_of = _def_map(lifter)
    inv_ret = _invoke_returns(lifter)
    dom_by_sub = {s.id: _dominators(s) for s in lifter.subs}
    entry_guards, called = _entry_guards(lifter, def_of, dom_by_sub, taint, inv_ret)
    findings: list = []
    for sub in lifter.subs:
        dom = dom_by_sub[sub.id]
        by_id = {b.id: b for b in sub.body}
        pidx = {id(p.register): i for i, p in enumerate(sub.parameters)}
        for b in sub.body:
            for idx, o in enumerate(b.ops):
                s = _intr(o)
                if s is None:
                    continue
                for label, severity, value_args in sink_of(s):
                    sources: set = set()
                    valreg = None
                    for a in value_args:
                        if isinstance(a, pre_ir.Register):
                            tt = taint.get(id(a), set())
                            if tt:
                                sources |= tt
                                valreg = a
                    if not sources:
                        continue
                    if valreg is not None:
                        walked = list(_walk(valreg, def_of))
                        sink_regs = {id(r) for r, _ in walked}
                        sink_keys = {k for _, oo in walked
                                     if (k := _input_key(_intr(oo) if oo is not None else None)) is not None}
                    else:
                        sink_regs, sink_keys = set(), set()
                    guards = _dominating_guards(by_id, dom, b.id, idx, def_of, sink_regs,
                                                sink_keys, inv_ret)
                    # Interprocedural: a value flowing from a caller-checked param.
                    feeding = {pidx[r] for r in sink_regs if r in pidx}
                    egp = entry_guards.get(sub.id, {})
                    if any(egp.get(i, (False, False))[0] for i in feeding):
                        guards.append(Guard("caller", None, True, False))
                    if any(egp.get(i, (False, False))[1] for i in feeding):
                        guards.append(Guard("caller", None, False, True))
                    if sender_only:
                        # Byte-taint owns input-validation (byte-precise); drop
                        # input-slot guards so only sender/creator checks suppress
                        # (and FundFlowFinding.guarded, a property over `guards`,
                        # reflects it).
                        guards = [g for g in guards if g.checks_sender]
                    guarded = any(g.checks_input or g.checks_sender for g in guards)
                    param_derived = bool(feeding) and not guarded and sub.id not in called
                    findings.append(FundFlowFinding(
                        label, severity, frozenset(sources),
                        sub.id, s.line, guards, param_derived, valreg))
    findings.sort(key=lambda f: (f.guarded, f.param_derived,
                                 -_SEV_ORDER[f.severity], f.sub_id, f.line))
    return findings


def _itxn_sink_of(fields):
    def sink_of(s):
        if s.op != "itxn_field" or not s.immediates:
            return ()
        field = str(s.immediates[0]).strip()
        if field not in fields:
            return ()
        return ((field, fields[field], s.args),)
    return sink_of


def tainted_itxn_flows(lifter, fields, taint=None, trusted_args=frozenset(),
                       sender_only=False) -> list:
    """User-input-tainted values reaching one of the inner-txn ``fields`` (a
    ``{field_name: severity}`` map). Powers fund-flow (Receiver/Amount/Close/Rekey),
    arbitrary-inner-appcall (ApplicationID), -asset (XferAsset), -asset-admin (acfg
    roles) -- each gets the IR layer's across-callsub dominance + cross-contract
    suppression for free."""
    return _tainted_sink_flows(lifter, _itxn_sink_of(fields), taint, trusted_args,
                               sender_only)


# Persistent-state-write ops -> the index of their KEY operand in the lifted
# Intrinsic's args (TOP-FIRST: arg[0] is the last value pushed). Verified
# empirically. The KEY is the destination slot a tainted value lets the attacker
# choose; the VALUE is not flagged (storing user data is normal).
_STATE_WRITE_KEY_IDX = {
    "app_global_put": 1,    # args: value, KEY
    "app_local_put": 1,     # args: value, KEY, account
    "box_put": 1,           # args: value, KEY
    "box_create": 1,        # args: size, KEY
    "box_replace": 2,       # args: bytes, start, KEY
}
_STATE_WRITE_SEV = {
    "app_global_put": "CRITICAL",   # overwrite ANY global slot (owner/admin state)
    "app_local_put": "HIGH",
    "box_put": "HIGH", "box_replace": "HIGH", "box_create": "MEDIUM",
}


def _state_write_sink_of(s):
    ki = _STATE_WRITE_KEY_IDX.get(s.op)
    if ki is None or ki >= len(s.args):
        return ()
    return ((s.op, _STATE_WRITE_SEV.get(s.op, "HIGH"), [s.args[ki]]),)


def tainted_state_writes(lifter, taint=None, trusted_args=frozenset()) -> list:
    """Tainted-KEY persistent state writes: a user-input value reaching the KEY of
    ``app_global_put`` / ``app_local_put`` / ``box_put`` / ``box_create`` /
    ``box_replace`` lets the attacker write to an arbitrary slot -- overwrite
    owner/admin global state, collide with a sensitive box. (A key derived from
    ``txn Sender`` -- the ubiquitous per-caller ``box[Sender]`` pattern -- is NOT a
    taint source, so it never surfaces; a key checked == Sender is guard-cleared.)"""
    return _tainted_sink_flows(lifter, _state_write_sink_of, taint, trusted_args)


def _log_sink_of(s):
    if s.op != "log" or not s.args:
        return ()
    return (("log", "LOW", s.args),)


def tainted_logs(lifter, taint=None, trusted_args=frozenset()) -> list:
    """User-input-tainted values emitted via ``log``. A contract that logs
    attacker-controlled data feeds FORGED data to anything that trusts its logs:
    a CALLER reading its ``LastLog`` (itself a taint source -- a spoofed ARC-4
    return / event), or an off-chain indexer. Output-integrity, hence LOW
    severity; the guard machinery clears a logged value that was validated first."""
    return _tainted_sink_flows(lifter, _log_sink_of, taint, trusted_args)


def tainted_fund_flows(lifter, taint=None, trusted_args=frozenset(),
                       sender_only=False) -> list:
    """Fund-flow specialisation of :func:`tainted_itxn_flows` -- tainted values
    reaching Receiver / Amount / CloseRemainderTo (+ asset variants)."""
    return tainted_itxn_flows(lifter, _FUND_FIELDS, taint, trusted_args, sender_only)


def fund_flow_report(lifter, name: str = "<program>") -> str:
    findings = tainted_fund_flows(lifter)
    out = [f"attacker-controlled inner-transaction fund flows  --  {name}",
           "=" * 72]
    if not findings:
        out.append("(no user-input-tainted fund-flow itxn fields)")
        return "\n".join(out)
    unguarded = [f for f in findings if not f.guarded and not f.param_derived]
    out.append(f"{len(findings)} tainted fund-flow sink(s); "
               f"{len(unguarded)} UNGUARDED")
    out.append("")
    for f in findings:
        out.append("  " + f.pretty())
    return "\n".join(out)


if __name__ == "__main__":
    import sys

    from ..ssa import SSAProgram
    from .lift import _Lifter
    for _src in [a for a in sys.argv[1:] if not a.startswith("-")]:
        _lf = _Lifter(SSAProgram(_src))
        _lf.build()
        _nm = _src.rstrip("/").rsplit("/", 1)[-1]
        print(fund_flow_report(_lf, _nm))
