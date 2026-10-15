"""Key-NAMESPACE confinement of an attacker-chosen state-write key.

The registry idiom: users may write any key of an app's state EXCEPT a reserved
internal namespace, enforced by a prefix test the write cannot avoid —
``assert(extract(key, 0, 2) != "i.")``, usually spelled through a helper that
returns ``key_prefix == "i."`` and a caller that asserts its negation, or a
``bnz reject`` on it inside a validation subroutine.

The shared guard walker (:mod:`..analysis.guard_coverage`) rightly gives a
disequality NO input credit: it excludes one value and leaves every other one
free. A PREFIX disequality excludes a whole namespace, and that is a real
confinement exactly when the namespace holds every slot the program itself
depends on. This module decides both halves, and a state-write sink is credited
only when both hold:

1. A must-hold fact ``key[0:len(P)] != P`` at the sink — a dominating (or
   unavoidable post-dominating) assert / forced branch, a dominating call to a
   subroutine that establishes it for the argument on EVERY return, or every
   call site establishing it for the sink's parameter (AND across sites).
2. Every access of the SAME storage (global / local / box) whose key is not
   itself attacker-chosen has a key provably inside ``P`` — a constant
   starting with ``P``, or a concatenation whose known leading bytes do. Global
   and local state count their READS (a slot nothing in the program reads
   cannot steer it); boxes count every operation, since ``box_create`` /
   ``box_replace`` / ``box_len`` behave differently on a box the attacker
   pre-created.

What is claimed, precisely: the attacker can no longer reach any slot the
program reads with a key it chose itself. Writes into the open namespace remain
possible — that is the design these programs document (an owner's free-form
user fields) — so the credit is an INPUT check, never a sender check.

HAZARD: an access whose key is ITSELF attacker-chosen (an input-tainted key) is
not a protected slot: it reads whatever slot the caller names, and that caller
could already name any of them. A key tainted only by stored state or by an
unresolved value IS protected — the attacker does not choose it.

HAZARD: a key the analysis cannot place (a dynamic key with no known prefix, a
param with an unknown call site, recursion, an exhausted budget) refuses the
whole namespace. Refusal leaves the finding standing — the silent direction is
crediting a namespace that does not hold the program's own state.
"""
from __future__ import annotations

from . import pre_ir
from .guards import Guard, _input_key
from .taint_flow import UNKNOWN_SOURCE, _intr, _invoke, source_label
from ..diagnostics.evidence import GuardEvidence
from ..language.avm import is_state_value_label
from ..language.effects import STATE_EFFECTS

#: Own-state READS, with the top-first index of their key operand.
_READS = {
    "app_global_get": ("global", 0), "app_global_get_ex": ("global", 0),
    "app_local_get": ("local", 0), "app_local_get_ex": ("local", 0),
    "box_get": ("box", 0), "box_len": ("box", 0), "box_extract": ("box", 2),
}

_BUDGET = 512


def _hex_bytes(c) -> bytes | None:
    raw = c.value if isinstance(c, pre_ir.BytesConstant) else None
    if not isinstance(raw, str):
        return None
    try:
        return bytes.fromhex(raw.removeprefix("0x"))
    except ValueError:
        return None


def _imm_int(src, i):
    imm = src.immediates or []
    try:
        return int(imm[i])
    except (IndexError, TypeError, ValueError):
        return None


class KeyNamespaces:
    """Per-lift namespace oracle. Read-only over the frozen pre-IR."""

    def __init__(self, lifter, def_of, inv_ret, sites, taint, dom_by_sub,
                 pdom_by_sub, dominating, post_dominating, all_fail_blocks):
        self.lifter = lifter
        self.def_of, self.inv_ret, self.sites, self.taint = def_of, inv_ret, sites, taint
        self.dom_by_sub, self.pdom_by_sub = dom_by_sub, pdom_by_sub
        self._dominating, self._post_dominating = dominating, post_dominating
        self._fails = all_fail_blocks
        self.subs = {s.id: s for s in lifter.subs}
        self.param_owner = {id(p.register): (s.id, i)
                            for s in lifter.subs for i, p in enumerate(s.parameters)}
        # sub id -> [(caller sub, block id, op index, invoke)]
        self.call_sites: dict = {s.id: [] for s in lifter.subs}
        for s in lifter.subs:
            for b in s.body:
                for idx, o in enumerate(b.ops):
                    inv = _invoke(o)
                    if inv is not None and inv.target in self.call_sites:
                        self.call_sites[inv.target].append((s, b.id, idx, inv))
        self._protected: dict = {}
        self._summary: dict = {}
        self._entry: dict = {}
        self._loads = None
        self._load_canon: dict = {}

    # --- value resolution -------------------------------------------------

    def _step(self, v, ctx):
        """One value-preserving step: a copy, a proved scratch round-trip, a
        call result that hands back the site's own argument, or a callee param
        inside a frame (leaving it to the site's argument).

        HAZARD: a call result is NOT stepped into the callee's own registers.
        Those are one register per callee, many values per program run: two
        calls of ``get_key()`` would resolve to the same register and share an
        identity, so a check of one call's key would credit a write of the
        other's. (:meth:`facts` does enter callee frames — for the CONDITION,
        whose parameters it maps back to this site's arguments.)"""
        if not isinstance(v, pre_ir.Register):
            return None
        rets = self.inv_ret.get(id(v)) if self.inv_ret else None
        if rets is not None:
            if len(rets) != 1:
                return None
            if self.sites is not None and id(v) in self.sites:
                _, args = self.sites[id(v)]
                if not any(rets[0] is a for a in args):
                    return None
            return rets[0], ctx
        o = self.def_of.get(id(v))
        if o is None:
            if ctx and self.sites is not None:
                pidx, args = self.sites[ctx[-1]]
                j = pidx.get(id(v))
                if j is not None and j < len(args):
                    return args[j], ctx[:-1]
            return None
        if isinstance(o, pre_ir.Assignment) and _intr(o) is None and \
                isinstance(o.source, (pre_ir.Register, pre_ir.BytesConstant,
                                      pre_ir.UInt64Constant)):
            return o.source, ctx
        return None

    def _resolve(self, v, ctx=()):
        for _ in range(64):
            nxt = self._step(v, ctx)
            if nxt is None:
                break
            v, ctx = nxt
        return v, ctx

    def _canonical_load(self, v):
        """The earliest ``load`` of the same slot that dominates ``v``'s load
        with no store of the slot (or call that may store it) able to run in
        between — both read the same value. ``v`` itself when there is none.
        The loop-index idiom: `load i; txnas ApplicationArgs` is re-read for
        the check and again for the write, and no single dominating store
        reaches either (the pre-header and the latch both store ``i``)."""
        if id(v) in self._load_canon:
            return self._load_canon[id(v)]
        if self._loads is None:
            from .fund_flow import _ScratchScan
            self._scan = _ScratchScan(self.lifter)
            self._loads = {} if self._scan.dynamic else {
                id(r): (slot, sid, bid, idx) for slot, sid, bid, idx, r in self._scan.loads}
            self._by_slot: dict = {}
            for slot, sid, bid, idx, r in ([] if self._scan.dynamic else self._scan.loads):
                self._by_slot.setdefault((sid, slot), []).append((bid, idx, r))
        out = v
        here = self._loads.get(id(v))
        if here is not None:
            slot, sid, bid, idx = here
            dom = self.dom_by_sub.get(sid, {})
            doms = dom.get(bid, {bid})
            # Dominating loads, earliest first (the dominators form a chain);
            # the first one nothing can clobber since is the representative.
            cands = sorted((len(dom.get(b1, ())), i1, b1, r1)
                           for b1, i1, r1 in self._by_slot[(sid, slot)]
                           if r1 is not v and ((b1 == bid and i1 < idx)
                                               or (b1 != bid and b1 in doms)))
            for _, i1, b1, r1 in cands:
                if not self._scan.clobbered(sid, b1, i1, bid, idx, slot):
                    out = r1
                    break
        self._load_canon[id(v)] = out
        return out

    def identity(self, v, ctx=(), depth=0):
        """A value identity two reads share when they provably hold the same
        value: the same root register, or the same input SLOT read through
        indices of the same identity (`txnas ApplicationArgs i` twice)."""
        v, ctx = self._resolve(v, ctx)
        if isinstance(v, pre_ir.Register) and depth < 8:
            canon = self._canonical_load(v)
            if canon is not v:
                return self.identity(canon, ctx, depth + 1)
        if isinstance(v, pre_ir.BytesConstant):
            return ("bytes", v.value)
        if isinstance(v, pre_ir.UInt64Constant):
            return ("int", v.value)
        if not isinstance(v, pre_ir.Register):
            return ("opaque", id(v))
        src = _intr(self.def_of.get(id(v)))
        # HAZARD: an inner-txn read (`itxn*` / `gitxn*`) is NOT one value per
        # program run — each `itxn_submit` replaces it — so two reads of the
        # same field share no identity; they keep their own registers.
        if (src is not None and depth < 8 and source_label(src) is not None
                and not src.op.startswith(("itxn", "gitxn"))):
            key = _input_key(src)
            if key is not None and not any(isinstance(k, tuple) for k in key):
                return ("input", *key)
            return ("src", src.op, tuple(str(i) for i in (src.immediates or ())),
                    tuple(self.identity(a, ctx, depth + 1) for a in src.args))
        return ("reg", id(v))

    # --- the must-hold prefix fact ---------------------------------------

    def _prefix_operand(self, v, ctx, n):
        """``x`` when ``v`` is ``x[0:n]`` (``extract``/``substring`` with
        constant bounds, or their stack forms), else ``None``. Each panics on a
        key shorter than ``n``, so the comparison is exactly a prefix test."""
        v, ctx = self._resolve(v, ctx)
        src = _intr(self.def_of.get(id(v))) if isinstance(v, pre_ir.Register) else None
        if src is None or not src.args:
            return None
        op = src.op
        if op == "extract" and len(src.args) == 1:
            if _imm_int(src, 0) == 0 and _imm_int(src, 1) == n:
                return src.args[0], ctx
        elif op == "substring" and len(src.args) == 1:
            if _imm_int(src, 0) == 0 and _imm_int(src, 1) == n:
                return src.args[0], ctx
        elif op in ("extract3", "substring3") and len(src.args) == 3:
            # TOP-FIRST: extract3 = [length, start, x]; substring3 = [end, start, x].
            bound, start = (self._resolve(a, ctx)[0] for a in src.args[:2])
            if (isinstance(start, pre_ir.UInt64Constant) and start.value == 0
                    and isinstance(bound, pre_ir.UInt64Constant) and bound.value == n):
                return src.args[2], ctx
        return None

    def facts(self, cond, sense, ctx=(), depth=0, active=frozenset()):
        """``{(identity, prefix)}``: ``identity[0:len(prefix)] != prefix`` holds
        whenever ``cond`` evaluates to ``sense``. Conjunction = union, join =
        intersection over the live arms (the shared walker's rules)."""
        if depth > 48 or not isinstance(cond, pre_ir.Register):
            return frozenset()
        key = (id(cond), ctx)
        if key in active:
            return frozenset()
        active = active | {key}
        rets = self.inv_ret.get(id(cond)) if self.inv_ret else None
        if rets is not None:
            inner = ctx + (id(cond),) if self.sites is not None and id(cond) in self.sites else ctx
            return self._join(rets, sense, inner, depth, active)
        o = self.def_of.get(id(cond))
        if o is None:
            nxt = self._step(cond, ctx)
            return self.facts(*nxt[:1], sense, nxt[1], depth + 1, active) if nxt else frozenset()
        if isinstance(o, pre_ir.Phi):
            return self._join([a.value for a in o.args], sense, ctx, depth, active)
        src = _intr(o)
        if src is None:
            if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                return self.facts(o.source, sense, ctx, depth + 1, active)
            return frozenset()
        op, args = src.op, src.args
        if op == "!" and len(args) == 1:
            return self.facts(args[0], not sense, ctx, depth + 1, active)
        if op in ("&&", "||") and len(args) == 2:
            parts = [self.facts(a, sense, ctx, depth + 1, active) for a in args]
            conj = (op == "&&") == sense
            return parts[0] | parts[1] if conj else parts[0] & parts[1]
        if op in ("==", "!=") and len(args) == 2 and (op == "==") != sense:
            out = set()
            for x, c in ((args[0], args[1]), (args[1], args[0])):
                p = _hex_bytes(self._resolve(c, ctx)[0])
                if not p:
                    continue
                hit = self._prefix_operand(x, ctx, len(p))
                if hit is not None:
                    out.add((self.identity(*hit), p))
            return frozenset(out)
        return frozenset()

    def _join(self, arms, sense, ctx, depth, active):
        live = []
        for a in arms:
            a, actx = self._resolve(a, ctx)
            if isinstance(a, pre_ir.UInt64Constant):
                if (a.value != 0) != sense:
                    continue                    # dead under `sense`
                return frozenset()              # a live constant arm: bypass
            if not isinstance(a, pre_ir.Register):
                return frozenset()
            live.append(self.facts(a, sense, actx, depth + 1, active))
        return frozenset.intersection(*live) if live else frozenset()

    def _classify(self, kind, polarity, cond, *_args, **_kw):
        return self.facts(cond, polarity != "false")

    def facts_at(self, sub, bid, idx, active=frozenset()):
        """Every prefix fact that must hold before op ``idx`` of block ``bid``."""
        dom = self.dom_by_sub[sub.id]
        by_id = {b.id: b for b in sub.body}
        out = set()
        for f in self._dominating(by_id, dom, bid, idx, self.def_of, set(), set(),
                                  self.inv_ret, self.taint, classify=self._classify):
            out |= f
        for f in self._post_dominating(by_id, self.pdom_by_sub[sub.id], bid, idx,
                                       self.def_of, set(), set(), self.inv_ret,
                                       self.taint, self._fails(by_id),
                                       classify=self._classify):
            out |= f
        # A dominating call to a sub that establishes the fact for a param on
        # every return holds it for that call's argument.
        for cbid in dom.get(bid, {bid}):
            cblk = by_id.get(cbid)
            if cblk is None:
                continue
            for co in (cblk.ops if cbid != bid else cblk.ops[:idx]):
                inv = _invoke(co)
                if inv is None or inv.target not in self.subs:
                    continue
                for pi, p in self.summary(inv.target, active):
                    if pi < len(inv.args):
                        out.add((self.identity(inv.args[pi]), p))
        # Every call site establishes it for one of this sub's params.
        for pi, p in self.entry(sub.id, active):
            out.add((self.identity(sub.parameters[pi].register), p))
        return out

    def summary(self, sub_id, active=frozenset()):
        """``{(param_index, prefix)}`` holding on EVERY return of the sub."""
        if sub_id in self._summary:
            return self._summary[sub_id]
        if ("s", sub_id) in active:
            return frozenset()
        active = active | {("s", sub_id)}
        sub = self.subs[sub_id]
        pid = {self.identity(p.register): i for i, p in enumerate(sub.parameters)}
        per_return = []
        for b in sub.body:
            if isinstance(b.terminator, pre_ir.SubroutineReturn):
                fs = self.facts_at(sub, b.id, len(b.ops), active)
                per_return.append({(pid[i], p) for i, p in fs if i in pid})
        out = frozenset(set.intersection(*per_return)) if per_return else frozenset()
        self._summary[sub_id] = out
        return out

    def entry(self, sub_id, active=frozenset()):
        """``{(param_index, prefix)}`` established at EVERY call site."""
        if sub_id in self._entry:
            return self._entry[sub_id]
        if ("e", sub_id) in active:
            return frozenset()
        sites = self.call_sites.get(sub_id) or []
        sub = self.subs[sub_id]
        if sub.is_main or not sites or not sub.parameters:
            self._entry[sub_id] = frozenset()
            return frozenset()
        active = active | {("e", sub_id)}
        per_site = []
        for caller, bid, idx, inv in sites:
            fs = self.facts_at(caller, bid, idx, active)
            got = set()
            for pi in range(min(len(sub.parameters), len(inv.args)) if fs else 0):
                ident = self.identity(inv.args[pi])
                got |= {(pi, p) for i, p in fs if i == ident}
            per_site.append(got)
            if not got:
                break                       # AND across sites: already empty
        out = frozenset(set.intersection(*per_site))
        self._entry[sub_id] = out
        return out

    # --- the protected half -----------------------------------------------

    def _attacker_keyed(self, v) -> bool:
        labels = self.taint.get(id(v)) if isinstance(v, pre_ir.Register) else None
        return bool(labels) and any(
            x != UNKNOWN_SOURCE and not is_state_value_label(x) for x in labels) \
            and UNKNOWN_SOURCE not in labels

    def in_namespace(self, v, prefix: bytes, budget=None) -> bool:
        """Every value ``v`` can hold starts with ``prefix``."""
        if budget is None:
            budget = [_BUDGET]
        budget[0] -= 1
        if budget[0] < 0:
            return False
        if not prefix:
            return True
        if isinstance(v, pre_ir.BytesConstant):
            b = _hex_bytes(v)
            return b is not None and b.startswith(prefix)
        if not isinstance(v, pre_ir.Register):
            return False
        rets = self.inv_ret.get(id(v)) if self.inv_ret else None
        if rets is not None:
            return bool(rets) and all(self.in_namespace(r, prefix, budget) for r in rets)
        o = self.def_of.get(id(v))
        if o is None:
            owner = self.param_owner.get(id(v))
            if owner is None:
                return False
            sid, pi = owner
            sites = self.call_sites.get(sid) or []
            return bool(sites) and not self.subs[sid].is_main and all(
                pi < len(inv.args) and (self._attacker_keyed(inv.args[pi])
                                        or self.in_namespace(inv.args[pi], prefix, budget))
                for _, _, _, inv in sites)
        if isinstance(o, pre_ir.Phi):
            return bool(o.args) and all(self.in_namespace(a.value, prefix, budget)
                                        for a in o.args)
        src = _intr(o)
        if src is None:
            if isinstance(o, pre_ir.Assignment) and isinstance(
                    o.source, (pre_ir.Register, pre_ir.BytesConstant)):
                return self.in_namespace(o.source, prefix, budget)
            return False
        if src.op == "concat" and len(src.args) == 2:
            # TOP-FIRST: args[1] is the LEFT (leading) operand.
            left, right = src.args[1], src.args[0]
            lead = _hex_bytes(self._resolve(left)[0])
            if lead is not None:
                if lead.startswith(prefix):
                    return True
                if prefix.startswith(lead):
                    return self.in_namespace(right, prefix[len(lead):], budget)
                return False
            return self.in_namespace(left, prefix, budget)
        return False

    def _foreign_app(self, app) -> bool:
        """A ``*_get_ex`` app operand that is a NON-ZERO constant id: another
        application's state (the program cannot know its own id before it is
        created). Anything else — ``0``, ``ApplicationID``, an index or id the
        caller supplies — may name this app and stays an own-state read."""
        a = self._resolve(app)[0]
        return isinstance(a, pre_ir.UInt64Constant) and a.value != 0

    def protected(self, storage: str, prefix: bytes) -> bool:
        """Every non-attacker-keyed access of ``storage`` stays inside
        ``prefix`` (see the module docstring for which accesses count)."""
        key = (storage, prefix)
        if key in self._protected:
            return self._protected[key]
        ok = True
        for s in self.lifter.subs:
            for b in s.body:
                for o in b.ops:
                    src = _intr(o)
                    if src is None:
                        continue
                    spec = _READS.get(src.op)
                    if spec is None and storage == "box":
                        eff = STATE_EFFECTS.get(src.op)
                        if eff is not None and eff.storage == "box":
                            spec = ("box", eff.key_index)
                    if spec is None or spec[0] != storage:
                        continue
                    if spec[1] >= len(src.args):
                        ok = False
                        break
                    if src.op.endswith("_ex") and self._foreign_app(src.args[1]):
                        continue
                    k = src.args[spec[1]]
                    if self._attacker_keyed(k) or self.in_namespace(k, prefix):
                        continue
                    ok = False
                    break
                if not ok:
                    break
            if not ok:
                break
        self._protected[key] = ok
        return ok

    # --- the sink hook ----------------------------------------------------

    def sink_guards(self, sub, block, idx, intrinsic):
        """The namespace guard of a state-write sink, or ``[]``."""
        eff = STATE_EFFECTS.get(intrinsic.op)
        if eff is None or eff.owner_index is not None or eff.key_index >= len(intrinsic.args):
            return []
        key = intrinsic.args[eff.key_index]
        if not isinstance(key, pre_ir.Register):
            return []
        ident = self.identity(key)
        prefixes = sorted({p for i, p in self.facts_at(sub, block.id, idx) if i == ident})
        for p in prefixes:
            if not self.protected(eff.storage, p):
                continue
            # Credit the key's own value chain: the coverage check needs a
            # credited register on every path from the sink key to its leaf.
            regs, v = set(), key
            for _ in range(64):
                if not isinstance(v, pre_ir.Register):
                    break
                regs.add(id(v))
                nxt = self._step(v, ())
                if nxt is None:
                    break
                v = nxt[0]
            root = _intr(self.def_of.get(id(v))) if isinstance(v, pre_ir.Register) else None
            k = _input_key(root) if root is not None else None
            return [Guard(
                "key-namespace", None, True, False,
                (GuardEvidence(
                    str(key), 'constraint-dependency', f'key prefix != {p!r}',
                    scope=('sink input',)),),
                frozenset(regs), frozenset({k}) if k is not None else frozenset())]
        return []
