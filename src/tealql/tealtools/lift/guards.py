"""Guard evidence and bounded value walks over frozen pre-IR definitions.

Shared by sink analysis and its caller/callee summaries. This module classifies
one condition; CFG reachability and sink traversal stay in ``fund_flow``.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from . import pre_ir
from .taint import _intr, source_label
from ..language.avm import is_current_sender_read
from ..diagnostics.evidence import GuardEvidence

#: Reads of the CURRENT transaction's Sender. HAZARD: the ``gtxn*`` family is
#: DELIBERATELY excluded -- whoever composes the group chooses `gtxn 1 Sender`,
#: so counting it as authorisation lets an attacker-satisfiable condition
#: suppress a real fund flow. Only the current txn's sender and the immutable
#: creator are sound authorisation signals.
_TXN_SENDER_FAM = frozenset({"txn", "txna", "txnas"})

#: Ops whose result depends on the LENGTH, not the VALUE, of their operand: a
#: guard reaching an input only through these bounds its length, not its value
#: (see :func:`_classify`).
_VALUE_OPAQUE_OPS = frozenset({"len", "bitlen", "bzero"})

#: Equality / inequality comparisons, uint64 and bytes. Which one encloses a
#: sender read decides whether that read PINS the sender or merely excludes one
#: address -- see the comparison-sense reasoning in :func:`_classify`.
_EQ_OPS = frozenset({"==", "b=="})
_NEQ_OPS = frozenset({"!=", "b!="})
_CMP_OPS = _EQ_OPS | _NEQ_OPS | frozenset({
    "<", "<=", ">", ">=", "b<", "b<=", "b>", "b>=",
})


#: Depth bound shared by :func:`_walk` (the sink side) and
#: :func:`_classify`'s ``visit`` (the guard side). ONE constant, deliberately:
#: with separate caps the two walks disagreed on what is "reachable", and at 8
#: a check nine copies/phis/`+ 1` steps upstream of the sink — ordinary compiled
#: depth — turned a validated value into an UNGUARDED finding. The def tree is a
#: DAG of registers memoised on shallowest reach, so 64 is cheap.
_WALK_MAX_DEPTH = 64


def _walk(value, def_of, depth=0, seen=None, inv_ret=None):
    """Yield ``(register, defining_op_or_None)`` for every register in the bounded
    def-expression tree behind ``value``, descending through a call result into
    the callee's returned values when ``inv_ret`` is given.

    HAZARD: ``seen`` maps ``id(register) -> shallowest depth expanded at``, NOT a
    plain visited set. With a set, a register first reached near the depth limit
    is expanded on a starved budget then permanently suppressed, so reaching it
    shallowly later skips its subtree -- which guards the walk finds becomes
    traversal-order dependent. Re-expanding on a strictly shallower reach still
    terminates: depth is bounded, so each register expands at most
    ``_WALK_MAX_DEPTH + 1`` times, and callers collect into sets."""
    if seen is None:
        seen = {}
    if not isinstance(value, pre_ir.Register) or depth > _WALK_MAX_DEPTH:
        return
    previous = seen.get(id(value))
    if previous is not None and previous <= depth:
        return
    seen[id(value)] = depth
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
    """The current txn's sender, per :func:`avm.is_current_sender_read` — the
    rule the SSA-level lifecycle guards share, so one program cannot get two
    verdicts. A ``txnas Accounts`` counts only under a CONSTANT index 0."""
    if not isinstance(src, pre_ir.Intrinsic) or src.op not in _TXN_SENDER_FAM:
        return False
    index = None
    if src.op == "txnas":
        a0 = src.args[0] if src.args else None
        index = a0.value if isinstance(a0, pre_ir.UInt64Constant) else None
    return is_current_sender_read(src.op, src.immediates or [], index)


class _Definitions(dict):
    def __init__(self, program=None):
        super().__init__()
        self.authority_program = program
        self.authority_evidence = set()


class _GuardDefinitions(_Definitions):
    """Query-local guard memo over a frozen definition graph.

    Keep both entry count and retained register/key count bounded. The return
    map is held strongly, so object-id reuse cannot cross query contexts.
    """
    def __init__(self, program=None):
        super().__init__(program)
        self.guard_cache = OrderedDict()
        self.sender_cache = OrderedDict()
        self.guard_weight = 0
        self.guard_returns = None
        self.guard_hits = 0

    def remember(self, key, condition, value):
        weight = 1 + len(key[2]) + len(key[3])
        if weight > 65536:
            return
        self.guard_cache[key] = condition, value, weight
        self.guard_weight += weight
        while len(self.guard_cache) > 1024 or self.guard_weight > 65536:
            _, (_, _, removed) = self.guard_cache.popitem(last=False)
            self.guard_weight -= removed


@dataclass
class Guard:
    kind: str                 # "assert" | "branch"
    polarity: str | None      # "true" / "false" for a branch, else None
    checks_input: bool        # the condition tests the (same-source) tainted input
    checks_sender: bool       # the condition tests txn Sender / Global.CreatorAddress
    evidence: tuple[GuardEvidence, ...] = ()

    def __post_init__(self):
        if not self.evidence and (self.checks_input or self.checks_sender):
            # Compatibility summaries describe a dependency until their
            # precise predicate and authority premises have been supplied.
            self.evidence = (GuardEvidence(
                'txn Sender' if self.checks_sender else 'sink input',
                'constraint-dependency', scope=(self.kind,)),)

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
    "0"))``, so two reads of the SAME slot match but ApplicationArgs[0] vs [1]
    don't; ``None`` if ``src`` isn't a user-input source op."""
    if src is None or source_label(src) is None:
        return None
    # HAZARD: dynamic-index reads carry the array INDEX on the stack, not in
    # immediates, so two DIFFERENT-index reads share one (op, immediates) key and
    # would collapse -- a guard on arg[0] crediting a use of arg[1]. Return None
    # so they fall back to register-identity matching.
    if src.op in ("txnas", "gtxnas", "gtxnsas", "gloadss"):
        return None
    return (src.op, tuple(str(i) for i in (src.immediates or [])))


def _classify(kind, polarity, cond, def_of, sink_regs, sink_keys, inv_ret=None) -> Guard:
    cache_key = None
    if isinstance(def_of, _GuardDefinitions) and isinstance(cond, pre_ir.Register):
        if def_of.guard_returns is not inv_ret:
            def_of.guard_cache.clear()
            def_of.sender_cache.clear()
            def_of.guard_weight = 0
            def_of.guard_returns = inv_ret
        cache_key = (id(cond), polarity, frozenset(sink_regs), frozenset(sink_keys))
        if cache_key in def_of.guard_cache:
            _, (ci, cs, evidence), _ = def_of.guard_cache[cache_key]
            def_of.guard_cache.move_to_end(cache_key)
            def_of.guard_hits += 1
            return Guard(kind, polarity, ci, cs, evidence)
    # HAZARD: guard-classification soundness. Every rule below exists because
    # crediting a check that does not actually constrain the sink's value
    # suppresses a real, exploitable flow.
    #
    # VALUE-level, not source-FAMILY-level: the guard must test the SAME value the
    # sink uses -- a shared register in their def-trees, or a read of the same
    # specific input slot. Family-level overlap (any ApplicationArgs read) would
    # read "validates SOME input" as "validates THIS value".
    #
    # BOOLEAN STRUCTURE: only a check the assert/branch GUARANTEES may be
    # credited. `assert(A && B)` guarantees both; `assert(A || B)` guarantees
    # NEITHER individually (A is bypassable whenever B holds), so everything below
    # an `||` is marked un-guaranteed.
    #
    # LENGTH vs VALUE: `assert(len(arg) == 8)` before `btoi(arg)` shares the
    # register and the input slot with the sink but bounds only the LENGTH -- the
    # attacker still picks any 8-byte value. `value_ok` goes false under
    # `_VALUE_OPAQUE_OPS` exactly as `guaranteed` goes false under `||`; a
    # value-preserving conjunct (`len==8 && btoi(arg) <= max`) still credits.
    #
    # COMPARISON SENSE: a sender check authorises only when it RESTRICTS the
    # sender. `Sender == creator` does; `Sender != creator` admits everyone BUT
    # the creator, and a payout on the FALSE edge of `Sender == creator` runs
    # precisely when the caller is not the creator. `sense` is what the enclosing
    # condition must evaluate to for the guard to hold -- True normally, False on
    # a branch whose FALSE edge reaches the sink; `!` flips it, and De Morgan
    # swaps which connective destroys the guarantee.
    # Memoise on the CONTEXT, not the register: one register can be reached
    # under different (guaranteed, value_ok, sense, sender_ok) flags
    # (`(A||B) && A`), and since the flags only weaken down a path, a stronger
    # path must still credit after a weaker one was walked.
    memo: dict = {}
    active: set = set()       # id(register) on the current descent: cycle guard
    sender_cache = def_of.sender_cache if isinstance(def_of, _GuardDefinitions) else OrderedDict()
    authorities = set()

    def _compute_sender_pin(src):
        """Exactly one operand is Sender and the other is a trusted identity.

        An attacker-supplied counterpart authorises nothing
        (``Sender == ApplicationArgs[2]`` is satisfied by any caller who passes
        their own address), nor does ``CreatorAddress == arg`` check Sender at
        all. The Sender operand must preserve its exact identity through
        copies and every join arm; a computation containing it is insufficient.
        """
        from .authority import address_authority, sender_identity
        from ..analysis.authority import AddressAuthority
        sender_arms = [sender_identity(a, def_of, inv_ret) for a in src.args]
        if sum(sender_arms) != 1:
            return AddressAuthority(False, 'comparison lacks one exact Sender operand')
        other = src.args[0] if sender_arms[1] else src.args[1]
        return address_authority(other, def_of, inv_ret)

    def _comparison_pins_sender(src) -> bool:
        # This property depends on definitions and return edges, never on the
        # current sink's taint set. A shared comparison must not re-walk its
        # whole operand graph for every parameter and call-site obligation.
        key = id(src)
        if key not in sender_cache:
            sender_cache[key] = (src, _compute_sender_pin(src))
            if len(sender_cache) > 1024:
                sender_cache.popitem(last=False)
        else:
            sender_cache.move_to_end(key)
        authority = sender_cache[key][1]
        authorities.add(authority)
        return authority.preserved

    def _every_leaf_pins_sender(src, connective, sense) -> bool:
        """``src`` is a ``connective`` tree (``||`` under a required-True
        condition, ``&&`` under a required-False one) whose EVERY leaf is a
        sender pin of the matching polarity (``==`` / ``!=``).

        `assert(Sender == creator || Sender == admin_state)` admits exactly the
        union of two trusted identities — a real authorisation check, the
        marketplace-template idiom — while `Sender == creator || btoi(arg)`
        admits anyone who passes a nonzero arg. Any leaf that is not a pin
        (an attacker-satisfiable term, an unknown, a deeper structure) keeps the
        existing refusal: nothing under a disjunction is guaranteed."""
        pin_ops = _EQ_OPS if sense else _NEQ_OPS
        stack, budget = list(src.args), _WALK_MAX_DEPTH
        while stack:
            v = stack.pop()
            budget -= 1
            if budget < 0:
                return False
            oo = None
            for _ in range(8):                          # through plain copies
                oo = def_of.get(id(v)) if isinstance(v, pre_ir.Register) else None
                if (isinstance(oo, pre_ir.Assignment)
                        and isinstance(oo.source, pre_ir.Register)):
                    v = oo.source
                    continue
                break
            leaf = _intr(oo) if oo is not None else None
            if leaf is None:
                return False
            if leaf.op == connective:
                stack.extend(leaf.args)
            elif not (leaf.op in pin_ops and len(leaf.args) == 2
                      and _comparison_pins_sender(leaf)):
                return False
        return True

    def _arm_credit(v, sense, flags, depth):
        """Credit of ONE arm of a join (phi arm / `retsub` return), or ``None``
        for an arm that cannot be taken under the required sense: a constant
        whose truth contradicts it (`assert` of a `0` arm fails, so that path
        never reaches the sink), or the join's own value carried round a loop
        (by induction it equals a value already being conjoined)."""
        # `materialize_phi_consts` has already turned a constant arm into a
        # `let pc%N = <const>` register, so read the constant back through
        # plain copies — otherwise every constant arm looks like an opaque
        # register and the dead-arm rule below can never fire.
        for _ in range(8):
            oo = def_of.get(id(v)) if isinstance(v, pre_ir.Register) else None
            if (isinstance(oo, pre_ir.Assignment) and not isinstance(
                    oo.source, (pre_ir.Register, pre_ir.Intrinsic, pre_ir.InvokeSubroutine))):
                v = oo.source
                break
            if isinstance(oo, pre_ir.Assignment) and isinstance(oo.source, pre_ir.Register):
                v = oo.source
                continue
            break
        if isinstance(v, pre_ir.UInt64Constant):
            if (v.value == 0) if sense else (v.value != 0):
                return None                             # dead under `sense`
            return (False, False)                       # LIVE constant: bypass
        if not isinstance(v, pre_ir.Register):
            return (False, False)                       # bytes / unknown: no credit
        if id(v) in active:
            return None
        return visit(v, *flags, depth=depth)

    def _join_credit(arms, sense, flags, depth):
        """A join is an OR of its arms, so the assert guarantees a check only
        if EVERY live arm carries it. This is the phi / multi-return twin of
        the `||` rule: `assert(phi(1, Sender == creator))` — PuyaPy's inlining
        of `if n == 3: return True; return sender == creator` — is bypassable
        on the constant arm, exactly like `assert(1 || Sender == creator)`."""
        credits = [c for c in (_arm_credit(v, sense, flags, depth) for v in arms)
                   if c is not None]
        if not credits:
            return (False, False)
        return (all(c[0] for c in credits), all(c[1] for c in credits))

    def visit(value, guaranteed, value_ok, sense, sender_ok, input_ok=True, depth=0):
        if not isinstance(value, pre_ir.Register) or depth > _WALK_MAX_DEPTH:
            return (False, False)
        key = (id(value), guaranteed, value_ok, sense, sender_ok, input_ok)
        if key in memo:
            return memo[key]
        if id(value) in active:
            return (False, False)         # a cycle contributes nothing new
        active.add(id(value))
        try:
            out = _visit_body(value, guaranteed, value_ok, sense, sender_ok,
                              input_ok, depth)
        finally:
            active.discard(id(value))
        memo[key] = out
        return out

    def _visit_body(value, guaranteed, value_ok, sense, sender_ok, input_ok, depth):
        ci = cs = False
        o = def_of.get(id(value))
        src = _intr(o) if o is not None else None
        if (src is not None and src.op in _CMP_OPS and len(src.args) == 2
                and src.args[0] is src.args[1]):
            return (False, False)               # x OP x is a constant predicate
        if (src is not None and src.op == "%" and len(src.args) == 2
                and isinstance(src.args[0], pre_ir.UInt64Constant)
                and src.args[0].value == 1):
            return (False, False)               # x % 1 is always zero
        if guaranteed and value_ok and input_ok:
            if id(value) in sink_regs:
                ci = True
            if src is not None:
                if _is_sender_op(src) and sender_ok:
                    cs = True
                if _input_key(src) in sink_keys:
                    ci = True
        # De Morgan: `||` breaks the guarantee under a required-True condition,
        # `&&` under a required-False one.
        breaks = "||" if sense else "&&"
        child_guar = guaranteed and not (src is not None and src.op == breaks)
        # ... unless EVERY leaf of that tree pins the sender: the union of
        # trusted identities is itself a sender guard.
        if (guaranteed and src is not None and src.op == breaks
                and _every_leaf_pins_sender(src, breaks, sense)):
            cs = True
        child_val = value_ok and not (src is not None and src.op in _VALUE_OPAQUE_OPS)
        child_sense = (not sense) if (src is not None and src.op == "!") else sense
        # An equality that must hold PINS a sender read below it; one that must
        # NOT hold (or a `!=` that must) only excludes one address.
        child_sender = sender_ok
        if src is not None and src.op in _EQ_OPS:
            child_sender = child_sense and _comparison_pins_sender(src)
        elif src is not None and src.op in _NEQ_OPS:
            child_sender = (not child_sense) and _comparison_pins_sender(src)
        # A relation that only EXCLUDES one value restricts nothing about which
        # value the sink gets. `assert(recipient != ZeroAddress)` says the payee is
        # not the zero address; every other address still passes, so it is not a
        # check on WHO gets paid. Ordering relations (`<=`, `<`, …) and a pinning
        # `==` do constrain, and keep the credit. This mirrors what `sender_ok`
        # already does for the sender — the asymmetry was the bug: one side of
        # `_EQ_OPS`/`_NEQ_OPS` x sense was implemented, the other was not.
        child_input = input_ok
        if src is not None and (
                (src.op in _NEQ_OPS and child_sense)
                or (src.op in _EQ_OPS and not child_sense)):
            child_input = False
        flags = (child_guar, child_val, child_sense, child_sender, child_input)
        # An intrinsic's operands are conjuncts of one expression: `A && B`
        # guarantees both, so the credits OR together. A JOIN (phi arms, the
        # `retsub` set of an asserted callee) is the opposite: its arms are
        # alternatives, so they AND — see `_join_credit`.
        if src is not None:
            for a in src.args:
                a_ci, a_cs = visit(a, *flags, depth=depth + 1)
                ci, cs = ci or a_ci, cs or a_cs
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            a_ci, a_cs = visit(o.source, *flags, depth=depth + 1)
            ci, cs = ci or a_ci, cs or a_cs
        elif isinstance(o, pre_ir.Phi):
            a_ci, a_cs = _join_credit([pa.value for pa in o.args], child_sense,
                                      flags, depth + 1)
            ci, cs = ci or a_ci, cs or a_cs
        if inv_ret:                       # descend into an asserted validation sub
            rvs = inv_ret.get(id(value), ())
            if rvs:
                a_ci, a_cs = _join_credit(rvs, child_sense, flags, depth + 1)
                ci, cs = ci or a_ci, cs or a_cs
        return (ci, cs)

    ci, cs = visit(cond, True, True, polarity != "false", False)
    evidence = []
    if ci:
        evidence.append(GuardEvidence(str(cond), 'constraint-dependency',
                        scope=('sink input',)))
    if cs:
        evidence.append(GuardEvidence('txn Sender', 'member-of-authority-set', str(cond),
            scope=('successful paths through this guard',), basis='must-predicate',
            assumptions=tuple(sorted({premise for result in authorities
                                      for premise in result.assumptions}))))
    evidence = tuple(evidence)
    if cache_key is not None:
        def_of.remember(cache_key, cond, (ci, cs, evidence))
    return Guard(kind, polarity, ci, cs, evidence)
