"""Guard evidence and bounded value walks over frozen pre-IR definitions.

Shared by sink analysis and its caller/callee summaries. This module classifies
one condition; CFG reachability and sink traversal stay in ``fund_flow``.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from . import pre_ir
from .taint import _intr, source_label
from ..language.avm import is_state_value_label
from ..language.avm import is_current_sender_read, is_group_signer_read
from ..diagnostics.evidence import GuardEvidence
from ..analysis.guard_coverage import (
    BOOL_AND, BOOL_OR, BOOL_PASS, CMP_OPS, EQ_OPS, NEQ_OPS, OPAQUE,
    PREDICATE_OPS, SELF_CANCEL_OPS, VALUE_OPAQUE_OPS, Coverage, CoverageWalker,
    NO_COVERAGE,
)

#: Reads of the CURRENT transaction's Sender. HAZARD: the ``gtxn*`` family is
#: DELIBERATELY excluded -- whoever composes the group chooses `gtxn 1 Sender`,
#: so counting it as authorisation lets an attacker-satisfiable condition
#: suppress a real fund flow. Only the current txn's sender and the immutable
#: creator are sound authorisation signals.
_TXN_SENDER_FAM = frozenset({"txn", "txna", "txnas"})

#: The op semantics (boolean combinators, comparison sense, existence
#: predicates, length-vs-value, self-cancelling ops) live in the shared walker
#: :mod:`tealql.tealtools.analysis.guard_coverage` with their HAZARDs; these
#: aliases keep this module's walks on the same tables.
_VALUE_OPAQUE_OPS = VALUE_OPAQUE_OPS
_SELF_CANCEL_OPS = SELF_CANCEL_OPS
_EQ_OPS = EQ_OPS
_NEQ_OPS = NEQ_OPS
_CMP_OPS = CMP_OPS
_BOOL_AND = BOOL_AND
_BOOL_OR = BOOL_OR
_PREDICATE_OPS = PREDICATE_OPS
_BOOL_PASS = BOOL_PASS

#: Reads of the current app's own global/local state — the slots whose WRITERS
#: the storage-authority analysis can inspect. A `==` pin of an attacker input
#: against one of these authorises only if every writer preserves authority;
#: an unguarded `app_global_put "payee" <- Accounts[1]` lets anyone pass the
#: later `assert(Accounts[1] == app_global_get "payee")`.
_STATE_READ_OPS = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
})


#: Depth bound shared by :func:`_walk` (the sink side) and
#: :func:`_classify`'s ``visit`` (the guard side). ONE constant, deliberately:
#: with separate caps the two walks disagreed on what is "reachable", and at 8
#: a check nine copies/phis/`+ 1` steps upstream of the sink — ordinary compiled
#: depth — turned a validated value into an UNGUARDED finding. The def tree is a
#: DAG of registers memoised on shallowest reach, so 64 is cheap.
_WALK_MAX_DEPTH = 64


def _walk(value, def_of, depth=0, seen=None, inv_ret=None, *, value_only=False):
    """Yield ``(register, defining_op_or_None)`` for every register in the bounded
    def-expression tree behind ``value``, descending through a call result into
    the callee's returned values when ``inv_ret`` is given.

    ``value_only`` stops below :data:`_VALUE_OPAQUE_OPS`: the registers under a
    ``len`` contribute their LENGTH to the value, not their value, so a walk
    asking "which values does this one depend on" must not list them — the
    callee-side transfer did, and `check32(len(arg))` read as a VALUE check on
    `arg` (the length-vs-value distinction `_classify` already draws).

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
            if not (value_only and src.op in _VALUE_OPAQUE_OPS):
                for a in src.args:
                    yield from _walk(a, def_of, depth + 1, seen, inv_ret,
                                     value_only=value_only)
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            yield from _walk(o.source, def_of, depth + 1, seen, inv_ret,
                             value_only=value_only)
        elif isinstance(o, pre_ir.Phi):
            for pa in o.args:
                yield from _walk(pa.value, def_of, depth + 1, seen, inv_ret,
                                 value_only=value_only)
    if inv_ret:                       # descend into an asserted validation sub
        for rv in inv_ret.get(id(value), ()):
            yield from _walk(rv, def_of, depth + 1, seen, inv_ret,
                             value_only=value_only)


def _value_children(value, def_of, inv_ret=None) -> list:
    """The registers ``value``'s VALUE is computed from — one step of the
    ``value_only`` walk, for walks that need to stop early."""
    if not isinstance(value, pre_ir.Register):
        return []
    o = def_of.get(id(value))
    out: list = []
    if o is not None:
        src = _intr(o)
        if src is not None:
            if src.op not in _VALUE_OPAQUE_OPS:
                out.extend(a for a in src.args if isinstance(a, pre_ir.Register))
        elif isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            out.append(o.source)
        elif isinstance(o, pre_ir.Phi):
            out.extend(pa.value for pa in o.args if isinstance(pa.value, pre_ir.Register))
    if inv_ret:
        out.extend(rv for rv in inv_ret.get(id(value), ()) if isinstance(rv, pre_ir.Register))
    return out


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


def _is_authoriser_op(src) -> bool:
    """A fixed-position group member's sender (``gtxn K Sender``, constant-index
    ``gtxns Sender``) or ``global CallerApplicationID`` — the AUTHORISATION
    leaves a pin accepted by :func:`_compute_sender_pin` may rest on. Never a
    caller identity (see :func:`avm.is_group_signer_read`)."""
    if not isinstance(src, pre_ir.Intrinsic):
        return False
    if src.op == "global":
        return tuple(src.immediates or ()) == ("CallerApplicationID",)
    index = None
    if src.op == "gtxns":
        a0 = src.args[0] if src.args else None
        index = a0.value if isinstance(a0, pre_ir.UInt64Constant) else None
    return is_group_signer_read(src.op, src.immediates or [], index)


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
        self.guard_taint = None
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
    #: WHICH of the sink's registers (by id) / input-slot keys the condition
    #: constrains. ``checks_input`` says "some tainted value is checked"; the
    #: sink needs EVERY tainted leaf of its value covered, and that is decided
    #: from the union of these over all its guards (see
    #: ``fund_flow._uncovered_leaves``). Empty for compatibility summaries.
    regs: frozenset = frozenset()
    keys: frozenset = frozenset()

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


def _const_arg(src, i):
    """The ``i``-th stack operand of ``src`` as an int if it is a constant."""
    a = src.args[i] if -len(src.args) <= i < len(src.args) else None
    return a.value if isinstance(a, pre_ir.UInt64Constant) else None


def _index_token(src, i):
    """The ``i``-th stack operand of ``src`` as a slot-key token: a constant
    index folds to its value; a REGISTER index keys on the register — two reads
    through the same register read the same slot (`txnas Assets i` in a guard
    and in the sink), two different registers may not; anything else is
    ``None`` (no key)."""
    c = _const_arg(src, i)
    if c is not None:
        return str(c)
    a = src.args[i] if -len(src.args) <= i < len(src.args) else None
    return ("reg", id(a)) if isinstance(a, pre_ir.Register) else None


def _input_key(src):
    """Identity of a specific user-input READ — the SLOT, not the spelling:
    ``("txn", "ApplicationArgs", "1")`` for ``txn ApplicationArgs 1`` AND
    ``txna ApplicationArgs 1`` (the lifter keeps both), ``("gtxn", "0",
    "ApplicationArgs", "1")`` for ``gtxna 0 ApplicationArgs 1`` and for
    ``int 0; gtxnsa ApplicationArgs 1`` alike — so two reads of the SAME slot
    match but ApplicationArgs[0] vs [1] don't; ``None`` if ``src`` isn't a
    user-input source op.

    HAZARD: stack-index reads carry an index on the STACK, not in immediates.
    ``gtxns``/``gtxnsa`` take the TXN index there, ``txnas``/``gtxnas`` the
    array index, ``gtxnsas`` both. Keying them on immediates alone collapsed
    different slots — `gtxnsa ApplicationArgs 1` of txn 0 and of txn 1 shared
    one key, so a bound on txn 0's arg credited txn 1's. A constant stack index
    folds into the key; anything else returns ``None`` so the read falls back
    to register-identity matching."""
    if src is None or source_label(src) is None:
        return None
    op = src.op
    imm = [str(i) for i in (src.immediates or [])]
    args = src.args or []
    if op in ("txn", "txna"):
        return ("txn", *imm)
    if op == "txnas":
        idx = _index_token(src, 0)
        return None if idx is None else ("txn", *imm, idx)
    if op in ("gtxn", "gtxna"):
        return ("gtxn", *imm)
    if op == "gtxnas":
        idx = _index_token(src, 0)
        return None if idx is None else ("gtxn", *imm, idx)
    if op in ("gtxns", "gtxnsa"):
        gidx = _index_token(src, 0)
        return None if gidx is None else ("gtxn", gidx, *imm)
    if op == "gtxnsas":
        # TOP-FIRST operands: the array index was pushed last.
        idx, gidx = _index_token(src, 0), _index_token(src, 1)
        if idx is None or gidx is None or len(args) < 2:
            return None
        return ("gtxn", gidx, *imm, idx)
    if op in ("itxn", "itxna"):
        return ("itxn", *imm)
    if op in ("gitxn", "gitxna"):
        return ("gitxn", *imm)
    if op in ("itxnas", "gitxnas", "gloadss"):
        return None
    if op in ("arg_0", "arg_1", "arg_2", "arg_3"):
        return ("arg", op[-1])
    if op == "arg":
        return ("arg", *imm)
    if op == "args":
        idx = _index_token(src, 0)
        return None if idx is None else ("arg", idx)
    return (op, tuple(imm))


class _LiftConditionModel:
    """The pre-IR spelling of a condition tree for the shared
    :class:`~..analysis.guard_coverage.CoverageWalker`: registers are nodes,
    an intrinsic is an op over its TOP-FIRST args, a register copy is a copy,
    a phi and a call's returned values (``inv_ret``) are joins; leaves credit
    the sink's tainted registers / input-slot keys and the current Sender."""

    def __init__(self, def_of, inv_ret, taint, sink_regs, sink_keys, sender_cache):
        self.def_of, self.inv_ret, self.taint = def_of, inv_ret, taint
        self.sink_regs, self.sink_keys = sink_regs, sink_keys
        self.sender_cache = sender_cache
        self.authorities: set = set()
        self.input_authorities: set = set()

    def is_node(self, v) -> bool:
        return isinstance(v, pre_ir.Register)

    def definition(self, v):
        o = self.def_of.get(id(v))
        src = _intr(o) if o is not None else None
        if src is not None:
            return "op", src.op, src.args
        if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
            return "copy", None, (o.source,)
        if isinstance(o, pre_ir.Phi):
            return "phi", None, tuple(pa.value for pa in o.args)
        return None, None, ()

    def returns(self, v):
        return self.inv_ret.get(id(v), ()) if self.inv_ret else ()

    def arm_value(self, v):
        """Read a join arm back through plain copies: `materialize_phi_consts`
        has already turned a constant arm into a `let pc%N = <const>` register,
        and an opaque register would hide the dead-arm rule."""
        for _ in range(8):
            oo = self.def_of.get(id(v)) if isinstance(v, pre_ir.Register) else None
            if (isinstance(oo, pre_ir.Assignment) and not isinstance(
                    oo.source, (pre_ir.Register, pre_ir.Intrinsic, pre_ir.InvokeSubroutine))):
                v = oo.source
                break
            if isinstance(oo, pre_ir.Assignment) and isinstance(oo.source, pre_ir.Register):
                v = oo.source
                continue
            break
        if isinstance(v, pre_ir.UInt64Constant):
            return v.value
        return v if isinstance(v, pre_ir.Register) else OPAQUE

    def literal_int(self, v):
        return v.value if isinstance(v, pre_ir.UInt64Constant) else None

    def leaf_credit(self, v, op, self_truthy, sender_ok):
        ci = cs = False
        regs = keys = frozenset()
        if id(v) in self.sink_regs and not self_truthy:
            ci, regs = True, frozenset({id(v)})
        if op is not None:
            src = _intr(self.def_of.get(id(v)))
            if sender_ok and (_is_sender_op(src) or _is_authoriser_op(src)):
                # Under a pin `pins_sender` accepted: the pinned side may also
                # be a fixed group member's sender or the caller app id.
                cs = True
            k = _input_key(src)
            if k is not None and k in self.sink_keys:
                ci, keys = True, frozenset({k})
        return Coverage(ci, cs, regs, keys) if (ci or cs) else NO_COVERAGE

    def pins_sender(self, v) -> bool:
        """Exactly one operand is Sender and the other a trusted identity.

        An attacker-supplied counterpart authorises nothing
        (``Sender == ApplicationArgs[2]`` is satisfied by any caller who passes
        their own address), nor does ``CreatorAddress == arg`` check Sender at
        all. The Sender operand must preserve its exact identity through
        copies and every join arm; a computation containing it is insufficient.
        This depends on definitions and return edges, never on the sink's
        taint set, so it is cached across sinks."""
        src = _intr(self.def_of.get(id(v)))
        key = id(src)
        cache = self.sender_cache
        if key not in cache:
            cache[key] = (src, _compute_sender_pin(src, self.def_of, self.inv_ret))
            if len(cache) > 1024:
                cache.popitem(last=False)
        else:
            cache.move_to_end(key)
        authority = cache[key][1]
        self.authorities.add(authority)
        return authority.preserved

    def dependent(self, v, state_ok=False) -> bool:
        """``v`` is (possibly) attacker-chosen: tainted per ``taint``, or —
        without an oracle — computed from a source op or a parameter.

        ``state_ok``: a ``StateValue`` source alone does not count. Set for an
        ``==`` pin that must hold, whose own-state counterpart is judged by
        :meth:`counterpart_ok` (the a07 rule: address pins need writer
        authority, a bytes key pinned to stored state is credited) — one
        arbiter for state-backed pins, not two. An ORDERING bound against
        attacker-writable state is no bound: the attacker raises the cap in
        one call and spends it in the next."""
        if isinstance(v, pre_ir.Undefined):
            return True
        if not isinstance(v, pre_ir.Register):
            return False
        if self.taint is not None:
            sources = self.taint.get(id(v)) or ()
            if state_ok:
                return any(not is_state_value_label(x) for x in sources)
            return bool(sources)
        for _, oo in _walk(v, self.def_of, inv_ret=self.inv_ret):
            if oo is None or source_label(_intr(oo)) is not None:
                return True
        return False

    def counterpart_ok(self, a, other) -> bool:
        """``other`` is a fit counterpart for pinning the ADDRESS ``a``: either
        no own-state read feeds it, or every writer of that state preserves
        authority (the sender-pin provenance rule, applied to the input side).

        Address-typed pins only (`Receiver == app_global_get "payee"`): the
        storage analysis is an ADDRESS authority — a dynamic-key write anywhere
        in the program leaves every slot unproven, which is the right
        conservatism for who-gets-paid and a false alarm for
        `assert(key == app_global_get "allowed_key")` on a bytes key."""
        if not isinstance(other, pre_ir.Register):
            return True
        if "account" not in (getattr(a, "ir_type", None), getattr(other, "ir_type", None)):
            return True
        if not any(_intr(oo) is not None and _intr(oo).op in _STATE_READ_OPS
                   for _, oo in _walk(other, self.def_of, inv_ret=self.inv_ret,
                                      value_only=True)):
            return True
        from .authority import address_authority
        authority = address_authority(other, self.def_of, self.inv_ret)
        self.input_authorities.add(authority)
        return authority.preserved

    def arm_dead(self, v, sense) -> bool:
        return False


def _compute_sender_pin(src, def_of, inv_ret):
    from .authority import (address_authority, caller_app_pin, sender_identity,
                            signer_principal)
    from ..analysis.authority import AddressAuthority
    if src is None:
        return AddressAuthority(False, 'not a comparison')
    pinned = caller_app_pin(src.args, def_of)
    if pinned is not None:
        return pinned
    sender_arms = [sender_identity(a, def_of, inv_ret) for a in src.args]
    if sum(sender_arms) == 1:
        other = src.args[0] if sender_arms[1] else src.args[1]
        return address_authority(other, def_of, inv_ret)
    if sum(sender_arms) == 0:
        # A fixed-position group member's sender authorises (its signature
        # covers the group id) — only against a SIGNING PRINCIPAL, never as
        # caller identity (an escrow lsig "signs" by its own logic).
        signer_arms = [sender_identity(a, def_of, inv_ret, signer=True) for a in src.args]
        if sum(signer_arms) == 1:
            other = src.args[0] if signer_arms[1] else src.args[1]
            if signer_principal(other, def_of, inv_ret):
                return address_authority(other, def_of, inv_ret)
            return AddressAuthority(False, 'sibling signer pinned to a non-principal address')
    return AddressAuthority(False, 'comparison lacks one exact Sender operand')


def _classify(kind, polarity, cond, def_of, sink_regs, sink_keys, inv_ret=None,
              taint=None) -> Guard:
    """Classify one condition against a sink's value: which of ``sink_regs`` /
    ``sink_keys`` it constrains (``Guard.regs`` / ``Guard.keys``), whether it
    pins the sender. ``taint`` (``{id(Register): sources}``) is the oracle for
    "is this operand attacker-dependent"; without it a structural walk of the
    operand's def tree (any source op or parameter) stands in."""
    cache_key = None
    if isinstance(def_of, _GuardDefinitions) and isinstance(cond, pre_ir.Register):
        if def_of.guard_returns is not inv_ret or def_of.guard_taint is not taint:
            def_of.guard_cache.clear()
            def_of.sender_cache.clear()
            def_of.guard_weight = 0
            def_of.guard_returns = inv_ret
            def_of.guard_taint = taint
        cache_key = (id(cond), polarity, frozenset(sink_regs), frozenset(sink_keys))
        if cache_key in def_of.guard_cache:
            _, (ci, cs, evidence, regs, keys), _ = def_of.guard_cache[cache_key]
            def_of.guard_cache.move_to_end(cache_key)
            def_of.guard_hits += 1
            return Guard(kind, polarity, ci, cs, evidence, regs, keys)
    # HAZARD: guard-classification soundness. Every rule exists because
    # crediting a check that does not actually constrain the sink's value
    # suppresses a real, exploitable flow. The REPRESENTATION-INDEPENDENT rules
    # — conjunction = union, join = intersection (phi / `retsub` set / `select`
    # arms / an OR-like op that must hold), boolean-vs-value position, `!`,
    # length-vs-value, comparison sense and exclusions, vacuous `x OP x`, the
    # input-vs-input withdrawal — live in the shared walker
    # (:mod:`..analysis.guard_coverage`, HAZARDs there). What stays here is how
    # the pre-IR spells a condition tree (:class:`_LiftConditionModel`):
    #
    # VALUE-level, not source-FAMILY-level: the guard must test the SAME value the
    # sink uses -- a shared register in their def-trees, or a read of the same
    # specific input slot. Family-level overlap (any ApplicationArgs read) would
    # read "validates SOME input" as "validates THIS value".
    #
    # An `==` pin against the app's OWN state additionally needs that state's
    # writers to preserve authority — `payee` set by anyone is no pin (see
    # `_STATE_READ_OPS`).
    model = _LiftConditionModel(def_of, inv_ret, taint, sink_regs, sink_keys,
                                def_of.sender_cache if isinstance(def_of, _GuardDefinitions)
                                else OrderedDict())
    ci, cs, regs, keys, _excluded = CoverageWalker(
        model, max_depth=_WALK_MAX_DEPTH).cover(cond, polarity != "false")
    authorities, input_authorities = model.authorities, model.input_authorities
    evidence = []
    if ci:
        evidence.append(GuardEvidence(str(cond), 'constraint-dependency',
                        scope=('sink input',),
                        assumptions=tuple(sorted({premise for result in input_authorities
                                                  for premise in result.assumptions}))))
    if cs:
        evidence.append(GuardEvidence('txn Sender', 'member-of-authority-set', str(cond),
            scope=('successful paths through this guard',), basis='must-predicate',
            assumptions=tuple(sorted({premise for result in authorities
                                      for premise in result.assumptions}))))
    evidence = tuple(evidence)
    if cache_key is not None:
        def_of.remember(cache_key, cond, (ci, cs, evidence, regs, keys))
    return Guard(kind, polarity, ci, cs, evidence, regs, keys)
