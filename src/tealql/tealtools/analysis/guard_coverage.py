"""ONE coverage-semantics guard walker, shared by both guard engines.

The lifted taint engine (``lift/guards._classify``) and the SSA detector layer
(``security/_action_guards``, ``security/_enforcement``,
``security/_field_protection``) each used to re-derive what a condition that
MUST hold (an ``assert`` operand, a branch's surviving side, an approving
``return``) guarantees. Every rule below was found missing or wrong in one of
them while the other had it. They now live here once, over an ABSTRACT
condition tree the caller describes through a :class:`ConditionModel`, so the
representation-specific parts — pre-IR registers vs SSA vars, scratch / phi
copy bridges, call-return edges, dominance, authority — stay in the engines.

The walker answers: given ``root`` must evaluate to ``sense``, WHICH leaves are
constrained (``Coverage.leaves`` / ``keys``), does a trusted sender pin hold
(``Coverage.sender``), and was a merely-excluding relation met
(``Coverage.excluded``).

THE RULES (each is mutation-gated in ``tests/test_guard_coverage_walker.py``):

* CONJUNCTION = UNION. The operands of a guaranteed ``&&`` (and of any op the
  truth of which needs every operand, ``&``/``b&``, comparisons, existence
  predicates) are all guaranteed, so their credits union.
* JOIN = INTERSECTION over the LIVE arms. A phi, a call's set of returned
  values, the two value arms of a ``select`` and an OR-like op that must hold
  (``||``/``|``/``b|``/``+``/``b+`` — ``A + B != 0`` iff A or B, uint64 ``+``
  cannot wrap) are alternatives: the guarantee covers only what EVERY live arm
  covers. An arm is dead when it cannot be taken under the required sense (a
  constant contradicting it; a model-specific dead arm). No live arm credits
  nothing — never a vacuous ``all(())``. De Morgan: under a required-FALSE
  sense ``&&`` is the join and ``||`` the conjunction.
* ``!`` flips the required sense.
* BOOLEAN vs VALUE position. Only the combinators above, ``!``, comparisons,
  ``select`` and the existence predicates carry a guarantee to their
  operands. Any other op in boolean position is a VALUE used as a predicate
  (``(Sender == creator) ^ 1``): nothing below it is guaranteed and its own
  truth is only an exclusion (``x != 0``). Below a comparison the operands are
  values, where ``+``/``|``/``&`` are arithmetic (``x + y <= 100`` bounds both).
* LENGTH vs VALUE. Below ``len``/``bitlen``/``bzero`` a value's LENGTH, not its
  value, is constrained.
* COMPARISON SENSE. An equality that must hold — or a disequality that must
  fail — PINS (sender pins included). The converse merely EXCLUDES one value
  and constrains nothing about which value passes; so do ``x > 0``,
  ``x >= 1``, ``0 < x``, ``1 <= x``.
* VACUOUS. ``x OP x`` for a comparison or a self-cancelling op (``-``, ``^``,
  ``/``, ``%``) and ``x % 1`` are constants: no credit.
* THE OTHER OPERAND. A comparison constrains an operand only against a
  counterpart the attacker does not also choose (:func:`counterpart_credits`):
  ``Accounts[1] == Accounts[2]`` is satisfied by any caller picking both.

Everything is pure: the walker reads the model and returns values.
"""
from __future__ import annotations

from typing import Any, Iterable, NamedTuple, Optional, Protocol

# --- the op semantics shared by both representations (TEAL opcode names) ---

EQ_OPS = frozenset({"==", "b=="})
NEQ_OPS = frozenset({"!=", "b!="})
CMP_OPS = EQ_OPS | NEQ_OPS | frozenset({
    "<", "<=", ">", ">=", "b<", "b<=", "b>", "b>=",
})
#: ``x OP x`` is a constant for these too (`(x - x) >= 0` asserts nothing).
SELF_CANCEL_OPS = frozenset({"-", "b-", "^", "b^", "/", "b/", "%", "b%"})
#: Boolean combinators in BOOLEAN position. `&`/`b&` are bitwise, but `A & B
#: != 0` does imply both non-zero; `|`/`+` are OR-like for truthiness.
BOOL_AND = frozenset({"&&", "&", "b&"})
BOOL_OR = frozenset({"||", "|", "b|", "+", "b+"})
#: Existence / membership predicates: their truth DOES constrain their
#: operands (`assert(box_get(key).exists)` admits only keys with a box).
PREDICATE_OPS = frozenset({
    "box_get", "box_len", "box_create", "box_del", "app_global_get_ex",
    "app_local_get_ex", "asset_holding_get", "asset_params_get",
    "app_params_get", "acct_params_get", "app_opted_in",
    "getbit",                                   # bitmap membership: bit i set / clear
})
#: Ops whose result depends on the LENGTH, not the VALUE, of their operand.
VALUE_OPAQUE_OPS = frozenset({"len", "bitlen", "bzero"})
BOOL_PASS = BOOL_AND | BOOL_OR | {"!", "select"} | CMP_OPS | PREDICATE_OPS

#: A join arm the model cannot read as a node or a uint64 constant (a bytes
#: constant, an unresolved value): a LIVE arm that credits nothing.
OPAQUE = object()


class Coverage(NamedTuple):
    """What a condition that must hold guarantees.

    ``checks`` — some leaf is constrained; ``sender`` — a trusted sender pin
    holds; ``leaves`` / ``keys`` — the constrained leaves (model identities)
    and input-slot keys; ``excluded`` — an excluding relation was met (it
    constrained nothing, which is why it is reported separately)."""
    checks: bool = False
    sender: bool = False
    leaves: frozenset = frozenset()
    keys: frozenset = frozenset()
    excluded: bool = False


NO_COVERAGE = Coverage()


class ConditionModel(Protocol):
    """How one representation spells its condition tree. ``definition``
    returns ``(form, op, args)``: ``("op", opcode, top-first operands)``,
    ``("copy", None, (source,))``, ``("phi", None, arms)`` or ``(None, None,
    ())`` for a node with no definition."""

    def is_node(self, v) -> bool: ...
    def definition(self, v) -> tuple: ...
    def returns(self, v) -> tuple: ...
    def arm_value(self, v) -> Any: ...
    def literal_int(self, v) -> Optional[int]: ...
    def leaf_credit(self, v, op, self_truthy: bool, sender_ok: bool) -> Coverage: ...
    def pins_sender(self, v) -> bool: ...
    def dependent(self, v, state_ok: bool) -> bool: ...
    def counterpart_ok(self, pinned, other) -> bool: ...
    def arm_dead(self, v, sense: bool) -> bool: ...


# --- the rules, as functions (the mutation gates patch these) --------------


def every(verdicts: Iterable[bool]) -> bool:
    """A JOIN of boolean verdicts: every arm, and at least one arm — a join
    with no arm guarantees nothing (never the vacuous ``all(())``)."""
    seen = False
    for v in verdicts:
        if not v:
            return False
        seen = True
    return seen


def join(credits: list) -> Coverage:
    """JOIN = intersection over the LIVE arms' credits (``None`` = dead arm)."""
    live = [c for c in credits if c is not None]
    if not live:
        return NO_COVERAGE
    return Coverage(
        all(c.checks for c in live), all(c.sender for c in live),
        frozenset.intersection(*(c.leaves for c in live)),
        frozenset.intersection(*(c.keys for c in live)),
        any(c.excluded for c in live))


def conjoin(a: Coverage, b: Coverage) -> Coverage:
    """CONJUNCTION = union."""
    return Coverage(a.checks or b.checks, a.sender or b.sender,
                    a.leaves | b.leaves, a.keys | b.keys, a.excluded or b.excluded)


def select_arms(args: tuple) -> list:
    """The JOINED arms of a ``select``: TOP-FIRST ``args[0]`` is the selector
    (attacker-steered, never constrained by the result's truth), ``args[1]``
    the non-zero arm, ``args[2]`` the zero arm."""
    return [args[1], args[2]]


def comparison_pins(op: str, sense: bool) -> bool:
    """An equality that must hold, or a disequality that must fail, pins."""
    return (op in EQ_OPS and sense) or (op in NEQ_OPS and not sense)


def comparison_excludes(op: str, sense: bool, lhs: Optional[int],
                        rhs: Optional[int]) -> bool:
    """The relation only EXCLUDES values. ``lhs``/``rhs`` are the constant
    operands in SOURCE order (TOP-FIRST ``args[1]`` / ``args[0]``)."""
    if (op in NEQ_OPS and sense) or (op in EQ_OPS and not sense):
        return True
    return sense and (
        (op in (">", "b>") and rhs == 0)
        or (op in (">=", "b>=") and rhs == 1)
        or (op in ("<", "b<") and lhs == 0)
        or (op in ("<=", "b<=") and lhs == 1))


def counterpart_credits(other, *, constant, dependent) -> bool:
    """A comparison credits an operand only against a counterpart that is a
    constant or not attacker-dependent — the ONE input-vs-input rule."""
    return constant(other) or not dependent(other)


def vacuous(op: Optional[str], args: tuple, literal_int) -> bool:
    """``x OP x`` (comparison / self-cancelling op) and ``x % 1`` are constants."""
    if op in CMP_OPS | SELF_CANCEL_OPS and len(args) == 2 and args[0] is args[1]:
        return True
    return op == "%" and len(args) == 2 and literal_int(args[0]) == 1


# --- the walker -----------------------------------------------------------


class CoverageWalker:
    """Evaluate one condition against a :class:`ConditionModel`.

    ``exclusions=False`` keeps every comparison's credit regardless of sense
    (the value-agnostic reading the txn-FIELD family uses: "the field is
    compared, and the comparison is enforced"). Memoised per walker on the
    CONTEXT, not the node: one node can be reached under different flags
    (``(A||B) && A``), and since the flags only weaken down a path, a stronger
    path must still credit after a weaker one was walked."""

    def __init__(self, model: ConditionModel, *, max_depth: int = 64,
                 exclusions: bool = True):
        self.m = model
        self.max_depth = max_depth
        self.exclusions = exclusions
        self.memo: dict = {}
        self.active: set = set()

    def cover(self, root, sense: bool = True) -> Coverage:
        return self.visit(root, True, True, sense, False)

    def _arm(self, v, sense, flags, depth):
        """Credit of ONE join arm, or ``None`` for an arm that cannot be taken
        under ``sense`` (a contradicting constant, a model-dead arm, or the
        join's own value carried round a loop — by induction it equals a
        value already being conjoined)."""
        v = self.m.arm_value(v)
        if isinstance(v, int) and not isinstance(v, bool):
            if (v == 0) if sense else (v != 0):
                return None                             # dead under `sense`
            return NO_COVERAGE                          # LIVE constant: bypass
        if v is OPAQUE or not self.m.is_node(v):
            return NO_COVERAGE
        if id(v) in self.active or self.m.arm_dead(v, sense):
            return None
        return self.visit(v, *flags, depth=depth)

    def _join(self, arms, sense, flags, depth):
        return join([self._arm(v, sense, flags, depth) for v in arms])

    def visit(self, value, guaranteed, value_ok, sense, sender_ok, input_ok=True,
              boolean=True, depth=0):
        if not self.m.is_node(value) or depth > self.max_depth:
            return NO_COVERAGE
        key = (id(value), guaranteed, value_ok, sense, sender_ok, input_ok, boolean)
        if key in self.memo:
            return self.memo[key]
        if id(value) in self.active:
            return NO_COVERAGE            # a cycle contributes nothing new
        self.active.add(id(value))
        try:
            out = self._body(value, guaranteed, value_ok, sense, sender_ok,
                             input_ok, boolean, depth)
        finally:
            self.active.discard(id(value))
        self.memo[key] = out
        return out

    def _body(self, value, guaranteed, value_ok, sense, sender_ok, input_ok,
              boolean, depth):
        m = self.m
        form, op, args = m.definition(value)
        if form == "op" and vacuous(op, args, m.literal_int):
            return NO_COVERAGE
        returns = m.returns(value)
        # A value used as a predicate: its truth guarantees nothing about its
        # operands, and about itself only that it is non-zero (an exclusion).
        # Carried booleans (a call return / bridged load) pass through.
        truthiness = boolean and form == "op" and op not in BOOL_PASS and not returns
        out = NO_COVERAGE
        if guaranteed and value_ok and input_ok:
            out = m.leaf_credit(value, op if form == "op" else None,
                                truthiness and sense, sender_ok)
        and_ops, or_ops = (BOOL_AND, BOOL_OR) if boolean else (
            frozenset({"&&"}), frozenset({"||"}))
        joins = or_ops if sense else and_ops            # De Morgan
        child_guar = guaranteed and not truthiness
        child_val = value_ok and op not in VALUE_OPAQUE_OPS
        child_sense = (not sense) if op == "!" else sense
        child_sender = sender_ok
        if op in EQ_OPS or op in NEQ_OPS:
            child_sender = comparison_pins(op, child_sense) and m.pins_sender(value)
        child_input = input_ok
        if self.exclusions and (op in EQ_OPS or op in NEQ_OPS) \
                and comparison_excludes(op, child_sense, None, None):
            child_input = False
        child_bool = boolean and op not in CMP_OPS and op not in PREDICATE_OPS
        if (self.exclusions and guaranteed and input_ok and op in CMP_OPS
                and len(args) == 2 and comparison_excludes(
                    op, child_sense, m.literal_int(args[1]), m.literal_int(args[0]))):
            out = out._replace(excluded=True)
        flags = (child_guar, child_val, child_sense, child_sender, child_input, child_bool)
        if form == "op":
            if op in joins:
                out = conjoin(out, self._join(args, child_sense, flags, depth + 1))
            elif op == "select" and len(args) == 3:
                out = conjoin(out, self._select(args, child_sense, flags, depth + 1))
            elif op in CMP_OPS and len(args) == 2:
                out = conjoin(out, self._compare(op, args, flags, depth))
            else:
                for a in args:
                    out = conjoin(out, self.visit(a, *flags, depth=depth + 1))
        elif form == "copy":
            out = conjoin(out, self.visit(args[0], *flags, depth=depth + 1))
        elif form == "phi":
            out = conjoin(out, self._join(args, child_sense, flags, depth + 1))
        if returns:                       # descend into an asserted validation sub
            out = conjoin(out, self._join(returns, child_sense, flags, depth + 1))
        return out

    def _select(self, args, sense, flags, depth):
        """A ``select`` is a JOIN of its two value arms: the selector picks
        either, so only what BOTH arms guarantee holds."""
        return self._join(select_arms(args), sense, flags, depth)

    def _compare(self, op, args, flags, depth):
        m = self.m
        guar, val, sense, sender, input_ok, boolean = flags
        excluded = self.exclusions and comparison_excludes(
            op, sense, m.literal_int(args[1]), m.literal_int(args[0]))
        pin = op in EQ_OPS and sense
        out = NO_COVERAGE
        for i, a in enumerate(args):
            other = args[1 - i]
            inp = input_ok and not excluded and counterpart_credits(
                other, constant=lambda _o: False,
                dependent=lambda o: m.dependent(o, pin))
            if inp and pin and m.dependent(a, False) and not m.counterpart_ok(a, other):
                inp = False
            out = conjoin(out, self.visit(a, guar, val, sense, sender, inp, boolean,
                                          depth=depth + 1))
        return out


__all__ = [
    "BOOL_AND", "BOOL_OR", "BOOL_PASS", "CMP_OPS", "EQ_OPS", "NEQ_OPS",
    "PREDICATE_OPS", "SELF_CANCEL_OPS", "VALUE_OPAQUE_OPS", "OPAQUE",
    "Coverage", "NO_COVERAGE", "ConditionModel", "CoverageWalker",
    "every", "join", "conjoin", "select_arms", "comparison_pins",
    "comparison_excludes", "counterpart_credits", "vacuous",
]
