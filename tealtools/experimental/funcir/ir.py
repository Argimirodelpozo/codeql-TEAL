"""Functional IR dataclasses.

Everything here is identity-equal (``eq=False``) so analyses can use
nodes as dict / set keys without weird hashing surprises.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Expressions — pure value-producing nodes.
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Expr:
    def children(self) -> list["Expr"]:
        return []


@dataclass(eq=False)
class Lit(Expr):
    """A literal — int, bytes, or addr (depending on the source op)."""

    value: object  # int / bytes / str
    kind: str = "int"  # "int" | "bytes" | "addr"


@dataclass(eq=False)
class Ref(Expr):
    """Reference to a named value.

    ``is_mut=False`` (default) → an SSA ``Let``-bound value (defined
    once). ``is_mut=True`` → a materialised-phi variable that can be
    re-assigned inside loops."""

    name: str
    is_mut: bool = False


@dataclass(eq=False)
class App(Expr):
    """Operator application — wraps a TEAL op + its immediates +
    operand expressions. Multi-result ops produce a ``TupleExpr`` of
    references when their outputs are individually consumed."""

    op: str
    immediates: str
    args: list[Expr] = field(default_factory=list)

    def children(self) -> list[Expr]:
        return list(self.args)


@dataclass(eq=False)
class TupleExpr(Expr):
    """Multiple values, e.g. the two-output result of
    ``app_global_get_ex``. Produced by ``App`` on multi-output ops."""

    parts: list[Expr] = field(default_factory=list)

    def children(self) -> list[Expr]:
        return list(self.parts)


# ---------------------------------------------------------------------------
# Statements — control flow and effects.
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Stmt:
    def children(self) -> list:
        return []


@dataclass(eq=False)
class Block(Stmt):
    """Sequence of statements."""

    body: list[Stmt] = field(default_factory=list)

    def children(self):
        return list(self.body)


@dataclass(eq=False)
class Let(Stmt):
    """``targets = value`` for SSA-named results. ``targets`` is
    usually a single name; multi-output ops produce a list."""

    targets: list[str]
    value: Expr

    def children(self):
        return [self.value]


@dataclass(eq=False)
class Assign(Stmt):
    """``mat_phi_k = value`` — assignment to a mutable
    materialized-phi variable. Multiple ``Assign``s with the same
    target are normal (that's how phis fan in)."""

    target: str
    value: Expr

    def children(self):
        return [self.value]


@dataclass(eq=False)
class If(Stmt):
    """``if cond: then`` (no else)."""

    cond: Expr
    then: Stmt
    negated: bool = False  # True when the source op was ``bz``

    def children(self):
        return [self.cond, self.then]


@dataclass(eq=False)
class IfElse(Stmt):
    """``if cond: then_ else: else_``."""

    cond: Expr
    then_: Stmt
    else_: Stmt
    negated: bool = False

    def children(self):
        return [self.cond, self.then_, self.else_]


@dataclass(eq=False)
class Switch(Stmt):
    """``switch cond { 0: arm0, 1: arm1, ... }`` — TEAL's ``switch`` /
    ``match`` op. ``cond`` is the index/selector; ``arms`` are the
    branch bodies in selector-value order. ``labels`` is the optional
    list of source-label names (one per arm) for clearer printing."""

    cond: Expr
    arms: list[Stmt] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    def children(self):
        return [self.cond, *self.arms]


@dataclass(eq=False)
class Loop(Stmt):
    """Unconditional loop — body contains an explicit ``If`` with
    a ``Break`` (or falls through to it via the SSA's back-edge
    semantics). For a typical TEAL do-while compiled as
    ``body...; bnz top``, the lifter produces
    ``Loop(body=Block([body..., If(not cond, Break)]))``."""

    body: Stmt

    def children(self):
        return [self.body]


@dataclass(eq=False)
class Break(Stmt):
    """Exit the innermost ``Loop``."""


@dataclass(eq=False)
class Guard(Stmt):
    """``if cond: exit_arm; ...`` — a structural guard, like an early
    return. The exit arm runs only on the branch-taken path; the
    parent ``Block`` continues with whatever comes after."""

    cond: Expr
    exit_arm: Stmt
    negated: bool = False

    def children(self):
        return [self.cond, self.exit_arm]


@dataclass(eq=False)
class Call(Stmt):
    """``results = call sub_name(args)``. ``results`` may be empty
    if the subroutine returns nothing."""

    sub_name: str
    args: list[Expr] = field(default_factory=list)
    results: list[str] = field(default_factory=list)

    def children(self):
        return list(self.args)


@dataclass(eq=False)
class Return(Stmt):
    """``return value`` from the program (TEAL ``return`` op) or
    ``retsub`` from a subroutine. ``value`` is None for ``retsub``
    in some cases."""

    value: Optional[Expr] = None
    kind: str = "return"  # "return" | "retsub"

    def children(self):
        return [self.value] if self.value is not None else []


@dataclass(eq=False)
class Halt(Stmt):
    """``err`` — abort program execution."""


@dataclass(eq=False)
class Assert(Stmt):
    """``assert value``."""

    value: Expr

    def children(self):
        return [self.value]


@dataclass(eq=False)
class Label(Stmt):
    """Source-style label, used inside :class:`Unstructured` blocks to
    name targets for :class:`Goto` / :class:`IfGoto`."""

    name: str


@dataclass(eq=False)
class Goto(Stmt):
    """Unconditional jump to a labelled location."""

    target: str


@dataclass(eq=False)
class IfGoto(Stmt):
    """Conditional jump: ``if cond: goto target``."""

    cond: Expr
    target: str
    negated: bool = False

    def children(self):
        return [self.cond]


@dataclass(eq=False)
class Unstructured(Stmt):
    """Escape hatch for irreducible regions. Body is a topologically
    sorted sequence of :class:`Label`-ed BBs with explicit
    :class:`Goto` / :class:`IfGoto` for branches between them — a
    "structured goto" rendering that preserves the original control
    flow without forcing it into a SESE shape."""

    label: str
    body: list[Stmt] = field(default_factory=list)

    def children(self):
        return list(self.body)


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Sub:
    """A subroutine — name, arg names from ``proto N M``, and body."""

    name: str
    params: list[str] = field(default_factory=list)
    body: Stmt = field(default_factory=Block)


@dataclass(eq=False)
class Prog:
    """A whole DB — one or more top-level entry points (``main``)
    plus the dictionary of subroutines."""

    mains: list[Stmt] = field(default_factory=list)
    subs: dict[str, Sub] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tree walking
# ---------------------------------------------------------------------------


def walk(node) -> Iterator:
    """Pre-order traversal: yield ``node`` then recurse into
    ``children()``. Works for both ``Expr`` and ``Stmt`` subtypes."""
    yield node
    for c in node.children():
        yield from walk(c)
