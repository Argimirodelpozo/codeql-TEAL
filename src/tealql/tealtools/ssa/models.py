"""The value types :class:`SSAProgram` is made of — no extraction of its own.

:class:`Assignment` (``outputs = op immediates (inputs)``) over :class:`SSAVar` /
:class:`Phi` / :class:`Const` operands, grouped into :class:`BasicBlock`\\ s.

HAZARD — identity keys are source positions, so one instruction per line is
architectural: SSAVar is ``(file, line, output_index)``, Phi is
``(file, line, stack_index)``, BasicBlock is
``(file, first_line, last_line)``.

HAZARD — ``Assignment.inputs`` and ``outputs`` are TOP-FIRST (index 0 = topmost
value popped / pushed); ``BasicBlock.exit_stack`` is BOTTOM-first. Reading either
in the other's order silently swaps operands of non-commutative ops.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union



@dataclass(frozen=True)
class Location:
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


class SSAVar:
    """A stack variable produced by one opcode — identity ``(file, line, index)``,
    rendered ``V#{index}@L{line}``; ``index`` is 1-based and TOP-FIRST."""

    __slots__ = (
        "file", "line", "index", "defined_by", "uses",
        "const_value", "range", "type",
    )

    def __init__(self, file: str, line: int, index: int):
        self.file = file
        self.line = line
        self.index = index
        self.defined_by: Optional["Assignment"] = None
        self.uses: list["Assignment"] = []
        # const_value: set by propagate_constants(); range: by propagate_ranges().
        # None means "not resolved", never "not constant"/"unbounded".
        self.const_value: Optional["Const"] = None
        self.range: Optional["IntRange"] = None
        self.type: Optional["TealType"] = None

    @property
    def identifier(self) -> str:
        return f"V#{self.index}@L{self.line}"

    def _key(self) -> tuple:
        return (self.file, self.line, self.index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, SSAVar) and self._key() == other._key()

    def __repr__(self) -> str:
        return self.identifier


class Phi:
    """An SSA phi at stack slot ``stack_index`` (1-based, top-first) — identity
    ``(file, line, stack_index)``; ``args`` holds the originating
    :class:`SSAVar`\\ s that can flow in.

    The CodeQL extractor once split phis into a ``DirectPhi`` (leaf args) and an
    ``IndirectPhi`` (a single chain-root phi), and a ``kind`` field carried the
    distinction into the identity key. Nothing has produced an ``IndirectPhi``
    since the builder moved to Python — chain structure lives on the ``PyPhi``
    graph now (:meth:`SSAProgram.chain_predecessors`) — so the field was a
    constant and is gone."""

    __slots__ = (
        "file", "line", "stack_index",
        "args", "uses", "basic_block",
        "const_value", "range", "type", "partial",
    )

    def __init__(self, file: str, line: int, stack_index: int):
        self.file = file
        self.line = line
        self.stack_index = stack_index
        self.args: list[Union[SSAVar, "Phi"]] = []
        self.uses: list["Assignment"] = []
        self.basic_block: Optional["BasicBlock"] = None
        # const_value: set only when EVERY arg resolves to the same literal.
        # range: union of the arg ranges, so ranges flow through joins.
        self.const_value: Optional["Const"] = None
        self.range: Optional["IntRange"] = None
        self.type: Optional["TealType"] = None
        # PARTIAL: the merged cell does not exist on every incoming path (a
        # predecessor arrived too shallow — max-window join, or a net-popping
        # loop's laps >= 2). `args` then lists only the paths that HAVE the
        # cell. Sound to consume as-is under panic-pruning: on an absent-arm
        # path the AVM op reading this cell underflows and the txn dies, so
        # every execution that proceeds past the read took a listed arm.
        # Analyses reasoning about which paths REACH a point (not values) must
        # not treat the absent arms as reaching it.
        self.partial: bool = False

    def _key(self) -> tuple:
        return (self.file, self.line, self.stack_index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, Phi) and self._key() == other._key()

    def _short(self) -> str:
        return f"φ_{self.stack_index}@L{self.line}"

    def __repr__(self) -> str:
        # Iterative DFS, cycle-protected and capped: phi-arg graphs can be
        # CYCLIC and ~1000 deep at constant-stack loops, so the recursive form
        # blows the recursion limit and full expansion blows memory. Identical
        # output to the naive form on acyclic graphs below the cap.
        if not self.args:
            return self._short()
        _CAP = 200
        visited = 0
        seen: set = {id(self)}
        stack: list = [[self, iter(self.args), []]]
        while True:
            phi, it, parts = stack[-1]
            try:
                arg = next(it)
            except StopIteration:
                rendered = "phi(" + ", ".join(parts) + ")"
                stack.pop()
                seen.discard(id(phi))
                if not stack:
                    return rendered
                stack[-1][2].append(rendered)
                continue
            if isinstance(arg, Phi):
                if id(arg) in seen or not arg.args or visited >= _CAP:
                    parts.append(arg._short())
                else:
                    seen.add(id(arg))
                    visited += 1
                    stack.append([arg, iter(arg.args), []])
            else:
                parts.append(repr(arg))


@dataclass(frozen=True)
class Const:
    """A resolved compile-time literal. ``kind`` ∈ ``{"int", "bytes"}``."""
    kind: str
    value: str

    def __repr__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IntRange:
    """Inclusive integer range ``[lo..hi]`` for a uint64-typed value."""
    lo: int
    hi: int

    def __post_init__(self):
        if self.lo > self.hi:
            raise ValueError(f"IntRange lo>hi: {self.lo}..{self.hi}")

    def annotate(self, var_id: str) -> str:
        if self.lo == self.hi:
            return f"[{var_id}={self.lo}]"
        if self.lo == 0:
            return f"[{var_id}<={self.hi}]"
        return f"[{self.lo}<={var_id}<={self.hi}]"


@dataclass(frozen=True)
class TealType:
    """Static type of a stack value. ``kind`` ∈ ``{"uint64", "bytes"}``.

    All three optional fields are bytes-only; for ``"uint64"`` read
    :attr:`SSAVar.range` instead. ``byte_length`` is the exact length when
    statically derivable, and mirrors itself into ``byte_length_range`` as
    ``IntRange(N, N)`` so range consumers read one field; ``byte_length_range``
    alone means only a bound is known (e.g. ``btoi(X)`` succeeding ⇒
    ``len(X) ∈ [1, 8]``).

    HAZARD: ``int_value_range`` is the bytes value read as a big-endian unsigned
    integer (the abstraction bytemath ``b+``/``b-``/``b*``/… work over) and is
    NOT capped at ``2^64-1`` — it can legitimately exceed uint64."""
    kind: str
    byte_length: Optional[int] = None
    byte_length_range: Optional["IntRange"] = None
    int_value_range: Optional["IntRange"] = None


Operand = Union[SSAVar, Phi, Const]


@dataclass(eq=False)
class Assignment:
    """``outputs = op immediates (inputs)`` — one TEAL opcode's SSA form.

    HAZARD: ``inputs`` and ``outputs`` are TOP-FIRST — ``inputs[0]`` is the
    topmost value popped. Reading them in source order swaps the operands of
    every non-commutative op (``-``, ``/``, ``%``, comparisons, ``concat``)."""

    outputs: list[SSAVar]
    op: str
    immediates: str
    inputs: list[Operand]
    location: Location
    ast_code: str
    const: Optional[Const] = None
    basic_block: Optional["BasicBlock"] = None
    # Set by propagate_stack_shuffles(): a pure shuffle whose outputs have been
    # redirected to their producing inputs at every consumer. Kept in the IR but
    # rendered as a `//` comment, so the stack movement stays inspectable.
    shuffled: bool = False

    def functional(
        self,
        *,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
        show_ranges: bool = False,
    ) -> str:
        """Render this assignment in functional form, optionally substituting
        resolved literals for const opcodes / inputs and annotating ranges."""
        def _annotate_var(v: "SSAVar") -> str:
            label = v.identifier
            if show_ranges and v.range is not None:
                label += f" /*{v.range.annotate(v.identifier)}*/"
            return label

        out_str = ", ".join(_annotate_var(v) if isinstance(v, SSAVar) else v.identifier
                            for v in self.outputs)
        if resolve_consts and self.const is not None:
            body = f"{out_str} = {self.const.value}" if self.outputs else self.const.value
            return f"// {body}" if self.shuffled else body

        def _input_label(operand) -> str:
            if propagate_consts:
                cv = getattr(operand, "const_value", None)
                if cv is not None:
                    return cv.value
            if isinstance(operand, SSAVar):
                return _annotate_var(operand)
            return repr(operand)

        # Copy assignment (materialized phi): no opcode/tuple syntax.
        if self.op == "=" and len(self.inputs) == 1 and self.outputs:
            body = f"{out_str} = {_input_label(self.inputs[0])}"
            return f"// {body}" if self.shuffled else body
        in_str = "(" + ", ".join(_input_label(i) for i in self.inputs) + ")"
        rhs = f"{self.op} {self.immediates} {in_str}" if self.immediates else f"{self.op} {in_str}"
        body = f"{out_str} = {rhs}" if self.outputs else rhs
        return f"// {body}" if self.shuffled else body

    def __repr__(self) -> str:
        return self.functional()


class BasicBlock:
    """A maximal straight-line region of assignments, identity
    ``(file, first_line, last_line)``, with entry ``phis`` and inter-BB
    ``predecessors`` / ``successors``.

    HAZARD: ``exit_stack`` is BOTTOM-FIRST (index 0 = bottom, last = top) —
    the opposite of ``Assignment.inputs`` — with ``None`` for dead slots. It
    carries the PER-EDGE values that ``Phi.args`` (a dedup'd value-set) no
    longer has, which out-of-SSA / block-argument lowering needs. Empty
    unless construction populated it."""

    __slots__ = (
        "file", "first_line", "last_line",
        "assignments", "phis",
        "predecessors", "successors",
        "exit_stack",
    )

    def __init__(self, file: str, first_line: int, last_line: int):
        self.file = file
        self.first_line = first_line
        self.last_line = last_line
        self.assignments: list[Assignment] = []
        self.phis: list[Phi] = []
        self.predecessors: list["BasicBlock"] = []
        self.successors: list["BasicBlock"] = []
        self.exit_stack: list = []

    def _key(self) -> tuple:
        return (self.file, self.first_line, self.last_line)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, BasicBlock) and self._key() == other._key()

    def __repr__(self) -> str:
        return f"BB({self.file}:{self.first_line}-{self.last_line})"

    def contains(self, line: int) -> bool:
        return self.first_line <= line <= self.last_line

    def slot(self, k: int):
        """The value at TOP-FIRST exit slot ``k`` (1 = top), or ``None`` when the
        block's ``exit_stack`` is not that deep.

        The convention flip this hides is the codebase's most-feared one:
        ``exit_stack`` is BOTTOM-first while slots are counted TOP-first, so the
        read is ``exit_stack[-k]`` guarded by a length check. That pair was
        open-coded at five sites (block-arg lowering, the lift's dead-edge phi
        rebuild, the frame bridges, type recovery), and an off-by-one there reads
        a neighbouring value rather than failing."""
        if k < 1 or len(self.exit_stack) < k:
            return None
        return self.exit_stack[-k]

# AVM metadata tables all live in :mod:`tealql.tealtools.avm`; only the
# MODEL-convention algorithms (top-first shuffle permutations) belong here.
from ..avm import _STACK_SHUFFLE_OPS  # noqa: F401  (re-export: ssa-layer callers)




def _shuffle_mapping(a: "Assignment") -> Optional[list[int]]:
    """``m`` such that ``a.outputs[i] = a.inputs[m[i]]`` for the shuffle opcodes
    in :data:`_STACK_SHUFFLE_OPS`, else ``None``.

    HAZARD: everything here is TOP-FIRST — ``inputs[0]``/``outputs[0]`` are the
    topmost value, the deepest sits at index ``n - 1``, and SSAVar
    ``output_index 1`` is likewise the topmost output. A shape that disagrees
    with the immediate returns ``None`` rather than redirecting consumers of a
    malformed Assignment."""
    op = a.op
    n_in = len(a.inputs)
    n_out = len(a.outputs)
    if op == "swap":
        # ... a b → ... b a;  in [b, a]  out [a, b]
        return [1, 0] if (n_in == 2 and n_out == 2) else None
    if op == "dup":
        # ... a → ... a a
        return [0, 0] if (n_in == 1 and n_out == 2) else None
    if op == "dup2":
        # ... a b → ... a b a b;  in [b, a]  out [b, a, b, a]
        return [0, 1, 0, 1] if (n_in == 2 and n_out == 4) else None
    if op not in ("dupn", "cover", "uncover", "dig", "bury",
                  "frame_dig", "frame_bury"):
        return None
    toks = a.immediates.split()
    if not toks:
        return None
    try:
        n = int(toks[0])
    except ValueError:
        return None
    if op == "dupn":
        # ... a → ... a a … a  (n+1 copies of the top)
        if n_in == 1 and n_out == n + 1:
            return [0] * (n + 1)
    elif op == "cover":
        # pop top A, place it n down;  in [A, X_1..X_n]  out [X_1..X_n, A]
        if n_in == n + 1 and n_out == n + 1:
            return list(range(1, n + 1)) + [0]
    elif op == "uncover":
        # lift depth-n to top;  in [X_0..X_n]  out [X_n, X_0..X_{n-1}]
        if n_in == n + 1 and n_out == n + 1:
            return [n] + list(range(n))
    elif op == "dig":
        # copy depth-n to top, no pops;  in [X_0..X_n]  out [X_n, X_0..X_n]
        if n_in == n + 1 and n_out == n + 2:
            return [n] + list(range(n + 1))
    elif op == "bury":
        # pop top A over depth-n;  in [A, X_1..X_n]  out [X_1..X_{n-1}, A]
        # `bury 0` fails at runtime (buries into the popped slot); rejecting it
        # also avoids a length-1 mapping for zero outputs (IndexError).
        if n >= 1 and n_in == n + 1 and n_out == n:
            return list(range(1, n)) + [0]
    elif op == "frame_dig":
        # A COPY of the slot it addresses: the simulator records the value found
        # there as input 0 and the op pushes its own output, exactly as the AVM
        # pushes a copy. N is not needed — the position was already resolved.
        # (The old fat-band shape, `n_out == n_in + 1` over a whole consumed
        # band, is gone with the model that produced it.)
        if n_in == 1 and n_out == 1:
            return [0]
    elif op == "frame_bury":
        # A WRITE, not a permutation of the operand list: it pops one value and
        # stores it at a resolved position, with no outputs to map.
        return None
    return None


def _canon_shuffle(op: str, immediates: str):
    """``(n_in, mapping)`` for a FIXED-arity shuffle from its CANONICAL arity, or
    ``(None, None)``.

    HAZARD: use this, not :func:`_shuffle_mapping`, when executing a clean value
    stack — that one keys off ``len(a.inputs)``, which an earlier shallow model
    UNDER-counts where its model stack was shallow (``dup2`` recorded with one
    input), so it returns ``None`` and the adapter drops the op, losing depth that
    later starves a callsub's args. Excludes ``frame_dig``/``frame_bury``, which
    are genuinely band-dependent."""
    if op == "swap":
        return (2, [1, 0])
    if op == "dup":
        return (1, [0, 0])
    if op == "dup2":
        return (2, [0, 1, 0, 1])
    toks = immediates.split() if immediates else []
    if not toks:
        return (None, None)
    try:
        n = int(toks[0])
    except ValueError:
        return (None, None)
    if op == "dupn":
        return (1, [0] * (n + 1))
    if op == "cover":
        return (n + 1, list(range(1, n + 1)) + [0])
    if op == "uncover":
        return (n + 1, [n] + list(range(n)))
    if op == "dig":
        return (n + 1, [n] + list(range(n + 1)))
    if op == "bury":
        if n < 1:                       # bury 0 fails at runtime — unmodellable
            return (None, None)
        return (n + 1, list(range(1, n)) + [0])
    return (None, None)

