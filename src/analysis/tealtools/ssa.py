"""Typed SSA-assignment representation of a TEAL program.

Built on top of :mod:`tealtools.graphs` (which runs the CodeQL queries). Where
``tealtools.graphs`` exposes a low-level ``MultiDiGraph`` keyed by AST nodes,
this module presents the same information as a first-class *program*
object: a sequence of :class:`Assignment`\\ s grouped into
:class:`BasicBlock`\\ s, referring to :class:`SSAVar`\\ s, :class:`Phi`\\ s,
and :class:`Const` literals.

    from tealtools.ssa import SSAProgram
    p = SSAProgram("tests/dbs/xgov-db")
    print(p.functional(file="approval.teal", line_range=(225, 260)))

Model
-----

- :class:`SSAVar` — a stack variable produced by one opcode.
  Identity: ``(file, line, output_index)``. Back-reference
  ``defined_by`` points at the :class:`Assignment` that produced it;
  ``uses`` lists assignments consuming it.

- :class:`Phi` — an SSA phi (direct or indirect). Identity:
  ``(file, line, kind, stack_index)``. ``args`` is an ordered list of
  :class:`SSAVar` (for ``DirectPhi``) or a single :class:`Phi` (for
  ``IndirectPhi``, pointing at its root ``DirectPhi``). Back-reference
  ``basic_block`` points at the :class:`BasicBlock` it lives in.

- :class:`Const` — a resolved compile-time literal
  (``intcblock``/``bytecblock`` entry, ``pushint``, ``pushbytes``,
  or the ``int`` pseudo-opcode).

- :class:`Assignment` — ``outputs = op immediates (inputs)``.
  ``outputs`` are SSAVars; ``inputs`` are :class:`SSAVar` / :class:`Phi`
  operands. ``const`` is populated for const-pushing opcodes so consumers
  can render ``V#1@L5 = 10`` instead of ``V#1@L5 = intc_2 ()``. Back-
  reference ``basic_block``.

- :class:`BasicBlock` — maximal single-entry/single-exit straight-line
  region. Identity: ``(file, first_line, last_line)``. Carries its
  ordered ``assignments`` + entry ``phis``, plus ``predecessors`` and
  ``successors`` (both lists of ``BasicBlock``).

Phi materialization is lazy: only phis referenced (directly or
transitively via ``IndirectPhi`` parents) by some assignment are
materialized. This keeps the object count tractable on programs where
the underlying QL model emits many unreferenced phi identities.

The module does not re-run CodeQL queries itself — it calls
:func:`tealtools.graphs.load_graph` and reads the populated node attributes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

import networkx as nx


@dataclass(frozen=True)
class Location:
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


class SSAVar:
    """A stack variable produced by one opcode.

    Identity is ``(file, line, index)`` — matching CodeQL's ``SSAVar``
    newtype ``MkSSAVar(idx, node)``. The textual form
    ``V#{index}@L{line}`` matches ``SSAVar.getIdentifier()`` in QL.
    """

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
        # Resolved by SSAProgram.propagate_constants(): when set, this
        # SSAVar's value is statically known and renders as the literal
        # in functional form. None means "unknown / not constant".
        self.const_value: Optional["Const"] = None
        # Resolved by SSAProgram.propagate_ranges(): independent pass,
        # purely informational. None means "no range info yet".
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
    """An SSA phi. ``kind`` is ``"DirectPhi"`` or ``"IndirectPhi"``.

    For ``DirectPhi``, ``args`` is the list of originating-input
    :class:`SSAVar`\\ s, one per contributing predecessor BB.
    For ``IndirectPhi``, ``args`` is a single-element list containing
    the root :class:`Phi` the indirect phi propagates from.
    """

    __slots__ = (
        "file", "line", "stack_index", "kind",
        "args", "uses", "basic_block",
        "const_value", "range", "type",
    )

    def __init__(self, file: str, line: int, stack_index: int, kind: str):
        self.file = file
        self.line = line
        self.stack_index = stack_index
        self.kind = kind
        self.args: list[Union[SSAVar, "Phi"]] = []
        self.uses: list["Assignment"] = []
        self.basic_block: Optional["BasicBlock"] = None
        # Resolved by SSAProgram.propagate_constants(): set when every
        # arg of this phi resolves to the same constant literal.
        self.const_value: Optional["Const"] = None
        # Resolved by SSAProgram.propagate_ranges(): tracked on phis so
        # ranges can flow through joins (union of arg ranges). Not
        # rendered — annotations are only attached to SSAVar outputs.
        self.range: Optional["IntRange"] = None
        self.type: Optional["TealType"] = None

    def _key(self) -> tuple:
        return (self.file, self.line, self.kind, self.stack_index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, Phi) and self._key() == other._key()

    def __repr__(self) -> str:
        if not self.args:
            tag = "φ" if self.kind == "DirectPhi" else "φᵢ"
            return f"{tag}_{self.stack_index}@L{self.line}"
        return "phi(" + ", ".join(repr(a) for a in self.args) + ")"


class MatPhiVar:
    """A materialised-phi variable produced by :meth:`SSAProgram.materialize_phis`.

    Identity: ``index`` (monotonic, globally unique per program). Unlike
    :class:`SSAVar`, a ``MatPhiVar`` has *multiple* definitions — one per
    DirectPhi argument — which is a legitimate post-SSA-lowering state
    where each copy assignment targets the same variable. Strict SSA is
    intentionally broken; see the "out-of-SSA" literature.
    """

    __slots__ = ("index",)

    def __init__(self, index: int):
        self.index = index

    @property
    def identifier(self) -> str:
        return f"mat_phi_{self.index}"

    def __hash__(self) -> int:
        return hash(("MatPhi", self.index))

    def __eq__(self, other) -> bool:
        return isinstance(other, MatPhiVar) and self.index == other.index

    def __repr__(self) -> str:
        return self.identifier


@dataclass(frozen=True)
class Const:
    """A resolved compile-time literal. ``kind`` ∈ ``{"int", "bytes"}``."""
    kind: str
    value: str

    def __repr__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IntRange:
    """Inclusive integer range ``[lo..hi]`` for a uint64-typed value.

    Set by :meth:`SSAProgram.propagate_ranges`. Currently only seeded
    from boolean-returning ops (always ``[0..1]``) and unioned through
    phis; collections-of-values aren't represented yet.
    """
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

    For ``"bytes"``:
      - ``byte_length`` is the exact length when statically derivable
        (forward propagation, e.g. ``itob`` always 8, ``sha256`` always
        32, ``concat`` of two known-length inputs).
      - ``byte_length_range`` is an inclusive ``[lo..hi]`` bound when
        only the *range* is known (typically from inverse constraints:
        ``btoi(X)`` succeeding ⇒ ``len(X) ∈ [1, 8]``, ``getbyte(X, i)``
        succeeding ⇒ ``len(X) ≥ i+1``, …). When ``byte_length`` is set,
        ``byte_length_range`` mirrors it as ``IntRange(N, N)`` so a
        consumer that only cares about the range has one field to read.

    ``int_value_range`` (also bytes-only) is the inclusive range of
    the bytes value *interpreted as a big-endian unsigned integer* —
    the abstraction TEAL's bytemath ops (``b+``, ``b-``, ``b*``,
    ``b/``, …) work over. Uses :class:`IntRange` storage but its
    bounds are not capped at ``2^64-1`` — Python ints are arbitrary
    precision, so a value derived from many ``b*``-style ops can
    legitimately exceed uint64. Populated by
    :meth:`SSAProgram.propagate_bytemath_ranges`.

    For ``"uint64"`` all three bytes-specific fields are unused (use
    :attr:`SSAVar.range` instead).
    """
    kind: str
    byte_length: Optional[int] = None
    byte_length_range: Optional["IntRange"] = None
    int_value_range: Optional["IntRange"] = None


Operand = Union[SSAVar, Phi, Const, MatPhiVar]


@dataclass
class Assignment:
    """``outputs = op immediates (inputs)`` — one TEAL opcode's SSA form.

    After :meth:`SSAProgram.materialize_phis`, outputs may include
    :class:`MatPhiVar` instances (for synthetic ``mat_phi_k = arg``
    copies inserted at the original phi-argument def sites), and inputs
    may reference :class:`MatPhiVar` where phis used to be.
    """

    outputs: list[Union[SSAVar, MatPhiVar]]
    op: str
    immediates: str
    inputs: list[Operand]
    location: Location
    ast_code: str
    const: Optional[Const] = None
    basic_block: Optional["BasicBlock"] = None
    # Set by :meth:`SSAProgram.propagate_stack_shuffles`. When True, this
    # opcode is a pure stack shuffle whose outputs have all been
    # redirected to their producing inputs at every consumer; the
    # assignment is kept around but rendered with a ``//`` comment
    # prefix so the original stack movement stays inspectable.
    shuffled: bool = False

    def functional(
        self,
        *,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
        show_ranges: bool = False,
    ) -> str:
        """Render this assignment in functional form.

        ``resolve_consts``: replace constblock-referencing opcodes
            (``intc_*``/``bytec_*``) with the resolved literal as the RHS.
        ``propagate_consts``: when an input's :class:`SSAVar` or :class:`Phi`
            has been resolved by :meth:`SSAProgram.propagate_constants`,
            render it as its literal instead of the variable identifier.
        ``show_ranges``: when an SSAVar has a ``range`` set by
            :meth:`SSAProgram.propagate_ranges`, suffix it with a
            ``/*[V<=hi]*/``-style annotation. Constant-collapsed inputs
            and phi expressions are not annotated.
        """
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

        # Copy assignment (materialized phi): render `mat_phi_k = arg` without
        # the opcode/tuple syntax.
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
    """A maximal straight-line region of assignments.

    Identity is ``(file, first_line, last_line)``. ``assignments`` is the
    ordered list of the BB's :class:`Assignment`\\ s (by source line).
    ``phis`` is the list of :class:`Phi`\\ s attached at the BB's entry.
    ``predecessors`` / ``successors`` are the other BBs this BB is
    directly connected to via inter-BB CFG edges.
    """

    __slots__ = (
        "file", "first_line", "last_line",
        "assignments", "phis",
        "predecessors", "successors",
    )

    def __init__(self, file: str, first_line: int, last_line: int):
        self.file = file
        self.first_line = first_line
        self.last_line = last_line
        self.assignments: list[Assignment] = []
        self.phis: list[Phi] = []
        self.predecessors: list["BasicBlock"] = []
        self.successors: list["BasicBlock"] = []

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


# -------------------------------------------------------------------------


_CONST_BLOCK_REF_NAMES = frozenset({
    # constblock references
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
    # inline-literal pushers (carry their literal in immediates; constValues.ql
    # already emits values for them via the IntegerConstant/BytesConstant
    # superclasses, so propagation reads through naturally).
    "IntOpcode", "PushintOpcode", "PushbytesOpcode",
})


# Control-flow terminators. These ops have side effects on the flow graph
# independent of their SSA outputs, so dead-code elimination must NOT drop
# them even if every output is a "dead constant" (e.g. a ``retsub`` whose
# return-value output is constant-propagated and has no remaining consumers
# in the SSA — the op still transfers control to the caller).
_TERMINATOR_OPS = frozenset({
    "callsub", "retsub",
    "b", "bnz", "bz",
    "return", "err",
    "switch", "match",
})


# Op-level constant folding (concat / itob / extract / arithmetic /
# comparisons / ...) is layered above the SSA substrate in
# :mod:`tealtools.const_fold`; lazily imported inside
# :meth:`SSAProgram.propagate_constants` so the substrate itself
# carries no TEAL-semantics knowledge.



# Per-op uint64 output ranges for ops whose bound is determined by the
# op semantics alone (no operand or immediate dependency). Source for
# `propagate_ranges`. AVM bytes-stack values are capped at 4096 bytes,
# which gives `len`/`bitlen` their upper bounds.
_OP_RANGE_SEEDS: dict = None  # filled in below

def _build_op_range_seeds():
    bool_ops = (
        "<", ">", "<=", ">=", "==", "!=",
        "b<", "b>", "b<=", "b>=", "b==", "b!=",
        "&&", "||", "!",
    )
    return {
        **{op: ("uint64", 0, 1) for op in bool_ops},
        # bit/byte extraction with hard-coded output width
        "getbit":         ("uint64", 0, 1),
        "getbyte":        ("uint64", 0, 0xFF),
        "extract_uint16": ("uint64", 0, 0xFFFF),
        "extract_uint32": ("uint64", 0, 0xFFFFFFFF),
        # length ops bounded by AVM stack-bytes cap (4096 bytes)
        "len":    ("uint64", 0, 4096),
        "bitlen": ("uint64", 0, 4096 * 8),
    }

_OP_RANGE_SEEDS = _build_op_range_seeds()

# Bounded enum fields for txn-family / global field reads. Values track
# the AVM spec: OnCompletion in {0..5}, TypeEnum in {0..6} (unknown..appl),
# GroupIndex 0-based with max group size 16, GroupSize ≥ 1.
_TXN_FIELD_RANGES: dict = {
    "OnCompletion": (0, 5),
    "TypeEnum":     (0, 6),
    "GroupIndex":   (0, 15),
}
_GLOBAL_FIELD_RANGES: dict = {
    "GroupSize": (1, 16),
}


# Pure stack-shuffle opcodes — they don't compute, they only permute /
# duplicate / drop existing stack values (or, for the frame variants,
# move values between the stack top and the visible frame slots). For
# each, the per-output input index is fixed by the opcode plus its
# immediate, so every output SSAVar can be rewritten to its source
# value at every consumer (see :meth:`SSAProgram.propagate_stack_shuffles`).
_STACK_SHUFFLE_OPS: frozenset = frozenset({
    "swap", "dup", "dup2", "dupn", "cover", "uncover", "dig", "bury",
    "frame_dig", "frame_bury",
})


def _shuffle_mapping(a: "Assignment") -> Optional[list[int]]:
    """Return ``m`` such that ``a.outputs[i] = a.inputs[m[i]]`` for the
    pure stack-shuffle opcodes in :data:`_STACK_SHUFFLE_OPS`. Returns
    ``None`` when ``a`` isn't a shuffle, or when its input/output shape
    doesn't match the immediate (defensive — a malformed Assignment
    should not silently get its consumers redirected).

    Stack convention: **top-first**. ``inputs[0]`` and ``outputs[0]``
    are the topmost stack value (ord 1 in QL terms); the deepest
    consumed/produced value sits at index ``n - 1``. This matches the
    QL doc on ``getStackInputByOrder`` (`AST.qll`) — *"ord is a 1-based
    stack position (1 = top consumed)"* — and the SSAVar identity
    convention where ``output_index 1`` ranks first by
    ``outStackOrder`` (i.e. is the topmost output).
    """
    op = a.op
    n_in = len(a.inputs)
    n_out = len(a.outputs)
    if op == "swap":
        # ... a b  →  ... b a   (b was top; a becomes new top)
        # in (top-first):  [b, a]
        # out (top-first): [a, b]
        return [1, 0] if (n_in == 2 and n_out == 2) else None
    if op == "dup":
        # ... a  →  ... a a   (both outputs = a)
        return [0, 0] if (n_in == 1 and n_out == 2) else None
    if op == "dup2":
        # ... a b  →  ... a b a b   (b was top)
        # in (top-first):  [b, a]
        # out (top-first): [b, a, b, a]
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
        # ... a  →  ... a a … a   (n+1 copies of the original top)
        if n_in == 1 and n_out == n + 1:
            return [0] * (n + 1)
    elif op == "cover":
        # cover n: pop top A, place it n positions down. Before:
        # ... X_n X_{n-1} … X_1 A   (A = top). After:
        # ... A X_n X_{n-1} … X_1   (X_1 = new top).
        # in  (top-first): [A, X_1, X_2, …, X_n]
        # out (top-first): [X_1, X_2, …, X_n, A]
        if n_in == n + 1 and n_out == n + 1:
            return list(range(1, n + 1)) + [0]
    elif op == "uncover":
        # uncover n: lift the value at depth n to the top. Before:
        # ... X_n X_{n-1} … X_1 X_0   (X_0 = top, X_n at depth n).
        # After: ... X_{n-1} … X_1 X_0 X_n   (X_n = new top).
        # in  (top-first): [X_0, X_1, …, X_n]
        # out (top-first): [X_n, X_0, X_1, …, X_{n-1}]
        if n_in == n + 1 and n_out == n + 1:
            return [n] + list(range(n))
    elif op == "dig":
        # dig n: copy the value at depth n to the top (no pops).
        # in  (top-first): [X_0, X_1, …, X_n]                (n+1 elts)
        # out (top-first): [X_n, X_0, X_1, …, X_{n-1}, X_n]  (n+2 elts)
        if n_in == n + 1 and n_out == n + 2:
            return [n] + list(range(n + 1))
    elif op == "bury":
        # bury n: pop top A, overwrite the value at depth n with A.
        # Before: ... X_n X_{n-1} … X_1 A     (A = top, n+1 elts).
        # After:  ... A   X_{n-1} … X_1       (n elts).
        # in  (top-first): [A, X_1, X_2, …, X_n]
        # out (top-first): [X_1, X_2, …, X_{n-1}, A]
        if n_in == n + 1 and n_out == n:
            return list(range(1, n)) + [0]
    elif op == "frame_dig":
        # SSA model layout (top-first): ``inputs`` is [top_local,
        # next_local, …, frame[N]]; the dug slot ``frame[N]`` is the
        # **deepest** of the consumed range, so ``inputs[n_in-1]``
        # always holds it regardless of whether ``N`` is positive
        # (locals above frame ptr) or negative (args below it).
        # ``outputs`` is the same block with the dug copy prepended on
        # top: ``[dug, top_local, …, frame[N]]``. We don't even need
        # to look at ``N`` — the model's ``n_in`` already encodes the
        # span "from dug slot up to top".
        if n_in < 1 or n_out != n_in + 1:
            return None
        return [n_in - 1] + list(range(n_in))
    elif op == "frame_bury":
        # SSA model layout (top-first): ``inputs[0]`` is the stack top
        # being popped (the value to bury); ``inputs[1:]`` is the
        # consumed frame band [top_local, …, frame[N+1]] (the dug
        # target ``frame[N]`` itself isn't consumed because it's
        # only being written, not read). After the bury, ``frame[N]``
        # holds the popped value, so the new output band is
        # ``[top_local, …, frame[N+1], frame[N]_new]`` — i.e. the
        # input frame slots shifted, with the popped value at the
        # deepest output position. Independent of ``N``.
        if n_out < 1 or n_in != n_out + 1:
            return None
        return list(range(1, n_out)) + [0]
    return None


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    def __init__(self, db_path: str | Path, *, refresh: bool = False, verbose: bool = False):
        from . import graphs as tg
        from .ast import Opcode, Label

        g = tg.load_graph(db_path, refresh=refresh, verbose=verbose)
        self._graph = g
        self.db_path = Path(db_path).resolve()

        self.vars: dict[tuple, SSAVar] = {}
        self.phis: dict[tuple, Phi] = {}
        self.assignments: list[Assignment] = []
        self.blocks: dict[tuple, BasicBlock] = {}
        self.mat_phis: list[MatPhiVar] = []
        # Sorted (file, line, label_text) — purely for rendering. Labels
        # have no SSA effect, but interleaving them with assignments in
        # ``functional()`` keeps the dump anchored to the source layout.
        self.labels: list[tuple[str, int, str]] = []
        self._materialized: bool = False
        self._consts_propagated: bool = False
        self._dead_eliminated: bool = False
        self._scratch_propagated: bool = False
        self._ranges_propagated: bool = False
        self._shuffles_propagated: bool = False
        self._inputs_propagated: bool = False

        # Index graph-side phis by key for fast lookup during lazy materialization.
        g_phi_by_key: dict[tuple, tg.PhiNode] = {}
        for n in g.nodes:
            if isinstance(n, tg.PhiNode):
                g_phi_by_key[
                    (n.location.file, n.location.start_line, n.kind, n.stack_index)
                ] = n

        def _to_var(gv: "tg.SSAVar") -> SSAVar:
            key = (gv.file, gv.line, gv.output_index)
            v = self.vars.get(key)
            if v is None:
                v = SSAVar(*key)
                self.vars[key] = v
            return v

        def _to_phi(gp: "tg.PhiNode") -> Phi:
            key = (gp.location.file, gp.location.start_line, gp.kind, gp.stack_index)
            p = self.phis.get(key)
            if p is None:
                p = Phi(gp.location.file, gp.location.start_line, gp.stack_index, gp.kind)
                self.phis[key] = p
            return p

        def _to_operand(x) -> Operand:
            if isinstance(x, tg.SSAVar):
                return _to_var(x)
            if isinstance(x, tg.PhiNode):
                return _to_phi(x)
            raise TypeError(f"unexpected stack-input type: {type(x).__name__}")

        def _bb_from_tuple(bb_id: tuple) -> BasicBlock:
            bb = self.blocks.get(bb_id)
            if bb is None:
                bb = BasicBlock(*bb_id)
                self.blocks[bb_id] = bb
            return bb

        # Pass 1: build Assignments (creating SSAVars + phis lazily via _to_operand).
        for n in g.nodes:
            if not isinstance(n, Opcode):
                continue
            outs_g = g.nodes[n].get("stack_outputs") or []
            ins_g = g.nodes[n].get("stack_inputs") or []
            code = n.code or n.ql_class
            op_name, _, imms = code.partition(" ")
            cv = g.nodes[n].get("const_value")
            const: Optional[Const] = None
            if cv is not None and type(n).__name__ in _CONST_BLOCK_REF_NAMES:
                kind, value = cv
                const = Const(kind, value)
            bb_id = g.nodes[n].get("bb")
            bb = _bb_from_tuple(bb_id) if bb_id is not None else None

            outs = [_to_var(v) for v in outs_g]
            ins = [_to_operand(x) for x in ins_g]
            a = Assignment(
                outputs=outs,
                op=op_name,
                immediates=imms,
                inputs=ins,
                location=Location(n.location.file, n.location.start_line),
                ast_code=code,
                const=const,
                basic_block=bb,
            )
            self.assignments.append(a)
            for v in outs:
                v.defined_by = a
            # Pre-attach per-output constant literals from constValues.ql
            # (literal-only, sound) AND from mustValues.ql (dataflow-
            # extended, also sound — covers arithmetic, scratch, callsub
            # bridges via the ConstantPropagation library, but with a
            # must-overwrite check that excludes may-be-K results).
            # constValues is the literal source; mustValues only fills
            # in slots not already populated.
            const_outputs = g.nodes[n].get("const_outputs") or {}
            must_outputs = g.nodes[n].get("must_outputs") or {}
            for v in outs:
                co = const_outputs.get(v.index)
                if co is not None:
                    v.const_value = Const(*co)
                    continue
                mo = must_outputs.get(v.index)
                if mo is not None:
                    v.const_value = Const(*mo)
            for inp in ins:
                inp.uses.append(a)
            if bb is not None:
                bb.assignments.append(a)

        # Pass 2: close over transitively-referenced phis. Each phi we've
        # already materialized references 0+ more phis via its ``args``;
        # resolve args lazily so we only touch phis that actually matter.
        pending = list(self.phis.values())
        while pending:
            p = pending.pop()
            if p.args:
                continue
            gp = g_phi_by_key.get((p.file, p.line, p.kind, p.stack_index))
            if gp is None:
                continue
            for a in gp.args:
                arg = _to_operand(a)
                p.args.append(arg)
                if isinstance(arg, Phi) and not arg.args:
                    pending.append(arg)

        # Pass 3: attach phis to their host BBs (phi.line == bb.first_line).
        bb_by_first_line: dict[tuple[str, int], BasicBlock] = {
            (bb.file, bb.first_line): bb for bb in self.blocks.values()
        }
        for p in self.phis.values():
            bb = bb_by_first_line.get((p.file, p.line))
            if bb is not None:
                p.basic_block = bb
                bb.phis.append(p)

        # Pass 4: wire BB predecessor/successor from CFG edges that
        # cross BB *boundaries*. An edge ``u → v`` represents entering
        # ``v``'s BB iff ``v`` is its BB's first node — that's the only
        # way to land on the BB. Filtering on "v is first node of v's
        # BB" rather than on "u_bb != v_bb" correctly captures
        # self-loops (single-BB loops where the BB's tail branch
        # targets the BB's own head — e.g. ``bnz l_loop`` at L25
        # branching back to the ``l_loop:`` label at L16, both inside
        # the same BB). The previous "u_bb != v_bb" filter dropped
        # such self-loops, so ``bb.predecessors`` for a one-BB loop
        # missed the back-edge entirely.
        seen_edges: set[tuple[BasicBlock, BasicBlock]] = set()
        for u, v, data in g.edges(data=True):
            if data.get("kind") != "cfg":
                continue
            succ = data.get("successor")
            if succ in ("PhiIn", "PhiOut"):
                continue
            u_bb_id = g.nodes[u].get("bb")
            v_bb_id = g.nodes[v].get("bb")
            if u_bb_id is None or v_bb_id is None:
                continue
            # Intra-BB CFG edges must represent a back-edge from a
            # branch at the BB's tail to its head — i.e. ``u.line >
            # v.line``. Equal-line intra-BB edges arise from the
            # CodeQL extractor modeling template markers
            # (``pushint TMPL_FOO`` → ``Label@TMPL_FOO``) as
            # same-line CFG edges that aren't real control flow;
            # including them creates spurious BB-self-loops that
            # ``find_loops`` then misclassifies as actual loops.
            if (
                u_bb_id == v_bb_id
                and u.location.start_line <= v.location.start_line
            ):
                continue
            # Only edges into the BB's first node represent BB entry.
            # Intra-BB sequential edges (op → next op within one BB)
            # target later nodes and don't add BB-level info.
            if v.location.start_line != v_bb_id[1]:
                continue
            u_bb = self.blocks.get(u_bb_id)
            v_bb = self.blocks.get(v_bb_id)
            if u_bb is None or v_bb is None:
                continue
            if (u_bb, v_bb) in seen_edges:
                continue
            seen_edges.add((u_bb, v_bb))
            u_bb.successors.append(v_bb)
            v_bb.predecessors.append(u_bb)

        # Pass 5: collect Label nodes for rendering. They aren't part of
        # the SSA — they don't define or consume values — but printing
        # them in :meth:`functional` lets the dump line up with the
        # source listing (branch targets stay visible).
        for n in g.nodes:
            if isinstance(n, Label):
                self.labels.append(
                    (n.location.file, n.location.start_line, n.code or "")
                )
        self.labels.sort()

        # Final ordering.
        self.assignments.sort(key=lambda a: (a.location.file, a.location.line))
        for bb in self.blocks.values():
            bb.assignments.sort(key=lambda a: a.location.line)
            bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    # -- iteration / lookup -------------------------------------------------

    def __iter__(self) -> Iterable[Assignment]:
        return iter(self.assignments)

    def __len__(self) -> int:
        return len(self.assignments)

    def var(self, file: str, line: int, index: int) -> Optional[SSAVar]:
        return self.vars.get((file, line, index))

    def phi(self, file: str, line: int, kind: str, stack_index: int) -> Optional[Phi]:
        return self.phis.get((file, line, kind, stack_index))

    def block(self, file: str, first_line: int, last_line: int) -> Optional[BasicBlock]:
        return self.blocks.get((file, first_line, last_line))

    def block_containing(self, file: str, line: int) -> Optional[BasicBlock]:
        for bb in self.blocks.values():
            if bb.file == file and bb.contains(line):
                return bb
        return None

    def assignments_in(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
    ) -> list[Assignment]:
        out = []
        for a in self.assignments:
            if file is not None and a.location.file != file:
                continue
            if line_range is not None and not (line_range[0] <= a.location.line <= line_range[1]):
                continue
            out.append(a)
        return out

    # -- passes -------------------------------------------------------------

    def propagate_constants(self) -> None:
        """Resolve each :class:`SSAVar` and :class:`Phi` to its compile-time
        literal value where statically known.

        Two passes:

        1. Every SSAVar whose defining :class:`Assignment` has ``const`` set
           (an ``intc_*``/``bytec_*``/``intc``/``bytec`` opcode resolved
           via the constblock) is tagged with that ``Const``. ``pushint``,
           ``pushbytes``, and the ``int`` pseudo-opcode all carry their
           literal in immediates and are similarly resolvable, but only
           constblock references currently set ``Assignment.const``; the
           others are left for later (extend ``_CONST_BLOCK_REF_NAMES`` in
           ``__init__`` to widen).

        2. A :class:`Phi` whose every arg (recursively) resolves to the
           *same* literal becomes constant. Iterates to a fixed point so
           phi → phi → … chains converge.

        After this pass, :meth:`Assignment.functional` substitutes any
        SSAVar/Phi input with its literal when ``propagate_consts=True``
        (default). Idempotent.
        """
        if self._consts_propagated:
            return

        # Pass 1: SSAVars from their defining Assignment's resolved constant.
        for v in self.vars.values():
            if v.defined_by is not None and v.defined_by.const is not None:
                v.const_value = v.defined_by.const

        # Pass 2: fixed point over (a) phi-arg unification and (b) the
        # value-identity step relation from `valueIdentitySteps.ql`.
        #
        # (a) phi unification: a phi resolves when every arg resolves to
        #     the same literal. Covers phi-of-phi chains via iteration.
        # (b) identity steps: the QL lib emits one row per src/sink pair
        #     where `valueIdentityFlowStep` proves the runtime values are
        #     equal (stack passthrough, single-source phi, callsub /
        #     scratch bridge). If src has a `const_value`, sink shares it.
        #     This is what plugs the gap multi-arg phi unification can't
        #     close at the lib stratum: a phi K resolved by `tryAsIntPhi`
        #     in the query layer flows here into downstream consumer
        #     SSAVars and further phis.
        steps = self._graph.graph.get("identity_steps", []) or []

        def _resolve_endpoint(key):
            if key[0] == "var":
                _, f, l, i = key
                return self.vars.get((f, l, i))
            _, f, l, kind, idx = key
            return self.phis.get((f, l, kind, idx))

        # Pre-resolve endpoints once; skip steps where either side is
        # missing (e.g. a phi pruned by the SSA layer).
        resolved_steps: list[tuple] = []
        for src_key, snk_key in steps:
            src = _resolve_endpoint(src_key)
            snk = _resolve_endpoint(snk_key)
            if src is not None and snk is not None and src is not snk:
                resolved_steps.append((src, snk))

        changed = True
        while changed:
            changed = False
            for phi in self.phis.values():
                if phi.const_value is not None:
                    continue
                arg_consts: list[Const] = []
                ok = True
                for arg in phi.args:
                    if isinstance(arg, SSAVar):
                        cv = arg.const_value
                    elif isinstance(arg, Phi):
                        cv = arg.const_value
                    else:
                        cv = None
                    if cv is None:
                        ok = False
                        break
                    arg_consts.append(cv)
                if ok and arg_consts and all(c == arg_consts[0] for c in arg_consts):
                    phi.const_value = arg_consts[0]
                    changed = True
            for src, snk in resolved_steps:
                if src.const_value is not None and snk.const_value is None:
                    snk.const_value = src.const_value
                    changed = True
            # Op-level constant folding: any single-output Assignment
            # whose every input is now const-resolved gets its output
            # computed (concat / extract / itob / btoi / arithmetic /
            # comparisons / logical / ...). Lazily imported so the
            # substrate carries no TEAL-semantics knowledge by itself.
            # Runs inside the fixpoint so a fold-then-propagate-then-
            # fold chain converges naturally.
            from .passes.const_fold import try_fold_assignment
            for a in self.assignments:
                if len(a.outputs) != 1:
                    continue
                out = a.outputs[0]
                if not isinstance(out, SSAVar) or out.const_value is not None:
                    continue
                folded = try_fold_assignment(a)
                if folded is not None:
                    out.const_value = folded
                    changed = True

        self._consts_propagated = True

    def propagate_inputs(self) -> None:
        """Unify execution-stable input reads (``txn`` / ``txna`` /
        ``gtxn``-family / ``global`` / ``arg``) so multiple syntactic
        reads of the same input collapse to one canonical SSAVar.

        Idempotent. Mutates the SSA: duplicate readers' outputs get
        rewired in every consumer (assignment inputs and phi args) to
        point at the first reader's output. Lazily imported because
        the unification logic lives in :mod:`tealtools.input_prop`
        — the substrate just provides the entry point.

        ``itxn``-family reads are deliberately *not* included; itxn
        fields observe the most-recently-submitted inner transaction
        and can legitimately differ between submits."""
        if getattr(self, "_inputs_propagated", False):
            return
        from .passes.input_prop import propagate_inputs as _impl
        _impl(self)
        self._inputs_propagated = True

    def propagate_scratch_values(self) -> int:
        """Generalises :meth:`propagate_scratch_constants` from compile-
        time literals to arbitrary SSA values.

        For each ``load N`` opcode whose may-influencing stores
        (provided by the CodeQL ``scratch_stores`` annotation) all
        write the *same* :class:`SSAVar` ``V``, rewire every consumer
        of the load's output to reference ``V`` directly. The load's
        ``Assignment`` stays in the IR with empty ``uses`` until a
        subsequent :meth:`cleanup_unused_ssavars` removes it.

        Returns the number of loads forwarded. Mutates the SSA in place.
        Idempotent — a second call finds nothing further to forward.

        Best run after :meth:`propagate_inputs` (so equivalent input
        reads are already unified and forwarding through scratch can
        see them as a single SSAVar) and :meth:`propagate_scratch_constants`
        (so const stores resolve via const_value first). Not part of
        :func:`run_all_passes` because — like ``propagate_inputs`` —
        the SSAVar-identity change can surprise analyses that expect a
        1:1 mapping between load assignments and their downstream uses.
        """
        forwarded = 0
        for n in self._graph.nodes:
            stores = self._graph.nodes[n].get("scratch_stores")
            if not stores:
                continue
            load_var = self.var(n.location.file, n.location.start_line, 1)
            if load_var is None:
                continue
            sources: list[SSAVar] = []
            ok = True
            for sv_file, sv_line, sv_idx in stores:
                src = self.var(sv_file, sv_line, sv_idx)
                if src is None:
                    ok = False
                    break
                sources.append(src)
            if not ok or not sources:
                continue
            first = sources[0]
            if not all(s is first for s in sources):
                continue
            if load_var is first:
                continue
            for cons in list(load_var.uses):
                for i, inp in enumerate(cons.inputs):
                    if inp is load_var:
                        cons.inputs[i] = first
                        first.uses.append(cons)
            for phi in self.phis.values():
                for i, arg in enumerate(phi.args):
                    if arg is load_var:
                        phi.args[i] = first
            load_var.uses = []
            forwarded += 1
        return forwarded

    def cleanup_unused_ssavars(self) -> int:
        """Drop side-effect-free :class:`Assignment` s whose every
        output has empty ``uses``. Typically called after
        :meth:`propagate_inputs` to physically remove the duplicate
        input reads it unified semantically. Returns the count of
        assignments removed.

        Idempotent on a fixed IR — repeated calls find nothing more
        to drop. Lazily imports the implementation from
        :mod:`tealtools.cleanup` so the substrate stays free of the
        per-op pure-set decisions."""
        from .passes.cleanup import cleanup_unused_ssavars as _impl
        return _impl(self)

    def propagate_scratch_constants(self) -> None:
        """Resolve each ``load N`` opcode's output to a literal when every
        ``store N`` that may influence the load wrote the same compile-
        time literal value.

        A separate pass from :meth:`propagate_constants` so the scratch
        analysis can be reasoned about (and toggled) independently of
        stack-based propagation. The QL ``scratchInfluence.ql`` query
        provides the may-influence relation and the SSAVar key of each
        store's consumed value; this pass aggregates them in Python.
        Must-semantics: any load whose stores include even one non-
        constant value is left non-resolved.
        """
        if self._scratch_propagated:
            return
        # Stack-side propagation needs to have run first so each store's
        # consumed SSAVar already has its const_value (if any) set.
        if not self._consts_propagated:
            self.propagate_constants()

        # Iterate to fixed point: a load resolved to K can in turn flow
        # back into another store, whose load can then resolve, and so on.
        changed = True
        while changed:
            changed = False
            for n in self._graph.nodes:
                stores = self._graph.nodes[n].get("scratch_stores")
                if not stores:
                    continue
                # The load op `n` has a single output SSAVar at outIdx=1.
                load_var = self.var(n.location.file, n.location.start_line, 1)
                if load_var is None or load_var.const_value is not None:
                    continue
                # Look up each store's consumed-value SSAVar by its key.
                resolved: list[Const] = []
                ok = True
                for sv_file, sv_line, sv_idx in stores:
                    src = self.var(sv_file, sv_line, sv_idx)
                    if src is None or src.const_value is None:
                        ok = False
                        break
                    resolved.append(src.const_value)
                if ok and resolved and all(c == resolved[0] for c in resolved):
                    load_var.const_value = resolved[0]
                    changed = True

        self._scratch_propagated = True

    def propagate_ranges(self) -> None:
        """Tag SSAVars / Phis with a static integer range and type.

        Independent, idempotent. Seeds come from three tables:
        :data:`_OP_RANGE_SEEDS` (op alone determines the bound, e.g.
        bool-shaped comparisons, ``getbyte``, ``len``),
        :data:`_TXN_FIELD_RANGES` (``txn``/``gtxn``/``gtxns``/``itxn``
        with an enum-valued field name as immediate), and
        :data:`_GLOBAL_FIELD_RANGES` (``global FIELD``). A second pass
        unions arg ranges through phis to fixed point.
        """
        if self._ranges_propagated:
            return

        UINT64 = TealType("uint64")

        def _seed(o, lo: int, hi: int) -> None:
            if isinstance(o, SSAVar) and o.range is None:
                o.range = IntRange(lo, hi)
                o.type = UINT64

        # Pass 1: seed from per-op rules. Single-output guard reflects
        # that every range-yielding op here produces exactly one stack
        # output; anything else would be a malformed Assignment.
        for a in self.assignments:
            if len(a.outputs) != 1:
                continue
            o = a.outputs[0]

            # 1a. Op alone gives the range (covers comparisons,
            # logical ops, getbit/getbyte, extract_uint{16,32},
            # len/bitlen).
            seed = _OP_RANGE_SEEDS.get(a.op)
            if seed is not None:
                _, lo, hi = seed
                _seed(o, lo, hi)
                continue

            if not a.immediates:
                continue
            toks = a.immediates.split()

            # 1b. txn-family field reads where the field carries the
            # range. ``txn``/``gtxns``/``itxn`` put the field in the
            # first immediate; ``gtxn`` / ``gtxna`` / ``gtxnsa`` etc.
            # put a group index first and the field second.
            field: Optional[str] = None
            if a.op in ("txn", "gtxns", "itxn") and toks:
                field = toks[0]
            elif a.op in ("gtxn", "gtxna", "gtxnas") and len(toks) >= 2:
                field = toks[1]
            if field is not None:
                rng = _TXN_FIELD_RANGES.get(field)
                if rng is not None:
                    _seed(o, *rng)
                    continue

            # 1c. global FIELD (only enum-valued fields seed).
            if a.op == "global" and toks:
                rng = _GLOBAL_FIELD_RANGES.get(toks[0])
                if rng is not None:
                    _seed(o, *rng)
                    continue

        # Pass 2: union ranges through phis to fixed point. A phi gets a
        # range only if every arg has one; the result is the smallest
        # box covering all of them. Type unifies to uint64 only when
        # every arg agrees.
        changed = True
        while changed:
            changed = False
            for ph in self.phis.values():
                if ph.range is not None or not ph.args:
                    continue
                arg_ranges: list[IntRange] = []
                ok = True
                for arg in ph.args:
                    r = getattr(arg, "range", None)
                    if r is None:
                        ok = False
                        break
                    arg_ranges.append(r)
                if not ok:
                    continue
                lo = min(r.lo for r in arg_ranges)
                hi = max(r.hi for r in arg_ranges)
                ph.range = IntRange(lo, hi)
                arg_types = [getattr(arg, "type", None) for arg in ph.args]
                if all(t is not None and t.kind == "uint64" for t in arg_types):
                    ph.type = UINT64
                changed = True

        self._ranges_propagated = True

    def propagate_range_arithmetic(self) -> int:
        """Forward ``IntRange`` annotations through ``+`` / ``-`` /
        ``*`` / ``/`` / ``%`` (and re-union phis with the widened
        ranges) — capabilities that :meth:`propagate_ranges` doesn't
        provide. Opt-in.

        Returns the number of SSAVars / Phis newly ranged or whose
        range was widened during a phi re-union. Lazy-trips
        :meth:`propagate_ranges` first so the stdlib seeds (boolean
        ops, txn enum fields) are in place before arithmetic
        composes them. Lazily imported from
        :mod:`tealtools.range_arith` so the substrate stays free of
        the AVM arithmetic semantics."""
        from .passes.range_arith import propagate_range_arithmetic as _impl
        return _impl(self)

    def propagate_bytemath_ranges(self) -> int:
        """Flow bigint ranges through bytemath ops (``b+``, ``b-``,
        ``b*``, ``b/``, ``b%``) using Python's arbitrary-precision
        ints, with ``itob`` / ``btoi`` bridging the uint64 ↔ bytes
        value spaces. Populates :attr:`TealType.int_value_range`.

        Returns the cumulative number of range installations /
        tightenings. Opt-in. Lazily trips
        :meth:`propagate_constants` and :meth:`propagate_ranges`
        first. Lazily imported from :mod:`tealtools.bytemath` so the
        substrate stays free of bytemath semantics."""
        from .passes.bytemath import propagate_bytemath_ranges as _impl
        return _impl(self)

    def propagate_byte_lengths(self) -> int:
        """Tag bytes-producing SSAVars / Phis with their statically
        derivable :attr:`TealType.byte_length`. Opt-in (not part of
        :func:`tealtools.passes.run_all_passes`) so
        analyses that don't care about lengths aren't paying for it.

        Covers ``itob`` (always 8), ``bzero N`` with const ``N``,
        ``extract A B`` / ``substring A B`` (immediate forms),
        ``concat`` (sum of input lengths), and lifts the length
        directly from any ``Const("bytes", "0x..")`` literal already
        on an output. Phis adopt a length only when every arg agrees.

        Returns the number of SSAVars / Phis newly tagged. Idempotent:
        a second call walks the fixed point again and finds nothing
        further to add. Lazily imported from
        :mod:`tealtools.byte_length_prop` so the TEAL byte-op
        semantics stay out of the substrate."""
        from .passes.byte_length_prop import propagate_byte_lengths as _impl
        return _impl(self)

    def propagate_stack_shuffles(self) -> None:
        """Copy-propagate the outputs of pure stack-shuffle opcodes
        (:data:`_STACK_SHUFFLE_OPS`) into their consumers and mark the
        shuffle assignments themselves with :attr:`Assignment.shuffled`
        so :meth:`Assignment.functional` renders them as ``// …``
        comments — the structural rewrite happens, but the original
        stack movement stays visible in the dump for inspection.

        For each shuffle ``a``, :func:`_shuffle_mapping` gives the
        per-output input index. Each output SSAVar ``a.outputs[i]`` is
        therefore guaranteed equal at runtime to ``a.inputs[m[i]]``, so
        every consumer (other ``Assignment.inputs`` slots and
        ``Phi.args``) is rewritten to read the input directly. Chains
        of shuffles are flattened in one pass via :func:`_resolve` so a
        single rewrite of consumers suffices.

        Should run before :meth:`materialize_phis` — phi args are
        list[SSAVar | Phi] until materialisation; rewriting them after
        materialisation could inject :class:`MatPhiVar` and break that
        invariant. Idempotent.
        """
        if self._shuffles_propagated:
            return

        # Step 1: collect the shuffle assignments and the per-output
        # redirect from each output SSAVar to its source operand.
        redirect: dict[SSAVar, Operand] = {}
        shuffle_assigns: list[Assignment] = []
        for a in self.assignments:
            if a.op not in _STACK_SHUFFLE_OPS:
                continue
            mapping = _shuffle_mapping(a)
            if mapping is None:
                continue
            shuffle_assigns.append(a)
            for out_idx, in_idx in enumerate(mapping):
                out = a.outputs[out_idx]
                if isinstance(out, SSAVar):
                    redirect[out] = a.inputs[in_idx]

        if not redirect:
            self._shuffles_propagated = True
            return

        # Step 2: flatten shuffle-of-shuffle chains so each output
        # resolves to its deepest non-shuffle source in one hop.
        def _resolve(o: Operand) -> Operand:
            seen: set[SSAVar] = set()
            while isinstance(o, SSAVar) and o in redirect:
                if o in seen:
                    break  # defensive: cycles shouldn't exist on valid TEAL
                seen.add(o)
                o = redirect[o]
            return o

        final: dict[SSAVar, Operand] = {v: _resolve(v) for v in redirect}

        # Step 3: rewrite every consumer. Both Assignment.inputs and
        # Phi.args may reference shuffle outputs.
        for a in self.assignments:
            a.inputs = [final.get(i, i) if isinstance(i, SSAVar) else i
                        for i in a.inputs]
        for ph in self.phis.values():
            ph.args = [final.get(arg, arg) if isinstance(arg, SSAVar) else arg
                       for arg in ph.args]

        # Step 4: mark the shuffle assignments. They stay in
        # ``self.assignments`` / ``bb.assignments`` and their output
        # SSAVars stay in ``self.vars`` so the commented dump line can
        # still resolve identifiers; the ``shuffled`` flag drives the
        # ``// …`` prefix in :meth:`Assignment.functional`.
        for a in shuffle_assigns:
            a.shuffled = True

        self._shuffles_propagated = True

    def eliminate_dead_constants(self) -> None:
        """Inline constant literals into every consumer's input list, then
        drop the now-orphan SSAVars / Phis and any Assignment whose
        outputs are *all* dead.

        Conservative: only touches SSAVars/Phis with ``const_value`` set
        (i.e. things whose literal was resolved by
        :meth:`propagate_constants`). Non-constant producers — ``txn``
        reads, ``load N``, function-call results — are kept even if they
        end up unreferenced after the inlining, because their AST node
        carries side-effect / source-meaning information we want to
        preserve in the trace.

        Effect on the functional dump: trivial constant pushes
        (``L 5: V#1@L5 = 0``) disappear, and consumers that previously
        showed ``(V#1@L5, …)`` already render as ``(0, …)``.

        Idempotent. Implicitly runs :meth:`propagate_constants` first if
        that hasn't been done.
        """
        if self._dead_eliminated:
            return
        if not self._consts_propagated:
            self.propagate_constants()

        def _resolve(o):
            if isinstance(o, (SSAVar, Phi)) and o.const_value is not None:
                return o.const_value
            return o

        # Pass 1: replace every const-resolvable reference with its literal.
        for a in self.assignments:
            a.inputs = [_resolve(i) for i in a.inputs]
        for ph in self.phis.values():
            ph.args = [_resolve(arg) for arg in ph.args]

        # Pass 2: recompute structural reference sets.
        ref_vars: set[SSAVar] = set()
        ref_phis: set[Phi] = set()
        for a in self.assignments:
            for i in a.inputs:
                if isinstance(i, SSAVar):
                    ref_vars.add(i)
                elif isinstance(i, Phi):
                    ref_phis.add(i)
        for ph in self.phis.values():
            for arg in ph.args:
                if isinstance(arg, SSAVar):
                    ref_vars.add(arg)
                elif isinstance(arg, Phi):
                    ref_phis.add(arg)

        # Pass 2b: pin the topmost-stack SSAVar at every ``return`` op.
        # The CodeQL extractor models ``return`` with 0 stack_inputs, so
        # the program's exit value (always 1 popped value at runtime —
        # ``pushint 1; return`` is the canonical success pattern) has no
        # SSA consumer. Without this pin, propagate_constants resolves
        # the exit value's SSAVar to a literal, ref_vars no longer
        # includes it, and Pass 3 drops it — and Pass 4 then deletes
        # the producing op (the ``pushint`` / ``intc_*``) from the dump
        # entirely, even though that op *is* the program return value.
        # Heuristic: in any BB whose last assignment is ``return``, the
        # last op with non-empty ``outputs`` before the return produced
        # the value being returned; keep its outputs alive.
        returned_vars: set[SSAVar] = set()
        for bb in self.blocks.values():
            ret_idx = None
            for i, a in enumerate(bb.assignments):
                if a.op == "return":
                    ret_idx = i
                    break
            if ret_idx is None:
                continue
            for a in reversed(bb.assignments[:ret_idx]):
                if a.outputs:
                    for v in a.outputs:
                        if isinstance(v, SSAVar):
                            returned_vars.add(v)
                    break

        # Pass 3: identify dead constant SSAVars / Phis (have const_value
        # AND no remaining structural references).
        dead_vars = {
            v for v in self.vars.values()
            if v.const_value is not None
            and v not in ref_vars
            and v not in returned_vars
        }
        dead_phis = {
            ph for ph in self.phis.values()
            if ph.const_value is not None and ph not in ref_phis
        }

        # Pass 4: assignments whose every output is dead are dropped. Use
        # `id()` for set membership because :class:`Assignment` is an
        # unfrozen dataclass and not hashable. Control-flow terminators
        # (``retsub``, ``callsub``, ``b``, branches, ``return``, ``err``,
        # ``switch``, ``match``) are *never* dead — they have flow-graph
        # side effects independent of whether their SSA outputs have
        # consumers. Excluding them here is the substrate's correctness
        # guarantee that every consumer (control-tree builder, dataflow,
        # path analyses) can rely on retsubs etc. remaining in the IR.
        dead_assignment_ids: set[int] = {
            id(a) for a in self.assignments
            if a.outputs
            and all(o in dead_vars for o in a.outputs)
            and a.op not in _TERMINATOR_OPS
        }
        # Also clear `defined_by` on the dropped SSAVars (defensive — they're
        # being removed from `self.vars` so back-refs into them shouldn't
        # accidentally bring them back).
        for v in dead_vars:
            v.defined_by = None

        # Pass 5: commit removals.
        self.vars = {k: v for k, v in self.vars.items() if v not in dead_vars}
        self.phis = {k: ph for k, ph in self.phis.items() if ph not in dead_phis}
        self.assignments = [a for a in self.assignments if id(a) not in dead_assignment_ids]
        for bb in self.blocks.values():
            bb.assignments = [a for a in bb.assignments if id(a) not in dead_assignment_ids]
            bb.phis = [ph for ph in bb.phis if ph not in dead_phis]

        self._dead_eliminated = True

    def materialize_phis(self) -> None:
        """Out-of-SSA lowering: replace each live :class:`Phi` with a
        synthetic :class:`MatPhiVar`, inserting copy assignments
        ``mat_phi_k = leaf_ssavar`` at each reachable leaf's def site.

        **DirectPhi ``p`` with args ``(v1, …, vN)``** — all SSAVars:
            1. Allocate a fresh ``mat_phi_k``.
            2. Insert one copy per ``v_i`` at ``v_i``'s def site.
            3. Consumers reading ``p`` now read ``mat_phi_k``.

        **IndirectPhi ``ip``** — ``args`` is a list of :class:`Phi`
        (DirectPhi roots from the QL ``getGenerator()`` walk):

            - Single root ``[root]``: ``ip`` re-uses ``root``'s
              ``mat_phi_k``. No extra allocation or copies.
            - Multiple roots ``[r1, r2, …]``: ``ip`` represents a meet
              across *all* rs. Allocate a fresh ``mat_phi_k`` for
              ``ip`` and insert copies at every originating SSAVar leaf
              transitively reachable from any ``r_i`` (so every
              incoming edge in the meet gets represented, none dropped).

        Idempotent — calling twice is a no-op.
        """
        if self._materialized:
            return

        def _leaf_ssavars(phi: Phi) -> list[SSAVar]:
            """Transitive SSAVar leaves reachable from ``phi.args``.
            Terminates on cycles via the ``seen`` set (the args DAG may
            rarely cycle under the raw SSA model; guard anyway)."""
            seen: set[Phi] = set()
            leaves: list[SSAVar] = []
            stack = [phi]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                for arg in cur.args:
                    if isinstance(arg, SSAVar):
                        leaves.append(arg)
                    elif isinstance(arg, Phi):
                        stack.append(arg)
            return leaves

        # Deterministic ordering so mat_phi indices are stable across runs.
        sorted_phis = sorted(
            self.phis.values(),
            key=lambda p: (p.file, p.line, p.kind, p.stack_index),
        )

        phi_to_mat: dict[Phi, MatPhiVar] = {}
        next_idx = 0

        # Pass A: allocate mat vars.
        #   DirectPhi: always fresh.
        #   IndirectPhi with 1 arg: alias its root's mat var (allocated
        #     earlier in the sort order if possible; otherwise deferred).
        #   IndirectPhi with >=2 args: fresh mat var — it's a true meet.
        # We do a second pass for the 1-arg indirects so their root's mat
        # is guaranteed to exist.
        for phi in sorted_phis:
            if phi.kind == "DirectPhi":
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)
            elif phi.kind == "IndirectPhi" and len(phi.args) >= 2:
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)

        # IndirectPhi with exactly 1 arg: alias if possible, else fresh.
        for phi in sorted_phis:
            if phi.kind != "IndirectPhi" or len(phi.args) != 1:
                continue
            parent = phi.args[0]
            if isinstance(parent, Phi) and parent in phi_to_mat:
                phi_to_mat[phi] = phi_to_mat[parent]
            else:
                # Defensive — shouldn't happen if the closure pass populated args.
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)

        # Pass B: insert copy assignments. For each phi with its own mat
        # var (DirectPhi or multi-arg IndirectPhi), emit `mat = leaf` at
        # every reachable SSAVar leaf's def site.
        seen_owned: set[MatPhiVar] = set()
        new_copies: list[Assignment] = []
        for phi in sorted_phis:
            mv = phi_to_mat.get(phi)
            if mv is None or mv in seen_owned:
                continue
            # Only emit copies for the phi that OWNS this mat var (first
            # occurrence in sorted order). Aliased indirects skip.
            if phi.kind == "IndirectPhi" and len(phi.args) == 1:
                # Single-arg indirect: already aliased to its parent's mat,
                # so the parent emits the copies.
                continue
            seen_owned.add(mv)
            for leaf in _leaf_ssavars(phi):
                producer = leaf.defined_by
                if producer is None:
                    continue
                copy = Assignment(
                    outputs=[mv],
                    op="=",
                    immediates="",
                    inputs=[leaf],
                    location=Location(producer.location.file, producer.location.line),
                    ast_code=f"mat_phi_{mv.index} = {leaf.identifier}",
                    const=None,
                    basic_block=producer.basic_block,
                )
                new_copies.append(copy)
                leaf.uses.append(copy)
                if producer.basic_block is not None:
                    producer.basic_block.assignments.append(copy)

        # Pass C: rewrite every Assignment's inputs — phis → mat vars.
        for a in self.assignments:
            new_inputs: list[Operand] = []
            for inp in a.inputs:
                if isinstance(inp, Phi) and inp in phi_to_mat:
                    new_inputs.append(phi_to_mat[inp])
                else:
                    new_inputs.append(inp)
            a.inputs = new_inputs

        self.assignments.extend(new_copies)
        self.assignments.sort(key=lambda a: (a.location.file, a.location.line))
        for bb in self.blocks.values():
            bb.assignments.sort(key=lambda a: a.location.line)

        # Pass D: prune the original phis. Pass C just rewrote every
        # Assignment.inputs reference from Phi to MatPhiVar, so no
        # Assignment still consumes a Phi; their only remaining incoming
        # references are within other Phi.args (the phi-of-phi DAG),
        # which becomes structurally unreachable from the program once
        # we clear self.phis and bb.phis. Python GC reclaims it.
        self.phis = {}
        for bb in self.blocks.values():
            bb.phis = []

        self._materialized = True

    # -- rendering ----------------------------------------------------------

    def functional(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
        show_ranges: bool = False,
    ) -> str:
        # Merge labels and assignments by (file, line). Labels carry no
        # SSA effect, so the ``kind`` tiebreaker (0 for label, 1 for
        # assignment) just makes labels sort above assignments at the
        # same line — matching how they appear in the source.
        items: list[tuple] = []
        for lbl_file, lbl_line, lbl_code in self.labels:
            if file is not None and lbl_file != file:
                continue
            if line_range is not None and not (line_range[0] <= lbl_line <= line_range[1]):
                continue
            items.append((lbl_file, lbl_line, 0, lbl_code))
        for a in self.assignments_in(file=file, line_range=line_range):
            items.append((a.location.file, a.location.line, 1, a))
        items.sort(key=lambda x: (x[0], x[1], x[2]))

        lines = []
        for _, line, kind, obj in items:
            if kind == 0:  # Label
                lines.append(f"L{line:>4}: {obj}")
            else:
                lines.append(
                    f"L{line:>4}: "
                    f"{obj.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
                )
        return "\n".join(lines)

    def print_functional(self, **kwargs) -> None:
        print(self.functional(**kwargs))

    def functional_by_block(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
        show_ranges: bool = False,
    ) -> str:
        """Same as :meth:`functional` but groups assignments by BB with a
        header line and predecessor/successor summary per block."""
        blocks = sorted(
            (bb for bb in self.blocks.values() if file is None or bb.file == file),
            key=lambda bb: (bb.file, bb.first_line),
        )
        out = []
        for bb in blocks:
            preds = ", ".join(f"L{p.first_line}" for p in bb.predecessors) or "-"
            succs = ", ".join(f"L{s.first_line}" for s in bb.successors) or "-"
            out.append(f"# {bb}  preds=[{preds}] succs=[{succs}]")
            for p in bb.phis:
                out.append(f"  {p.kind[0]}_{p.stack_index} = {p!r}")
            for a in bb.assignments:
                out.append(
                    f"  L{a.location.line:>4}: "
                    f"{a.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
                )
            out.append("")
        return "\n".join(out)

    # -- graph view ---------------------------------------------------------

    def data_graph(self) -> nx.MultiDiGraph:
        """Data-dependency graph over SSA objects.

        Nodes: :class:`Assignment`, :class:`SSAVar`, :class:`Phi`.
        Edges:

        - ``Assignment → SSAVar`` (``kind="def"``)
        - ``SSAVar → Assignment`` (``kind="use"``)
        - ``Phi → Assignment`` (``kind="use"``)
        - ``SSAVar → Phi`` (``kind="phi_in"``)
        - ``Phi → Phi`` (``kind="phi_in"``)
        """
        h = nx.MultiDiGraph()
        for a in self.assignments:
            h.add_node(a)
            for v in a.outputs:
                h.add_node(v)
                h.add_edge(a, v, kind="def")
            for inp in a.inputs:
                if isinstance(inp, Const):
                    continue
                h.add_node(inp)
                h.add_edge(inp, a, kind="use")
        for p in self.phis.values():
            h.add_node(p)
            for arg in p.args:
                if isinstance(arg, Const):
                    continue
                h.add_node(arg)
                h.add_edge(arg, p, kind="phi_in")
        return h

    def cfg(self) -> nx.MultiDiGraph:
        """Basic-block CFG: nodes are :class:`BasicBlock`, edges are
        ``pred → succ``. No labels beyond the structural relation;
        consult ``bb.assignments[-1]`` for branch discrimination."""
        h = nx.MultiDiGraph()
        for bb in self.blocks.values():
            h.add_node(bb)
        for bb in self.blocks.values():
            for succ in bb.successors:
                h.add_edge(bb, succ)
        return h

    # -- graphviz rendering ------------------------------------------------

    def to_dot(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        rankdir: str = "TB",
        max_lines_per_bb: int = 80,
    ) -> str:
        """Emit Graphviz DOT source: one rounded box per BB, labeled with
        entry phis + functional assignments; edges are pred→succ. Pass
        ``file`` to restrict to one source file."""

        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        def _bb_id(bb: BasicBlock) -> str:
            return f'"BB_{bb.file}_{bb.first_line}_{bb.last_line}"'

        def _bb_label(bb: BasicBlock) -> str:
            header = f"BB L{bb.first_line}-L{bb.last_line}"
            lines_out = [header]
            for phi in bb.phis:
                lines_out.append(f"  φ_{phi.stack_index}[{phi.kind[0]}] = {repr(phi)}")
            for a in bb.assignments:
                lines_out.append(f"  L{a.location.line:>4}: {a.functional(resolve_consts=resolve_consts)}")
            if len(lines_out) > max_lines_per_bb:
                elided = len(lines_out) - (max_lines_per_bb - 1)
                lines_out = lines_out[: max_lines_per_bb - 1] + [f"  ... (+{elided} more)"]
            return "\\l".join(lines_out) + "\\l"

        blocks = [
            bb for bb in self.blocks.values()
            if file is None or bb.file == file
        ]
        blocks.sort(key=lambda bb: (bb.file, bb.first_line))

        out = [
            "digraph TEAL_SSA {",
            f"  rankdir={rankdir};",
            "  overlap=false;",
            "  splines=true;",
            '  node [shape=box, fontname="Monospace", fontsize=9];',
            '  edge [fontname="Monospace", fontsize=9];',
        ]
        node_set = set(blocks)
        for bb in blocks:
            attrs = (
                f'label="{_esc(_bb_label(bb))}", '
                'style="rounded,filled", fillcolor="#f4f4f8"'
            )
            out.append(f"  {_bb_id(bb)} [{attrs}];")
        seen = set()
        for bb in blocks:
            for succ in bb.successors:
                if succ not in node_set:
                    continue
                pair = (bb, succ)
                if pair in seen:
                    continue
                seen.add(pair)
                out.append(f"  {_bb_id(bb)} -> {_bb_id(succ)};")
        out.append("}")
        return "\n".join(out)

    def draw(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        format: str = "svg",
        engine: str = "dot",
        rankdir: str = "TB",
        max_lines_per_bb: int = 80,
    ):
        """Render :meth:`to_dot` via Graphviz; returns a Jupyter-renderable
        SVG (same ``_SvgResult`` type :mod:`tealtools.graphs` uses)."""
        from .graphs import _render_dot  # reuse the same subprocess helper
        return _render_dot(
            self.to_dot(
                file=file,
                resolve_consts=resolve_consts,
                rankdir=rankdir,
                max_lines_per_bb=max_lines_per_bb,
            ),
            format=format,
            engine=engine,
        )
