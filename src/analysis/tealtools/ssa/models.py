"""Typed SSA-assignment representation of a TEAL program.

Built on top of :mod:`tealtools.graph`. Where
``tealtools.graph`` exposes a low-level ``MultiDiGraph`` keyed by AST nodes,
this module presents the same information as a first-class *program*
object: a sequence of :class:`Assignment`\\ s grouped into
:class:`BasicBlock`\\ s, referring to :class:`SSAVar`\\ s, :class:`Phi`\\ s,
and :class:`Const` literals.

    from tealtools.ssa import SSAProgram
    p = SSAProgram("approval.teal")
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
the underlying model emits many unreferenced phi identities.

The module performs no extraction itself — it calls
:func:`tealtools.graph.load_graph` and reads the populated node attributes.
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
    """A stack variable produced by one opcode.

    Identity is ``(file, line, index)``; the textual form is
    ``V#{index}@L{line}``.
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

    def _short(self) -> str:
        tag = "φ" if self.kind == "DirectPhi" else "φᵢ"
        return f"{tag}_{self.stack_index}@L{self.line}"

    def __repr__(self) -> str:
        # Iterative DFS with cycle protection and a visited-node cap.
        # PySSA's unified PyPhi can have cyclic phi-arg graphs AND chains
        # of ~1000 phis at constant-stack CFG loops. The naive recursive
        # form blows the Python recursion limit; full expansion of a deep
        # graph blows memory. Iterative DFS handles recursion; a
        # ``_REPR_NODE_CAP`` short-renders after visiting that many phis
        # to keep output bounded. Output identical to the naive form on
        # acyclic graphs below the cap.
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


Operand = Union[SSAVar, Phi, Const]


@dataclass(eq=False)
class Assignment:
    """``outputs = op immediates (inputs)`` — one TEAL opcode's SSA form."""

    outputs: list[SSAVar]
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

    ``exit_stack`` is the operand in each stack slot at the BB's exit,
    **bottom-first** (index 0 = bottom of stack, last = top), with
    ``None`` for a slot whose value is dead. Each entry is an
    :class:`SSAVar` or :class:`Phi`. It is surfaced verbatim from PySSA
    construction (the per-edge value a successor's phi reads on this
    edge) so out-of-SSA / block-argument lowering has the per-edge
    values that ``Phi.args`` (a dedup'd value-set) no longer carries.
    Empty unless construction populated it.
    """

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


# -------------------------------------------------------------------------


_CONST_BLOCK_REF_NAMES = frozenset({
    # constblock references
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
    # inline-literal pushers (carry their literal in immediates; the
    # resolved-constant table already emits values for them, so
    # propagation reads through naturally).
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
        # isqrt of any uint64 never exceeds 2^32 - 1, regardless of input.
        "sqrt":   ("uint64", 0, 0xFFFFFFFF),
        # length ops bounded by AVM stack-bytes cap (4096 bytes)
        "len":    ("uint64", 0, 4096),
        "bitlen": ("uint64", 0, 4096 * 8),
    }

_OP_RANGE_SEEDS = _build_op_range_seeds()

# Bounded enum / count fields for txn-family / global field reads. Values
# track the AVM consensus spec: OnCompletion in {0..5}, TypeEnum in {0..6}
# (unknown..appl), GroupIndex 0-based with max group size 16, GroupSize ≥ 1.
# The Num* fields are array lengths capped by the per-txn reference limits
# (MaxAppArgs 16, accounts 4, foreign assets/apps 8, logs 32); the schema
# counts by MaxGlobalSchemaEntries 64 / MaxLocalSchemaEntries 16; asset
# decimals at 19; extra program pages at 3. Each bound is the *sound* upper
# limit for the field read in isolation (a too-tight cap would be unsound).
_TXN_FIELD_RANGES: dict = {
    "OnCompletion":        (0, 5),
    "TypeEnum":            (0, 6),
    "GroupIndex":          (0, 15),
    # Reference-array lengths.
    "NumAppArgs":          (0, 16),
    "NumAccounts":         (0, 4),
    "NumAssets":           (0, 8),
    "NumApplications":     (0, 8),
    "NumLogs":             (0, 32),
    # State-schema entry counts.
    "GlobalNumUint":       (0, 64),
    "GlobalNumByteSlice":  (0, 64),
    "LocalNumUint":        (0, 16),
    "LocalNumByteSlice":   (0, 16),
    # Other spec-capped scalars.
    "ExtraProgramPages":   (0, 3),
    "ConfigAssetDecimals": (0, 19),
}
_GLOBAL_FIELD_RANGES: dict = {
    "GroupSize": (1, 16),
}

# Positional output range seeds for multi-output ops, top-first:
# ``op -> [(output_index, lo, hi), …]``. The ``*_get`` / ``*_ex`` family
# pushes a 0/1 "exists / found" flag as its top output (``outputs[0]``) —
# the value most often fed to ``assert`` / ``bz`` / ``bnz`` — which the
# single-output ``_OP_RANGE_SEEDS`` path can't reach. ``box_len`` also
# bounds its length output (``outputs[1]``) by the 32768-byte max box size.
# ``addw`` pushes ``(high, low)`` with low on top, so its high word
# (``outputs[1]``) is the carry of a 64+64-bit add — always 0 or 1.
# ``vrf_verify`` pushes ``(output, verified)`` with the 0/1 verified flag
# on top (its 64-byte output length is seeded in ``_OP_OUTPUT_BYTELEN``).
_OP_OUTPUT_SEEDS: dict = {
    "asset_params_get":  [(0, 0, 1)],
    "app_params_get":    [(0, 0, 1)],
    "acct_params_get":   [(0, 0, 1)],
    "app_global_get_ex": [(0, 0, 1)],
    "app_local_get_ex":  [(0, 0, 1)],
    "box_get":           [(0, 0, 1)],
    "box_len":           [(0, 0, 1), (1, 0, 32768)],
    "addw":              [(1, 0, 1)],
    "vrf_verify":        [(0, 0, 1)],
}

# Static byte_length seeds, consumed by ``passes/byte_length_prop``.
#
# ``_TXN_FIELD_BYTELEN`` / ``_GLOBAL_FIELD_BYTELEN`` — txn-family / global
# field reads whose output is a fixed-width bytes value: 32-byte addresses
# and the participation keys (StateProofPK is 64). ``_OP_OUTPUT_BYTELEN``
# — positional fixed lengths on multi-output crypto ops, top-first
# (``op -> [(output_index, byte_length), …]``).
_TXN_FIELD_BYTELEN: dict = {
    # 32-byte addresses.
    "Sender":              32,
    "Receiver":            32,
    "CloseRemainderTo":    32,
    "RekeyTo":             32,
    "AssetSender":         32,
    "AssetReceiver":       32,
    "AssetCloseTo":        32,
    "FreezeAssetAccount":  32,
    "ConfigAssetManager":  32,
    "ConfigAssetReserve":  32,
    "ConfigAssetFreeze":   32,
    "ConfigAssetClawback": 32,
    # Fixed-width keys / lease.
    "Lease":               32,
    "VotePK":              32,
    "SelectionPK":         32,
    "StateProofPK":        64,
    # Array-element address (read via ``txna``/``gtxnsa``/… ``Accounts i``).
    "Accounts":            32,
}
_GLOBAL_FIELD_BYTELEN: dict = {
    "ZeroAddress":              32,
    "CreatorAddress":           32,
    "CurrentApplicationAddress": 32,
    "CallerApplicationAddress": 32,
}
_OP_OUTPUT_BYTELEN: dict = {
    # ecdsa pubkey ops push two 32-byte words (X, Y).
    "ecdsa_pk_decompress": [(0, 32), (1, 32)],
    "ecdsa_pk_recover":    [(0, 32), (1, 32)],
    # vrf_verify's non-flag output (outputs[1]) is the 64-byte VRF output.
    "vrf_verify":          [(1, 64)],
}

# ``asset_params_get`` / ``app_params_get`` / ``acct_params_get`` push
# ``(value, exists)`` — the 0/1 exists flag (``outputs[0]``) is seeded by
# ``_OP_OUTPUT_SEEDS``; the *value* (``outputs[1]``) is keyed by the field
# immediate here. Field names are globally unique (Asset*/App*/Acct*), so a
# single flat table per kind is unambiguous. Range fields are bounded scalars
# / booleans; byte-length fields are 32-byte addresses + the metadata hash.
_PARAMS_OPS: frozenset = frozenset({
    "asset_params_get", "app_params_get", "acct_params_get",
})
_PARAMS_VALUE_RANGES: dict = {
    "AssetDecimals":        (0, 19),
    "AssetDefaultFrozen":   (0, 1),
    "AppExtraProgramPages": (0, 3),
    "AppGlobalNumUint":      (0, 64),
    "AppGlobalNumByteSlice": (0, 64),
    "AppLocalNumUint":       (0, 16),
    "AppLocalNumByteSlice":  (0, 16),
    "AcctIncentiveEligible": (0, 1),
}
_PARAMS_VALUE_BYTELEN: dict = {
    "AssetManager":      32,
    "AssetReserve":      32,
    "AssetFreeze":       32,
    "AssetClawback":     32,
    "AssetCreator":      32,
    "AssetMetadataHash": 32,
    "AppCreator":        32,
    "AppAddress":        32,
    "AcctAuthAddr":      32,
}

# Field-immediate position for every txn-family field-reading op. The field
# name is the *first* immediate for current-txn / stack-group forms, and the
# *second* (after the immediate group index) for the ``gtxn``/``gitxn``
# group-indexed forms. One helper unifies field extraction across the range,
# byte-length and any future field-keyed seeding (so the inner-txn ``itxna`` /
# ``gitxn*`` and stack-group ``gtxnsa`` / ``gtxnsas`` forms are covered too).
_FIELD_OPS_POS0: frozenset = frozenset({
    "txn", "txna", "gtxns", "gtxnsa", "gtxnsas", "itxn", "itxna",
})
_FIELD_OPS_POS1: frozenset = frozenset({
    "gtxn", "gtxna", "gtxnas", "gitxn", "gitxna", "gitxnas",
})


def _txn_field_name(op: str, toks: list) -> Optional[str]:
    """The field-name immediate of a txn-family field read, or ``None``
    when ``op`` doesn't read a named field (or its immediates are absent).
    ``toks`` is ``immediates.split()``."""
    if op in _FIELD_OPS_POS0 and toks:
        return toks[0]
    if op in _FIELD_OPS_POS1 and len(toks) >= 2:
        return toks[1]
    return None


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
    are the topmost stack value (a 1-based stack position where 1 = top
    consumed); the deepest consumed/produced value sits at index
    ``n - 1``. The SSAVar identity convention agrees: ``output_index 1``
    ranks first by stack order (i.e. is the topmost output).
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


def _canon_shuffle(op: str, immediates: str):
    """``(n_in, mapping)`` for a FIXED-arity stack shuffle from its CANONICAL
    arity, independent of a possibly fat-band-clamped ``Assignment.inputs``.

    The resim re-simulates the stack on a clean depth, but :func:`_shuffle_mapping`
    keys off ``len(a.inputs)`` -- which the SSA's fat-band sim can UNDER-count when
    its model stack was shallow at the op (e.g. ``dup2`` recorded with 1 input, so
    ``_shuffle_mapping`` defensively returns ``None`` and the resim drops the op,
    losing stack depth that then starves a downstream callsub's args). Computing the
    effect from the op's true arity fixes that. Excludes ``frame_dig`` /
    ``frame_bury`` (genuinely band-dependent, handled separately). Returns
    ``(None, None)`` when ``op`` isn't a fixed-arity shuffle."""
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
        return (n + 1, list(range(1, n)) + [0])
    return (None, None)


