"""Detect non-unique external field values flowing into box keys.

A box's address space is keyed by an arbitrary byte string. If a contract
uses a *non-unique* external field (an ASA's ``AssetName`` is the canonical
example — multiple ASAs may share a name) as the box key without mixing
in something distinguishing, two different real-world entities collide
on the same box. The mistake usually surfaces as silent data overwrites.

Detector
--------

Forward taint propagation on top of :class:`teal_ssa.SSAProgram`:

    1. **Sources.** SSAVars produced by an opcode that returns a
       non-unique external field (default: ``asset_params_get
       AssetName``'s value output) are seeded as tainted.

    2. **Propagation.** A taint flows through identity-preserving ops
       only — stack shuffles via :func:`teal_ssa._shuffle_mapping`,
       phi joins (any tainted arg taints the phi), and scratch
       passthrough (``store N`` / ``load N`` reading via the cached
       ``scratch_stores`` graph annotation). Anything else
       (``concat``, ``sha256``, arithmetic, ...) blocks taint by
       default.

    3. **Sinks.** A :class:`Violation` is reported when the box-key
       input of a sink op (default: ``box_create`` / ``box_put``) is
       a tainted operand.

Extension
---------

Pluggable :class:`Source`, :class:`Sink`, and :class:`FlowRule` types
let analysts add fields, sinks, or per-op rules without touching the
detector. The defaults are exposed as :data:`DEFAULT_SOURCES` /
:data:`DEFAULT_SINKS` so callers can append rather than replace.

A :class:`FlowRule` can override the default block-non-shuffle
behaviour for any op — e.g. propagate taint through ``concat`` only
when the other operand is a known constant prefix (which doesn't add
distinguishing entropy and so the result is still a collision risk).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Union

from teal_ssa import (
    Assignment,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _shuffle_mapping,
)

# Pre-materialized SSA only: see ``NonUniqueBoxKeyDetector`` for the
# precondition — phi structure is needed to track taint across BB
# joins, and ``materialize_phis`` destroys it.
Operand = Union[SSAVar, Phi, Const]
TaintedOperand = Union[SSAVar, Phi]  # Const never tainted.


# ---------------------------------------------------------------------------
# Source / Sink / FlowRule descriptors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """A non-unique external field source.

    ``matches(a)`` is true for assignments that produce this kind of
    value. ``tainted_outputs(a)`` returns the 1-based output indices on
    that assignment that carry the non-unique value (output 1 = topmost
    after the op runs; matches :class:`teal_ssa.SSAVar`'s
    ``output_index`` and CodeQL's ``getInternalOutputIndex``).
    """

    name: str
    matches: Callable[[Assignment], bool]
    tainted_outputs: Callable[[Assignment], list[int]] = field(
        default=lambda a: [1]
    )


@dataclass(frozen=True)
class Sink:
    """A box-key sink.

    ``key_input_index(a)`` returns the 1-based stack-input position of
    the box key on assignment ``a`` (input 1 = topmost; matches
    :class:`teal_ssa.Assignment`'s top-first ``inputs``).
    """

    name: str
    matches: Callable[[Assignment], bool]
    key_input_index: Callable[[Assignment], int]


@dataclass(frozen=True)
class FlowRule:
    """Custom per-op decision for how taint flows.

    ``flows(a, tainted_input_indices)`` returns:
        - ``None`` to abstain (default rules apply),
        - ``[]`` to block (no output is tainted),
        - a list of 1-based output indices that should be tainted.

    Rules are consulted in registration order; first non-``None``
    answer wins. Defaults are applied last.
    """

    name: str
    matches: Callable[[Assignment], bool]
    flows: Callable[[Assignment, list[int]], Optional[list[int]]]


# ---------------------------------------------------------------------------
# Built-in sources / sinks
# ---------------------------------------------------------------------------


def _is_asset_params_get(a: Assignment, field_name: str) -> bool:
    return (
        a.op == "asset_params_get"
        and a.immediates.strip().split()[:1] == [field_name]
    )


# ``asset_params_get F``: consumes 1 (asset id), produces 2 (value, did_exist).
# By the SSA model's top-first output convention, ``outputs[0]`` (output_index=1)
# is the topmost — that's ``did_exist``. The actual field value sits at
# ``outputs[1]`` (output_index=2). The detector taints the value, never the flag.
ASSET_PARAMS_NAME_SOURCE = Source(
    name="asset_params_get AssetName",
    matches=lambda a: _is_asset_params_get(a, "AssetName"),
    tainted_outputs=lambda a: [2],
)


# Box ops are stack-bottom-keyed: the key sits *below* the other args
# because it was pushed first. By top-first convention this means the
# key has the largest input index.
#
# - ``box_create key length``  → top: length (1), key: 2.
# - ``box_put key value``      → top: value (1), key: 2.
BOX_CREATE_SINK = Sink(
    name="box_create",
    matches=lambda a: a.op == "box_create",
    key_input_index=lambda a: 2,
)
BOX_PUT_SINK = Sink(
    name="box_put",
    matches=lambda a: a.op == "box_put",
    key_input_index=lambda a: 2,
)


# ---------------------------------------------------------------------------
# Built-in flow rules — ops that do NOT add distinguishing entropy
# ---------------------------------------------------------------------------
#
# Each rule below extends taint through an op family that produces a
# value deterministically derived from a non-unique input. Same input
# bytes always yield the same output bytes, so two real-world entities
# colliding on the source (two ASAs sharing a name) still collide on
# the result. These rules run AFTER user-supplied rules — users can
# pre-empt any of them by registering a custom rule for the same op.


_HASH_OPS = frozenset({"sha256", "keccak256", "sha512_256", "sha3_256"})

HASH_PROPAGATION_RULE = FlowRule(
    name="hash-of-tainted",
    matches=lambda a: a.op in _HASH_OPS,
    # Hashes are 1-input, 1-output and pure deterministic functions.
    # Tainted bytes in → tainted hash out. Empty list when not tainted
    # is fine because the detector only invokes this rule for
    # assignments that have at least one tainted input.
    flows=lambda a, ti: [1] if 1 in ti else [],
)


# Slice ops — extract / substring family. The bytes input is always
# the deepest (highest stack-input ord). A slice of a non-unique field
# is *more* collision-prone than the field itself (less entropy),
# never less. Other inputs (start, length, position) don't carry the
# value — only the bytes input matters for taint.
_SLICE_OPS = frozenset({
    "extract", "extract3",
    "extract_uint16", "extract_uint32", "extract_uint64",
    "substring", "substring3",
})

SLICE_PROPAGATION_RULE = FlowRule(
    name="slice-of-tainted",
    matches=lambda a: a.op in _SLICE_OPS,
    flows=lambda a, ti: [1] if len(a.inputs) in ti else [],
)


def _operand_is_constant(op) -> bool:
    """True if ``op`` is statically a known constant.

    Two shapes count:

    - ``Const`` itself — only appears after :meth:`SSAProgram.
      eliminate_dead_constants` rewrites consumers to read the literal
      directly.
    - An operand (``SSAVar`` / ``Phi`` / ``MatPhiVar``) whose
      ``const_value`` is set. ``SSAProgram.__init__`` seeds this from
      the ``constValues.ql`` / ``mustValues.ql`` data on every literal
      pusher (``pushbytes``, ``pushint``, ``intc_*``, ``bytec_*``,
      ``int``), so simple cases work without running any propagation
      pass. ``propagate_constants`` extends this to phis and
      identity-preserving flow steps.
    """
    if isinstance(op, Const):
        return True
    return getattr(op, "const_value", None) is not None


def _concat_flows(a: Assignment, tainted_in: list[int]) -> Optional[list[int]]:
    """``concat A B`` → ``A ++ B``.

    Propagate taint to the (sole) output if every non-tainted input is
    statically constant. Two important cases this captures:

    1. **concat with a constant prefix/suffix.** ``concat("asset_", N)``
       still collides for two ASAs named ``N`` — the prefix carries
       no per-asset entropy.
    2. **concat of two non-unique fields.** ``concat(unit_name, name)``
       is non-unique iff *both* operands can collide — which they
       can if both are tainted (potentially from different sources,
       potentially the same source twice).

    Anything else — a dynamic, non-tainted operand (asset id, sender,
    txn arg, etc.) — adds enough entropy to disambiguate, so we BLOCK.
    """
    if a.op != "concat":
        return None
    for i, inp in enumerate(a.inputs):
        if (i + 1) in tainted_in:
            continue
        if not _operand_is_constant(inp):
            return []  # dynamic non-tainted operand → distinguishes
    return [1]


CONCAT_PROPAGATION_RULE = FlowRule(
    name="concat-of-tainted-and-const-or-tainted",
    matches=lambda a: a.op == "concat",
    flows=_concat_flows,
)


DEFAULT_SOURCES: list[Source] = [ASSET_PARAMS_NAME_SOURCE]
DEFAULT_SINKS: list[Sink] = [BOX_CREATE_SINK, BOX_PUT_SINK]
DEFAULT_RULES: list[FlowRule] = [
    HASH_PROPAGATION_RULE,
    SLICE_PROPAGATION_RULE,
    CONCAT_PROPAGATION_RULE,
]


# ---------------------------------------------------------------------------
# Violation
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    """A non-unique field reached a box-key sink."""

    source: Assignment
    source_name: str
    sink: Assignment
    sink_name: str
    # The exact tainted operand consumed at the sink's key position.
    # May be an SSAVar (locally produced) or a Phi/MatPhiVar (carried
    # across BB joins). Trace ``defined_by`` / ``args`` from here to
    # reconstruct the path the value took.
    sink_key_operand: TaintedOperand

    def pretty(self) -> str:
        sf = self.source.location
        kf = self.sink.location
        return (
            f"{self.source_name}@{sf.file}:{sf.line}  "
            f"→  {self.sink_name}@{kf.file}:{kf.line}  "
            f"(key = {self.sink_key_operand!r})"
        )

    def __repr__(self) -> str:
        return f"Violation({self.pretty()})"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class NonUniqueBoxKeyDetector:
    """Detects non-unique external fields flowing into box keys.

    Construct with optional custom :class:`Source` / :class:`Sink` /
    :class:`FlowRule` lists; otherwise uses the defaults above.

        det = NonUniqueBoxKeyDetector(prog)
        for v in det.detect():
            print(v.pretty())

    The detector does NOT mutate ``prog``. It reads only the structural
    SSA layer + the cached ``scratch_stores`` annotation from
    ``prog._graph`` (populated by ``scratchInfluence.ql``). Re-running
    SSA passes after construction is safe; the next ``detect()`` call
    will see the updated state.
    """

    def __init__(
        self,
        prog: SSAProgram,
        *,
        sources: Optional[Iterable[Source]] = None,
        sinks: Optional[Iterable[Sink]] = None,
        rules: Optional[Iterable[FlowRule]] = None,
        default_rules: Optional[Iterable[FlowRule]] = None,
    ):
        # Operates on the pre-materialized SSA. ``materialize_phis``
        # rewrites consumers from Phi → MatPhiVar references and emits
        # ``mat_phi_k = leaf`` copy assignments at every leaf def
        # site, after which the propagation loop here would silently
        # miss the BB-join taint flow (phis carry no .args anymore).
        # Build a fresh SSAProgram for this detector if you've already
        # called ``materialize_phis`` for some other downstream use.
        if getattr(prog, "_materialized", False):
            raise ValueError(
                "NonUniqueBoxKeyDetector requires the pre-materialized SSA "
                "representation; this SSAProgram has had `materialize_phis()` "
                "called on it. Build a fresh SSAProgram or run this analysis "
                "before materialization."
            )
        # ``eliminate_dead_constants`` is intentionally NOT a precondition.
        # Tainted SSAVars descend from ``asset_params_get`` outputs which
        # have no ``const_value`` (runtime field) and therefore never
        # become candidates for dead elimination — they survive the
        # pass. Their consumers' OTHER inputs may get rewritten from
        # SSAVar references to bare ``Const`` literals, which the
        # propagation loop handles correctly (``Const`` is never tainted
        # and the concat-with-const built-in already accepts both
        # ``isinstance(op, Const)`` and ``op.const_value is not None``).
        # The detector is therefore robust to dead elimination.
        self.prog = prog
        self.sources: list[Source] = (
            list(sources) if sources is not None else list(DEFAULT_SOURCES)
        )
        self.sinks: list[Sink] = (
            list(sinks) if sinks is not None else list(DEFAULT_SINKS)
        )
        # Custom rules consulted first (user can pre-empt defaults).
        self.rules: list[FlowRule] = list(rules) if rules is not None else []
        # Built-in propagation through hash / slice / concat-with-const.
        # Pass ``default_rules=[]`` to disable them, or a custom list
        # to subset (e.g. ``default_rules=[HASH_PROPAGATION_RULE]`` to
        # keep only hash propagation).
        self.default_rules: list[FlowRule] = (
            list(default_rules) if default_rules is not None else list(DEFAULT_RULES)
        )

    # -- public ---------------------------------------------------------

    def detect(self) -> list[Violation]:
        tainted, source_for = self._compute_taint()
        violations: list[Violation] = []
        for a in self.prog.assignments:
            for sink in self.sinks:
                if not sink.matches(a):
                    continue
                key_idx = sink.key_input_index(a)
                if key_idx < 1 or key_idx > len(a.inputs):
                    continue  # malformed input shape — defensively skip.
                key_op = a.inputs[key_idx - 1]
                if isinstance(key_op, Const) or key_op not in tainted:
                    continue
                source_a, source_name = source_for[key_op]
                violations.append(
                    Violation(
                        source=source_a,
                        source_name=source_name,
                        sink=a,
                        sink_name=sink.name,
                        sink_key_operand=key_op,
                    )
                )
        return violations

    def tainted_operands(self) -> set[TaintedOperand]:
        """Diagnostic hook: full set of operands the propagation
        marked as carrying a non-unique field's value. Useful for
        inspecting *why* a sink was (or wasn't) flagged."""
        tainted, _ = self._compute_taint()
        return tainted

    # -- core -----------------------------------------------------------

    def _compute_taint(
        self,
    ) -> tuple[set[TaintedOperand], dict[TaintedOperand, tuple[Assignment, str]]]:
        """Forward-propagate taint to a fixed point.

        Returns ``(tainted_set, source_for)`` where ``source_for`` maps
        each tainted operand to the originating ``(source_assignment,
        source_name)`` — reused when building :class:`Violation`s so
        we can name the field that started the chain.
        """
        tainted: set[TaintedOperand] = set()
        # Track which source each tainted operand traces back to. When
        # multiple sources reach the same operand we keep the first
        # one seen — the violation mostly cares "is this tainted",
        # less about which of N possible sources is canonical.
        source_for: dict[TaintedOperand, tuple[Assignment, str]] = {}

        # Step 1: seed from sources.
        for a in self.prog.assignments:
            for src in self.sources:
                if not src.matches(a):
                    continue
                for out_idx in src.tainted_outputs(a):
                    if not (1 <= out_idx <= len(a.outputs)):
                        continue
                    v = a.outputs[out_idx - 1]
                    if isinstance(v, Const):
                        continue
                    if v not in tainted:
                        tainted.add(v)
                        source_for[v] = (a, src.name)

        # Step 2: fixpoint propagation.
        changed = True
        while changed:
            changed = False
            # 2a. Propagate through assignments.
            for a in self.prog.assignments:
                tainted_in_idx = [
                    i + 1
                    for i, x in enumerate(a.inputs)
                    if not isinstance(x, Const) and x in tainted
                ]
                if not tainted_in_idx:
                    continue
                out_idxs = self._decide_flow(a, tainted_in_idx)
                if not out_idxs:
                    continue
                # Pick the first tainted input as the provenance source
                # for any newly-tainted output. This is a heuristic but
                # keeps :class:`Violation` reporting deterministic.
                provenance = source_for[a.inputs[tainted_in_idx[0] - 1]]
                for out_idx in out_idxs:
                    if not (1 <= out_idx <= len(a.outputs)):
                        continue
                    v = a.outputs[out_idx - 1]
                    if isinstance(v, Const) or v in tainted:
                        continue
                    tainted.add(v)
                    source_for[v] = provenance
                    changed = True
            # 2b. Propagate through phis. Any tainted arg taints the phi —
            # a phi just witnesses one of N path values reaching this BB,
            # and if any path carries the non-unique field the merged
            # operand is also tainted (its consumers can see that value
            # at runtime).
            for ph in self.prog.phis.values():
                if ph in tainted:
                    continue
                for arg in ph.args:
                    if isinstance(arg, Const):
                        continue
                    if arg in tainted:
                        tainted.add(ph)
                        source_for[ph] = source_for[arg]
                        changed = True
                        break
            # 2c. Propagate through scratch. ``scratch_stores`` on a
            # ``load`` op is the SSAVar list of every store that may
            # influence this load; if any is tainted the load's output
            # picks up the taint.
            for n in self.prog._graph.nodes:
                stores = self.prog._graph.nodes[n].get("scratch_stores")
                if not stores:
                    continue
                load_var = self.prog.var(
                    n.location.file, n.location.start_line, 1
                )
                if load_var is None or load_var in tainted:
                    continue
                for sv_file, sv_line, sv_idx in stores:
                    src_var = self.prog.var(sv_file, sv_line, sv_idx)
                    if src_var is not None and src_var in tainted:
                        tainted.add(load_var)
                        source_for[load_var] = source_for[src_var]
                        changed = True
                        break
        return tainted, source_for

    def _decide_flow(
        self, a: Assignment, tainted_input_indices: list[int]
    ) -> list[int]:
        """Resolution order:

        1. User-supplied rules (``self.rules``) — pre-empt anything.
        2. Built-in defaults (``self.default_rules``) — hash / slice /
           concat-with-const, propagating through ops that don't add
           distinguishing entropy.
        3. Pure stack shuffles via ``_shuffle_mapping``.
        4. BLOCK.

        First non-``None`` decision wins.
        """
        for rule_list in (self.rules, self.default_rules):
            for rule in rule_list:
                if not rule.matches(a):
                    continue
                decision = rule.flows(a, list(tainted_input_indices))
                if decision is not None:
                    return list(decision)
        # Pure stack shuffles. ``_shuffle_mapping`` returns ``m`` such
        # that ``outputs[i] = inputs[m[i]]`` (0-based on both sides).
        # An output is tainted iff its source input is.
        mapping = _shuffle_mapping(a)
        if mapping is not None:
            return [
                out_idx + 1
                for out_idx, in_idx in enumerate(mapping)
                if (in_idx + 1) in tainted_input_indices
            ]
        # Arithmetic, ``btoi``, etc. fall through to BLOCK.
        return []
