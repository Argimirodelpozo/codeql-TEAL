"""Generic taint-flow framework.

A detector specifies three things and runs :class:`TaintAnalysis`:

- :class:`Source` — assignments whose outputs are seeded as tainted.
- :class:`Sink`   — assignments whose specific input is checked for
                    a tainted value at the end.
- :class:`FlowRule` — per-op decisions for how taint flows
                      (default behaviour: identity preservation
                      through stack shuffles, propagation through
                      hashes / slices / concat-with-const, BLOCK on
                      everything else).

Yields :class:`Violation` records — ``source → sink`` provenance pairs
with the tainted operand at the sink.

Consumed by:
- :mod:`tealtools.nonunique_box_key` (asset-params source → box-key sinks)
- :mod:`tealtools.box_dataflow` (external args / box reads / state writes)
- :mod:`tealtools.predicate_aware` (post-filter on any TaintAnalysis result)

Pre-materialized SSA only (phi structure is needed to track taint
across BB joins; ``materialize_phis()`` would erase it).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Union

from ..ssa import (
    Assignment,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _shuffle_mapping,
)


Operand = Union[SSAVar, Phi, Const]
TaintedOperand = Union[SSAVar, Phi]  # Const never tainted.


# ---------------------------------------------------------------------------
# Source / Sink / FlowRule descriptors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """A taint source.

    ``matches(a)`` is true for assignments that produce a tainted value.
    ``tainted_outputs(a)`` returns the 1-based output indices on that
    assignment that carry the tainted value (output 1 = topmost after
    the op runs; matches :class:`tealtools.ssa.SSAVar`'s
    ``output_index`` and CodeQL's ``getInternalOutputIndex``).
    """

    name: str
    matches: Callable[[Assignment], bool]
    tainted_outputs: Callable[[Assignment], list[int]] = field(
        default=lambda a: [1]
    )


@dataclass(frozen=True)
class Sink:
    """A taint sink.

    ``tainted_input_index(a)`` returns the 1-based stack-input position
    of the operand we want to check for taint on assignment ``a``
    (input 1 = topmost; matches ``Assignment.inputs`` top-first order).
    """

    name: str
    matches: Callable[[Assignment], bool]
    tainted_input_index: Callable[[Assignment], int]


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
# Built-in flow rules — ops that propagate taint without breaking the chain
# ---------------------------------------------------------------------------


_HASH_OPS = frozenset({"sha256", "keccak256", "sha512_256", "sha3_256"})

HASH_PROPAGATION_RULE = FlowRule(
    name="hash-of-tainted",
    matches=lambda a: a.op in _HASH_OPS,
    flows=lambda a, ti: [1] if 1 in ti else [],
)


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
    if isinstance(op, Const):
        return True
    return getattr(op, "const_value", None) is not None


def _concat_flows(a: Assignment, tainted_in: list[int]) -> Optional[list[int]]:
    """``concat A B`` propagates taint to its output iff every
    non-tainted input is statically constant (a constant prefix /
    suffix doesn't break a taint chain — same bytes flow through)."""
    if a.op != "concat":
        return None
    for i, inp in enumerate(a.inputs):
        if (i + 1) in tainted_in:
            continue
        if not _operand_is_constant(inp):
            return []
    return [1]


CONCAT_PROPAGATION_RULE = FlowRule(
    name="concat-of-tainted-and-const-or-tainted",
    matches=lambda a: a.op == "concat",
    flows=_concat_flows,
)


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
    """A tainted operand reached a sink."""

    source: Assignment
    source_name: str
    sink: Assignment
    sink_name: str
    # The exact tainted operand consumed at the sink. May be an
    # SSAVar (locally produced) or a Phi/MatPhiVar (carried across
    # BB joins). Trace ``defined_by`` / ``args`` from here to
    # reconstruct the path the value took.
    sink_operand: TaintedOperand

    def pretty(self) -> str:
        sf = self.source.location
        kf = self.sink.location
        return (
            f"{self.source_name}@{sf.file}:{sf.line}  "
            f"→  {self.sink_name}@{kf.file}:{kf.line}  "
            f"(operand = {self.sink_operand!r})"
        )

    def to_dict(self) -> dict:
        from ..serialize import assignment_ref, operand_repr
        return {
            "source": {"name": self.source_name, **assignment_ref(self.source)},
            "sink": {"name": self.sink_name, **assignment_ref(self.sink)},
            "operand": operand_repr(self.sink_operand),
        }

    def __repr__(self) -> str:
        return f"Violation({self.pretty()})"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TaintAnalysis:
    """Forward taint propagation with pluggable Source / Sink / FlowRule
    configuration.

    Construct with the (sources, sinks, rules) you want; call
    :meth:`detect` for ``list[Violation]`` or
    :meth:`tainted_operands` for the raw set (useful for diagnostics
    or downstream analyses that want their own sink semantics).

    Doesn't mutate ``prog``. Reads the structural SSA layer + the
    cached ``scratch_stores`` annotation populated by
    ``scratchInfluence.ql``. Re-running SSA passes between calls is
    safe; the next ``detect()`` will see the updated state.
    """

    def __init__(
        self,
        prog: SSAProgram,
        *,
        sources: Iterable[Source],
        sinks: Iterable[Sink],
        rules: Optional[Iterable[FlowRule]] = None,
        default_rules: Optional[Iterable[FlowRule]] = None,
    ):
        if getattr(prog, "_materialized", False):
            raise ValueError(
                "TaintAnalysis requires the pre-materialized SSA "
                "representation; this SSAProgram has had `materialize_phis()` "
                "called on it. Build a fresh SSAProgram or run this analysis "
                "before materialization."
            )
        self.prog = prog
        self.sources: list[Source] = list(sources)
        self.sinks: list[Sink] = list(sinks)
        # Custom rules consulted first (user can pre-empt defaults).
        self.rules: list[FlowRule] = list(rules) if rules is not None else []
        # Built-in propagation through hash / slice / concat-with-const.
        # Pass ``default_rules=[]`` to disable them, or a custom list to
        # subset.
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
                idx = sink.tainted_input_index(a)
                if idx < 1 or idx > len(a.inputs):
                    continue
                op = a.inputs[idx - 1]
                if isinstance(op, Const) or op not in tainted:
                    continue
                source_a, source_name = source_for[op]
                violations.append(Violation(
                    source=source_a,
                    source_name=source_name,
                    sink=a,
                    sink_name=sink.name,
                    sink_operand=op,
                ))
        return violations

    def tainted_operands(self) -> set[TaintedOperand]:
        """Diagnostic hook: full set of operands the propagation
        marked as tainted. Useful for inspecting why a sink was
        (or wasn't) flagged."""
        tainted, _ = self._compute_taint()
        return tainted

    # -- core -----------------------------------------------------------

    def _compute_taint(
        self,
    ) -> tuple[set[TaintedOperand], dict[TaintedOperand, tuple[Assignment, str]]]:
        tainted: set[TaintedOperand] = set()
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
            # 2a. Through assignments.
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
            # 2b. Through phis. Any tainted arg taints the phi.
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
            # 2c. Through scratch (store/load via scratch_stores annotation).
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

        1. User rules (``self.rules``) — pre-empt anything.
        2. Built-in defaults (``self.default_rules``) — hash / slice /
           concat-with-const.
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
        mapping = _shuffle_mapping(a)
        if mapping is not None:
            return [
                out_idx + 1
                for out_idx, in_idx in enumerate(mapping)
                if (in_idx + 1) in tainted_input_indices
            ]
        return []
