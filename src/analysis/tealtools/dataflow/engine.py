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
- ``src/security/detections/box-key/`` (asset-params source → box-key sinks)
- :mod:`tealtools.dataflow.box` (external args / box reads / state writes)
- :mod:`tealtools.dataflow.predicate_aware` (post-filter on any result)

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
    is_const,
)
from ..passes.frame_flow import frame_param_sources


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
    ``output_index``).
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
    # getbyte reads a byte out of the value (bytes -> scalar); the byte it
    # returns is part of the tainted value, so taint flows. Same operand shape
    # as the extract family: the value is the bottom (highest-index) input.
    "getbyte",
})

SLICE_PROPAGATION_RULE = FlowRule(
    name="slice-of-tainted",
    matches=lambda a: a.op in _SLICE_OPS,
    flows=lambda a, ti: [1] if len(a.inputs) in ti else [],
)


# itob / btoi re-encode the SAME value between uint64 and bytes — taint passes
# straight through (a tainted scalar `itob`'d into a box key is still attacker-
# influenced). Single input, single output.
_TRANSCODE_OPS = frozenset({"itob", "btoi"})

TRANSCODE_PROPAGATION_RULE = FlowRule(
    name="transcode-of-tainted",
    matches=lambda a: a.op in _TRANSCODE_OPS,
    flows=lambda a, ti: [1] if 1 in ti else [],
)


def _concat_flows(a: Assignment, tainted_in: list[int]) -> Optional[list[int]]:
    """``concat A B`` propagates taint to its output iff every
    non-tainted input is statically constant (a constant prefix /
    suffix doesn't break a taint chain — same bytes flow through)."""
    if a.op != "concat":
        return None
    for i, inp in enumerate(a.inputs):
        if (i + 1) in tainted_in:
            continue
        if not is_const(inp):
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
    TRANSCODE_PROPAGATION_RULE,
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
    # SSAVar (locally produced) or a Phi (carried across
    # BB joins). Trace ``defined_by`` / ``args`` from here to
    # reconstruct the path the value took.
    sink_operand: TaintedOperand

    def pretty(self) -> str:
        return (
            f"{self.source_name}@{self.source.location}  "
            f"→  {self.sink_name}@{self.sink.location}  "
            f"(operand = {self.sink_operand!r})"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref, operand_repr
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
    cached ``scratch_stores`` annotation from the scratch-influence
    pass. Re-running SSA passes between calls is
    safe; the next ``detect()`` will see the updated state.

    ``file`` scopes the analysis to a single source file: source
    seeding and sink reporting only consider assignments in that
    file. Since each ``.teal`` is an independent program (no SSAVars
    shared across files), this isolates one program inside a
    multi-file DB — the shape ``scan`` relies on.
    """

    def __init__(
        self,
        prog: SSAProgram,
        *,
        sources: Iterable[Source],
        sinks: Iterable[Sink],
        rules: Optional[Iterable[FlowRule]] = None,
        default_rules: Optional[Iterable[FlowRule]] = None,
        file: Optional[str] = None,
        cross_state: bool = False,
    ):
        self.prog = prog
        self.file = file
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
        # Opt-in: also carry taint through an application-global-state roundtrip
        # (`app_global_put` value -> `app_global_get` of the same key). Off by
        # default (most detectors don't want state to be a taint conduit); the
        # box-key detector enables it to catch a non-unique value laundered
        # through state before becoming a box key.
        self.cross_state = cross_state

    # -- public ---------------------------------------------------------

    def _in_scope(self, a: Assignment) -> bool:
        """True if ``a`` belongs to the file this analysis is scoped to
        (or no ``file`` scope was set)."""
        return self.file is None or a.location.file == self.file

    def detect(self) -> list[Violation]:
        tainted, source_for = self._compute_taint()
        violations: list[Violation] = []
        for a in self.prog.assignments:
            if not self._in_scope(a):
                continue
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
        # This engine reads ``const_value`` (concat-with-const / cross-state
        # rules via ``is_const`` / ``operand_const``) and the ``scratch_stores``
        # annotation WITHOUT running ``propagate_constants`` — it relies on the
        # const seeds SSA construction used to set eagerly (now lazy). Trigger
        # ``_ensure_identity_steps`` (which also ensures scratch influence): it
        # restores EXACTLY those shuffle-passthrough + scratch const seeds and
        # nothing more, so the taint result is unchanged. (``propagate_constants``
        # would seed additional phi/fold consts and change behaviour.)
        self.prog._ensure_identity_steps()
        tainted: set[TaintedOperand] = set()
        source_for: dict[TaintedOperand, tuple[Assignment, str]] = {}

        # Step 1: seed from sources. Scoped to ``self.file`` so a
        # multi-file DB only seeds the program under analysis; taint
        # then can't reach another file because SSAVars aren't shared
        # across programs.
        for a in self.prog.assignments:
            if not self._in_scope(a):
                continue
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

        # Interprocedural frame edges (callee param <- the caller args bound to
        # it), so taint crosses the callsub/proto boundary natively — the base
        # def-use leaves frame_dig disconnected. See passes.frame_flow.
        frame_src = frame_param_sources(self.prog)

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
            # 2d. Through frame params (callee param <- caller args).
            for dig_out, args in frame_src.items():
                if dig_out in tainted:
                    continue
                for arg in args:
                    if not isinstance(arg, Const) and arg in tainted:
                        tainted.add(dig_out)
                        source_for[dig_out] = source_for[arg]
                        changed = True
                        break
            # 2e. Through application-global state (opt-in): a value written by
            # `app_global_put` re-emerges tainted from `app_global_get` of the
            # same key. Key-aware where both keys are static constants; otherwise
            # conservative (any tainted put may reach the get). A realistic
            # laundering path the def-use relation can't see.
            if self.cross_state:
                changed = self._propagate_state(tainted, source_for) or changed
        return tainted, source_for

    def _propagate_state(self, tainted: set, source_for: dict) -> bool:
        """One round of the app-global-state taint bridge. Returns whether any
        new value became tainted."""
        from ..ssa import operand_const
        puts: list = []   # (key_const_or_None, value_var)
        for a in self.prog.assignments:
            if a.op == "app_global_put" and len(a.inputs) >= 2 and self._in_scope(a):
                val = a.inputs[0]
                if not isinstance(val, Const) and val in tainted:
                    puts.append((operand_const(a.inputs[1]), val))
        if not puts:
            return False
        changed = False
        for a in self.prog.assignments:
            if a.op != "app_global_get" or not a.outputs or not self._in_scope(a):
                continue
            out = a.outputs[0]
            if isinstance(out, Const) or out in tainted:
                continue
            get_key = operand_const(a.inputs[0]) if a.inputs else None
            for put_key, put_val in puts:
                # connect on a matching const key, or conservatively when either
                # side's key isn't statically known.
                if put_key is None or get_key is None or put_key == get_key:
                    tainted.add(out)
                    source_for[out] = source_for[put_val]
                    changed = True
                    break
        return changed

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
