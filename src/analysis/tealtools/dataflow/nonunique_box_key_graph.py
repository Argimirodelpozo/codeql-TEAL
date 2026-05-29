"""Graph-based reimplementation of the non-unique-box-key detector.

Sits on the same QL flow substrate as :class:`TaintGraph` and uses
the same :class:`Violation` shape as the existing
:class:`NonUniqueBoxKeyDetector`, so callers can A/B test the two
on the same fixtures. The key difference: this version uses the
QL-resolved flow graph (with cross-subroutine + scratch + phi
bridges built in) rather than the Python ``TaintAnalysis`` fixpoint.

What this detector says: an ``asset_params_get AssetName``'s value
output reaches the key position of a ``box_put`` / ``box_create``
through identity-preserving steps, where "identity" includes:

- The QL ``identity`` channel (``valueIdentityFlowStep``).
- ``ssa-step`` edges landing on a no-output consumer (``box_put``,
  ``app_global_put``, etc.) — value passes through unchanged.
- Hash and slice ops — output is deterministic in the input, so
  non-uniqueness collisions survive.
- ``concat`` where every non-flow input is a known constant — a
  static prefix doesn't add disambiguating entropy.

Anything else (arithmetic, ``btoi``, comparison) is *not* identity
and breaks the chain.
"""
from __future__ import annotations


from ..ssa import Const, SSAProgram
from .engine import Violation
from .taint_graph import Node, TaintGraph


# Ops where the result of a one-input opcode preserves the
# non-uniqueness of the input (same input bytes ⇒ same output bytes).
_HASH_OPS = frozenset({"sha256", "keccak256", "sha512_256", "sha3_256"})
_SLICE_OPS = frozenset({
    "extract", "extract3",
    "extract_uint16", "extract_uint32", "extract_uint64",
    "substring", "substring3",
})

# Ops that consume their inputs without producing a new SSA value
# (so an SSA-step landing on them is identity in our taint sense).
_NO_OUTPUT_CONSUMERS = frozenset({
    "box_put", "box_create", "box_replace",
    "app_global_put", "app_local_put",
    "assert", "log", "pop", "popn", "return", "err",
})


def _nonunique_identity(graph: TaintGraph, u: Node, v: Node, data: dict) -> bool:
    """Identity-promotion rule for this detector. The QL ``identity``
    channel is already covered by :meth:`TaintGraph.identity_subgraph`'s
    default — this hook adds the extras."""
    kinds = data.get("kinds", set())
    v_op = graph.op_of(v)

    # SSA-step into a no-output consumer: value passes through.
    if "ssa-step" in kinds and v_op in _NO_OUTPUT_CONSUMERS:
        return True

    # Hash / slice: non-uniqueness preserved (same bytes in → same out).
    if v_op in _HASH_OPS or v_op in _SLICE_OPS:
        return True

    # concat: identity iff at most one input to the concat
    # assignment is non-const. A const prefix/suffix doesn't add
    # disambiguating entropy. We inspect the SSA-level inputs (not
    # graph predecessors) because stack shuffles fold and the
    # operand identity is what carries the const_value annotation.
    if v_op == "concat":
        sink_assignment = graph._assignment_at(v)
        if sink_assignment is None:
            return False
        non_const = sum(
            1 for inp in sink_assignment.inputs
            if not isinstance(inp, Const)
            and getattr(inp, "const_value", None) is None
        )
        return non_const <= 1

    return False


def _source_name(graph: TaintGraph, n: Node) -> str:
    """Render a source's name, e.g. ``"asset_params_get AssetName"``."""
    op = graph.op_of(n) or n.ql_class
    im = graph.immediates_of(n)
    return f"{op} {im}".strip() if im else op


def _sink_name(graph: TaintGraph, n: Node) -> str:
    op = graph.op_of(n) or n.ql_class
    return op


def detect(prog: SSAProgram) -> list[Violation]:
    """Find non-unique field flows into box keys via the QL TaintGraph.

    Returns the same :class:`Violation` shape as the existing
    Python detector for direct comparability.
    """
    graph = TaintGraph.of(prog)
    sources = graph.find(op="asset_params_get", immediates="AssetName")
    sinks = [
        n for n in graph.nodes()
        if graph.op_of(n) in {"box_put", "box_create"}
    ]
    if not sources or not sinks:
        return []

    id_g = graph.identity_subgraph(also_identity=_nonunique_identity)

    violations: list[Violation] = []
    seen: set[tuple[int, int]] = set()  # dedupe by (source_line, sink_line)
    for src in sources:
        reach = id_g.reachable_from(src)
        for sink in sinks:
            if sink not in reach:
                continue
            key = (src.line, sink.line)
            if key in seen:
                continue
            seen.add(key)
            src_a = graph._assignment_at(src)
            sink_a = graph._assignment_at(sink)
            if src_a is None or sink_a is None:
                continue
            # Per existing detector's stack convention: key is the
            # deepest input on box_put / box_create (input 2 in
            # top-first order, i.e. inputs[1] in 0-based Python).
            if len(sink_a.inputs) < 2:
                continue
            sink_operand = sink_a.inputs[1]
            violations.append(Violation(
                source=src_a,
                source_name=_source_name(graph, src),
                sink=sink_a,
                sink_name=_sink_name(graph, sink),
                sink_operand=sink_operand,
            ))
    return violations
