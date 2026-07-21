"""Taint-flow framework + the detectors built on it.

Layout:

- :mod:`tealql.tealtools.dataflow.engine` — the generic engine (``TaintAnalysis``)
  plus the descriptor classes (``Source``, ``Sink``, ``FlowRule``,
  ``Violation``) and the built-in propagation rules (hash / slice /
  concat-with-const).
- :mod:`tealql.tealtools.dataflow.box` — into-box / out-of-box / key-correlated
  flow detectors.

The non-unique-box-key detector built on this framework is a
first-class detection — it lives at ``src/tealql/security/detections/box-key/``
and is reached via :data:`tealql.security.DETECTORS`.
- :mod:`tealql.tealtools.dataflow.predicate_aware` — post-filter on any
  ``Violation`` list using path-predicate constraints.

Most-used names are re-exported here so callers can do
``from tealql.tealtools.dataflow import TaintAnalysis``.
"""

from .engine import (
    DEFAULT_RULES,
    ATTACKER_CONTROL_RULES,
    CONCAT_ANY_PROPAGATION_RULE,
    CONCAT_PROPAGATION_RULE,
    HASH_PROPAGATION_RULE,
    SLICE_PROPAGATION_RULE,
    FlowRule,
    Operand,
    Sink,
    Source,
    TaintAnalysis,
    TaintedOperand,
    Violation,
)

from .box import (
    APP_GLOBAL_PUT_VALUE_SINK,
    APP_LOCAL_PUT_VALUE_SINK,
    BOX_CREATE_SIZE_SINK,
    BOX_EXTRACT_SOURCE,
    BOX_GET_VALUE_SOURCE,
    BOX_LEN_SOURCE,
    BOX_PUT_VALUE_SINK,
    BOX_REPLACE_VALUE_SINK,
    CorrelatedViolation,
    DEFAULT_INTO_BOX_SINKS,
    DEFAULT_INTO_BOX_SOURCES,
    DEFAULT_OUT_OF_BOX_SINKS,
    DEFAULT_OUT_OF_BOX_SOURCES,
    EXTERNAL_ARG_SOURCE,
    ITXN_FIELD_SENSITIVE_SINKS,
    detect_correlated_flows,
    detect_into_box_flows,
    detect_out_of_box_flows,
)

from .xcontract_taint_graph import (
    XContractNode,
    XContractTaintGraph,
    CrossTaintFinding,
    cross_taint_findings,
    render_cross_taint,
)

from .state import (
    APP_GLOBAL_GET_SOURCE,
    APP_GLOBAL_GET_EX_SOURCE,
    APP_LOCAL_GET_SOURCE,
    APP_LOCAL_GET_EX_SOURCE,
    DEFAULT_OUT_OF_STATE_SINKS,
    DEFAULT_OUT_OF_STATE_SOURCES,
    detect_out_of_state_flows,
)

from .predicate_aware import SuppressedViolation, filter_validated

__all__ = [
    # engine
    "TaintAnalysis", "Source", "Sink", "FlowRule",
    "Violation", "Operand", "TaintedOperand",
    "HASH_PROPAGATION_RULE", "SLICE_PROPAGATION_RULE",
    "ATTACKER_CONTROL_RULES", "CONCAT_ANY_PROPAGATION_RULE",
    "CONCAT_PROPAGATION_RULE", "DEFAULT_RULES",
    # box
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "EXTERNAL_ARG_SOURCE", "BOX_GET_VALUE_SOURCE",
    "BOX_EXTRACT_SOURCE", "BOX_LEN_SOURCE",
    "BOX_PUT_VALUE_SINK", "BOX_REPLACE_VALUE_SINK",
    "BOX_CREATE_SIZE_SINK", "APP_GLOBAL_PUT_VALUE_SINK",
    "APP_LOCAL_PUT_VALUE_SINK", "ITXN_FIELD_SENSITIVE_SINKS",
    "DEFAULT_INTO_BOX_SOURCES", "DEFAULT_INTO_BOX_SINKS",
    "DEFAULT_OUT_OF_BOX_SOURCES", "DEFAULT_OUT_OF_BOX_SINKS",
    # cross-contract taint
    "XContractTaintGraph", "XContractNode", "CrossTaintFinding",
    "cross_taint_findings", "render_cross_taint",
    # state
    "detect_out_of_state_flows",
    "APP_GLOBAL_GET_SOURCE", "APP_GLOBAL_GET_EX_SOURCE",
    "APP_LOCAL_GET_SOURCE", "APP_LOCAL_GET_EX_SOURCE",
    "DEFAULT_OUT_OF_STATE_SOURCES", "DEFAULT_OUT_OF_STATE_SINKS",
    # predicate_aware
    "filter_validated", "SuppressedViolation",
]
