"""Taint/dataflow compatibility facade; analysis modules load on demand."""
from importlib import import_module


_LAZY_EXPORTS = {
    # Engine.
    "DEFAULT_RULES": (".engine", "DEFAULT_RULES"),
    "ATTACKER_CONTROL_RULES": (".engine", "ATTACKER_CONTROL_RULES"),
    "CONCAT_ANY_PROPAGATION_RULE": (".engine", "CONCAT_ANY_PROPAGATION_RULE"),
    "CONCAT_PROPAGATION_RULE": (".engine", "CONCAT_PROPAGATION_RULE"),
    "HASH_PROPAGATION_RULE": (".engine", "HASH_PROPAGATION_RULE"),
    "SLICE_PROPAGATION_RULE": (".engine", "SLICE_PROPAGATION_RULE"),
    "OPAQUE_READ_RULE": (".engine", "OPAQUE_READ_RULE"),
    "CONSERVATIVE_VALUE_PROPAGATION_RULE": (
        ".engine", "CONSERVATIVE_VALUE_PROPAGATION_RULE"
    ),
    "FlowRule": (".engine", "FlowRule"),
    "Operand": (".engine", "Operand"),
    "Sink": (".engine", "Sink"),
    "Source": (".engine", "Source"),
    "TaintAnalysis": (".engine", "TaintAnalysis"),
    "TaintedOperand": (".engine", "TaintedOperand"),
    "Violation": (".engine", "Violation"),
    # Box.
    "APP_GLOBAL_PUT_VALUE_SINK": (".box", "APP_GLOBAL_PUT_VALUE_SINK"),
    "APP_LOCAL_PUT_VALUE_SINK": (".box", "APP_LOCAL_PUT_VALUE_SINK"),
    "BOX_CREATE_SIZE_SINK": (".box", "BOX_CREATE_SIZE_SINK"),
    "BOX_EXTRACT_SOURCE": (".box", "BOX_EXTRACT_SOURCE"),
    "BOX_GET_VALUE_SOURCE": (".box", "BOX_GET_VALUE_SOURCE"),
    "BOX_LEN_SOURCE": (".box", "BOX_LEN_SOURCE"),
    "BOX_PUT_VALUE_SINK": (".box", "BOX_PUT_VALUE_SINK"),
    "BOX_REPLACE_VALUE_SINK": (".box", "BOX_REPLACE_VALUE_SINK"),
    "CorrelatedViolation": (".box", "CorrelatedViolation"),
    "DEFAULT_INTO_BOX_SINKS": (".box", "DEFAULT_INTO_BOX_SINKS"),
    "DEFAULT_INTO_BOX_SOURCES": (".box", "DEFAULT_INTO_BOX_SOURCES"),
    "DEFAULT_OUT_OF_BOX_SINKS": (".box", "DEFAULT_OUT_OF_BOX_SINKS"),
    "DEFAULT_OUT_OF_BOX_SOURCES": (".box", "DEFAULT_OUT_OF_BOX_SOURCES"),
    "EXTERNAL_ARG_SOURCE": (".box", "EXTERNAL_ARG_SOURCE"),
    "ITXN_FIELD_SENSITIVE_SINKS": (".box", "ITXN_FIELD_SENSITIVE_SINKS"),
    "detect_correlated_flows": (".box", "detect_correlated_flows"),
    "detect_into_box_flows": (".box", "detect_into_box_flows"),
    "detect_out_of_box_flows": (".box", "detect_out_of_box_flows"),
    # Cross-contract.
    "XContractNode": (".xcontract_taint_graph", "XContractNode"),
    "XContractTaintGraph": (".xcontract_taint_graph", "XContractTaintGraph"),
    "CrossTaintFinding": (".xcontract_taint_graph", "CrossTaintFinding"),
    "cross_taint_findings": (".xcontract_taint_graph", "cross_taint_findings"),
    "render_cross_taint": (".xcontract_taint_graph", "render_cross_taint"),
    # State.
    "CorrelatedStateViolation": (".state", "CorrelatedStateViolation"),
    "detect_correlated_state_flows": (".state", "detect_correlated_state_flows"),
    "APP_GLOBAL_GET_SOURCE": (".state", "APP_GLOBAL_GET_SOURCE"),
    "APP_GLOBAL_GET_EX_SOURCE": (".state", "APP_GLOBAL_GET_EX_SOURCE"),
    "APP_LOCAL_GET_SOURCE": (".state", "APP_LOCAL_GET_SOURCE"),
    "APP_LOCAL_GET_EX_SOURCE": (".state", "APP_LOCAL_GET_EX_SOURCE"),
    "DEFAULT_OUT_OF_STATE_SINKS": (".state", "DEFAULT_OUT_OF_STATE_SINKS"),
    "DEFAULT_OUT_OF_STATE_SOURCES": (".state", "DEFAULT_OUT_OF_STATE_SOURCES"),
    "detect_out_of_state_flows": (".state", "detect_out_of_state_flows"),
    # Predicate-aware filter.
    "SuppressedViolation": (".predicate_aware", "SuppressedViolation"),
    "filter_validated": (".predicate_aware", "filter_validated"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    value = getattr(import_module(module_name, __name__), attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
