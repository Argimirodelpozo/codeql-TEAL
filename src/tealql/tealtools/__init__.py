"""TEAL static-analysis toolkit (pure Python: source -> graph -> SSA -> analysis).

The package root is a compatibility facade, not a dependency hub. Public names
are resolved lazily so importing a substrate module such as :mod:`ast.parse`
does not pull SSA, dataflow, detectors, or cross-contract analysis into the
same import cycle.
"""
from importlib import import_module
import logging as _logging


_logging.getLogger("tealql.tealtools").addHandler(_logging.NullHandler())

# Public attribute -> (relative module, attribute). This retains the historical
# package-root API while keeping every dependency edge demand-driven.
_LAZY_EXPORTS = {
    # Errors and source identity.
    "TealQLError": (".errors", "TealQLError"),
    "TealParseError": (".errors", "TealParseError"),
    "TargetError": (".errors", "TargetError"),
    "TargetNotFoundError": (".errors", "TargetNotFoundError"),
    "UnknownOpcodeError": (".errors", "UnknownOpcodeError"),
    "ParseDiagnostic": (".errors", "ParseDiagnostic"),
    "ProgramSources": (".sources", "ProgramSources"),
    "SourceFile": (".sources", "SourceFile"),
    "AnalysisDegradation": (".health", "AnalysisDegradation"),
    "AnalysisHealth": (".health", "AnalysisHealth"),
    "AnalysisResult": (".health", "AnalysisResult"),
    # SSA and CFG.
    "SSAProgram": (".ssa", "SSAProgram"),
    "BasicBlock": (".ssa", "BasicBlock"),
    "Const": (".ssa", "Const"),
    "Phi": (".ssa", "Phi"),
    "SSAVar": (".ssa", "SSAVar"),
    "Assignment": (".ssa", "Assignment"),
    "PathPredicateAnalysis": (".path_predicates", "PathPredicateAnalysis"),
    "BranchCondition": (".path_predicates", "BranchCondition"),
    "CFG": (".cfg", "CFG"),
    # Detector framework.
    "Detector": (".detector", "Detector"),
    "Report": (".detector", "Report"),
    "Finding": (".detector", "Finding"),
    "ALL_DETECTORS": (".detector", "ALL_DETECTORS"),
    "ALL_REPORTS": (".detector", "ALL_REPORTS"),
    "run_all": (".detector", "run_all"),
    # Generic taint framework.
    "TaintAnalysis": (".dataflow.engine", "TaintAnalysis"),
    "Source": (".dataflow.engine", "Source"),
    "Sink": (".dataflow.engine", "Sink"),
    "FlowRule": (".dataflow.engine", "FlowRule"),
    "Violation": (".dataflow.engine", "Violation"),
    "TaintedOperand": (".dataflow.engine", "TaintedOperand"),
    # Reports and analyses.
    "AuthDominationDetector": (".auth_domination", "AuthDominationDetector"),
    "AuthViolation": (".auth_domination", "AuthViolation"),
    "InnerTxnReport": (".inner_txn_report", "InnerTxnReport"),
    "analyze_group_shape": (".group_reasoning", "analyze"),
    "GroupShape": (".group_reasoning", "GroupShape"),
    "filter_validated": (".dataflow.predicate_aware", "filter_validated"),
    "SuppressedViolation": (".dataflow.predicate_aware", "SuppressedViolation"),
    # Box and state dataflow.
    "detect_into_box_flows": (".dataflow.box", "detect_into_box_flows"),
    "detect_out_of_box_flows": (".dataflow.box", "detect_out_of_box_flows"),
    "detect_correlated_flows": (".dataflow.box", "detect_correlated_flows"),
    "CorrelatedViolation": (".dataflow.box", "CorrelatedViolation"),
    "detect_out_of_state_flows": (".dataflow.state", "detect_out_of_state_flows"),
    # Cross-contract analysis.
    "XContractGraph": (".xcontract", "XContractGraph"),
    "AppcallSite": (".xcontract", "AppcallSite"),
    "AppcallEdge": (".xcontract", "AppcallEdge"),
    "cross_auth_findings": (".xcontract", "cross_auth_findings"),
    "load_registry": (".xcontract", "load_registry"),
    # Structural partition.
    "ProgramStructure": (".structure", "ProgramStructure"),
    "Subroutine": (".structure", "Subroutine"),
    "CallSite": (".structure", "CallSite"),
    "analyze_structure": (".structure", "analyze_structure"),
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
