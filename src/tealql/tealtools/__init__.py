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
    "TealQLError": (".diagnostics.errors", "TealQLError"),
    "TealParseError": (".diagnostics.errors", "TealParseError"),
    "TargetError": (".diagnostics.errors", "TargetError"),
    "TargetNotFoundError": (".diagnostics.errors", "TargetNotFoundError"),
    "UnknownOpcodeError": (".diagnostics.errors", "UnknownOpcodeError"),
    "ParseDiagnostic": (".diagnostics.errors", "ParseDiagnostic"),
    "ProgramSources": (".frontend.sources", "ProgramSources"),
    "SourceFile": (".frontend.sources", "SourceFile"),
    "AnalysisDegradation": (".diagnostics.health", "AnalysisDegradation"),
    "AnalysisHealth": (".diagnostics.health", "AnalysisHealth"),
    "AnalysisResult": (".diagnostics.health", "AnalysisResult"),
    # SSA and CFG.
    "SSAProgram": (".ssa", "SSAProgram"),
    "BasicBlock": (".ssa", "BasicBlock"),
    "Const": (".ssa", "Const"),
    "Phi": (".ssa", "Phi"),
    "SSAVar": (".ssa", "SSAVar"),
    "Assignment": (".ssa", "Assignment"),
    "PathPredicateAnalysis": (".cfg.path_predicates", "PathPredicateAnalysis"),
    "BranchCondition": (".cfg.path_predicates", "BranchCondition"),
    "CFG": (".cfg", "CFG"),
    # Detector framework.
    "Detector": (".reporting.registry", "Detector"),
    "Report": (".reporting.registry", "Report"),
    "Finding": (".reporting.registry", "Finding"),
    "ALL_DETECTORS": (".reporting.registry", "ALL_DETECTORS"),
    "ALL_REPORTS": (".reporting.registry", "ALL_REPORTS"),
    "run_all": (".reporting.registry", "run_all"),
    # Generic taint framework.
    "TaintAnalysis": (".dataflow.engine", "TaintAnalysis"),
    "Source": (".dataflow.engine", "Source"),
    "Sink": (".dataflow.engine", "Sink"),
    "FlowRule": (".dataflow.engine", "FlowRule"),
    "Violation": (".dataflow.engine", "Violation"),
    "TaintedOperand": (".dataflow.engine", "TaintedOperand"),
    # Reports and analyses.
    "AuthDominationDetector": (".analysis.auth", "AuthDominationDetector"),
    "AuthViolation": (".analysis.auth", "AuthViolation"),
    "InnerTxnReport": (".reporting.inner_transactions", "InnerTxnReport"),
    "analyze_group_shape": (".cfg.group", "analyze"),
    "GroupShape": (".cfg.group", "GroupShape"),
    "filter_validated": (".dataflow.predicate_aware", "filter_validated"),
    "SuppressedViolation": (".dataflow.predicate_aware", "SuppressedViolation"),
    # Conservative verifier resource-demand boundary.
    "BoxAccess": (".analysis.resource_demand", "BoxAccess"),
    "DemandSite": (".analysis.resource_demand", "DemandSite"),
    "ForeignStateRead": (".analysis.resource_demand", "ForeignStateRead"),
    "RESOURCE_DEMAND_SCHEMA_VERSION": (
        ".analysis.resource_demand", "RESOURCE_DEMAND_SCHEMA_VERSION"
    ),
    "ResourceDemand": (".analysis.resource_demand", "ResourceDemand"),
    "ResourceReference": (".analysis.resource_demand", "ResourceReference"),
    "resource_demand": (".analysis.resource_demand", "resource_demand"),
    # Box and state dataflow.
    "detect_into_box_flows": (".dataflow.box", "detect_into_box_flows"),
    "detect_out_of_box_flows": (".dataflow.box", "detect_out_of_box_flows"),
    "detect_correlated_flows": (".dataflow.box", "detect_correlated_flows"),
    "CorrelatedViolation": (".dataflow.box", "CorrelatedViolation"),
    "detect_out_of_state_flows": (".dataflow.state", "detect_out_of_state_flows"),
    # Cross-contract analysis.
    "XContractGraph": (".intercontract.analysis", "XContractGraph"),
    "AppcallSite": (".intercontract.analysis", "AppcallSite"),
    "AppcallEdge": (".intercontract.analysis", "AppcallEdge"),
    "cross_auth_findings": (".intercontract.analysis", "cross_auth_findings"),
    "load_registry": (".intercontract.analysis", "load_registry"),
    # Structural partition.
    "ProgramStructure": (".cfg.structure", "ProgramStructure"),
    "Subroutine": (".cfg.structure", "Subroutine"),
    "CallSite": (".cfg.structure", "CallSite"),
    "analyze_structure": (".cfg.structure", "analyze_structure"),
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
