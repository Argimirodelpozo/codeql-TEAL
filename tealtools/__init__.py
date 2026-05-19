"""TEAL static-analysis toolkit built on the CodeQL substrate.

Each submodule is loadable directly (``from tealtools.ssa import
SSAProgram``); the most-used names are re-exported here for
convenience interactive use::

    from tealtools import SSAProgram, AuthDominationDetector

Run as a CLI::

    python -m tealtools --help
"""

# Substrate
from .ssa import SSAProgram, BasicBlock, Const, Phi, SSAVar, Assignment
from .path_predicates import PathPredicateAnalysis, BranchCondition
from .cfg import CFG
from .detector import (
    Detector, Report, Finding,
    ALL_DETECTORS, ALL_REPORTS, run_all,
)

# Generic taint framework
from .dataflow.engine import (
    TaintAnalysis, Source, Sink, FlowRule, Violation, TaintedOperand,
)

# Reports / detectors
from .auth_domination import AuthDominationDetector, AuthViolation
from .dataflow.nonunique_box_key import NonUniqueBoxKeyDetector
from .inner_txn_report import InnerTxnReport
from .group_reasoning import analyze as analyze_group_shape, GroupShape
from .cost_analysis import (
    per_line_costs, per_line_cost_paths, render as render_cost,
)
from .control_tree import build_control_tree, pretty as pretty_control_tree
from .loops import find_loops
from .dataflow.predicate_aware import filter_validated, SuppressedViolation

# Box dataflow
from .dataflow.box import (
    detect_into_box_flows,
    detect_out_of_box_flows,
    detect_correlated_flows,
    CorrelatedViolation,
)

# Cross-contract
from .xcontract import (
    XContractGraph,
    AppcallSite,
    cross_auth_findings,
    load_registry,
)

# Detections subpackage (Algorand-security-guide ports + helpers).
# Importing the package here exposes ``tealtools.detections`` for
# ``from tealtools import detections``; individual detectors stay one
# import deeper to avoid 17 names at the top level.
from . import detections

__all__ = [
    "SSAProgram", "BasicBlock", "Const", "Phi", "SSAVar", "Assignment",
    "PathPredicateAnalysis", "BranchCondition",
    "CFG",
    "Detector", "Report", "Finding",
    "ALL_DETECTORS", "ALL_REPORTS", "run_all",
    "TaintAnalysis", "Source", "Sink", "FlowRule", "Violation", "TaintedOperand",
    "AuthDominationDetector", "AuthViolation",
    "NonUniqueBoxKeyDetector",
    "InnerTxnReport",
    "analyze_group_shape", "GroupShape",
    "per_line_costs", "per_line_cost_paths", "render_cost",
    "build_control_tree", "pretty_control_tree", "find_loops",
    "filter_validated", "SuppressedViolation",
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "XContractGraph", "AppcallSite", "cross_auth_findings", "load_registry",
    "detections",
]
