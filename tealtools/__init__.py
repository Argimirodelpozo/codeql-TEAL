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
from .cost_analysis import per_line_costs, render as render_cost
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

# Sec-guide detector subpackage. Importing the package here exposes
# ``tealtools.sec_guide`` for ``from tealtools import sec_guide``;
# individual detectors stay one import deeper to avoid 17 names at the
# top level.
from . import sec_guide

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
    "per_line_costs", "render_cost",
    "filter_validated", "SuppressedViolation",
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "XContractGraph", "AppcallSite", "cross_auth_findings", "load_registry",
    "sec_guide",
]
