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

# Reports / detectors
from .auth_domination import AuthDominationDetector, AuthViolation
from .nonunique_box_key import NonUniqueBoxKeyDetector, Violation
from .inner_txn_report import InnerTxnReport
from .group_reasoning import analyze as analyze_group_shape, GroupShape
from .cost_analysis import per_line_costs, render as render_cost
from .predicate_aware import filter_validated, SuppressedViolation

# Box dataflow
from .box_dataflow import (
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

__all__ = [
    "SSAProgram", "BasicBlock", "Const", "Phi", "SSAVar", "Assignment",
    "PathPredicateAnalysis", "BranchCondition",
    "AuthDominationDetector", "AuthViolation",
    "NonUniqueBoxKeyDetector", "Violation",
    "InnerTxnReport",
    "analyze_group_shape", "GroupShape",
    "per_line_costs", "render_cost",
    "filter_validated", "SuppressedViolation",
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "XContractGraph", "AppcallSite", "cross_auth_findings", "load_registry",
]
