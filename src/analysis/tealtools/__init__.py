"""TEAL static-analysis toolkit (pure-Python: source → graph → SSA → analysis).

Each submodule is loadable directly (``from tealtools.ssa import
SSAProgram``); the most-used names are re-exported here for
convenience interactive use::

    from tealtools import SSAProgram, AuthDominationDetector

The CLI front-end lives in the separate ``cli`` package — run it with
the ``tealql`` console script or ``python -m cli``.

Progress logging: library modules emit through the ``tealtools``
logger hierarchy (``tealtools.passes``, ``tealtools._utils.targets``, …).
As a library we attach only a :class:`logging.NullHandler` so nothing
is printed unless the embedding application configures a handler; the
CLI does that from its ``-v`` / ``-vv`` flags.
"""

import logging as _logging

_logging.getLogger("tealtools").addHandler(_logging.NullHandler())

# Substrate
from .errors import (
    ParseDiagnostic, TargetError, TargetNotFoundError,
    TealParseError, TealQLError,
)
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

# App-state dataflow
from .dataflow.state import detect_out_of_state_flows

# Cross-contract
from .xcontract import (
    XContractGraph,
    AppcallSite,
    AppcallEdge,
    cross_auth_findings,
    load_registry,
)

# Structural partition (routing / subroutines / call sites)
from .structure import (
    ProgramStructure,
    Subroutine,
    CallSite,
    analyze_structure,
)

# The security detectors (Algorand-security-guide ports) live in the separate
# top-level ``security`` package, which depends on tealtools — not the reverse.
# tealtools is the pure analysis library and surfaces no detector registry.

__all__ = [
    "TealQLError", "TealParseError", "TargetError", "TargetNotFoundError",
    "ParseDiagnostic",
    "SSAProgram", "BasicBlock", "Const", "Phi", "SSAVar", "Assignment",
    "PathPredicateAnalysis", "BranchCondition",
    "CFG",
    "Detector", "Report", "Finding",
    "ALL_DETECTORS", "ALL_REPORTS", "run_all",
    "TaintAnalysis", "Source", "Sink", "FlowRule", "Violation", "TaintedOperand",
    "AuthDominationDetector", "AuthViolation",
    "InnerTxnReport",
    "analyze_group_shape", "GroupShape",
    "per_line_costs", "per_line_cost_paths", "render_cost",
    "build_control_tree", "pretty_control_tree", "find_loops",
    "filter_validated", "SuppressedViolation",
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "detect_out_of_state_flows",
    "XContractGraph", "AppcallSite", "AppcallEdge", "cross_auth_findings", "load_registry",
    "ProgramStructure", "Subroutine", "CallSite", "analyze_structure",
]
