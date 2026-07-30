"""TEAL static-analysis toolkit (pure-Python: source → graph → SSA → analysis).

Each submodule is loadable directly (``from tealql.tealtools.ssa import
SSAProgram``); the most-used names are re-exported here for
convenience interactive use::

    from tealql.tealtools import SSAProgram, AuthDominationDetector

The CLI front-end lives in the separate ``cli`` package — run it with
the ``tealql`` console script or ``python -m tealql.cli``.

Progress logging: library modules emit through the ``tealtools``
logger hierarchy (``tealql.tealtools.passes``, ``tealql.tealtools._utils.targets``, …).
As a library we attach only a :class:`logging.NullHandler` so nothing
is printed unless the embedding application configures a handler; the
CLI does that from its ``-v`` / ``-vv`` flags.
"""

import logging as _logging

_logging.getLogger("tealql.tealtools").addHandler(_logging.NullHandler())

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
    "filter_validated", "SuppressedViolation",
    "detect_into_box_flows", "detect_out_of_box_flows",
    "detect_correlated_flows", "CorrelatedViolation",
    "detect_out_of_state_flows",
    "XContractGraph", "AppcallSite", "AppcallEdge", "cross_auth_findings", "load_registry",
    "ProgramStructure", "Subroutine", "CallSite", "analyze_structure",
]
