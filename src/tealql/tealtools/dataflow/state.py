"""App-state dataflow detector.

Companion to :mod:`tealql.tealtools.dataflow.box`. Where box-out flow treats
box reads as sources, this treats *application-state reads*
(``app_global_get`` / ``app_local_get`` and their ``_ex`` variants) as
sources and looks for a stored value reaching a sensitive consumer
(payment-routing / app-control ``itxn_field`` sets, or another state
write) without validation.

The risk this models: a contract that trusts a value it previously
stored in global / local state -- a withdrawal address, an amount, an
admin app id -- and routes a payment or app call from it without
re-checking, so anyone who can influence that stored value (an earlier
unguarded write, a sibling app in the group) steers the outflow.

Same substrate and caveats as :mod:`tealql.tealtools.dataflow.box`: taint-only
(not predicate-aware on its own -- compose with
:mod:`tealql.tealtools.dataflow.predicate_aware` to drop guarded flows), stops
at BLOCK ops (arithmetic, ``btoi``), propagates through hash / slice /
concat-with-const.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .engine import Sink, Source, TaintAnalysis, Violation
from .box import APP_GLOBAL_PUT_VALUE_SINK, APP_LOCAL_PUT_VALUE_SINK, ITXN_FIELD_SENSITIVE_SINKS
from ..ssa import SSAProgram


# --- app-state read sources ------------------------------------------
#
# Output-index conventions (1-based, top-first after the op runs; the
# arities live in tealql.tealtools.avm):
#   app_global_get     (1 -> 1): pushes [value]            -> value = 1
#   app_local_get      (2 -> 1): pushes [value]            -> value = 1
#   app_global_get_ex  (2 -> 2): pushes [value, did_exist] -> value = 2
#   app_local_get_ex   (3 -> 2): pushes [value, did_exist] -> value = 2
# The ``_ex`` variants leave ``did_exist`` on top (output 1); the stored
# value we care about is the deeper output 2 -- mirrors box_get/box_len.

APP_GLOBAL_GET_SOURCE = Source(
    name="app_global_get value",
    matches=lambda a: a.op == "app_global_get",
    tainted_outputs=lambda a: [1],
)

APP_LOCAL_GET_SOURCE = Source(
    name="app_local_get value",
    matches=lambda a: a.op == "app_local_get",
    tainted_outputs=lambda a: [1],
)

APP_GLOBAL_GET_EX_SOURCE = Source(
    name="app_global_get_ex value",
    matches=lambda a: a.op == "app_global_get_ex",
    tainted_outputs=lambda a: [2],
)

APP_LOCAL_GET_EX_SOURCE = Source(
    name="app_local_get_ex value",
    matches=lambda a: a.op == "app_local_get_ex",
    tainted_outputs=lambda a: [2],
)


DEFAULT_OUT_OF_STATE_SOURCES: list[Source] = [
    APP_GLOBAL_GET_SOURCE,
    APP_LOCAL_GET_SOURCE,
    APP_GLOBAL_GET_EX_SOURCE,
    APP_LOCAL_GET_EX_SOURCE,
]

# Payment-routing / app-control itxn fields are the high-value sinks
# (a stored address/amount steering an outflow). The state-write sinks
# are included so a state value laundered into a *different* state slot
# and then used downstream is still reachable; they don't create
# trivial self-flows because a read's own output never feeds its own
# write input.
DEFAULT_OUT_OF_STATE_SINKS: list[Sink] = [
    *ITXN_FIELD_SENSITIVE_SINKS,
    APP_GLOBAL_PUT_VALUE_SINK,
    APP_LOCAL_PUT_VALUE_SINK,
]


def detect_out_of_state_flows(
    prog: SSAProgram,
    *,
    sources: Optional[Iterable[Source]] = None,
    sinks: Optional[Iterable[Sink]] = None,
) -> list[Violation]:
    """Find app-state values reaching sensitive consumers without
    sanitisation. Treats *every* state read as a source; compose with
    :mod:`tealql.tealtools.dataflow.predicate_aware` to suppress flows a
    dominating guard already constrains."""
    return TaintAnalysis(
        prog,
        sources=list(sources) if sources is not None
        else DEFAULT_OUT_OF_STATE_SOURCES,
        sinks=list(sinks) if sinks is not None
        else DEFAULT_OUT_OF_STATE_SINKS,
    ).detect()
