"""Detect non-unique external field values flowing into box keys.

Multiple ASAs may share an ``AssetName``, so keying a box on one without mixing in
something distinguishing collides two real-world entities on the same box — the
mistake surfaces as silent data overwrites. A :class:`TaintAnalysis` configured
with that value as source and the ``box_create``/``box_put`` key positions as sinks.
"""
from __future__ import annotations

from typing import Iterable, Optional

from tealql.tealtools.dataflow.engine import (
    DEFAULT_RULES,
    FlowRule,
    Sink,
    Source,
    TaintAnalysis,
    TaintedOperand,
    Violation,
)
from tealql.tealtools.ssa import Assignment, SSAProgram


# Re-export the taint-framework names this detector is configured from.
__all__ = [
    "Source", "Sink", "FlowRule", "Violation", "TaintedOperand",
    "ASSET_PARAMS_NAME_SOURCE",
    "BOX_CREATE_SINK", "BOX_PUT_SINK",
    "DEFAULT_SOURCES", "DEFAULT_SINKS", "DEFAULT_RULES",
    "NonUniqueBoxKeyDetector",
]


# --- this analysis's default config -----------------------------------


def _is_asset_params_get(a: Assignment, field_name: str) -> bool:
    return (
        a.op == "asset_params_get"
        and a.immediates.strip().split()[:1] == [field_name]
    )


# HAZARD: outputs are TOP-FIRST. ``asset_params_get`` produces (value, did_exist)
# with ``did_exist`` topmost, so the field VALUE is output_index=2, not 1.
ASSET_PARAMS_NAME_SOURCE = Source(
    name="asset_params_get AssetName",
    matches=lambda a: _is_asset_params_get(a, "AssetName"),
    tainted_outputs=lambda a: [2],
)


# HAZARD: inputs are TOP-FIRST and the key was pushed FIRST, so it sits below the
# other arg and takes the LARGEST input index — 2 for both ops here.
BOX_CREATE_SINK = Sink(
    name="box_create",
    matches=lambda a: a.op == "box_create",
    tainted_input_index=lambda a: 2,
)
BOX_PUT_SINK = Sink(
    name="box_put",
    matches=lambda a: a.op == "box_put",
    tainted_input_index=lambda a: 2,
)


DEFAULT_SOURCES: list[Source] = [ASSET_PARAMS_NAME_SOURCE]
DEFAULT_SINKS: list[Sink] = [BOX_CREATE_SINK, BOX_PUT_SINK]


# --- detector ---------------------------------------------------------


class NonUniqueBoxKeyDetector(TaintAnalysis):
    """:class:`TaintAnalysis` preconfigured for non-unique box keys; override
    ``sources`` / ``sinks`` / ``rules`` for custom configs."""

    severity = "high"
    applies_to = frozenset({"app"})   # box_create / box_put are app-only opcodes

    def __init__(
        self,
        prog: SSAProgram,
        *,
        file: Optional[str] = None,
        sources: Optional[Iterable[Source]] = None,
        sinks: Optional[Iterable[Sink]] = None,
        rules: Optional[Iterable[FlowRule]] = None,
        default_rules: Optional[Iterable[FlowRule]] = None,
    ):
        super().__init__(
            prog,
            sources=sources if sources is not None else DEFAULT_SOURCES,
            sinks=sinks if sinks is not None else DEFAULT_SINKS,
            rules=rules,
            default_rules=default_rules,
            file=file,
            # A non-unique value laundered through global state before keying a
            # box still collides, so follow the state roundtrip.
            cross_state=True,
        )
