"""Detect non-unique external field values flowing into box keys.

A box's address space is keyed by an arbitrary byte string. If a contract
uses a *non-unique* external field (an ASA's ``AssetName`` is the canonical
example — multiple ASAs may share a name) as the box key without mixing
in something distinguishing, two different real-world entities collide
on the same box. The mistake usually surfaces as silent data overwrites.

Thin wrapper over :class:`tealql.tealtools.dataflow.TaintAnalysis` configured
with this analysis's defaults: ``asset_params_get AssetName``'s value
output as the source; ``box_create`` / ``box_put`` key positions as
sinks; the standard hash / slice / concat-with-const flow rules.
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


# Re-export the taint-framework names this detector is configured from,
# so callers can pull them straight off this module.
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


# ``asset_params_get F``: consumes 1 (asset id), produces 2 (value, did_exist).
# By the SSA model's top-first output convention, ``outputs[0]`` (output_index=1)
# is the topmost — that's ``did_exist``. The actual field value sits at
# ``outputs[1]`` (output_index=2).
ASSET_PARAMS_NAME_SOURCE = Source(
    name="asset_params_get AssetName",
    matches=lambda a: _is_asset_params_get(a, "AssetName"),
    tainted_outputs=lambda a: [2],
)


# Box ops are stack-bottom-keyed: the key sits *below* the other args
# because it was pushed first. By top-first convention this means the
# key has the largest input index.
#
# - ``box_create key length``  → top: length (1), key: 2.
# - ``box_put key value``      → top: value (1), key: 2.
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
    severity = "high"
    """Configured :class:`TaintAnalysis` with this analysis's defaults.

        det = NonUniqueBoxKeyDetector(prog)
        for v in det.detect():
            print(v.pretty())

    Override ``sources`` / ``sinks`` / ``rules`` for custom configs.
    """

    # Boxes are application storage — ``box_create`` / ``box_put`` are
    # app-only opcodes, so this detection never applies to a LogicSig.
    applies_to = frozenset({"app"})

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
            # A non-unique value laundered through app-global state before keying
            # a box still collides — follow the state roundtrip.
            cross_state=True,
        )
