"""Visualization + debug-dump for TEAL contracts.

- :mod:`.render` — Graphviz/DOT renderers (op-graph, CFG, BB-CFG, control-tree
  regions), promoted from the old ``tealql.tealtools.viz`` module so
  ``from tealql.tealtools.viz import to_dot`` / ``region_to_dot`` / … keep working.
- :mod:`.dump` — :func:`dump_all`, a one-shot dump of EVERY representation of a
  contract (source → graph → CFG → SSA → structure → control tree → path
  predicates → inner-txn report → Puya IR) as a text report, plus the
  graph-shaped layers as ``.svg`` / ``.dot`` files.
"""
from .render import (  # noqa: F401
    cfg_view, to_dot, draw_cfg, cfg_bb_graph, to_bb_dot, draw_cfg_bb,
    region_to_dot, region_to_mermaid,
)
from .dump import dump_all  # noqa: F401

__all__ = [
    "cfg_view", "to_dot", "draw_cfg", "cfg_bb_graph", "to_bb_dot",
    "draw_cfg_bb", "region_to_dot", "region_to_mermaid", "dump_all",
]
