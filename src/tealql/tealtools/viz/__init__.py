"""Visualization + debug-dump for TEAL contracts: :mod:`.render` (Graphviz/DOT for
the op-graph, CFG, BB-CFG and control-tree regions) and :mod:`.dump`
(:func:`dump_all`, every representation of a contract in one report).
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
