"""Visualization + debug-dump for TEAL contracts.

:mod:`.render` provides focused op/CFG Graphviz helpers; :mod:`.catalog`
maintains every representation, analysis and pass view; :mod:`.dump` renders
that catalog as one annotated report plus its applicable graphs.
"""
from .render import (  # noqa: F401
    cfg_view, to_dot, draw_cfg, cfg_bb_graph, to_bb_dot, draw_cfg_bb,
)
from .catalog import (  # noqa: F401
    CATALOG,
    CATALOG_BY_KEY,
    RenderedView,
    ViewKind,
    ViewSpec,
    VisualizationContext,
    render_views,
)
from .dump import dump_all  # noqa: F401

__all__ = [
    "cfg_view", "to_dot", "draw_cfg", "cfg_bb_graph", "to_bb_dot",
    "draw_cfg_bb", "dump_all", "CATALOG", "CATALOG_BY_KEY",
    "RenderedView", "ViewKind", "ViewSpec", "VisualizationContext",
    "render_views",
]
