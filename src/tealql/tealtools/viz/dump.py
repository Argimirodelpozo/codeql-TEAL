"""Dump every catalogued representation, analysis, and pass of a TEAL contract.

The executable catalog lives in :mod:`.catalog`. Each layer is best-effort:
one that fails to build is reported as ``(unavailable: …)`` and the rest still
dump. Graph-shaped products are written beside the annotated text report.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .._utils.dot import render as _dot_render
from .catalog import RenderedView, render_views


def dump_all(
    source,
    out_dir: Optional[str] = None,
    *,
    svg: bool = True,
    registry=None,
    group_members=None,
    views: Optional[list[str] | tuple[str, ...]] = None,
) -> str:
    """Render every catalog entry, or the selected ``views`` keys.

    ``source`` may be a ``.teal`` file, a directory, or an in-memory mapping.
    With ``out_dir``, ``contract.txt`` and one SVG/DOT per graph-capable view
    are written. A cross-contract registry enables ``repr.supercfg``.
    """
    rendered = render_views(
        source,
        keys=views,
        registry=registry,
        group_members=group_members,
        graphs=out_dir is not None,
    )
    parts = []
    for view in rendered:
        if view.spec.requires_registry and registry is None:
            graph = "graph: context required — supply --registry"
        elif view.spec.requires_group and not group_members:
            graph = "graph: context required — supply ordered group members"
        else:
            graph = (
                "graph: available"
                if view.spec.has_graph
                else f"graph: not applicable — {view.spec.graph_reason}"
            )
        if view.graph_error:
            graph = f"graph: unavailable — {view.graph_error}"
        header = (
            f"[{view.spec.kind.value}] {view.spec.key}\n"
            f"{view.spec.description}\n{graph}\n\n{view.text}"
        )
        parts.append(_section(view.spec.title, header))
    text = "\n\n".join(parts) + "\n"
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "contract.txt").write_text(text)
        _write_rendered_graphs(out, rendered, svg=svg)
    return text


def _write_rendered_graphs(
    out: Path, rendered: list[RenderedView], *, svg: bool,
) -> None:
    """Write every successfully rendered catalog graph with a stable key name."""

    def emit(name: str, dot: str) -> None:
        if svg:
            try:
                (out / f"{name}.svg").write_bytes(bytes(_dot_render(dot)))
                return
            except Exception:
                pass
        (out / f"{name}.dot").write_text(dot)

    for view in rendered:
        if view.dot is not None:
            emit(view.spec.key.replace(".", "-"), view.dot)


def _section(title: str, body: str) -> str:
    bar = "=" * 72
    return f"{bar}\n=== {title}\n{bar}\n{body}"
