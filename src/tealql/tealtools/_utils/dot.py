"""Shared Graphviz DOT primitives — string escaping plus a render-to-SVG helper
(needs a ``dot`` binary on PATH at render time).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def escape(s: str) -> str:
    """Escape a string for use inside a DOT ``"..."`` label."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def sanitize_id(s: str) -> str:
    """Turn a source path into a DOT-safe node-id fragment (``/``, ``.``, ``-`` ->
    ``_``)."""
    return s.replace("/", "_").replace(".", "_").replace("-", "_")


def header(name: str, *, rankdir: str = "TB",
           node_attrs: str = 'shape=box, fontname="monospace"') -> list[str]:
    """The standard DOT preamble lines for a node-box digraph."""
    return [f"digraph {name} {{", f"  rankdir={rankdir};",
            f"  node [{node_attrs}];"]


def bb_label(head: str, lines: list[str]) -> str:
    """A basic-block DOT label: ``head`` plus each body line, ``\\l``-joined (DOT's
    left-align)."""
    if not lines:
        return escape(head)
    # Escape each part FIRST, then join with the literal ``\l``: escaping the
    # joined string doubles the separators' backslashes, and Graphviz then
    # renders literal "\l" text instead of left-aligned breaks.
    return "\\l".join(escape(p) for p in [head, *lines]) + "\\l"


class SvgResult:
    """Graphviz SVG output: renders inline in Jupyter, savable to a file."""

    def __init__(self, svg: bytes):
        self.svg = svg

    def _repr_svg_(self) -> str:
        return self.svg.decode("utf-8")

    def __bytes__(self) -> bytes:
        return self.svg

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(self.svg)
        return p


def render(dot_source: str, *, format: str = "svg", engine: str = "dot"):
    """Pipe ``dot_source`` through Graphviz, returning an :class:`SvgResult` for
    ``svg`` or the raw bytes for other formats."""
    res = subprocess.run(
        [engine, f"-T{format}"],
        input=dot_source.encode("utf-8"),
        capture_output=True,
    )
    if res.returncode != 0:
        sys.stderr.write(res.stderr.decode("utf-8", errors="replace"))
        raise RuntimeError(f"{engine} failed (exit {res.returncode})")
    if format == "svg":
        return SvgResult(res.stdout)
    return res.stdout
