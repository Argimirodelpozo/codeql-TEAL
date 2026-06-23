"""Shared Graphviz DOT primitives.

String escaping + a render-to-SVG helper, used by every module that emits
DOT (:mod:`tealtools.viz`, :class:`tealtools.ssa.SSAProgram`,
:mod:`tealtools.cfg`, ...). Depends only on the stdlib + a ``dot`` binary
on PATH at render time.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def escape(s: str) -> str:
    """Escape a string for use inside a DOT ``"..."`` label."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def sanitize_id(s: str) -> str:
    """Turn a source path into a DOT-safe node-id fragment (``/``, ``.``, ``-``
    -> ``_``). The shared core of every emitter's BB-id builder."""
    return s.replace("/", "_").replace(".", "_").replace("-", "_")


def header(name: str, *, rankdir: str = "TB",
           node_attrs: str = 'shape=box, fontname="monospace"') -> list[str]:
    """The standard DOT preamble lines for a node-box digraph: ``digraph
    <name> {``, the ``rankdir``, and the default ``node [...]`` attributes."""
    return [f"digraph {name} {{", f"  rankdir={rankdir};",
            f"  node [{node_attrs}];"]


def bb_label(head: str, lines: list[str]) -> str:
    """A basic-block DOT label: just ``head`` (escaped) when there are no body
    ``lines``, else ``head`` followed by each line, ``\\l``-joined (DOT's
    left-align) and escaped with a trailing ``\\l``."""
    if not lines:
        return escape(head)
    return escape("\\l".join([head, *lines])) + "\\l"


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
    """Pipe ``dot_source`` through Graphviz (``engine``), returning an
    :class:`SvgResult` for ``svg`` or the raw bytes for other formats."""
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
