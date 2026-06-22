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
