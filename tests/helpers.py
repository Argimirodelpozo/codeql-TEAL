"""Shared test helpers (importable — conftest puts tests/ on sys.path).

``make_xcontract`` centralises the cross-contract setup boilerplate that was
re-rolled in 8 test files: write a caller ``.teal`` (+ optional callee sources)
to ``tmp_path``, build its :class:`SSAProgram` with constants propagated, and
return ``(caller_prog, {app_id: callee_path})``. Each test keeps its own
*builder* call (``SuperCFG.build`` / ``XContractTaintGraph.build`` /
``XContractGraph.build`` / ``find_appcall_sites``) — only the plumbing is shared.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from tealtools.ssa import SSAProgram


def make_xcontract(
    tmp_path: Path,
    caller_src: str,
    callee_srcs: Optional[dict[int, str]] = None,
    *,
    propagate: bool = True,
    caller_name: str = "caller",
) -> tuple[SSAProgram, dict[int, str]]:
    """Write ``caller_src`` (and each ``{app_id: teal}`` in ``callee_srcs``) to
    ``tmp_path``, build the caller ``SSAProgram`` (propagating constants unless
    ``propagate=False``), and return ``(caller_prog, registry)`` where registry
    maps each callee AppID to its written ``.teal`` path."""
    caller_path = tmp_path / f"{caller_name}.teal"
    caller_path.write_text(caller_src)
    caller = SSAProgram(str(caller_path), verbose=False)
    if propagate:
        caller.propagate_constants()
    registry: dict[int, str] = {}
    for app_id, src in (callee_srcs or {}).items():
        p = tmp_path / f"app_{app_id}.teal"
        p.write_text(src)
        registry[app_id] = str(p)
    return caller, registry
