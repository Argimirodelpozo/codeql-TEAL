"""JSON-serialisation primitives shared by detectors and reports — each finding
owns its own ``to_dict()``; only the SSA-primitive compressors live here.
"""
from __future__ import annotations

from typing import Any

# Typing only — not enforced at runtime, so this module stays decoupled from
# the SSA substrate.
try:
    from ..ssa import Assignment, Location
except Exception:  # pragma: no cover — defensive for partial imports
    Assignment = Location = object  # type: ignore[assignment,misc]


def assignment_ref(a) -> dict[str, Any]:
    """Compact reference to an SSA assignment — ``{op, file, line}``, enough to
    identify the site without reconstructing the instruction."""
    loc = a.location
    return {"op": a.op, "file": loc.file, "line": loc.line}


def operand_repr(op) -> dict[str, Any]:
    """Serialise an operand (SSAVar / Phi / Const) as ``{"repr": …}`` — the same
    identity string the text renderers print, so both consumers agree."""
    return {"repr": repr(op)}


def finding_to_dict(f) -> dict[str, Any]:
    """Best-effort JSON for any finding: ``f.to_dict()`` when present, else
    ``{"message": f.pretty()}`` so ``pretty()``-only detectors still emit JSON."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    out: dict[str, Any] = {"message": f.pretty() if hasattr(f, "pretty") else str(f)}
    # A violation that knows where it is must say so in JSON too — a consumer
    # must never have to regex the prose for the location.
    line = getattr(f, "line", None)
    if isinstance(line, int):
        out["line"] = line
        file = getattr(f, "file", None)
        if isinstance(file, str):
            out["file"] = file
    return out
