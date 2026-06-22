"""JSON-serialisation helpers shared across detectors and reports.

Each violation / finding / report class owns its own ``to_dict()`` (so
type-specific shape stays close to the type), but the small helpers
that compress SSA primitives into JSON-safe forms live here.

Conventions used by every detector's ``to_dict()``:

* ``location: {file: str, line: int}`` for any source location.
* ``ref:      {op: str, file: str, line: int}`` for a reference to an
  SSA assignment — enough for a reader to find it without dumping the
  whole assignment tree.
* SSA operands (``SSAVar``, ``Phi``, ``Const``) are serialised via
  ``repr(...)`` under the key ``"repr"``. The repr is the same string
  the text renderers show, so JSON consumers and text consumers see
  identical operand identities.
"""
from __future__ import annotations

from typing import Any

# Imported for typing only; we don't enforce the types at runtime so
# this module can stay decoupled from the SSA substrate.
try:
    from ..ssa import Assignment, Location
except Exception:  # pragma: no cover — defensive for partial imports
    Assignment = Location = object  # type: ignore[assignment,misc]


def loc_dict(loc) -> dict[str, Any]:
    """Serialise a :class:`tealtools.ssa.Location`."""
    return {"file": loc.file, "line": loc.line}


def assignment_ref(a) -> dict[str, Any]:
    """Compact reference to an SSA assignment: opcode + location.

    Intended for embedding inside violation/finding payloads where the
    consumer wants to identify the site, not reconstruct the full
    instruction.
    """
    loc = a.location
    return {"op": a.op, "file": loc.file, "line": loc.line}


def operand_repr(op) -> dict[str, Any]:
    """Serialise a tainted operand (SSAVar / Phi / MatPhiVar / Const).

    Uses ``repr`` because it is the canonical identity string the SSA
    layer prints, and matches what the ``.pretty()`` renderers show.
    """
    return {"repr": repr(op)}


def finding_to_dict(f) -> dict[str, Any]:
    """Best-effort JSON serialisation for any detector finding.

    Calls ``f.to_dict()`` when present; otherwise falls back to
    ``{"message": f.pretty()}``. The fallback keeps sec-guide
    detectors — which all expose ``pretty()`` but not yet
    ``to_dict()`` — working under ``--json``.
    """
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if hasattr(f, "pretty"):
        return {"message": f.pretty()}
    return {"message": str(f)}
