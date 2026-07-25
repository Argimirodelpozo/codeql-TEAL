"""One structured finding shape for the whole detector layer.

:class:`Finding` is the normalized record every output path (JSON, SARIF,
text) is built from. Every violation class carries a STRUCTURED location —
the contract :func:`normalize` reads:

  - ``.line`` (int) + ``.file`` — the anchor line, mirroring the location the
    class's ``pretty()`` message names (the exit BB's last line, the sink
    assignment's line, …); or
  - ``.location`` — a well-formed ``"file:line"`` string (the taint-family
    classes build one at construction); or
  - ``line = None`` — an explicitly whole-program finding (the violation is
    the ABSENCE of a validation, e.g. the ``_FieldValidatedViolation``
    family), which reports without a line anchor.

There is deliberately NO parsing of ``pretty()`` prose here — the old
best-effort regex extraction made machine locations only as reliable as the
sentence wording. A custom violation that satisfies none of the contract
simply reports as whole-program.

The JSON shape is versioned (:data:`SCHEMA_VERSION`) so downstream consumers
can pin it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as _field
from pathlib import Path
from typing import Any, Optional

#: Bump on any breaking change to :meth:`Finding.to_dict`.
SCHEMA_VERSION = 1

# The tail of a well-formed ``location`` string: ``<file>:<line>``.
_FILE_LINE_TAIL_RE = re.compile(r"([\w./\-]+):(\d+)$")


@dataclass(frozen=True)
class Finding:
    """A single normalized detection result.

    ``line`` is 1-based or ``None`` (whole-program finding). ``witness`` holds
    structured provenance when the violation carries it (the IR taint road's
    ``sources``), else ``None``. ``file`` is the path the finding is reported
    against (the scanned file's rel-path, or the file parsed from the message)."""

    rule_id: str                 # kebab detector name, e.g. "ir-tainted-fund-flow"
    message: str
    severity: str = "medium"
    confidence: str = "medium"
    file: Optional[str] = None
    line: Optional[int] = None
    witness: Optional[dict] = None
    # The ABI method the finding sits in, recovered from source `method "sig"`
    # info (OPTIONAL enrichment — None on raw bytecode or non-ABI code).
    method: Optional[str] = None
    _extra: dict = _field(default_factory=dict)   # detector-specific to_dict keys

    def to_dict(self) -> dict[str, Any]:
        """The stable, versioned JSON record."""
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }
        if self.method:
            out["method"] = self.method
        if self.witness:
            out["witness"] = self.witness
        if self._extra:
            out["details"] = self._extra
        return out


def _extract_line(violation) -> tuple[Optional[str], Optional[int]]:
    """Structured location from a violation (see the module docstring for the
    contract). ``(None, None)`` = whole-program finding."""
    line = getattr(violation, "line", None)
    if isinstance(line, int):
        f = getattr(violation, "file", None)
        return (f if isinstance(f, str) else None), line
    loc = getattr(violation, "location", None)
    if isinstance(loc, str) and loc:
        m = _FILE_LINE_TAIL_RE.search(loc)
        if m:
            return m.group(1), int(m.group(2))
    return None, None


def violation_line(violation) -> Optional[int]:
    """The 1-based source line a violation anchors to (see :func:`_extract_line`),
    or ``None`` (whole-program). Public so the scanner can attribute a finding to
    an ABI method by line before the :class:`Finding` is built."""
    return _extract_line(violation)[1]


def _extract_witness(violation) -> Optional[dict]:
    """Structured provenance if the violation carries it — the IR taint road's
    ``sources`` (attacker-input origins), else ``None``."""
    srcs = getattr(violation, "sources", None)
    if srcs:
        return {"sources": [str(s) for s in srcs]}
    return None


def normalize(
    violation,
    *,
    rule_id: str,
    rel_path: "str | Path | None" = None,
    severity: str = "medium",
    confidence: str = "medium",
    method: Optional[str] = None,
) -> Finding:
    """Build a :class:`Finding` from any detector violation.

    ``rel_path`` (the scanned file) WINS as the reported ``file`` — the caller
    knows which artifact it handed the detector, and a violation's own
    structured file is a basename from the SSA location, not a path relative to
    the scan root. The violation's file is used only as the fallback when no
    ``rel_path`` is supplied (direct library use). Structured extra keys from a
    violation's ``to_dict()`` (minus the ones Finding already models) are kept
    under ``details`` so nothing is lost."""
    msg = violation.pretty() if hasattr(violation, "pretty") else str(violation)
    msg_file, line = _extract_line(violation)
    file = str(rel_path) if rel_path is not None else msg_file
    extra: dict = {}
    to_dict = getattr(violation, "to_dict", None)
    if callable(to_dict):
        try:
            d = to_dict()
            extra = {k: v for k, v in d.items()
                     if k not in ("message", "severity", "location", "sources")}
        except Exception:
            extra = {}
    return Finding(
        rule_id=rule_id, message=msg, severity=severity, confidence=confidence,
        file=file, line=line, method=method,
        witness=_extract_witness(violation), _extra=extra,
    )
