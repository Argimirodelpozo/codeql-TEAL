""":class:`Finding` — the one normalized, versioned record every output path
(JSON, SARIF, text) is built from.

A violation must carry a STRUCTURED location for :func:`normalize` to read: an
int ``.line`` (plus ``.file``), or a ``"file:line"`` ``.location`` string, or
neither for a deliberately whole-program finding (the violation IS the absence of
a validation). ``pretty()`` prose is never parsed — that would make machine
locations only as reliable as the sentence wording — so a violation satisfying
none of the contract simply reports as whole-program.
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
    """A single normalized detection result; ``line`` is 1-based, or ``None`` for
    a whole-program finding."""

    rule_id: str                 # kebab detector name, e.g. "tainted-fund-flow"
    message: str
    severity: str = "medium"
    confidence: str = "medium"
    file: Optional[str] = None
    line: Optional[int] = None
    witness: Optional[dict] = None
    # OPTIONAL enrichment — None on raw bytecode or non-ABI code.
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
    """Structured ``(file, line)`` from a violation; ``(None, None)`` = whole-program."""
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
    """The 1-based line a violation anchors to, or ``None`` — public so the scanner
    can attribute a finding to an ABI method before the :class:`Finding` exists."""
    return _extract_line(violation)[1]


def _extract_witness(violation) -> Optional[dict]:
    """The violation's ``sources`` (attacker-input origins) as provenance, else ``None``."""
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

    ``rel_path`` WINS as the reported ``file``: a violation's own file is an SSA
    basename, not a path relative to the scan root, so it is only the fallback for
    direct library use. Unmodelled ``to_dict()`` keys are kept under ``details``."""
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
