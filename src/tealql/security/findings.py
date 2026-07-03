"""One structured finding shape for the whole detector layer.

Detector violations grew ad-hoc: some expose ``.to_dict()``, most only
``.pretty()``, and the source LINE lived only inside the prose message for
many of them. That blocked a stable machine-readable output (CI needs
``file`` + ``line``, not "... at prog.teal:11 ..." to grep). :class:`Finding`
is the normalized record every output path (JSON, SARIF, text) is built from;
:func:`normalize` extracts it from any existing violation without touching the
violation classes.

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

# A `<file>.teal:<line>` anchor as it appears inside a pretty() message or a
# violation's ``location`` string. The line is optional (some findings are
# whole-program, e.g. "does not validate AssetCloseTo anywhere").
_LOC_RE = re.compile(r"([\w./\-]+\.teal):(\d+)")


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
        if self.witness:
            out["witness"] = self.witness
        if self._extra:
            out["details"] = self._extra
        return out


def _parse_loc(text: str) -> tuple[Optional[str], Optional[int]]:
    """First ``file.teal:line`` anchor in ``text`` → ``(file, line)`` (either
    part ``None`` if absent)."""
    m = _LOC_RE.search(text or "")
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def _extract_line(violation) -> tuple[Optional[str], Optional[int]]:
    """Best-effort structured location from a violation, else parsed from its
    message. Order: an explicit ``.location`` string, a ``.line`` / ``.sink``
    attr, then the ``pretty()`` text."""
    loc = getattr(violation, "location", None)
    if isinstance(loc, str) and loc:
        f, ln = _parse_loc(loc)
        # ``location`` may be just "file:line" without the .teal suffix in some
        # detectors; accept a trailing ":N" too.
        if ln is None:
            m = re.search(r"([\w./\-]+):(\d+)$", loc)
            if m:
                f, ln = m.group(1), int(m.group(2))
        if ln is not None:
            return f, ln
    line = getattr(violation, "line", None)
    if isinstance(line, int):
        return getattr(violation, "file", None), line
    sink = getattr(violation, "sink", None)
    if sink is not None and isinstance(getattr(sink, "line", None), int):
        return getattr(sink, "file", None), sink.line
    # Fall back to the message text.
    pretty = getattr(violation, "pretty", None)
    if callable(pretty):
        return _parse_loc(pretty())
    return None, None


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
) -> Finding:
    """Build a :class:`Finding` from any detector violation.

    ``rel_path`` (the scanned file) is the reported ``file`` unless the
    violation's own message names a different one. Structured extra keys from a
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
        file=file, line=line, witness=_extract_witness(violation), _extra=extra,
    )
