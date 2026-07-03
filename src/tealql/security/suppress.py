"""Suppressions — inline ``// tealql-ignore`` comments and a baseline file.

Table stakes for adopting a scanner on an existing (brownfield) codebase:
a way to accept known findings so CI fails only on NEW ones.

Two mechanisms:

* **Inline** — a ``// tealql-ignore`` comment on the flagged line (or the line
  directly above it) suppresses findings there. Scope it to detectors with
  ``// tealql-ignore: rekey-to, fee-validation``; bare ``// tealql-ignore``
  suppresses every detector on that line. Best for an intentional,
  locally-justified exception (pair it with a human reason in the same
  comment).

* **Baseline** — a JSON file of finding FINGERPRINTS (``--baseline``). Findings
  whose fingerprint is in the file are dropped; ``--update-baseline`` rewrites
  it from the current run. Best for "accept everything as-is today, fail on
  regressions." The fingerprint is LINE-INSENSITIVE (rule + file + message with
  line numbers stripped) so unrelated edits elsewhere don't invalidate it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

_IGNORE_RE = re.compile(r"//\s*tealql-ignore\b(?::\s*([\w,\s-]+))?")
_LINE_NUM_RE = re.compile(r":\d+")


def fingerprint(finding) -> str:
    """A stable, line-insensitive fingerprint of a :class:`ScanFinding`:
    ``sha256(rule_id | file | message-with-line-numbers-stripped)``. Line
    numbers are stripped from the message so an edit that shifts lines
    elsewhere in the file doesn't churn the baseline."""
    msg = _LINE_NUM_RE.sub(":N", finding.violation.pretty())
    key = f"{finding.detector_name}\x00{finding.rel_path}\x00{msg}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _ignore_directive(line: str) -> "tuple[bool, frozenset[str]] | None":
    """Parse a ``// tealql-ignore[: names]`` directive from a source line, or
    ``None``. Returns ``(is_ignore, detector_names)`` where an empty name set
    means "all detectors"."""
    m = _IGNORE_RE.search(line)
    if not m:
        return None
    names = m.group(1)
    if not names:
        return True, frozenset()
    return True, frozenset(n.strip() for n in names.split(",") if n.strip())


def inline_suppressed(finding, source_lines: "list[str]") -> bool:
    """True when the finding's line — or the line directly above it — carries a
    ``// tealql-ignore`` directive covering this detector. Findings with no line
    (whole-program) can only be suppressed by a directive on line 1."""
    line = finding.to_finding().line or 1
    for probe in (line, line - 1):          # same line, or the line above
        if 1 <= probe <= len(source_lines):
            d = _ignore_directive(source_lines[probe - 1])
            if d is not None:
                _, names = d
                if not names or finding.detector_name in names:
                    return True
    return False


def load_baseline(path: "str | Path") -> set[str]:
    """Load fingerprints from a baseline JSON file (``{"fingerprints": [...]}``);
    empty set if the file doesn't exist yet."""
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return set(data.get("fingerprints", []))


def write_baseline(path: "str | Path", findings: Iterable) -> int:
    """Write the findings' fingerprints to ``path`` (sorted, deduped). Returns
    the count written."""
    fps = sorted({fingerprint(f) for f in findings})
    Path(path).write_text(json.dumps(
        {"tool": "tealql", "fingerprints": fps}, indent=2))
    return len(fps)


def partition(
    findings: list,
    *,
    root: "str | Path | None" = None,
    baseline: "set[str] | None" = None,
) -> "tuple[list, list]":
    """Split findings into ``(kept, suppressed)``. A finding is suppressed if an
    inline ``// tealql-ignore`` covers it (source read relative to ``root``) or
    its fingerprint is in ``baseline``. Source read is cached per file."""
    baseline = baseline or set()
    root = Path(root) if root is not None else None
    src_cache: dict[str, list[str]] = {}

    def _lines(rel) -> list[str]:
        key = str(rel)
        if key not in src_cache:
            p = (root / rel) if root is not None else Path(rel)
            try:
                src_cache[key] = p.read_text().splitlines()
            except Exception:
                src_cache[key] = []
        return src_cache[key]

    kept, suppressed = [], []
    for f in findings:
        if fingerprint(f) in baseline or inline_suppressed(f, _lines(f.rel_path)):
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
