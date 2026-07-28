"""Suppressions, so CI on a brownfield codebase fails only on NEW findings.

* **Inline** — ``// tealql-ignore`` on the flagged line or the one above it;
  ``// tealql-ignore: rekey-to, fee-validation`` scopes it to detectors, bare
  suppresses all. For an intentional, locally-justified exception.
* **Baseline** — a JSON file of finding FINGERPRINTS. The fingerprint is
  LINE-INSENSITIVE (rule + file + line-stripped message), so unrelated edits
  elsewhere in the file do not invalidate it.
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
    """``sha256(rule_id | file | line-stripped message)`` — line-insensitive so an
    edit that shifts lines elsewhere doesn't churn the baseline."""
    msg = _LINE_NUM_RE.sub(":N", finding.violation.pretty())
    key = f"{finding.detector_name}\x00{finding.rel_path}\x00{msg}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _ignore_directive(line: str) -> "tuple[bool, frozenset[str]] | None":
    """``(is_ignore, detector_names)`` for a ``// tealql-ignore[: names]`` directive,
    or ``None``; an empty name set means all detectors."""
    m = _IGNORE_RE.search(line)
    if not m:
        return None
    names = m.group(1)
    if not names:
        return True, frozenset()
    return True, frozenset(n.strip() for n in names.split(",") if n.strip())


def inline_suppressed(finding, source_lines: "list[str]") -> bool:
    """The finding's line, or the one above it, carries a directive covering this
    detector. A whole-program finding can only be suppressed from line 1."""
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
    """Fingerprints from a baseline JSON file; empty set when it doesn't exist yet."""
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return set(data.get("fingerprints", []))


def write_baseline(path: "str | Path", findings: Iterable) -> int:
    """Write the findings' fingerprints to ``path``, sorted and deduped."""
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
    """Split findings into ``(kept, suppressed)`` by inline directive (source read
    relative to ``root``, cached per file) or ``baseline`` fingerprint."""
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
