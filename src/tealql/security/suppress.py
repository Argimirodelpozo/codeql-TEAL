"""Suppressions, so CI on a brownfield codebase fails only on NEW findings.

* **Inline** — ``// tealql-ignore`` on the flagged line or the one above it;
  ``// tealql-ignore: rekey-to, fee-validation`` scopes it to detectors (comma
  or space separated; the ``sec-guide/`` prefix the reports print is accepted),
  bare suppresses all. A whole-program finding (no line) is suppressed by a
  directive on any line before the first instruction. Unknown detector names
  are warned about — a typo must not read as "suppressed".
* **Baseline** — a JSON file of finding FINGERPRINTS (``version: 2``).

Fingerprint v2 is LINE-INSENSITIVE and (almost) INJECTIVE per distinct finding:

  ``sha256(rule | file | normalized message | anchor | ordinal)``

``normalized message`` has every line-number spelling neutralised (``file:17``,
``@L4`` taint roads, ``line 30``), so an edit elsewhere in the file does not
churn the baseline. ``anchor`` is the comment-stripped text of the anchored
source line (what the scanner stores on ``ScanFinding.anchor``; deliberately
NOT a multi-line window, which would let an edit to a neighbouring block churn
this finding). ``ordinal`` ranks the findings that still share all of the above
by line, so two approval exits that differ only by line number — the whole
approval-exit family prints such messages — no longer collapse into one
fingerprint and a NEWLY added unguarded exit is not silently accepted by an old
baseline. The ordinal is the one line-ORDER-sensitive component, and only among
otherwise indistinguishable findings (GitHub code scanning makes the same trade
with its line hashes).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("tealql.security.suppress")

#: Bump when the fingerprint function changes; a baseline written by another
#: version cannot match and is reported rather than silently treated as empty.
FINGERPRINT_VERSION = 2

_IGNORE_RE = re.compile(r"//\s*tealql-ignore\b(?::\s*([\w,\s/\-]+))?")
_NAME_SPLIT_RE = re.compile(r"[,\s]+")
_LINE_SPELLINGS = (
    (re.compile(r":\d+\b"), ":N"),          # file:17
    (re.compile(r"@L\d+\b"), "@LN"),        # taint road `txn ApplicationArgs 0 @L4`, SSA `V#1@L8`
    (re.compile(r"\bline \d+\b"), "line N"),  # "(pay line 30)"
)
_COMMENT_RE = re.compile(r"//.*$")


def normalize_message(message: str) -> str:
    """``message`` with every line-number spelling neutralised."""
    for rx, repl in _LINE_SPELLINGS:
        message = rx.sub(repl, message)
    return message


def anchor_text(source_lines: "list[str]", line: Optional[int]) -> str:
    """The fingerprint anchor for a finding at ``line``: the comment-stripped,
    whitespace-collapsed text of that line; ``""`` for a whole-program finding.
    Computed once by the scanner."""
    if line is None or not source_lines or not 1 <= line <= len(source_lines):
        return ""
    return " ".join(_COMMENT_RE.sub("", source_lines[line - 1]).split())


def _finding_line(finding) -> Optional[int]:
    to_finding = getattr(finding, "to_finding", None)
    if callable(to_finding):
        try:
            return to_finding().line
        except Exception:
            return None
    from .findings import violation_line
    return violation_line(getattr(finding, "violation", None))


def _base_key(finding) -> tuple:
    return (finding.detector_name, str(finding.rel_path),
            normalize_message(finding.violation.pretty()),
            getattr(finding, "anchor", "") or "")


def fingerprint(finding, *, ordinal: int = 0) -> str:
    """The v2 fingerprint of one finding; ``ordinal`` disambiguates findings that
    share rule, file, normalized message AND anchor — :func:`fingerprints`
    assigns it for a whole result set."""
    key = "\x00".join((*_base_key(finding), str(ordinal)))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def fingerprints(findings: Iterable) -> list[str]:
    """One fingerprint per finding, in order, with ordinals assigned by line
    among findings sharing the same base key."""
    findings = list(findings)
    groups: dict[tuple, list[int]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(_base_key(f), []).append(i)
    ordinal = [0] * len(findings)
    for idxs in groups.values():
        ranked = sorted(idxs, key=lambda j: (_finding_line(findings[j]) or -1, j))
        for rank, i in enumerate(ranked):
            ordinal[i] = rank
    return [fingerprint(f, ordinal=ordinal[i]) for i, f in enumerate(findings)]


def _ignore_directive(line: str) -> "tuple[bool, frozenset[str]] | None":
    """``(is_ignore, detector_names)`` for a ``// tealql-ignore[: names]`` directive,
    or ``None``; an empty name set means all detectors. Names may be comma or
    space separated and may carry the ``sec-guide/`` prefix the reports print."""
    m = _IGNORE_RE.search(line)
    if not m:
        return None
    raw = m.group(1)
    if not raw or not raw.strip():
        return True, frozenset()
    names = frozenset(n.removeprefix("sec-guide/")
                      for n in _NAME_SPLIT_RE.split(raw.strip()) if n)
    _warn_unknown(names, line)
    return True, names


def _warn_unknown(names: frozenset, line: str) -> None:
    try:
        from . import DETECTORS
    except Exception:            # pragma: no cover — registry import failure
        return
    unknown = sorted(n for n in names if n not in DETECTORS)
    if unknown:
        logger.warning("tealql-ignore names unknown detector(s) %s (directive: %s) — "
                       "nothing is suppressed for them", unknown, line.strip())


def _first_instruction_line(source_lines: "list[str]") -> int:
    """1-based line of the first non-blank, non-comment, non-pragma line (or
    ``len + 1`` when there is none): the prologue a whole-program directive may
    sit in."""
    for i, text in enumerate(source_lines, 1):
        s = text.strip()
        if not s or s.startswith("//") or s.startswith("#pragma"):
            continue
        return i
    return len(source_lines) + 1


def inline_suppressed(finding, source_lines: "list[str]") -> bool:
    """The finding's line, or the one above it, carries a directive covering this
    detector. A whole-program finding (no line) is covered by a directive on any
    prologue line — the ``#pragma`` or a comment before the first instruction."""
    line = _finding_line(finding)
    if line is None:
        probes = range(1, _first_instruction_line(source_lines))
    else:
        probes = (line, line - 1)          # same line, or the line above
    for probe in probes:
        if 1 <= probe <= len(source_lines):
            d = _ignore_directive(source_lines[probe - 1])
            if d is not None:
                _, names = d
                if not names or finding.detector_name in names:
                    return True
    return False


def load_baseline(path: "str | Path") -> set[str]:
    """Fingerprints from a baseline JSON file; empty set when it doesn't exist yet.
    A baseline written by an older fingerprint version is loaded but warned about:
    none of its entries can match, so every finding reads as new."""
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    version = data.get("version", 1)
    if version != FINGERPRINT_VERSION:
        logger.warning("baseline %s was written with fingerprint version %s (current %s); "
                       "regenerate it with --update-baseline, nothing in it will match",
                       p, version, FINGERPRINT_VERSION)
    return set(data.get("fingerprints", []))


def write_baseline(path: "str | Path", findings: Iterable) -> int:
    """Write the findings' fingerprints to ``path``, sorted and deduped."""
    fps = sorted(set(fingerprints(findings)))
    Path(path).write_text(json.dumps(
        {"tool": "tealql", "version": FINGERPRINT_VERSION, "fingerprints": fps},
        indent=2))
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
    findings = list(findings)
    fps = fingerprints(findings)
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
    for f, fp in zip(findings, fps):
        if fp in baseline or inline_suppressed(f, _lines(f.rel_path)):
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
