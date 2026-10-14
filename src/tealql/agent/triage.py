"""Agent-side triage: a store of reviewer verdicts on detector findings.

The model is the MCP CLIENT here, not something tealql calls (no API key, no
model dependency): it works :func:`triage_queue`, reads the pre-joined
``source_context`` (and ``tealql_decompile`` when needed), decides, and writes a
verdict with :func:`record_triage`. :func:`triage_report` joins the records back
to the CURRENT findings, so a record whose finding vanished (the program
changed) is reported as STALE instead of silently applying to something else.

Records are ADVICE. They never change a finding's detector verdict, severity or
exit code; they are surfaced next to findings. The one place a verdict has an
effect is :func:`export_baseline`, which writes a fingerprint-v2 baseline of
the findings triaged ``false_positive`` — an explicit, audited opt-in for
``detections-scan --baseline``. Before trusting a reviewer's verdicts (model or
person) measure them with :func:`evaluate_against_benchmark` (``tealql
triage-eval``) against the labelled benchmark.

Store layout (JSON, default ``<scan root>/.tealql/triage.json``)::

    {"tool": "tealql", "kind": "triage", "version": 1, "fingerprint_version": 2,
     "records": {"<fingerprint>:<rule>:<file>": {
         "fingerprint", "rule", "file", "root", "verdict", "rationale",
         "evidence_lines", "reviewer", "timestamp", "tool_version", "finding"}}}

``root`` is the scan root RELATIVE to the store's directory, so a store moved
together with the code keeps matching. ``file`` is the finding's path relative
to that root — the same identity the fingerprint hashes.
"""
from __future__ import annotations

import json
import os
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .tools import ToolError, _options, _teal_files, resolve_target

STORE_VERSION = 1
VERDICTS = ("true_positive", "false_positive", "needs_context")
DEFAULT_STORE = Path(".tealql") / "triage.json"

_SEV_RANK = {s: i for i, s in enumerate(("informational", "low", "medium", "high", "critical"))}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _tool_version() -> str:
    try:
        from importlib.metadata import version
        return version("tealql")
    except Exception:
        return "0.0.0"


# ---------------------------------------------------------------------------
# Scanning a target (cached by file stats)
# ---------------------------------------------------------------------------


def scan_root(path: Path) -> Path:
    """The root findings' ``rel_path`` (and so their fingerprints) are relative
    to: the directory itself, or a single file's parent — exactly what
    ``scan_target`` / ``detections-scan`` use."""
    path = Path(path).resolve()
    return path if path.is_dir() else path.parent


_SCANS: "OrderedDict[tuple, tuple]" = OrderedDict()


def current_findings(path: Path, *, mode: Optional[str] = "auto") -> "tuple[list[dict], bool, list[dict]]":
    """``(rows, complete, notifications)`` for ``path``: each row is the
    normalized finding dict plus ``fingerprint`` (v2, with ordinals — the same
    identity a baseline stores) and ``rule``. Cached per (path, mode, stats)."""
    from tealql.security.scan import scan_target
    from tealql.security.suppress import fingerprints
    from tealql.tealtools.diagnostics.errors import TealQLError
    path = Path(path).resolve()
    files = _teal_files(path)
    key = (str(path), mode) + tuple((str(f), f.stat().st_mtime_ns, f.stat().st_size)
                                    for f in files)
    hit = _SCANS.get(key)
    if hit is not None:
        _SCANS.move_to_end(key)
        return hit
    try:
        results = scan_target(path, options=_options(mode, None, None), strict=False)
    except TealQLError as e:
        raise ToolError(str(e)) from e
    rows = []
    for sf, fp in zip(results, fingerprints(results)):
        d = sf.to_dict()
        d["fingerprint"] = fp
        d["rule"] = sf.detector_name
        d["file"] = str(sf.rel_path)
        rows.append(d)
    out = (rows, results.complete, [n.to_dict() for n in results.notifications])
    _SCANS[key] = out
    while len(_SCANS) > 16:
        _SCANS.popitem(last=False)
    return out


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


def record_key(fingerprint: str, rule: str, file: str) -> str:
    return f"{fingerprint}:{rule}:{file}"


class TriageStore:
    """The JSON triage store. ``load`` tolerates a missing file (empty store);
    ``save`` writes atomically (temp file + rename)."""

    def __init__(self, path: "str | Path"):
        self.path = Path(path).expanduser().resolve()
        self.records: dict[str, dict] = {}
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
            except json.JSONDecodeError as e:
                raise ToolError(f"triage store {self.path} is not valid JSON: {e}") from e
            if data.get("kind") != "triage" or data.get("version") != STORE_VERSION:
                raise ToolError(f"{self.path} is not a tealql triage store "
                                f"(version {STORE_VERSION})")
            self.records = dict(data.get("records") or {})

    @classmethod
    def for_target(cls, path: Path, store: Optional[str] = None) -> "TriageStore":
        return cls(store if store else scan_root(path) / DEFAULT_STORE)

    def rel_root(self, root: Path) -> str:
        return os.path.relpath(Path(root).resolve(), self.path.parent)

    def abs_root(self, record: dict) -> Path:
        return (self.path.parent / record.get("root", ".")).resolve()

    def records_for(self, path: Path) -> dict[str, dict]:
        """Records belonging to ``path``'s scan root and files."""
        root = scan_root(path)
        files = {str(f.resolve().relative_to(root)) for f in _teal_files(Path(path).resolve())}
        return {k: r for k, r in self.records.items()
                if self.abs_root(r) == root and r.get("file") in files}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"tool": "tealql", "kind": "triage", "version": STORE_VERSION,
                "fingerprint_version": _fingerprint_version(),
                "records": dict(sorted(self.records.items()))}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, self.path)


def _fingerprint_version() -> int:
    from tealql.security.suppress import FINGERPRINT_VERSION
    return FINGERPRINT_VERSION


# ---------------------------------------------------------------------------
# Operations (the tool / CLI bodies)
# ---------------------------------------------------------------------------


def _rank(row: dict) -> tuple:
    return (-_SEV_RANK.get(row.get("severity"), -1), -_CONF_RANK.get(row.get("confidence"), -1),
            row.get("file") or "", row.get("line") or 0, row.get("rule") or "")


def triage_queue(target: Optional[str] = None, teal: Optional[str] = None, *,
                 store: Optional[str] = None, mode: Optional[str] = "auto",
                 limit: int = 10, context: bool = True) -> dict:
    """Findings for ``target`` with no triage record yet, highest severity and
    confidence first; the first ``limit`` carry the ``source_context`` payload
    for their line (window, dominating predicates, reaching sources, ...)."""
    from .tools import source_context
    path = resolve_target(target, teal)
    rows, complete, notes = current_findings(path, mode=mode)
    st = TriageStore.for_target(path, store)
    done = {(r["fingerprint"], r["rule"], r["file"]) for r in st.records_for(path).values()}
    pending = sorted((r for r in rows if (r["fingerprint"], r["rule"], r["file"]) not in done),
                     key=_rank)
    root = scan_root(path)
    items = []
    for i, row in enumerate(pending):
        item = dict(row)
        if context and i < limit:
            if row.get("line"):
                try:
                    item["source_context"] = source_context(
                        target=str(path), file=None if path.is_file() else row["file"],
                        line=int(row["line"]))
                except Exception as e:     # context is a convenience: never lose the item
                    item["source_context_error"] = f"{type(e).__name__}: {e}"
            else:
                item["source_context"] = None   # whole-program finding: read the program
        items.append(item)
    return {
        "target": str(path), "root": str(root), "store": str(st.path),
        "complete": complete, "notifications": notes,
        "summary": {"findings": len(rows), "triaged": len(rows) - len(pending),
                    "pending": len(pending),
                    "with_context": min(limit, len(pending)) if context else 0},
        "queue": items,
        "semantics": ("Untriaged detector findings, highest severity/confidence first. "
                      "Each verdict you record is ADVICE stored beside the finding; it "
                      "never changes the detector's verdict. Record a verdict with "
                      "tealql_record_triage (fingerprint + verdict + rationale + "
                      "evidence_lines); false_positive REQUIRES evidence_lines citing the "
                      "guarding TEAL lines."),
    }


def record_triage(target: Optional[str] = None, teal: Optional[str] = None, *,
                  fingerprint: str, verdict: str, rationale: str,
                  evidence_lines: Optional[list] = None, reviewer: str = "unknown",
                  store: Optional[str] = None, mode: Optional[str] = "auto") -> dict:
    """Validate and persist one verdict. Refuses a fingerprint that is not a
    CURRENT finding of ``target``, an unknown verdict, an empty rationale, a
    false_positive without evidence lines, and evidence lines outside the file."""
    if verdict not in VERDICTS:
        raise ToolError(f"verdict must be one of {list(VERDICTS)}, got {verdict!r}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ToolError("rationale must be a non-empty explanation of the verdict")
    evidence = list(evidence_lines or [])
    if any(isinstance(n, bool) or not isinstance(n, int) for n in evidence):
        raise ToolError("evidence_lines must be integers (1-based TEAL lines)")
    if verdict == "false_positive" and not evidence:
        raise ToolError("a false_positive verdict must cite evidence_lines: the TEAL "
                        "lines of the guard the detector missed")
    path = resolve_target(target, teal)
    rows, _complete, _notes = current_findings(path, mode=mode)
    match = [r for r in rows if r["fingerprint"] == fingerprint]
    if not match:
        raise ToolError(f"fingerprint {fingerprint!r} is not a current finding of "
                        f"{path}; take fingerprints from tealql_triage_queue / "
                        f"tealql_analyze for this target")
    row = match[0]
    root = scan_root(path)
    n_lines = len((root / row["file"]).read_text(errors="replace").splitlines())
    bad = [n for n in evidence if not 1 <= n <= n_lines]
    if bad:
        raise ToolError(f"evidence_lines {bad} outside 1..{n_lines} of {row['file']}")
    st = TriageStore.for_target(path, store)
    key = record_key(fingerprint, row["rule"], row["file"])
    snapshot = {k: v for k, v in row.items() if k not in ("fingerprint", "rule")}
    rec = {
        "fingerprint": fingerprint, "rule": row["rule"], "file": row["file"],
        "root": st.rel_root(root), "verdict": verdict, "rationale": rationale.strip(),
        "evidence_lines": sorted(set(evidence)), "reviewer": reviewer or "unknown",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": _tool_version(), "finding": snapshot,
    }
    replaced = key in st.records
    st.records[key] = rec
    st.save()
    return {"stored": True, "replaced": replaced, "key": key, "store": str(st.path),
            "record": rec,
            "semantics": "Stored as advice; the finding's detector verdict is unchanged."}


def triage_report(target: Optional[str] = None, teal: Optional[str] = None, *,
                  store: Optional[str] = None, mode: Optional[str] = "auto") -> dict:
    """Records joined to the current findings: live records (with their finding),
    STALE records (fingerprint no longer produced — the program or the detector
    changed; the verdict no longer applies), untriaged findings, and counts per
    verdict and per detector."""
    path = resolve_target(target, teal)
    rows, complete, notes = current_findings(path, mode=mode)
    st = TriageStore.for_target(path, store)
    current = {(r["fingerprint"], r["rule"], r["file"]): r for r in rows}
    live, stale = [], []
    by_verdict: dict[str, int] = {}
    by_detector: dict[str, dict[str, int]] = {}
    seen = set()
    for rec in st.records_for(path).values():
        ident = (rec["fingerprint"], rec["rule"], rec["file"])
        finding = current.get(ident)
        if finding is None:
            stale.append(rec)
            continue
        seen.add(ident)
        live.append({**rec, "finding": finding})
        by_verdict[rec["verdict"]] = by_verdict.get(rec["verdict"], 0) + 1
        det = by_detector.setdefault(rec["rule"], {})
        det[rec["verdict"]] = det.get(rec["verdict"], 0) + 1
    untriaged = sorted((r for i, r in current.items() if i not in seen), key=_rank)
    live.sort(key=lambda r: _rank(r["finding"]))
    return {
        "target": str(path), "root": str(scan_root(path)), "store": str(st.path),
        "complete": complete, "notifications": notes,
        "summary": {"findings": len(rows), "triaged": len(live), "untriaged": len(untriaged),
                    "stale_records": len(stale), "by_verdict": dict(sorted(by_verdict.items())),
                    "by_detector": dict(sorted(by_detector.items()))},
        "records": live, "stale": stale, "untriaged": untriaged,
        "semantics": ("Triage verdicts are reviewer ADVICE joined to the current detector "
                      "findings; they never change a finding's verdict. A stale record's "
                      "fingerprint is no longer produced (program or detector changed) and "
                      "must be re-triaged, not trusted."),
    }


def export_baseline(target: str, out: "str | Path", *, store: Optional[str] = None,
                    mode: Optional[str] = "auto") -> dict:
    """Write a fingerprint-v2 baseline holding ONLY the current findings triaged
    ``false_positive`` (stale records excluded), with the audit trail (who, why,
    which lines) beside the fingerprints. ``detections-scan ROOT --baseline OUT``
    then suppresses exactly those findings."""
    rep = triage_report(target=target, store=store, mode=mode)
    if not rep["complete"]:
        raise ToolError("cannot export a baseline from an incomplete scan "
                        "(see notifications); a partial scan cannot vouch for fingerprints")
    fps = [r for r in rep["records"] if r["verdict"] == "false_positive"]
    data = {"tool": "tealql", "version": _fingerprint_version(),
            "fingerprints": sorted({r["fingerprint"] for r in fps}),
            "source": "tealql triage --export-baseline",
            "triage": [{"fingerprint": r["fingerprint"], "rule": r["rule"], "file": r["file"],
                        "line": r["finding"].get("line"), "reviewer": r["reviewer"],
                        "timestamp": r["timestamp"], "rationale": r["rationale"],
                        "evidence_lines": r["evidence_lines"]}
                       for r in sorted(fps, key=lambda r: (r["file"], r["rule"]))]}
    Path(out).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return {"written": str(out), "fingerprints": len(data["fingerprints"]),
            "stale_excluded": sum(1 for r in rep["stale"] if r["verdict"] == "false_positive")}


# ---------------------------------------------------------------------------
# Agreement with the labelled benchmark
# ---------------------------------------------------------------------------


def _benchmark_label(abs_file: Path, rule: str) -> Optional[str]:
    """``"vuln"`` / ``"safe"`` when ``abs_file`` is a benchmark fixture
    ``.../<detector>/{vuln,safe}/<x>.teal`` for THIS rule; else ``None`` (the
    benchmark only labels a fixture for its own detector)."""
    parts = abs_file.parts
    if len(parts) >= 3 and parts[-2] in ("vuln", "safe") and parts[-3] == rule:
        return parts[-2]
    return None


def evaluate_against_benchmark(store: "str | Path") -> dict:
    """Agreement of stored verdicts with the benchmark labels, per detector.

    A record on a ``vuln`` fixture of its own detector should be
    ``true_positive``; one on a ``safe`` fixture ``false_positive`` (any finding
    of that detector there is, by label, a false alarm). ``needs_context`` is an
    abstention: counted, never as agreement. Records on unlabelled findings
    (another detector's finding on a fixture, or a non-benchmark file) are
    counted as ``unlabelled`` and excluded from the rate."""
    st = TriageStore(store)
    per: dict[str, dict[str, Any]] = {}
    unlabelled = 0
    disagreements = []
    for rec in st.records.values():
        abs_file = st.abs_root(rec) / rec["file"]
        label = _benchmark_label(abs_file, rec["rule"])
        if label is None:
            unlabelled += 1
            continue
        row = per.setdefault(rec["rule"], {"agree": 0, "disagree": 0, "abstain": 0})
        if rec["verdict"] == "needs_context":
            row["abstain"] += 1
            continue
        expected = "true_positive" if label == "vuln" else "false_positive"
        if rec["verdict"] == expected:
            row["agree"] += 1
        else:
            row["disagree"] += 1
            disagreements.append({"rule": rec["rule"], "file": str(abs_file), "label": label,
                                  "verdict": rec["verdict"], "reviewer": rec.get("reviewer"),
                                  "rationale": rec.get("rationale")})
    for row in per.values():
        decided = row["agree"] + row["disagree"]
        row["agreement"] = round(row["agree"] / decided, 4) if decided else None
    tot_a = sum(r["agree"] for r in per.values())
    tot_d = sum(r["disagree"] for r in per.values())
    return {
        "store": str(st.path),
        "per_detector": dict(sorted(per.items())),
        "overall": {"agree": tot_a, "disagree": tot_d,
                    "abstain": sum(r["abstain"] for r in per.values()),
                    "agreement": round(tot_a / (tot_a + tot_d), 4) if tot_a + tot_d else None},
        "unlabelled": unlabelled,
        "disagreements": disagreements,
        "semantics": ("Agreement of reviewer verdicts with the labelled benchmark "
                      "(tests/benchmark/<detector>/{vuln,safe}/): vuln => true_positive, "
                      "safe => false_positive. Measure a reviewer (model or person) this "
                      "way before trusting its verdicts; needs_context is an abstention."),
    }


__all__ = ["VERDICTS", "DEFAULT_STORE", "TriageStore", "current_findings", "scan_root",
           "triage_queue", "record_triage", "triage_report", "export_baseline",
           "evaluate_against_benchmark"]
