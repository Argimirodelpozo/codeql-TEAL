"""Truth triage of the mainnet findings ratchet — labels, matching, field precision.

Why this exists
---------------
``tests/mainnet_findings_digest.json`` pins finding COUNTS (and lines) on 231
distinct real mainnet programs. A pinned number is not a true number: the
``abi-method-selector`` bare-handler false positive sat pinned on 180/231
probes for months because nothing said which rows were right. This module
attaches a human/rule-made TRUTH label to each digest cell and turns the
ratchet into a measured FIELD precision per detector (``docs/FIELD_PRECISION.md``).

Unit and labels
---------------
One label per finding CELL ``(contract hash, detector, anchor line)`` of the
digest (a cell with two findings on one line, ``"45,45"``, is one cell).

* ``TP``       — the detector's claim holds and is a weakness a reviewer should act on.
* ``FP``       — the claim is false, or the code provably neutralises the risk
                 the detector describes (the ``class`` names the shape).
* ``INTENDED`` — the claim is TRUE but is the author's evident design
                 (creator-gated update, close-out to the creator, admin-only path).
* ``UNKNOWN``  — not decided from the program text alone (needs off-chain or
                 deployment context, or the cell was not read). UNKNOWN beats a guess.

Policy classes
--------------
Some shapes are decided by POLICY, not per cell: ``POLICY`` maps
``(detector, class)`` to the label every such cell carries. A cell may depart
from it only through an explicit ``"override"`` — one line saying why this cell
is the exception — so a policy can't be eroded by quietly relabelling cells.

``labelled_by`` is ``"manual"`` for a cell whose TEAL was read, or
``"rule:<class>"`` when a shape verified on a manually-read representative was
extended mechanically (the label still carries THIS probe's own evidence lines).

Staleness
---------
Probes are immutable files, so a label is matched to the CURRENT digest by
``(hash, detector, line)`` and its anchor TEXT (normalised) must still be that
line's text. A label whose cell vanished is ``resolved`` (the detector stopped
reporting it — good for an FP, a regression for a TP); a current cell with no
label is ``unlabelled``. Neither fails a test: the instrument reports them.

    python -m tests.mainnet_triage               # coverage + staleness report
    python -m tests.mainnet_triage --write-doc   # regenerate docs/FIELD_PRECISION.md
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
PROBES = TESTS / "mainnet-random-probes"
DIGEST = TESTS / "mainnet_findings_digest.json"
MANIFEST = TESTS / "mainnet_triage.json"
DOC = ROOT / "docs" / "FIELD_PRECISION.md"

LABELS = ("TP", "FP", "INTENDED", "UNKNOWN")
REQUIRED = ("contract", "probe", "detector", "line", "anchor", "label",
            "class", "reason", "evidence", "labelled_by", "severity")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
#: Severities whose cells the triage covers in full (the rest is sampled).
FULL_COVERAGE = ("critical", "high")
#: ``(detector, class) -> label`` decided by policy; departures need ``"override"``.
#: An ungated Delete on an app with no inner txns is TP: whatever the account
#: holds can never leave, and anyone can delete it.
POLICY = {("delete-funds-check", "ungated-delete-no-itxn"): "TP"}
_CLASS_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_LABELLED_BY_RE = re.compile(r"^(manual|rule:[a-z0-9][a-z0-9-]*)$")


# --- probes ---------------------------------------------------------------

def norm(text: str) -> str:
    """A TEAL line with its comment stripped and whitespace collapsed."""
    return " ".join(text.split("//", 1)[0].split())


def probe_paths() -> "dict[str, Path]":
    """``{content hash: representative path}`` — the ratchet's own keying."""
    from tests.corpus_manifest import distinct_files
    return dict(distinct_files(PROBES))


_LINES: "dict[Path, list[str]]" = {}


def probe_lines(path: Path) -> "list[str]":
    if path not in _LINES:
        _LINES[path] = path.read_text().splitlines()
    return _LINES[path]


def line_text(path: Path, line: int) -> "str | None":
    lines = probe_lines(path)
    return norm(lines[line - 1]) if 1 <= line <= len(lines) else None


# --- digest cells ---------------------------------------------------------

def load_digest(path: Path = DIGEST) -> dict:
    return json.loads(path.read_text())


def digest_cells(digest: dict) -> "dict[tuple[str, str, int], int]":
    """``{(hash, detector, line): findings on that line}`` (crashes and
    line-less findings are not labellable cells and are skipped)."""
    cells: "dict[tuple[str, str, int], int]" = {}
    for h, row in digest.get("per_contract", {}).items():
        for det, cell in row.items():
            if not isinstance(cell, str) or cell.startswith("CRASH:") or not cell:
                continue
            for tok in cell.split(","):
                if tok.isdigit():
                    key = (h, det, int(tok))
                    cells[key] = cells.get(key, 0) + 1
    return cells


# --- manifest -------------------------------------------------------------

def load_manifest(path: Path = MANIFEST) -> dict:
    return json.loads(path.read_text())


def save_manifest(manifest: dict, path: Path = MANIFEST) -> None:
    """One label per line (diffable, ~half the size of an indented dump)."""
    labels = sorted(manifest["labels"], key=lambda r: (r["probe"], r["detector"], r["line"]))
    head = {k: v for k, v in manifest.items() if k != "labels"}
    body = json.dumps(head, indent=1, sort_keys=True, ensure_ascii=False)
    rows = ",\n".join("  " + json.dumps(r, sort_keys=True, ensure_ascii=False) for r in labels)
    path.write_text(body[:-2] + ',\n "labels": [\n' + rows + "\n ]\n}\n")


def evidence_line(entry: str) -> "tuple[int, str]":
    """``"123: txn Sender"`` -> ``(123, "txn Sender")``."""
    num, _, text = entry.partition(":")
    return int(num), norm(text)


def validate_label(rec: dict, paths: "dict[str, Path]") -> "list[str]":
    """Schema + evidence errors for one label (empty list = valid)."""
    where = f"{rec.get('probe')}:{rec.get('line')} {rec.get('detector')}"
    errs = [f"{where}: missing {k}" for k in REQUIRED if k not in rec]
    if errs:
        return errs
    if rec["label"] not in LABELS:
        errs.append(f"{where}: label {rec['label']!r}")
    if rec["severity"] not in SEVERITIES:
        errs.append(f"{where}: severity {rec['severity']!r}")
    if not _CLASS_RE.match(rec["class"]):
        errs.append(f"{where}: class {rec['class']!r} is not a short kebab tag")
    if not _LABELLED_BY_RE.match(rec["labelled_by"]):
        errs.append(f"{where}: labelled_by {rec['labelled_by']!r}")
    if not rec["reason"].strip() or "\n" in rec["reason"]:
        errs.append(f"{where}: reason must be one non-empty line")
    policy = POLICY.get((rec["detector"], rec["class"]))
    override = rec.get("override")
    if override is not None:
        if policy is None or rec["label"] == policy:
            errs.append(f"{where}: override departs from no policy label")
        elif not isinstance(override, str) or not override.strip() or "\n" in override:
            errs.append(f"{where}: override must be one non-empty line")
    elif policy is not None and rec["label"] != policy:
        errs.append(f"{where}: class {rec['class']} is {policy} by policy; "
                    f"label {rec['label']} needs an explicit override")
    path = paths.get(rec["contract"])
    if path is None:
        return errs + [f"{where}: contract {rec['contract']} is not a probe"]
    if path.name != rec["probe"]:
        errs.append(f"{where}: probe name {rec['probe']} != {path.name}")
    if line_text(path, rec["line"]) != norm(rec["anchor"]):
        errs.append(f"{where}: anchor text differs from the probe line")
    if rec["label"] in ("TP", "FP", "INTENDED") and not rec["evidence"]:
        errs.append(f"{where}: a decided label needs evidence lines")
    for ev in rec["evidence"]:
        try:
            ln, text = evidence_line(ev)
        except ValueError:
            errs.append(f"{where}: evidence {ev!r} is not '<line>: <text>'")
            continue
        if line_text(path, ln) != text:
            errs.append(f"{where}: evidence {ev!r} does not match the probe")
    return errs


# --- matching -------------------------------------------------------------

@dataclass
class Match:
    matched: "dict[tuple, dict]" = field(default_factory=dict)   # cell -> label
    resolved: "list[dict]" = field(default_factory=list)         # label, cell gone
    unlabelled: "list[tuple]" = field(default_factory=list)      # cell, no label
    cells: "dict[tuple, int]" = field(default_factory=dict)


def match(manifest: dict, digest: dict, paths: "dict[str, Path] | None" = None) -> Match:
    """Attach labels to the current digest's cells by (hash, detector, line)
    with an anchor-text check; a label whose line moved is re-attached to a
    unique same-text unlabelled cell of the same (hash, detector)."""
    paths = paths if paths is not None else probe_paths()
    cells = digest_cells(digest)
    out = Match(cells=cells)
    pending = []
    for rec in manifest["labels"]:
        key = (rec["contract"], rec["detector"], rec["line"])
        path = paths.get(rec["contract"])
        if key in cells and path is not None and line_text(path, rec["line"]) == norm(rec["anchor"]):
            out.matched[key] = rec
        else:
            pending.append(rec)
    free = defaultdict(list)
    for key in cells:
        if key not in out.matched:
            path = paths.get(key[0])
            text = line_text(path, key[2]) if path is not None else None
            free[(key[0], key[1], text)].append(key)
    for rec in pending:
        cands = free.get((rec["contract"], rec["detector"], norm(rec["anchor"])), [])
        if len(cands) == 1:
            out.matched[cands.pop()] = rec
        else:
            out.resolved.append(rec)
    out.unlabelled = sorted(k for k in cells if k not in out.matched)
    return out


# --- precision table ------------------------------------------------------

def cell_severity(key, m: Match) -> str:
    rec = m.matched.get(key)
    if rec is not None:
        return rec["severity"]
    from tealql.security import severity_of
    return severity_of(key[1])


def detector_table(m: Match) -> "dict[str, dict]":
    rows: "dict[str, dict]" = {}
    for key in m.cells:
        det = key[1]
        row = rows.setdefault(det, {"cells": 0, **{lab: 0 for lab in LABELS},
                                    "unlabelled": 0, "contracts": set(),
                                    "fp_classes": Counter(), "fp_example": {},
                                    "tp_classes": Counter()})
        row["cells"] += 1
        row["contracts"].add(key[0])
        rec = m.matched.get(key)
        if rec is None:
            row["unlabelled"] += 1
            continue
        row[rec["label"]] += 1
        if rec["label"] == "FP":
            row["fp_classes"][rec["class"]] += 1
            row["fp_example"].setdefault(rec["class"], rec)
        elif rec["label"] == "TP":
            row["tp_classes"][rec["class"]] += 1
    return rows


def precision(row: dict) -> "float | None":
    decided = row["TP"] + row["FP"]
    return row["TP"] / decided if decided else None


def table_line(det: str, row: dict) -> str:
    """The doc's per-detector row — the unit the staleness test compares."""
    labelled = row["cells"] - row["unlabelled"] - row["UNKNOWN"]
    p = precision(row)
    return (f"| `{det}` | {row['cells']} | {len(row['contracts'])} | "
            f"{100 * labelled / row['cells']:.0f}% | {row['TP']} | {row['FP']} | "
            f"{row['INTENDED']} | {row['UNKNOWN'] + row['unlabelled']} | "
            f"{'—' if p is None else f'{p:.2f}'} |")


def coverage(m: Match) -> "dict[str, tuple[int, int]]":
    """``{tier: (decided cells, cells)}`` — decided = TP/FP/INTENDED."""
    out: "dict[str, list[int]]" = defaultdict(lambda: [0, 0])
    for key in m.cells:
        tier = "high+" if cell_severity(key, m) in FULL_COVERAGE else "other"
        out[tier][1] += 1
        rec = m.matched.get(key)
        if rec is not None and rec["label"] != "UNKNOWN":
            out[tier][0] += 1
    return {k: tuple(v) for k, v in out.items()}


def render_doc(manifest: dict, m: Match) -> str:
    rows = detector_table(m)
    cov = coverage(m)
    total = len(m.cells)
    decided = sum(1 for k in m.cells if k in m.matched and m.matched[k]["label"] != "UNKNOWN")
    order = sorted(rows, key=lambda d: (-rows[d]["cells"], d))
    tp = sum(r["TP"] for r in rows.values())
    fp = sum(r["FP"] for r in rows.values())
    hi = cov.get("high+", (0, 0))
    out = [
        "# Field precision — the mainnet ratchet, labelled",
        "",
        "<!-- GENERATED by `python -m tests.mainnet_triage --write-doc`; do not edit by hand. -->",
        "",
        "`docs/PRECISION.md` scores each detector on a curated corpus we wrote; it is a",
        "specification, not a field rate. This page is the field number: every finding",
        f"cell of the mainnet findings ratchet ({len({k[0] for k in m.cells})} of the 231 distinct",
        "real mainnet programs in `tests/mainnet-random-probes/` have findings) carries a",
        "truth label in `tests/mainnet_triage.json` — `TP` (real weakness), `FP` (claim",
        "false or provably neutralised), `INTENDED` (true, but the author's evident",
        "design, e.g. creator-gated update or close-out to the creator), `UNKNOWN`",
        "(not decidable from the program text, or not read).",
        "",
        f"**Coverage:** {decided}/{total} cells decided ({100 * decided / total:.0f}%); "
        f"critical/high cells {hi[0]}/{hi[1]} ({100 * hi[0] / max(hi[1], 1):.0f}%). "
        f"Overall labelled precision TP/(TP+FP) = {tp}/{tp + fp} "
        f"= {tp / max(tp + fp, 1):.2f}.",
        "",
        "> **Caveats.** Precision is over DECIDED cells only — UNKNOWN cells are",
        "> excluded, so a detector with many UNKNOWNs has a wide error bar. `INTENDED`",
        "> counts neither for nor against precision: it is the share of findings a",
        "> reviewer will dismiss as by-design. Labels marked `rule:<class>` were",
        "> extended from a manually-read representative of the same code shape; the",
        "> rest were read individually. The ratchet's 231 programs are a random",
        "> mainnet sample, deduplicated by content hash, not a holdout set.",
        "",
        "Sampled rather than fully triaged (cells left unlabelled): "
        + (", ".join(f"`{d}` ({rows[d]['unlabelled']} unlabelled)"
                     for d in order if rows[d]["unlabelled"]) or "none") + ".",
        "",
        "| Detector | Cells | Contracts | Decided | TP | FP | INTENDED | UNKNOWN | Precision |",
        "| --- | --: | --: | --: | --: | --: | --: | --: | --: |",
    ]
    out += [table_line(d, rows[d]) for d in order]
    out += ["", "## False-positive classes", "",
            "Each FP class with its count and one example (`probe:line`). Classes",
            "marked *fixable* are shapes a detector could recognise from the program",
            "text alone.", ""]
    notes = manifest.get("class_notes", {})
    for d in order:
        r = rows[d]
        if not r["fp_classes"]:
            continue
        out.append(f"### `{d}`")
        out.append("")
        for cls, n in r["fp_classes"].most_common():
            ex = r["fp_example"][cls]
            note = notes.get(cls, "")
            out.append(f"- **{cls}** ×{n} — e.g. `{ex['probe']}:{ex['line']}`: {ex['reason']}"
                       + (f" *{note}*" if note else ""))
        out.append("")
    overrides = sorted((r for r in m.matched.values() if "override" in r),
                       key=lambda r: (r["detector"], r["probe"], r["line"]))
    if POLICY:
        out += ["## Policy labels", "",
                "These classes are labelled by policy; a cell departs only through a",
                "written override, listed here.", ""]
        out += [f"- `{d}` / **{c}** = {lab}" for (d, c), lab in sorted(POLICY.items())]
        out += [f"  - override: `{r['probe']}:{r['line']}` ({r['detector']}) → {r['label']}: "
                f"{r['override']}" for r in overrides]
        out.append("")
    sem = manifest.get("label_semantics", {})
    if sem:
        out += ["## What TP/FP/INTENDED mean per detector", ""]
        out += [f"- `{d}`: {sem[d]}" for d in sorted(sem)]
        out.append("")
    out += ["## Staleness", "",
            "Detector engines change; the labels do not. `python -m tests.mainnet_triage`",
            "reports labels whose cell vanished (`resolved` — good for an FP, a",
            "regression to explain for a TP) and new cells with no label",
            "(`unlabelled`). `tests/test_mainnet_triage.py` fails only when a",
            "detector with FP labels has a row on this page that no longer matches the",
            "manifest + digest — regenerate with `--write-doc`.", ""]
    return "\n".join(out)


def doc_rows(text: str) -> "dict[str, str]":
    """``{detector: table line}`` parsed back from the published doc."""
    rows = {}
    for line in text.splitlines():
        mm = re.match(r"^\| `([a-z0-9-]+)` \| \d", line)
        if mm:
            rows[mm.group(1)] = line.strip()
    return rows


def report(m: Match) -> str:
    rows = detector_table(m)
    cov = coverage(m)
    lines = [f"cells {len(m.cells)}  matched {len(m.matched)}  "
             f"unlabelled {len(m.unlabelled)}  resolved labels {len(m.resolved)}"]
    for tier, (d, n) in sorted(cov.items()):
        lines.append(f"  {tier:7} decided {d}/{n} ({100 * d / max(n, 1):.0f}%)")
    for det in sorted(rows, key=lambda d: -rows[d]["cells"]):
        lines.append("  " + table_line(det, rows[det]))
    for rec in m.resolved[:20]:
        lines.append(f"  resolved: {rec['probe']}:{rec['line']} {rec['detector']} "
                     f"[{rec['label']}/{rec['class']}]")
    return "\n".join(lines)


def main(argv: "list[str]") -> int:
    manifest, digest = load_manifest(), load_digest()
    m = match(manifest, digest)
    if "--write-doc" in argv:
        DOC.write_text(render_doc(manifest, m))
        print(f"wrote {DOC.relative_to(ROOT)}")
    print(report(m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
