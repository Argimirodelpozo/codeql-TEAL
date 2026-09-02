"""Per-detector findings digest over the real mainnet corpus.

Why this exists
---------------
Every other gate in this suite measures the tool against cases *we wrote*. The
precision/recall benchmark scores 1.00 on ~3 hand-authored fixtures per detector
and has scored 1.00 through every false-positive swarm this project has shipped:
the 104-finding ``unvalidated-group-sibling`` swarm was caught by a MANUAL mainnet
diff, and nothing in CI would have caught it. The corpus pins *instances*; real
contracts explore the *space*.

This module turns that manual diff into a committed number. It runs every
app-mode detector over the mainnet probe corpus and records, per (contract,
detector), the sorted finding LINES (``"12,45,45"``; ``?`` for a finding with
no location), plus per-detector totals. A change in detector behaviour — in
either direction, including the same count at a different line — moves the
digest and must be explained.

Deduplication is not optional
-----------------------------
The 929 committed probes are only **141 distinct programs**: one popular
template accounts for 135 files, another for 65. An undeduplicated census
measures whichever template happens to be popular, and a detector that fires
once on that template appears to fire on 15% of "the corpus". Everything here
keys on the content hash.

A crash is a digest change, not a silence
-----------------------------------------
A detector that raises is recorded as ``CRASH:<n>``. The alternative — swallowing
it — is exactly the silent-clean failure mode this project has been bitten by:
"0 findings because we checked nothing" must never read the same as "0 findings
because it is clean".
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tealql.security import DETECTORS
from tealql.security.findings import violation_line
from tealql.security.scan import default_detection_names
from tealql.tealtools.ssa import SSAProgram

TESTS = Path(__file__).resolve().parent
PROBES = TESTS / "mainnet-random-probes"
DIGEST = TESTS / "mainnet_findings_digest.json"

#: Per-contract analysis ceiling. A probe that blows past this is recorded as a
#: timeout rather than hanging the suite.
_TIMEOUT_S = 180


def app_mode_detectors() -> "list[str]":
    """The default app-mode selection — the same set ``tealql audit`` runs."""
    return default_detection_names(
        [n for n, c in DETECTORS.items()
         if "app" in getattr(c, "applies_to", frozenset({"app", "logicsig"}))])


def distinct_probes() -> "list[tuple[str, Path]]":
    """``(content_hash, representative_path)`` for each DISTINCT probe program,
    ordered by hash so the digest is stable regardless of filesystem order."""
    seen: "dict[str, Path]" = {}
    for f in sorted(PROBES.glob("*.teal")):
        h = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
        seen.setdefault(h, f)
    return sorted(seen.items())


#: Placeholder for a finding that anchors to no line (whole-program finding).
#: It still counts as ONE finding, so the digest degrades to a count for it.
_NO_LINE = "?"


def encode_findings(violations) -> str:
    """The digest cell for one (contract, detector): the SORTED finding lines
    joined by ``,`` (e.g. ``"12,45,45"``), ``?`` for a finding with no line.

    Lines, not counts: a detector that reports the right NUMBER of findings at
    the wrong location (or swaps one exit for another inside the same contract)
    must move the digest. The count is recoverable as the number of tokens."""
    lines = [violation_line(v) for v in violations]
    keyed = sorted((ln is None, ln if ln is not None else 0) for ln in lines)
    return ",".join(_NO_LINE if none else str(ln) for none, ln in keyed)


def is_crash(cell) -> bool:
    return isinstance(cell, str) and cell.startswith("CRASH:")


def finding_count(cell) -> int:
    """Number of findings in a digest cell (0 for a crash)."""
    if is_crash(cell):
        return 0
    if isinstance(cell, int):                   # legacy count-only cell
        return cell
    return len(cell.split(",")) if cell else 0


def _analyse(path: Path, names: "list[str]") -> "dict[str, str]":
    """``{detector: encoded_finding_lines}`` for one program, with crashes recorded."""
    row: "dict[str, str]" = {}
    try:
        prog = SSAProgram(str(path))
        prog.propagate_constants()
    except Exception as e:                      # a program we cannot even load
        return {"LOAD": f"CRASH:{type(e).__name__}"}
    for name in names:
        try:
            vs = DETECTORS[name](prog, file=path.name).detect()
        except Exception as e:
            row[name] = f"CRASH:{type(e).__name__}"
            continue
        if vs:
            row[name] = encode_findings(vs)
    return row


def summarize_rows(names: "list[str]", per_contract: dict) -> dict:
    """Aggregate detector totals from exact per-contract result rows."""
    totals: "dict[str, dict]" = {}
    for name in names:
        contracts = [h for h, row in per_contract.items() if name in row]
        crashes = [h for h in contracts if is_crash(per_contract[h][name])]
        findings = sum(finding_count(per_contract[h][name]) for h in contracts)
        totals[name] = {
            "contracts": len(contracts) - len(crashes),
            "findings": findings,
            "crashes": len(crashes),
        }
    return totals


def unlocated_detectors(per_contract: dict) -> "dict[str, int]":
    """``{detector: n}`` findings recorded WITHOUT a line (count-only fallback)."""
    out: "dict[str, int]" = {}
    for row in per_contract.values():
        for name, cell in row.items():
            if isinstance(cell, str) and not is_crash(cell):
                n = cell.split(",").count(_NO_LINE)
                if n:
                    out[name] = out.get(name, 0) + n
    return out


def compute_digest(limit: "int | None" = None) -> dict:
    """The full digest: per-detector totals plus the per-contract detail that
    makes a diff actionable (which contract started or stopped firing)."""
    names = app_mode_detectors()
    probes = distinct_probes()
    if limit is not None:
        probes = probes[:limit]

    per_contract: "dict[str, dict]" = {}
    for h, path in probes:
        row = _analyse(path, names)
        if row:
            per_contract[h] = row

    totals = summarize_rows(names, per_contract)

    return {
        "_comment": "Regenerate with UPDATE_MAINNET_DIGEST=1 pytest "
                    "tests/test_mainnet_ratchet.py. Any movement is a "
                    "behaviour change that needs an explanation in the commit.",
        "distinct_contracts": len(probes),
        "detectors": totals,
        "per_contract": per_contract,
    }


def load_digest() -> "dict | None":
    if not DIGEST.exists():
        return None
    return json.loads(DIGEST.read_text())


def save_digest(digest: dict) -> None:
    DIGEST.write_text(json.dumps(digest, indent=1, sort_keys=True) + "\n")


def diff_rows(old: dict, new: dict,
              paths: "dict[str, Path] | None" = None) -> "list[str]":
    """Row-level deltas: one line per moved ``(contract, detector)`` cell,
    ``old -> new`` — what a reviewer classifies (TP gained / FP removed /
    regression) by opening the contract at the reported lines."""
    out: "list[str]" = []
    o, n = old.get("per_contract", {}), new.get("per_contract", {})
    for h in sorted(set(o) | set(n)):
        a, b = o.get(h, {}), n.get(h, {})
        label = f"{paths[h].name} ({h})" if paths and h in paths else h
        for name in sorted(set(a) | set(b)):
            if a.get(name) != b.get(name):
                out.append(f"  {label:48} {name:32} "
                           f"{a.get(name, '-')} -> {b.get(name, '-')}")
    return out


def diff_totals(old: dict, new: dict) -> "list[str]":
    """Human-readable per-detector deltas — the part a reviewer reads."""
    out: "list[str]" = []
    o, n = old.get("detectors", {}), new.get("detectors", {})
    for name in sorted(set(o) | set(n)):
        a = o.get(name, {"contracts": 0, "findings": 0, "crashes": 0})
        b = n.get(name, {"contracts": 0, "findings": 0, "crashes": 0})
        if a == b:
            continue
        out.append(
            f"  {name:32} contracts {a['contracts']:4} -> {b['contracts']:<4} "
            f"findings {a['findings']:5} -> {b['findings']:<5} "
            f"crashes {a['crashes']} -> {b['crashes']}")
    return out
