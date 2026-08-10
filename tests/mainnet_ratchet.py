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
app-mode detector over the mainnet probe corpus and records, per detector, how
many contracts it fires on and how many findings it produces. A change in
detector behaviour — in either direction — moves the digest and must be
explained.

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


def _analyse(path: Path, names: "list[str]") -> "dict[str, int | str]":
    """``{detector: finding_count}`` for one program, with crashes recorded."""
    row: "dict[str, int | str]" = {}
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
            row[name] = len(vs)
    return row


def summarize_rows(names: "list[str]", per_contract: dict) -> dict:
    """Aggregate detector totals from exact per-contract result rows."""
    totals: "dict[str, dict]" = {}
    for name in names:
        contracts = [h for h, row in per_contract.items() if name in row]
        crashes = [h for h in contracts if isinstance(per_contract[h][name], str)]
        findings = sum(per_contract[h][name] for h in contracts
                       if isinstance(per_contract[h][name], int))
        totals[name] = {
            "contracts": len(contracts) - len(crashes),
            "findings": findings,
            "crashes": len(crashes),
        }
    return totals


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
