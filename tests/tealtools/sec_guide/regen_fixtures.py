"""Regenerate the sec-guide fixture tree from `security/detections/`.

Each `.teal` file under `security/detections/<detection>/` (recursive)
gets a fixture directory at `tests/tealtools/sec_guide/<detection>/<case>/`
with `prog.teal` copied in. Symlinks aren't used because the codeql
extractor scanner doesn't follow them — copies make the DB build see
the source directly. Run this script if you edit a fixture .teal in
`security/detections/`; missing DBs are then auto-built by the
session-start hook in `tests/conftest.py`.

Idempotent: existing prog.teal files are overwritten with the source
contents.
"""
from __future__ import annotations

import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO / "security" / "detections"
DST_ROOT = REPO / "tests" / "tealtools" / "sec_guide"

# Production sec-guide queries that have a Python port. Anything else
# under security/detections/ (constant-propagation-tests, phi-liveness,
# puya-benchmarks, experimental-archive) isn't a detection and is
# skipped intentionally.
PORTED = (
    "asset-close-to", "asset-id-validation", "close-remainder-to",
    "delete-funds-check", "fee-validation", "group-size-check",
    "hardcoded-min-balance", "inner-txn-close-rekey", "inner-txn-fee",
    "is-deletable", "is-updatable", "rekey-to", "timelock-upgrade",
    "tx-type-check", "unprotected-deletable", "unprotected-updatable",
    "unsafe-lsig-args",
)


def case_name(rel: Path) -> str:
    """`proto-sub/vuln-proto-arg.teal` -> `proto_sub__vuln_proto_arg`."""
    no_ext = rel.with_suffix("")
    parts = [str(p).replace("-", "_") for p in no_ext.parts]
    return "__".join(parts)


def main() -> int:
    total = 0
    for det in PORTED:
        src_dir = SRC_ROOT / det
        if not src_dir.is_dir():
            print(f"WARN: source dir {src_dir} missing")
            continue
        dst_det = DST_ROOT / det.replace("-", "_")
        dst_det.mkdir(parents=True, exist_ok=True)
        for teal in sorted(src_dir.rglob("*.teal")):
            rel = teal.relative_to(src_dir)
            dst_case = dst_det / case_name(rel)
            dst_case.mkdir(parents=True, exist_ok=True)
            shutil.copy2(teal, dst_case / "prog.teal")
            total += 1
    print(f"copied {total} sec-guide fixtures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
