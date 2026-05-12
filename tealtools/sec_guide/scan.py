"""Recursive sec-guide scan over a TEAL codebase.

Walks a root directory for ``.teal`` files, groups them by parent dir,
builds (or re-uses) one CodeQL DB per dir, then runs each registered
sec-guide detector against each ``.teal`` independently using the
``file=`` filter on the detector. The DB cache lives at
``~/.cache/teal-sec-guide-scan/<sha-of-dir-contents>/`` and is keyed
by the contents of every ``.teal`` in the dir, so re-running on the
same tree is fast and a single edit only invalidates one dir's DB.

Per-file detector selection is driven by an optional yaml/json config:

.. code-block:: yaml

    # First matching rule wins; if no rule matches, every detector runs.
    # `match` is one or more glob patterns evaluated against the file's
    # path relative to the scan root. `only` is a whitelist (run exactly
    # these detectors); `exclude` is a blacklist (skip these). They are
    # mutually exclusive on the same rule.
    rules:
      - match: "**/*lsig*.teal"
        only: [unsafe-lsig-args, fee-validation, tx-type-check, group-size-check]
      - match: ["**/*clearstate*.teal", "**/clear/*.teal"]
        only: []                         # nothing applies to clear-state programs
      - match: "**/*.teal"               # catch-all: skip lsig detector on
        exclude: [unsafe-lsig-args]      # everything that didn't match above

JSON works the same way; the loader picks based on file extension.

Library use::

    from tealtools.sec_guide.scan import scan, ScanConfig
    findings = scan(Path("contracts/"), ScanConfig.from_path(Path("rules.yml")))
    for f in findings:
        print(f.format())

CLI: ``python -m tealtools sec-guide-scan <root> [--config rules.yml]
[--cache <dir>] [--json]``.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..ssa import SSAProgram
from . import DETECTORS

# Lives outside the project so it survives `git clean`. The keys in
# `_dir_db_cache_dir` are content-addressed, so re-running on the same
# tree reuses prior DBs even after a checkout switch.
DEFAULT_CACHE = Path(
    os.environ.get("TEAL_SEC_GUIDE_SCAN_CACHE",
                   Path.home() / ".cache" / "teal-sec-guide-scan")
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRule:
    """One config rule. ``match`` is one or more glob patterns
    (``fnmatch`` semantics — ``*`` matches anything including ``/``,
    so ``*lsig*`` matches at any depth). ``only`` and ``exclude`` are
    mutually exclusive on the same rule. The relative-path-from-root
    is what gets matched."""

    match: tuple[str, ...]
    only: Optional[tuple[str, ...]] = None
    exclude: Optional[tuple[str, ...]] = None

    def matches(self, rel_path: str) -> bool:
        return any(fnmatch.fnmatch(rel_path, pat) for pat in self.match)

    def select(self, all_detectors: Iterable[str]) -> list[str]:
        if self.only is not None:
            return [d for d in self.only if d in DETECTORS]
        if self.exclude is not None:
            excl = set(self.exclude)
            return [d for d in all_detectors if d not in excl]
        return list(all_detectors)


@dataclass(frozen=True)
class ScanConfig:
    """List of :class:`ScanRule` evaluated first-match-wins. Empty
    config (no rules) means every detector runs on every file."""

    rules: tuple[ScanRule, ...] = ()

    @classmethod
    def empty(cls) -> "ScanConfig":
        return cls(())

    @classmethod
    def from_path(cls, path: Path) -> "ScanConfig":
        text = Path(path).read_text()
        if str(path).endswith((".yml", ".yaml")):
            import yaml
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        rules: list[ScanRule] = []
        for raw in data.get("rules", []):
            match = raw.get("match")
            if isinstance(match, str):
                match_tuple = (match,)
            else:
                match_tuple = tuple(match or ())
            rules.append(ScanRule(
                match=match_tuple,
                only=tuple(raw["only"]) if "only" in raw else None,
                exclude=tuple(raw["exclude"]) if "exclude" in raw else None,
            ))
        return cls(tuple(rules))

    def detectors_for(self, rel_path: str) -> list[str]:
        """Resolve the detector set for ``rel_path`` against the rules.
        First match wins; no match means all detectors run."""
        for rule in self.rules:
            if rule.matches(rel_path):
                return rule.select(DETECTORS)
        return list(DETECTORS)


# ---------------------------------------------------------------------------
# Per-dir DB build (content-addressed cache)
# ---------------------------------------------------------------------------


def _codeql() -> str:
    cmd = os.environ.get("CODEQL") or shutil.which("codeql")
    if cmd is None:
        raise RuntimeError(
            "codeql binary not found (set $CODEQL or add to PATH)"
        )
    return cmd


def _search_path() -> Optional[str]:
    """The repo's bundled extractor lives at
    ``<repo>/.codeql-extractors/``. We locate it relative to this file
    so a freshly-cloned checkout works without environment setup."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / ".codeql-extractors"
        if candidate.exists():
            return str(candidate)
    return None


def _dir_signature(teal_files: list[Path]) -> str:
    """Hash the (basename, content) of every teal file in the dir.
    Stable across path moves of the dir as long as basenames + content
    don't change."""
    h = hashlib.sha256()
    for f in sorted(teal_files, key=lambda p: p.name):
        h.update(f.name.encode())
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:16]


def build_db_for_dir(
    teal_files: list[Path],
    *,
    cache_root: Path = DEFAULT_CACHE,
    verbose: bool = False,
) -> Path:
    """Build a CodeQL DB from ``teal_files`` (must all live in the same
    parent dir). Returns the DB path. Idempotent when the contents
    haven't changed.

    The build copies each .teal to a per-cache-entry ``src/`` dir
    (codeql's extractor doesn't follow symlinks), then runs
    ``codeql database create``. Subsequent calls hit the cache.
    """
    if not teal_files:
        raise ValueError("teal_files is empty")
    sig = _dir_signature(teal_files)
    cache_dir = cache_root / sig
    db = cache_dir / "db"
    if (db / "codeql-database.yml").exists():
        return db
    cache_dir.mkdir(parents=True, exist_ok=True)
    src = cache_dir / "src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir()
    for f in teal_files:
        shutil.copy2(f, src / f.name)
    cmd = [_codeql(), "database", "create", str(db),
           "--overwrite", "-l", "teal", "-s", str(src)]
    sp = _search_path()
    if sp is not None:
        cmd.append(f"--search-path={sp}")
    if verbose:
        print(f"[scan] building DB for {sig} from {len(teal_files)} files...")
    subprocess.run(cmd, check=True, capture_output=not verbose)
    return db


# ---------------------------------------------------------------------------
# Discovery + scanning
# ---------------------------------------------------------------------------


def discover_teal_files(root: Path) -> dict[Path, list[Path]]:
    """Walk ``root`` for ``*.teal`` files and group them by parent
    directory. The returned dict's keys are absolute parent dirs; each
    value is a list of teal file paths, sorted by basename."""
    by_dir: dict[Path, list[Path]] = {}
    for teal in sorted(root.rglob("*.teal")):
        by_dir.setdefault(teal.parent.resolve(), []).append(teal.resolve())
    for paths in by_dir.values():
        paths.sort(key=lambda p: p.name)
    return by_dir


@dataclass(frozen=True)
class ScanFinding:
    """One sec-guide finding from the scan. ``rel_path`` is the
    .teal's path relative to the scan root; ``detector_name`` is the
    kebab-case short name (no ``sec-guide/`` prefix)."""

    rel_path: Path
    detector_name: str
    violation: object  # has .pretty()

    def format(self) -> str:
        """One-line greppable form: ``<rel_path>: sec-guide/<name>  <message>``."""
        return f"{self.rel_path}: sec-guide/{self.detector_name}  {self.violation.pretty()}"  # type: ignore[attr-defined]

    def to_dict(self) -> dict:
        return {
            "file": str(self.rel_path),
            "detector": f"sec-guide/{self.detector_name}",
            "message": self.violation.pretty(),  # type: ignore[attr-defined]
        }


def scan(
    root: Path,
    config: ScanConfig = ScanConfig.empty(),
    *,
    cache_root: Path = DEFAULT_CACHE,
    verbose: bool = False,
) -> list[ScanFinding]:
    """Discover, build, and detect. Returns a flat list of findings
    sorted by ``(rel_path, detector_name)``."""
    root = Path(root).resolve()
    by_dir = discover_teal_files(root)
    findings: list[ScanFinding] = []
    for dir_path, teal_files in sorted(by_dir.items()):
        try:
            db = build_db_for_dir(teal_files, cache_root=cache_root, verbose=verbose)
        except subprocess.CalledProcessError as e:
            if verbose:
                print(f"[scan] codeql build failed for {dir_path}: {e}")
            continue
        prog = SSAProgram(str(db))
        for teal in teal_files:
            rel = teal.relative_to(root)
            names = config.detectors_for(str(rel))
            for name in names:
                cls = DETECTORS.get(name)
                if cls is None:
                    continue
                # The DB stores files by basename (since we copied them
                # into the per-DB ``src/``); pass that as the file
                # filter so detectors see exactly this program.
                det = cls(prog, file=teal.name)
                for v in det.detect():
                    findings.append(ScanFinding(
                        rel_path=rel, detector_name=name, violation=v,
                    ))
    findings.sort(key=lambda f: (str(f.rel_path), f.detector_name))
    return findings


def render_text(findings: list[ScanFinding]) -> str:
    if not findings:
        return "(no findings)"
    return "\n".join(f.format() for f in findings)


def render_json(findings: list[ScanFinding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
