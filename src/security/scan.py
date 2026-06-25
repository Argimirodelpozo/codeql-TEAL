"""Recursive sec-guide scan over a TEAL codebase.

Walks a root directory for ``.teal`` files, groups them by parent dir,
reconstructs the SSA for each dir straight from its raw ``.teal`` source,
then runs each registered sec-guide detector against each ``.teal``
independently using the ``file=`` filter on the detector.

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

    from security.scan import scan, ScanConfig
    findings = scan(Path("contracts/"), ScanConfig.from_path(Path("rules.yml")))
    for f in findings:
        print(f.format())

CLI: ``python -m tealtools sec-guide-scan <root> [--config rules.yml]
[--json]``.
"""
from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from tealtools.ssa import SSAProgram
from . import DETECTORS
from .config import DetectionConfig

logger = logging.getLogger("security.scan")


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

    @property
    def severity(self) -> str:
        """The detector's severity (``"informational"`` for property-style
        findings like ``is-deletable``; ``"medium"`` by default)."""
        from . import severity_of
        return severity_of(self.detector_name)

    def format(self) -> str:
        """One-line greppable form:
        ``[SEVERITY] <rel_path>: sec-guide/<name>  <message>``."""
        return (f"[{self.severity.upper()}] {self.rel_path}: "
                f"sec-guide/{self.detector_name}  {self.violation.pretty()}")  # type: ignore[attr-defined]

    def to_dict(self) -> dict:
        return {
            "file": str(self.rel_path),
            "detector": f"sec-guide/{self.detector_name}",
            "severity": self.severity,
            "message": self.violation.pretty(),  # type: ignore[attr-defined]
        }


def scan(
    root: Path,
    config: ScanConfig = ScanConfig.empty(),
    *,
    detection_config: "Optional[DetectionConfig]" = None,
) -> list[ScanFinding]:
    """Discover, reconstruct, and detect. Returns a flat list of findings
    sorted by ``(rel_path, detector_name)``.

    ``config`` selects *which* detectors run per file (glob → only /
    exclude). ``detection_config`` declares each file's *mode* (app /
    logicsig); a detector whose ``applies_to`` excludes the declared
    mode is skipped. A file the ``detection_config`` doesn't match (or
    no ``detection_config`` at all) is left unfiltered — every selected
    detector runs. No opcode inference happens.

    Progress is reported through the ``tealtools`` logger (CLI ``-v``)."""
    root = Path(root).resolve()
    by_dir = discover_teal_files(root)
    logger.info("scan: %d .teal file(s) across %d director(ies) under %s",
                sum(len(v) for v in by_dir.values()), len(by_dir), root)
    findings: list[ScanFinding] = []
    for dir_path, teal_files in sorted(by_dir.items()):
        # Reconstruct straight from the raw .teal directory (pure-Python graph
        # backend) -- no DB build. `SSAProgram` over a directory loads
        # every .teal in it, keyed by basename, which is the same `file=`
        # filter the detectors use below.
        try:
            prog = SSAProgram(str(dir_path))
        except Exception as e:                       # pragma: no cover
            logger.warning("could not reconstruct SSA for %s: %s", dir_path, e)
            continue
        for teal in teal_files:
            rel = teal.relative_to(root)
            names = config.detectors_for(str(rel))
            mode = (detection_config.mode_for(str(rel))
                    if detection_config is not None else None)
            logger.info("scanning %s (mode=%s): %d detection(s)",
                        rel, mode or "unfiltered", len(names))
            for name in names:
                cls = DETECTORS.get(name)
                if cls is None:
                    continue
                if mode is not None:
                    applies = getattr(
                        cls, "applies_to", frozenset({"app", "logicsig"}),
                    )
                    if mode not in applies:
                        continue
                # ``SSAProgram`` keys files by basename; pass that as the
                # file filter so detectors see exactly this program.
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
