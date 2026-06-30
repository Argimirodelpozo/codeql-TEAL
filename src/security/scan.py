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


def _drop_superseded(detectors: Iterable[str]) -> list[str]:
    """Drop any detector marked ``superseded_by`` a superseder that is actually
    going to run -- the superseder covers it (and falls back to it internally),
    so a default scan runs only the superseder and avoids duplicate findings.

    A detector is dropped only when its superseder is BOTH registered AND present
    in this very set: if the superseder was filtered out (e.g. ``exclude``-d), the
    superseded detector is KEPT so its analysis still runs as the fallback. An
    explicit ``only`` list bypasses this entirely (request a detector by name)."""
    survivors = list(detectors)
    present = set(survivors)
    out: list[str] = []
    for d in survivors:
        cls = DETECTORS.get(d)
        sup = getattr(cls, "superseded_by", None)
        if sup and sup in DETECTORS and sup in present:
            continue
        out.append(d)
    return out


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
            # explicit list overrides supersession -- ask for any detector by name
            return [d for d in self.only if d in DETECTORS]
        if self.exclude is not None:
            excl = set(self.exclude)
            return _drop_superseded(d for d in all_detectors if d not in excl)
        return _drop_superseded(all_detectors)


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
        return _drop_superseded(DETECTORS)


# ---------------------------------------------------------------------------
# Unified detection options (one YAML)
# ---------------------------------------------------------------------------


# Ascending severity. "informational" findings (e.g. is-deletable) are reported
# but, by default, do not constitute a failure — see DetectionOptions.fail_on.
SEVERITY_ORDER = ("informational", "low", "medium", "high")


@dataclass(frozen=True)
class DetectionOptions:
    """Declarative detection options from ONE YAML/JSON file — no inference.

    .. code-block:: yaml

        modes:                       # per-glob mode; scopes detectors by applies_to
          - match: "**/*.approval.teal"
            mode: app
          - match: "**/*Verifier.teal"
            mode: logicsig
        detectors:                   # per-glob detector selection (only | exclude)
          - match: "**/*.teal"
            exclude: [unsafe-lsig-args]
        severity:                    # per-detector severity override
          rekey-to: high
          is-deletable: informational
        fail_on: medium              # findings at/above this level are FAILURES;
                                     # informational (and anything below) never fails
        auto_mode: false             # opt-in: classify undeclared files by opcode

    A file matching no ``modes`` rule is unfiltered (every selected detector
    runs) unless ``auto_mode`` is set, which then classifies it by opcode."""

    modes: DetectionConfig = DetectionConfig.empty()
    selection: ScanConfig = ScanConfig.empty()
    severity: tuple[tuple[str, str], ...] = ()   # (detector, level) pairs
    fail_on: str = "low"
    auto_mode: bool = False

    @classmethod
    def from_path(cls, path: Path) -> "DetectionOptions":
        text = Path(path).read_text()
        if str(path).endswith((".yml", ".yaml")):
            import yaml
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionOptions":
        fail_on = data.get("fail_on", "low")
        if fail_on not in SEVERITY_ORDER:
            raise ValueError(
                f"fail_on {fail_on!r} invalid (expected one of {SEVERITY_ORDER})")
        sev = data.get("severity") or {}
        for det, lvl in sev.items():
            if lvl not in SEVERITY_ORDER:
                raise ValueError(
                    f"severity[{det!r}] = {lvl!r} invalid "
                    f"(expected one of {SEVERITY_ORDER})")
        return cls(
            modes=DetectionConfig.from_dict(data),
            selection=ScanConfig.from_dict({"rules": data.get("detectors", [])}),
            severity=tuple(sorted(sev.items())),
            fail_on=fail_on,
            auto_mode=bool(data.get("auto_mode", False)),
        )

    def mode_for(self, rel_path: str, prog=None, file=None) -> Optional[str]:
        """Declared mode for ``rel_path``; if none and ``auto_mode`` is set,
        classify ``prog`` by opcode (opt-in inference). Else ``None``."""
        m = self.modes.mode_for(rel_path)
        if m is None and self.auto_mode and prog is not None:
            from .common import classify_program
            return classify_program(prog, file=file)
        return m

    def detectors_for(self, rel_path: str) -> list[str]:
        return self.selection.detectors_for(rel_path)

    def severity_for(self, detector_name: str) -> str:
        from . import severity_of
        return dict(self.severity).get(detector_name, severity_of(detector_name))

    def is_failure(self, severity: str) -> bool:
        """A finding of this severity is a FAILURE (something is wrong) iff it is
        at or above ``fail_on``. Informational findings never fail by default."""
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(self.fail_on)


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
    severity_override: Optional[str] = None  # set by scan from DetectionOptions

    @property
    def severity(self) -> str:
        """The finding's severity — a per-detector override from the detection
        options if given, else the detector's declared ``severity``
        (``"informational"`` for property-style findings like ``is-deletable``;
        ``"medium"`` by default)."""
        if self.severity_override is not None:
            return self.severity_override
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
    options: "Optional[DetectionOptions]" = None,
) -> list[ScanFinding]:
    """Discover, reconstruct, and detect. Returns a flat list of findings
    sorted by ``(rel_path, detector_name)``.

    Pass a single unified ``options`` (:class:`DetectionOptions` from one YAML)
    for detector selection + mode scoping + per-detector severity (and it carries
    the ``fail_on`` threshold for :func:`failures`). The legacy ``config`` /
    ``detection_config`` pair still works and is used when ``options`` is None.

    A detector whose ``applies_to`` excludes a file's declared mode is skipped.
    A file with no declared mode is unfiltered (every selected detector runs)
    unless ``options.auto_mode`` is set, which classifies it by opcode."""
    if options is not None:
        config = options.selection
        detection_config = options.modes
    root = Path(root).resolve()
    by_dir = discover_teal_files(root)
    logger.info("scan: %d .teal file(s) across %d director(ies) under %s",
                sum(len(v) for v in by_dir.values()), len(by_dir), root)
    findings: list[ScanFinding] = []
    for dir_path, teal_files in sorted(by_dir.items()):
        for teal in teal_files:
            rel = teal.relative_to(root)
            # ONE SSAProgram PER FILE. Each .teal is an independent program (the
            # AVM runs approval / clear-state programs separately), and a per-file
            # program keeps a per-file detector's cost from scaling with the whole
            # directory -- loading a directory of N contracts into one program made
            # the per-file detectors roughly O(N^2). Genuine cross-contract
            # analysis builds its own multi-program setup in `security.xcontract`;
            # it does not go through this single-contract scanner.
            try:
                prog = SSAProgram(str(teal))
            except Exception as e:                   # pragma: no cover
                logger.warning("could not reconstruct SSA for %s: %s", rel, e)
                continue
            names = config.detectors_for(str(rel))
            if options is not None:
                mode = options.mode_for(str(rel), prog=prog, file=teal.name)
            else:
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
                # The program holds exactly this file (keyed by basename); pass
                # it as the file filter so the detector scopes to it.
                det = cls(prog, file=teal.name)
                sev = options.severity_for(name) if options is not None else None
                for v in det.detect():
                    findings.append(ScanFinding(
                        rel_path=rel, detector_name=name, violation=v,
                        severity_override=sev,
                    ))
    findings.sort(key=lambda f: (str(f.rel_path), f.detector_name))
    return findings


def failures(
    findings: list[ScanFinding], options: "Optional[DetectionOptions]" = None,
) -> list[ScanFinding]:
    """The subset of ``findings`` that are FAILURES — at or above the
    ``options.fail_on`` threshold (default ``"low"``, so informational findings
    are reported but never fail). With no options, every finding counts."""
    if options is None:
        return list(findings)
    return [f for f in findings if options.is_failure(f.severity)]


def render_text(findings: list[ScanFinding]) -> str:
    if not findings:
        return "(no findings)"
    return "\n".join(f.format() for f in findings)


def render_json(findings: list[ScanFinding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
