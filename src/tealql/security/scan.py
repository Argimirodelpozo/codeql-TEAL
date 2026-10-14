"""Recursive sec-guide scan over a TEAL codebase.

Each ``.teal`` file is reconstructed independently. :class:`DetectionOptions`
is the single configuration surface for selection, modes, severity, and failure
thresholds.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Iterable, Optional

from tealql.tealtools.diagnostics.errors import (
    TargetError, TargetNotFoundError, TealParseError, TealQLError,
)
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.diagnostics.health import AnalysisDegradation, AnalysisHealth, AnalysisResult, health_for
from . import DETECTORS
from .config import ConfigError, DetectionConfig, glob_match

logger = logging.getLogger("tealql.security.scan")


def _method_ranges_for(teal: Path, method_table=None):
    """ABI method line-spans for a ``.teal`` (source ``method "sig"`` comments or an
    ARC-56 ``method_table``), or ``[]`` — an OPTIONAL enrichment, so every failure
    degrades to no attribution rather than breaking the scan."""
    try:
        from tealql.tealtools.metadata.abi import method_line_ranges
        return method_line_ranges(
            Path(teal).read_text(errors="ignore"), method_table=method_table)
    except Exception:
        return []


def _arc56_method_table(arc56):
    """``{selector_hex: AbiMethod}`` from an ARC-56 spec (or a path to one), or
    ``None`` — an OPTIONAL enrichment, so a bad/absent spec degrades to no table."""
    if arc56 is None:
        return None
    try:
        from tealql.tealtools.metadata.arc56 import Arc56Spec, load_optional
        spec = arc56 if isinstance(arc56, Arc56Spec) else load_optional(arc56)
        return spec.method_table() if spec is not None else None
    except Exception:
        return None


class _PartitionFallback:
    """Lazily-built method partitions for one program (OPTIONAL enrichment:
    any failure means no fallback attribution, never a broken scan)."""

    def __init__(self, prog, file: str, method_table=None):
        self.prog, self.file, self.method_table = prog, file, method_table
        self._built = False
        self._pp = None

    def get(self):
        if not self._built:
            self._built = True
            try:
                from tealql.tealtools.cfg.partition import PartitionedPredicates
                self._pp = PartitionedPredicates(
                    self.prog, key="method", method_table=self.method_table)
            except Exception:
                self._pp = None
        return self._pp


def _method_at(ranges, violation, fallback: "_PartitionFallback | None" = None) -> Optional[str]:
    """The ABI method name a violation sits in (by its source line), or ``None``;
    when the line spans miss, the trace partitions may attribute it."""
    if not ranges and fallback is None:
        return None
    try:
        from tealql.tealtools.metadata.abi import method_at_line_or_partition
        from .findings import violation_line
        line = violation_line(violation)
        m = method_at_line_or_partition(ranges, line)
        if m is None and fallback is not None and line is not None:
            m = method_at_line_or_partition(
                ranges, line, partitions=fallback.get(), file=fallback.file)
        return m.name if m is not None else None
    except Exception:
        return None


def default_detection_names(names: Optional[Iterable[str]] = None) -> list[str]:
    """Materialize ``names``, defaulting to the canonical detector registry."""
    return list(DETECTORS if names is None else names)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DetectorRule:
    """One config rule, matched against the file's path relative to the scan root.

    ``match`` globs use ``fnmatch`` semantics: ``*`` matches ``/`` too, so
    ``*lsig*`` matches at any depth and a ``**/`` prefix also matches files at the
    root. ``only`` and ``exclude`` are mutually exclusive on the same rule."""

    match: tuple[str, ...]
    only: Optional[tuple[str, ...]] = None
    exclude: Optional[tuple[str, ...]] = None

    def matches(self, rel_path: str) -> bool:
        return any(glob_match(rel_path, pat) for pat in self.match)

    def select(self, all_detectors: Iterable[str]) -> list[str]:
        if self.only is not None:
            # explicit list overrides supersession — ask for any detector by name
            return [d for d in self.only if d in DETECTORS]
        if self.exclude is not None:
            excl = set(self.exclude)
            return [d for d in all_detectors if d not in excl]
        return list(all_detectors)


@dataclass(frozen=True)
class _DetectorSelection:
    """First-match-wins detector rules owned by :class:`DetectionOptions`."""

    rules: tuple[_DetectorRule, ...] = ()

    @classmethod
    def empty(cls) -> "_DetectorSelection":
        return cls(())

    @classmethod
    def from_rules(cls, raw_rules) -> "_DetectorSelection":
        """Build + validate — every mistake that would silently change scan coverage
        (unknown detector name, both ``only`` and ``exclude``, missing ``match``,
        unknown rule key) raises :class:`ConfigError` at load time."""
        rules: list[_DetectorRule] = []
        for raw in raw_rules or ():
            unknown = set(raw) - {"match", "only", "exclude"}
            if unknown:
                raise ConfigError(
                    f"rule has unknown key(s) {sorted(unknown)}: {raw!r}")
            match = raw.get("match")
            if isinstance(match, str):
                match_tuple = (match,)
            else:
                match_tuple = tuple(match or ())
            if not match_tuple:
                raise ConfigError(f"rule missing 'match': {raw!r}")
            if "only" in raw and "exclude" in raw:
                raise ConfigError(
                    f"rule has BOTH 'only' and 'exclude' (mutually "
                    f"exclusive): {raw!r}")
            for key in ("only", "exclude"):
                bad = [d for d in (raw.get(key) or ()) if d not in DETECTORS]
                if bad:
                    raise ConfigError(
                        f"rule {key!r} names unknown detector(s) {bad} "
                        f"(run `tealql detections --list` for the registry)")
            rules.append(_DetectorRule(
                match=match_tuple,
                only=tuple(raw["only"]) if "only" in raw else None,
                exclude=tuple(raw["exclude"]) if "exclude" in raw else None,
            ))
        return cls(tuple(rules))

    def detectors_for(self, rel_path: str) -> list[str]:
        """Detector set for ``rel_path``; first match wins, no match means all run."""
        for rule in self.rules:
            if rule.matches(rel_path):
                return rule.select(DETECTORS)
        return list(DETECTORS)


# ---------------------------------------------------------------------------
# Unified detection options (one YAML)
# ---------------------------------------------------------------------------


# Ascending. "informational" is reported but never fails by default (fail_on).
SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class DetectionOptions:
    """Declarative detection options from ONE YAML/JSON file — no inference.

    .. code-block:: yaml

        modes:                                  # per-glob mode; scopes by applies_to
          - {match: "**/*.approval.teal", mode: app}
        detectors:                              # per-glob selection (only | exclude)
          - {match: "**/*.teal", exclude: [unsafe-lsig-args]}
        severity: {rekey-to: high}              # per-detector override
        fail_on: medium                         # at/above this level = FAILURE
        auto_mode: false                        # opt-in: classify by opcode

    A file matching no ``modes`` rule is unfiltered (every selected detector runs)
    unless ``auto_mode`` is set."""

    modes: DetectionConfig = DetectionConfig.empty()
    selection: _DetectorSelection = _DetectorSelection.empty()
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
        unknown = set(data) - {"modes", "detectors", "severity", "fail_on",
                               "auto_mode"}
        if unknown:
            raise ConfigError(
                f"unknown top-level option key(s) {sorted(unknown)} "
                f"(expected: modes, detectors, severity, fail_on, auto_mode)")
        fail_on = data.get("fail_on", "low")
        if fail_on not in SEVERITY_ORDER:
            raise ConfigError(
                f"fail_on {fail_on!r} invalid (expected one of {SEVERITY_ORDER})")
        sev = data.get("severity") or {}
        for det, lvl in sev.items():
            if det not in DETECTORS:
                raise ConfigError(
                    f"severity override names unknown detector {det!r} "
                    f"(run `tealql detections --list` for the registry)")
            if lvl not in SEVERITY_ORDER:
                raise ConfigError(
                    f"severity[{det!r}] = {lvl!r} invalid "
                    f"(expected one of {SEVERITY_ORDER})")
        return cls(
            modes=DetectionConfig.from_dict(data),
            selection=_DetectorSelection.from_rules(data.get("detectors", [])),
            severity=tuple(sorted(sev.items())),
            fail_on=fail_on,
            auto_mode=bool(data.get("auto_mode", False)),
        )

    def mode_for(self, rel_path: str, prog=None, file=None) -> Optional[str]:
        """Declared mode for ``rel_path``, else opcode inference when ``auto_mode``."""
        m = self.modes.mode_for(rel_path)
        if m is None and self.auto_mode and prog is not None:
            from ._program_shape import classify_program
            return classify_program(prog, file=file)
        return m

    def detectors_for(self, rel_path: str) -> list[str]:
        return self.selection.detectors_for(rel_path)

    def severity_for(self, detector_name: str) -> str:
        from . import severity_of
        return dict(self.severity).get(detector_name, severity_of(detector_name))

    def severity_override_for(self, detector_name: str) -> Optional[str]:
        """An explicitly configured severity, or ``None``.

        Finding-level severities (for example CRITICAL close fields versus
        MEDIUM amounts) must remain authoritative when no override was declared.
        """
        return dict(self.severity).get(detector_name)

    def is_failure(self, severity: str) -> bool:
        """A finding of this severity is a FAILURE iff it is at or above ``fail_on``."""
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(self.fail_on)


# ---------------------------------------------------------------------------
# Discovery + scanning
# ---------------------------------------------------------------------------


def discover_teal_files(root: Path) -> dict[Path, list[Path]]:
    """Walk ``root`` for ``*.teal``, grouped by absolute parent dir, sorted by basename.

    HAZARD: a missing or non-directory ``root`` RAISES rather than returning empty —
    a mistyped path would otherwise rglob nothing, report "(no findings)" and exit 0,
    a green CI run on a directory that was never scanned."""
    if not root.exists():
        raise TargetNotFoundError(f"scan root does not exist: {root}")
    if not root.is_dir():
        raise TargetError(f"scan root is not a directory: {root}")
    by_dir: dict[Path, list[Path]] = {}
    for teal in sorted(root.rglob("*.teal")):
        by_dir.setdefault(teal.parent.resolve(), []).append(teal.resolve())
    for paths in by_dir.values():
        paths.sort(key=lambda p: p.name)
    return by_dir


@dataclass(frozen=True)
class ScanFinding:
    """One scan finding: ``rel_path`` is relative to the scan root, ``detector_name``
    the kebab short name (no ``sec-guide/`` prefix)."""

    rel_path: Path
    detector_name: str
    violation: object  # has .pretty()
    severity_override: Optional[str] = None  # set by scan from DetectionOptions
    # OPTIONAL — None on raw bytecode / non-ABI code; set by scan when available.
    method_name: Optional[str] = None
    #: Source context around the anchored line (see ``suppress.anchor_text``):
    #: what makes the baseline fingerprint distinguish two findings whose
    #: messages differ only by line number. ``""`` for whole-program findings.
    anchor: str = ""

    @property
    def severity(self) -> str:
        """Severity, in precedence order: the per-detector options override; else the
        VIOLATION's own ``severity`` when valid (the IR taint family grades per sink
        field); else the detector's declared class ``severity``."""
        if self.severity_override is not None:
            return self.severity_override
        from . import SEVERITY_LEVELS, severity_of
        v = getattr(self.violation, "severity", None)
        if isinstance(v, str) and v.lower() in SEVERITY_LEVELS:
            return v.lower()
        return severity_of(self.detector_name)

    @property
    def confidence(self) -> str:
        """How likely this finding is a true positive (:func:`..confidence_of`)."""
        from . import confidence_of
        return confidence_of(self.detector_name)

    def format(self) -> str:
        """Greppable ``[SEVERITY] <rel_path> [method]: sec-guide/<name>  <message>``."""
        loc = f"{self.rel_path} [{self.method_name}]" if self.method_name else self.rel_path
        return (f"[{self.severity.upper()}] {loc}: "
                f"sec-guide/{self.detector_name}  {self.to_finding().message}")

    @cached_property
    def _normalized(self):
        """Normalize to the stable versioned :class:`.findings.Finding` record."""
        from .findings import normalize_violation
        return normalize_violation(
            self.violation, self.detector_name, rel_path=self.rel_path,
            method=self.method_name, severity_override=self.severity_override,
        )

    def to_finding(self):
        return self._normalized

    def to_dict(self) -> dict:
        """Return the versioned normalized finding record."""
        return self.to_finding().to_dict()


@dataclass(frozen=True)
class ScanNotification:
    """Something the scan could NOT do, carried alongside the findings.

    HAZARD: without this, "no findings" has two meanings — analyzed and clean,
    or never analyzed at all — and the output cannot tell them apart. A contract
    that fails to lift cannot run lifted policies and must not look clean.

    ``kind`` is a stable machine-readable slug; ``message`` is for humans."""

    kind: str
    message: str
    rel_path: Optional[str] = None
    detector: Optional[str] = None
    line: Optional[int] = None

    def format(self) -> str:
        where = (f" {self.rel_path}:{self.line}" if self.rel_path and self.line
                 else f" {self.rel_path}" if self.rel_path else "")
        who = f" [{self.detector}]" if self.detector else ""
        return f"[DEGRADED]{where}{who}: {self.message}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "message": self.message,
                "file": self.rel_path, "line": self.line, "detector": self.detector}


@dataclass(frozen=True, init=False)
class ScanResults(AnalysisResult):
    """Structured scan output: findings plus incomplete-analysis notices."""

    notifications: tuple[ScanNotification, ...]

    def __init__(self, findings=(), notifications=()):
        notifications = tuple(notifications)
        super().__init__(tuple(findings), AnalysisHealth(tuple(
            AnalysisDegradation(n.kind, n.message, n.rel_path, n.line, detector=n.detector)
            for n in notifications)))
        object.__setattr__(self, 'notifications', notifications)

    @property
    def findings(self):
        return self.value

    def __iter__(self):
        return iter(self.findings)

    def __len__(self):
        return len(self.findings)

    def __getitem__(self, index):
        return self.findings[index]


def _notifications_of(results: ScanResults) -> tuple[ScanNotification, ...]:
    return results.notifications


def scan(
    root: Path,
    *,
    options: "Optional[DetectionOptions]" = None,
    strict: bool = False,
    arc56=None,
) -> ScanResults:
    """Discover, reconstruct, and detect; findings sorted by ``(rel_path, detector)``.

    ``options`` supplies selection, mode scoping, severity, and failure policy. A detector whose
    ``applies_to`` excludes a file's declared mode is skipped; a file with no declared
    mode is unfiltered unless ``options.auto_mode``. ``arc56`` is an OPTIONAL
    selector→method-name source and degrades cleanly when absent.

    HAZARD: a file the grammar cannot fully parse is analyzed PARTIALLY (unparsed
    spans excluded — findings there may be missing) and one whose SSA cannot be
    reconstructed is SKIPPED, both with a warning only. ``strict=True`` raises
    instead, so CI can refuse a clean bill for input that was never analyzed."""
    options = options or DetectionOptions()
    root = Path(root).resolve()
    by_dir = discover_teal_files(root)
    return _scan_discovered(root, by_dir, options=options, strict=strict, arc56=arc56)


def scan_target(
    target: "str | Path",
    *,
    options: "Optional[DetectionOptions]" = None,
    strict: bool = False,
    arc56=None,
) -> ScanResults:
    """:func:`scan` for the CLI's universal ``<target>``: a directory (walked
    recursively, paths relative to it) OR a single ``.teal`` file (scanned alone,
    reported by basename).

    :func:`discover_teal_files` deliberately refuses a file as a scan ROOT — a
    mistyped CI root must not scan nothing and pass. A single file named
    explicitly is a different intent, so it is honoured here without relaxing
    that guard; a non-``.teal`` file still raises."""
    path = Path(target).resolve()
    if path.is_dir():
        return scan(path, options=options, strict=strict, arc56=arc56)
    if not path.exists():
        raise TargetNotFoundError(f"target does not exist: {target}")
    if path.suffix != ".teal":
        raise TargetError(f"{target}: not a .teal file or a directory")
    return _scan_discovered(path.parent, {path.parent: [path]},
                            options=options or DetectionOptions(),
                            strict=strict, arc56=arc56)


def _scan_discovered(root: Path, by_dir: "dict[Path, list[Path]]", *,
                     options: DetectionOptions, strict: bool, arc56) -> ScanResults:
    """The scan proper over already-discovered files; ``rel_path`` is each
    file's path relative to ``root``."""
    method_table = _arc56_method_table(arc56)
    n_files = sum(len(v) for v in by_dir.values())
    logger.info("scan: %d .teal file(s) across %d director(ies) under %s",
                n_files, len(by_dir), root)
    findings: list[ScanFinding] = []
    notes: list[ScanNotification] = []
    if not n_files:
        # "(no findings)" here is true but misleading — nothing was analyzed.
        msg = f"no .teal files found under {root} — nothing was analyzed"
        if strict:
            raise TealQLError(msg)
        logger.warning("%s", msg)
        notes.append(ScanNotification('empty-scan', msg))
    for dir_path, teal_files in sorted(by_dir.items()):
        for teal in teal_files:
            rel = teal.relative_to(root)
            # ONE SSAProgram PER FILE: each .teal is an independent AVM program, and
            # sharing one program across a directory of N contracts makes the
            # per-file detectors O(N^2). Cross-contract analysis lives in
            # `tealql.security.xcontract`, not in this single-contract scanner.
            try:
                prog = SSAProgram(str(teal), strict=False)
            except Exception as e:                   # pragma: no cover
                if strict:
                    raise TealQLError(
                        f"could not reconstruct SSA for {rel}: {e}") from e
                logger.warning("could not reconstruct SSA for %s: %s", rel, e)
                notes.append(ScanNotification(
                    kind="ssa-failed", rel_path=str(rel),
                    message=f"SSA could not be reconstructed, so NO detector "
                            f"ran on this file: {e}"))
                continue
            diags = getattr(prog, "parse_diagnostics", ())
            if diags:
                if strict:
                    raise TealParseError(diags)
                logger.warning(
                    "%s: %d TEAL span(s) failed to parse and were EXCLUDED "
                    "from analysis — findings for this file may be "
                    "incomplete (first: %s)", rel, len(diags), diags[0])
                notes.append(ScanNotification(
                    kind="parse-incomplete", rel_path=str(rel),
                    message=f"{len(diags)} TEAL span(s) failed to parse and "
                            f"were EXCLUDED from analysis, so findings for "
                            f"this file may be incomplete (first: {diags[0]})"))
            for degradation in health_for(prog).degradations:
                if degradation.code == 'parse-diagnostic':
                    continue  # Detailed parse handling above preserves TealParseError.
                if strict:
                    raise TealQLError(f'incomplete input {rel}: {degradation.message}')
                notes.append(ScanNotification(degradation.code, degradation.message, str(rel),
                                              line=degradation.line))
            names = options.detectors_for(str(rel))
            try:
                mode = options.mode_for(str(rel), prog=prog, file=teal.name)
            except Exception as e:                   # auto-mode classifies by opcode
                if strict:
                    raise TealQLError(
                        f"mode classification failed for {rel}: {e}") from e
                logger.warning(
                    "mode classification failed for %s (scanning unfiltered): %s",
                    rel, e)
                notes.append(ScanNotification('mode-classification-failed', str(e), str(rel)))
                mode = None
            logger.info("scanning %s (mode=%s): %d detection(s)",
                        rel, mode or "unfiltered", len(names))
            # OPTIONAL: map each finding's line to the ABI method it sits in.
            method_ranges = _method_ranges_for(teal, method_table)
            method_fallback = _PartitionFallback(prog, teal.name, method_table)
            try:
                source_lines = Path(teal).read_text(errors="ignore").splitlines()
            except OSError:
                source_lines = []
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
                # The program holds exactly this file (keyed by basename); the
                # file filter scopes the detector to it.
                sev = options.severity_override_for(name)
                try:
                    # Construction AND detection are both guarded: detectors that
                    # analyze in __init__ must not kill a whole corpus scan either.
                    # The ERROR log keeps the crash visible; strict mode raises.
                    det = cls(prog, file=teal.name)
                    violations = list(det.detect())
                except Exception as e:
                    if strict:
                        raise TealQLError(
                            f"detector {name} crashed on {rel}: {e}") from e
                    logger.error(
                        "detector %s crashed on %s (skipped): %s", name, rel, e)
                    notes.append(ScanNotification(
                        kind="detector-crashed", rel_path=str(rel), detector=name,
                        message=f"detector crashed and was skipped, so it "
                                f"produced no findings for this file: {e}"))
                    continue
                degraded = getattr(det, "degraded", None)
                if degraded:
                    if strict:
                        raise TealQLError(
                            f"detector {name} ran degraded on {rel}: {degraded}")
                    logger.warning("detector %s degraded on %s: %s",
                                   name, rel, degraded)
                    notes.append(ScanNotification(
                        kind="detector-degraded", rel_path=str(rel),
                        detector=name, message=degraded))
                for v in violations:
                    try:
                        from .findings import violation_line
                        from .suppress import anchor_text
                        finding = ScanFinding(
                            rel_path=rel, detector_name=name, violation=v,
                            severity_override=sev,
                            method_name=_method_at(method_ranges, v, method_fallback),
                            anchor=anchor_text(source_lines, violation_line(v)),
                        )
                        # Normalize once inside the failure boundary. All output
                        # formats then use the same validated finding snapshot.
                        json.dumps(finding.to_dict())
                        finding.format()
                    except Exception as e:
                        if strict:
                            raise TealQLError(f'finding from {name} could not render on {rel}: {e}') from e
                        notes.append(ScanNotification('finding-render-failed', str(e), str(rel), name))
                        continue
                    findings.append(finding)
    findings.sort(key=lambda f: (str(f.rel_path), f.detector_name))
    return ScanResults(findings, notes)


def failures(
    findings: ScanResults, options: "Optional[DetectionOptions]" = None,
) -> list[ScanFinding]:
    """Findings at or above ``options.fail_on``; with no options, every finding counts."""
    if options is None:
        return list(findings)
    return [f for f in findings if options.is_failure(f.severity)]


def render_text(findings: ScanResults) -> str:
    notes = _notifications_of(findings)
    body = "\n".join(f.format() for f in findings) if findings else "(no findings)"
    if not notes:
        return body
    # Degradation goes BELOW the findings and is never omitted: "(no findings)"
    # on its own is a clean bill, and it must not be printed as one when part of
    # the analysis did not run.
    return "\n".join([
        body, "",
        f"{len(notes)} analysis degradation(s) — results are INCOMPLETE:",
        *(f"  {n.format()}" for n in notes),
    ])


def render_json(findings: ScanResults) -> str:
    """Versioned envelope ``{schema_version, tool, findings, notifications}``.

    ``notifications`` is always present, so a consumer can tell "analyzed and
    clean" from "never analyzed" without knowing whether this version emits the
    key at all."""
    from .findings import SCHEMA_VERSION
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "tool": "tealql",
        "complete": findings.complete,
        "findings": [f.to_dict() for f in findings],
        "notifications": [n.to_dict() for n in _notifications_of(findings)],
    }, indent=2)


def render_sarif(findings: ScanResults) -> str:
    """SARIF 2.1.0 — the format GitHub code scanning / most CI dashboards ingest.

    Each result carries ``partialFingerprints`` (the v2 baseline fingerprint, so
    code scanning dedups across commits the same way ``--baseline`` does), each
    rule a ``helpUri`` + ``help`` (the detector README), and a whole-program
    finding has NO region (SARIF allows an artifact-only location) plus
    ``properties.wholeProgram`` — forcing it to line 1 made every such finding
    look like a line-1 annotation."""
    from . import description_of, help_uri_of, readme_of, severity_of
    from .findings import SCHEMA_VERSION
    from .suppress import FINGERPRINT_VERSION, fingerprints

    # SARIF level is a 3-value scale; map our 5 onto it.
    _LEVEL = {"critical": "error", "high": "error", "medium": "warning",
              "low": "note", "informational": "note"}

    rules: dict[str, dict] = {}
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    fps = fingerprints(findings)
    for f, fp in zip(findings, fps):
        rid = f"sec-guide/{f.detector_name}"
        if rid not in rules:
            readme = readme_of(f.detector_name)
            rule = {
                "id": rid,
                "name": f.detector_name,
                "shortDescription": {"text": f.detector_name},
                "fullDescription": {"text": description_of(f.detector_name)[:1000]},
                "helpUri": help_uri_of(f.detector_name),
                "defaultConfiguration": {"level": _LEVEL.get(severity_of(f.detector_name), "warning")},
            }
            if readme:
                rule["help"] = {"text": description_of(f.detector_name), "markdown": readme}
            rule_index[rid] = len(rules)
            rules[rid] = rule
        fnd = f.to_finding()
        physical: dict = {"artifactLocation": {"uri": (fnd.file or str(f.rel_path)).replace("\\", "/")}}
        if fnd.line:
            physical["region"] = {"startLine": fnd.line}
        props = {"confidence": f.confidence, "severity": f.severity,
                 **({"method": fnd.method} if fnd.method else {})}
        if not fnd.line:
            props["wholeProgram"] = True
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": fnd.message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {f"tealqlFingerprint/v{FINGERPRINT_VERSION}": fp},
            "properties": props,
        }
        if fnd.witness and fnd.witness.get("sources"):
            # HAZARD: every threadFlowLocation MUST carry a physicalLocation or a
            # SARIF viewer (GitHub included) silently drops the whole code flow.
            # Witness sources are input-slot LABELS, not lines, so each step is
            # anchored at the sink and the label rides in the message.
            steps = [
                {"location": {"physicalLocation": physical,
                              "message": {"text": f"attacker input: {s}"}}}
                for s in fnd.witness["sources"]
            ]
            steps.append({"location": {"physicalLocation": physical,
                                       "message": {"text": "reaches this sink"}}})
            result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
        results.append(result)

    # SARIF's own home for "the tool could not do its job here" is
    # invocations[].toolExecutionNotifications — NOT a result. Emitting these as
    # results would put them in the dashboard's finding count and make a broken
    # analysis look like a vulnerable contract.
    notes = _notifications_of(findings)
    invocation = {"executionSuccessful": not notes}
    if notes:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "warning",
                "message": {"text": n.format()},
                "descriptor": {"id": n.kind},
                **({"locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": n.rel_path},
                    **({"region": {"startLine": n.line}} if n.line else {}),
                }}]} if n.rel_path else {}),
            }
            for n in notes
        ]

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "tealql",
                "informationUri": "https://github.com/Argimirodelpozo/codeql-TEAL",
                "rules": list(rules.values()),
            }},
            "invocations": [invocation],
            "results": results,
            "properties": {"tealqlSchemaVersion": SCHEMA_VERSION,
                           "fingerprintVersion": FINGERPRINT_VERSION},
        }],
    }
    return json.dumps(doc, indent=2)
