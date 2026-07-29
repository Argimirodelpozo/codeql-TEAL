"""Recursive sec-guide scan over a TEAL codebase — one SSA program per ``.teal``,
every selected detector run against it. Selection comes from a YAML/JSON config
(:class:`DetectionOptions`, or the legacy :class:`ScanConfig`).
CLI: ``tealql detections-scan <root> [--config rules.yml] [--json]``.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from tealql.tealtools.errors import (
    TargetError, TargetNotFoundError, TealParseError, TealQLError,
)
from tealql.tealtools.ssa import SSAProgram
from . import DETECTORS
from .config import ConfigError, DetectionConfig, glob_match

logger = logging.getLogger("tealql.security.scan")


def _method_ranges_for(teal: Path, method_table=None):
    """ABI method line-spans for a ``.teal`` (source ``method "sig"`` comments or an
    ARC-56 ``method_table``), or ``[]`` — an OPTIONAL enrichment, so every failure
    degrades to no attribution rather than breaking the scan."""
    try:
        from tealql.tealtools.abi import method_line_ranges
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
        from tealql.tealtools.arc56 import Arc56Spec, load_optional
        spec = arc56 if isinstance(arc56, Arc56Spec) else load_optional(arc56)
        return spec.method_table() if spec is not None else None
    except Exception:
        return None


def _method_at(ranges, violation) -> Optional[str]:
    """The ABI method name a violation sits in (by its source line), or ``None``."""
    if not ranges:
        return None
    try:
        from tealql.tealtools.abi import method_at_line
        from .findings import violation_line
        m = method_at_line(ranges, violation_line(violation))
        return m.name if m is not None else None
    except Exception:
        return None


def _drop_superseded(detectors: Iterable[str]) -> list[str]:
    """Drop detectors whose ``superseded_by`` superseder is also going to run.

    HAZARD: the superseder must be BOTH registered AND present in this very set —
    if it was filtered out (e.g. ``exclude``-d) the superseded detector is KEPT as
    the fallback, or the scan silently loses that coverage."""
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


def default_detection_names(names: Optional[Iterable[str]] = None) -> list[str]:
    """``names`` (default: the whole registry) minus detectors superseded by another
    present in the same set — the "run everything" default. Naming a superseded
    detector explicitly (``--detector``, an ``only:`` rule) still runs it."""
    return _drop_superseded(DETECTORS if names is None else names)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRule:
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
            return _drop_superseded(d for d in all_detectors if d not in excl)
        return _drop_superseded(all_detectors)


@dataclass(frozen=True)
class ScanConfig:
    """:class:`ScanRule` list, first-match-wins; no rules means every detector runs."""

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
        unknown = set(data) - {"rules"}
        if unknown:
            raise ConfigError(
                f"{path}: unknown top-level key(s) {sorted(unknown)} "
                f"(a selection config holds only 'rules:')")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        """Build + validate — every mistake that would silently change scan coverage
        (unknown detector name, both ``only`` and ``exclude``, missing ``match``,
        unknown rule key) raises :class:`ConfigError` at load time."""
        rules: list[ScanRule] = []
        for raw in data.get("rules", []):
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
            rules.append(ScanRule(
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
        return _drop_superseded(DETECTORS)


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
            selection=ScanConfig.from_dict({"rules": data.get("detectors", [])}),
            severity=tuple(sorted(sev.items())),
            fail_on=fail_on,
            auto_mode=bool(data.get("auto_mode", False)),
        )

    def mode_for(self, rel_path: str, prog=None, file=None) -> Optional[str]:
        """Declared mode for ``rel_path``, else opcode inference when ``auto_mode``."""
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
                f"sec-guide/{self.detector_name}  {self.violation.pretty()}")  # type: ignore[attr-defined]

    def to_finding(self):
        """Normalize to the stable versioned :class:`.findings.Finding` record."""
        from .findings import normalize
        return normalize(
            self.violation, rule_id=self.detector_name,
            rel_path=self.rel_path, severity=self.severity,
            confidence=self.confidence, method=self.method_name,
        )

    def to_dict(self) -> dict:
        """The finding record as a dict; ``detector`` keeps the ``sec-guide/``
        display form for back-compat alongside the kebab ``rule_id``."""
        d = self.to_finding().to_dict()
        d["detector"] = f"sec-guide/{self.detector_name}"
        return d


@dataclass(frozen=True)
class ScanNotification:
    """Something the scan could NOT do, carried alongside the findings.

    HAZARD: without this, "no findings" has two meanings — analyzed and clean,
    or never analyzed at all — and the output cannot tell them apart. Five of
    the nine ``ir-*`` detectors have no SSA sibling, so a contract that fails to
    lift silently drops them and the report still reads as a clean bill.

    ``kind`` is a stable machine-readable slug; ``message`` is for humans."""

    kind: str
    message: str
    rel_path: Optional[str] = None
    detector: Optional[str] = None

    def format(self) -> str:
        where = f" {self.rel_path}" if self.rel_path else ""
        who = f" [{self.detector}]" if self.detector else ""
        return f"[DEGRADED]{where}{who}: {self.message}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "message": self.message,
                "file": self.rel_path, "detector": self.detector}


class ScanResults(list):
    """The findings list, plus what the scan could not do.

    Subclasses ``list`` on purpose: every existing caller treats a scan result
    as a list of findings (iterate, len, comprehend, index) and keeps working
    untouched. ``notifications`` is additive."""

    def __init__(self, findings=(), notifications=()):
        super().__init__(findings)
        self.notifications: list[ScanNotification] = list(notifications)


def _notifications_of(findings) -> list:
    """Notifications carried by a scan result; ``()`` for a plain list, so the
    renderers accept either."""
    return list(getattr(findings, "notifications", ()))


def scan(
    root: Path,
    config: ScanConfig = ScanConfig.empty(),
    *,
    detection_config: "Optional[DetectionConfig]" = None,
    options: "Optional[DetectionOptions]" = None,
    strict: bool = False,
    arc56=None,
) -> list[ScanFinding]:
    """Discover, reconstruct, and detect; findings sorted by ``(rel_path, detector)``.

    ``options`` (one YAML) supplies selection + mode scoping + severity; the legacy
    ``config``/``detection_config`` pair is used when it is None. A detector whose
    ``applies_to`` excludes a file's declared mode is skipped; a file with no declared
    mode is unfiltered unless ``options.auto_mode``. ``arc56`` is an OPTIONAL
    selector→method-name source and degrades cleanly when absent.

    HAZARD: a file the grammar cannot fully parse is analyzed PARTIALLY (unparsed
    spans excluded — findings there may be missing) and one whose SSA cannot be
    reconstructed is SKIPPED, both with a warning only. ``strict=True`` raises
    instead, so CI can refuse a clean bill for input that was never analyzed."""
    if options is not None:
        config = options.selection
        detection_config = options.modes
    method_table = _arc56_method_table(arc56)
    root = Path(root).resolve()
    by_dir = discover_teal_files(root)
    n_files = sum(len(v) for v in by_dir.values())
    logger.info("scan: %d .teal file(s) across %d director(ies) under %s",
                n_files, len(by_dir), root)
    if not n_files:
        # "(no findings)" here is true but misleading — nothing was analyzed.
        msg = f"no .teal files found under {root} — nothing was analyzed"
        if strict:
            raise TealQLError(msg)
        logger.warning("%s", msg)
    findings: list[ScanFinding] = []
    notes: list[ScanNotification] = []
    for dir_path, teal_files in sorted(by_dir.items()):
        for teal in teal_files:
            rel = teal.relative_to(root)
            # ONE SSAProgram PER FILE: each .teal is an independent AVM program, and
            # sharing one program across a directory of N contracts makes the
            # per-file detectors O(N^2). Cross-contract analysis lives in
            # `tealql.security.xcontract`, not in this single-contract scanner.
            try:
                # ONE preparation per program, so every detector sees the same
                # resolved constants instead of depending on run order.
                from .common import prepare
                prog = prepare(SSAProgram(str(teal)))
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
            names = config.detectors_for(str(rel))
            try:
                if options is not None:
                    mode = options.mode_for(str(rel), prog=prog, file=teal.name)
                else:
                    mode = (detection_config.mode_for(str(rel))
                            if detection_config is not None else None)
            except Exception as e:                   # auto-mode classifies by opcode
                if strict:
                    raise TealQLError(
                        f"mode classification failed for {rel}: {e}") from e
                logger.warning(
                    "mode classification failed for %s (scanning unfiltered): %s",
                    rel, e)
                mode = None
            logger.info("scanning %s (mode=%s): %d detection(s)",
                        rel, mode or "unfiltered", len(names))
            # OPTIONAL: map each finding's line to the ABI method it sits in.
            method_ranges = _method_ranges_for(teal, method_table)
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
                sev = options.severity_for(name) if options is not None else None
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
                    findings.append(ScanFinding(
                        rel_path=rel, detector_name=name, violation=v,
                        severity_override=sev,
                        method_name=_method_at(method_ranges, v),
                    ))
    findings.sort(key=lambda f: (str(f.rel_path), f.detector_name))
    return ScanResults(findings, notes)


def failures(
    findings: list[ScanFinding], options: "Optional[DetectionOptions]" = None,
) -> list[ScanFinding]:
    """Findings at or above ``options.fail_on``; with no options, every finding counts."""
    if options is None:
        return list(findings)
    return [f for f in findings if options.is_failure(f.severity)]


def render_text(findings: list[ScanFinding]) -> str:
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


def render_json(findings: list[ScanFinding]) -> str:
    """Versioned envelope ``{schema_version, tool, findings, notifications}``.

    ``notifications`` is always present, so a consumer can tell "analyzed and
    clean" from "never analyzed" without knowing whether this version emits the
    key at all."""
    from .findings import SCHEMA_VERSION
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "tool": "tealql",
        "findings": [f.to_dict() for f in findings],
        "notifications": [n.to_dict() for n in _notifications_of(findings)],
    }, indent=2)


def render_sarif(findings: list[ScanFinding]) -> str:
    """SARIF 2.1.0 — the format GitHub code scanning / most CI dashboards ingest."""
    from . import severity_of
    from .findings import SCHEMA_VERSION

    # SARIF level is a 3-value scale; map our 5 onto it.
    _LEVEL = {"critical": "error", "high": "error", "medium": "warning",
              "low": "note", "informational": "note"}

    detections_root = Path(__file__).resolve().parent / "detections"

    def _readme(name: str) -> str:
        # detections/<kebab>/README.md sits beside the detector module.
        p = detections_root / name / "README.md"
        try:
            return p.read_text().strip() if p.exists() else name
        except Exception:
            return name

    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rid = f"sec-guide/{f.detector_name}"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.detector_name,
                "shortDescription": {"text": f.detector_name},
                "fullDescription": {"text": _readme(f.detector_name).split("\n\n")[0][:1000]},
                "defaultConfiguration": {"level": _LEVEL.get(severity_of(f.detector_name), "warning")},
            }
        fnd = f.to_finding()
        region = {"startLine": fnd.line} if fnd.line else {"startLine": 1}
        physical = {
            "artifactLocation": {"uri": fnd.file or str(f.rel_path)},
            "region": region,
        }
        result = {
            "ruleId": rid,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": fnd.message},
            "locations": [{"physicalLocation": physical}],
            "properties": {"confidence": f.confidence, "severity": f.severity,
                           **({"method": fnd.method} if fnd.method else {})},
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
                    "artifactLocation": {"uri": n.rel_path}}}]}
                   if n.rel_path else {}),
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
            "properties": {"tealqlSchemaVersion": SCHEMA_VERSION},
        }],
    }
    return json.dumps(doc, indent=2)
