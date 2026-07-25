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

    from tealql.security.scan import scan, ScanConfig
    findings = scan(Path("contracts/"), ScanConfig.from_path(Path("rules.yml")))
    for f in findings:
        print(f.format())

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
    """ABI method line-spans for a ``.teal`` file (source ``method "sig"`` router
    info, or an ARC-56 ``method_table`` when the comments were stripped), or ``[]``.
    Fully defensive: an OPTIONAL enrichment must never break a scan, so any
    read/parse failure degrades to no attribution."""
    try:
        from tealql.tealtools.abi import method_line_ranges
        return method_line_ranges(
            Path(teal).read_text(errors="ignore"), method_table=method_table)
    except Exception:
        return []


def _arc56_method_table(arc56):
    """``{selector_hex: AbiMethod}`` from an ARC-56 spec (an ``Arc56Spec`` or a path
    to one), or ``None``. Fully defensive — a bad/absent spec degrades to no table
    (source ``method "sig"`` comments then remain the only attribution source)."""
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


def default_detection_names(names: Optional[Iterable[str]] = None) -> list[str]:
    """``names`` (default: the whole registry, registration order) minus any
    detector superseded by another detector present in the same set — the
    default selection for "run everything" surfaces (``tealql detections
    --all``, the ``tealql all`` aggregate). Explicitly requesting a superseded
    detector (``--detector``, an ``only:`` rule) still runs it."""
    return _drop_superseded(DETECTORS if names is None else names)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRule:
    """One config rule. ``match`` is one or more glob patterns
    (``fnmatch`` semantics — ``*`` matches anything including ``/``,
    so ``*lsig*`` matches at any depth; a ``**/`` prefix also matches
    files at the scan root). ``only`` and ``exclude`` are mutually
    exclusive on the same rule. The relative-path-from-root is what
    gets matched."""

    match: tuple[str, ...]
    only: Optional[tuple[str, ...]] = None
    exclude: Optional[tuple[str, ...]] = None

    def matches(self, rel_path: str) -> bool:
        return any(glob_match(rel_path, pat) for pat in self.match)

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
        unknown = set(data) - {"rules"}
        if unknown:
            raise ConfigError(
                f"{path}: unknown top-level key(s) {sorted(unknown)} "
                f"(a selection config holds only 'rules:')")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        """Build + VALIDATE. Every mistake that would silently change scan
        coverage is a :class:`ConfigError` at load time instead: an unknown
        detector name (typo), a rule with both ``only`` and ``exclude``, a
        rule that can never match (missing/empty ``match``), an unknown
        rule key."""
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
SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


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
    value is a list of teal file paths, sorted by basename.

    Raises :class:`tealql.tealtools.errors.TargetNotFoundError` when ``root``
    does not exist, and :class:`~tealql.tealtools.errors.TargetError` when it
    is not a directory. A mistyped path used to ``rglob`` an empty result, so
    the scan reported "(no findings)" and exited 0 — a GREEN CI run on a
    directory that was never scanned, the exact silent-clean outcome the rest
    of this module (``--strict``, parse diagnostics, ``has_instructions``) is
    built to prevent."""
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
    """One sec-guide finding from the scan. ``rel_path`` is the
    .teal's path relative to the scan root; ``detector_name`` is the
    kebab-case short name (no ``sec-guide/`` prefix)."""

    rel_path: Path
    detector_name: str
    violation: object  # has .pretty()
    severity_override: Optional[str] = None  # set by scan from DetectionOptions
    # ABI method the finding sits in, from source `method "sig"` info (OPTIONAL —
    # None on raw bytecode / non-ABI code); set by scan when available.
    method_name: Optional[str] = None

    @property
    def severity(self) -> str:
        """The finding's severity. Precedence: a per-detector override from
        the detection options; else the VIOLATION's own ``severity`` when it
        carries a valid one (the IR taint family grades per sink field —
        ``critical`` for CloseRemainderTo, ``medium`` for Amount); else the
        detector's declared class ``severity`` (``"informational"`` for
        property-style findings like ``is-deletable``; ``"medium"`` by
        default)."""
        if self.severity_override is not None:
            return self.severity_override
        from . import SEVERITY_LEVELS, severity_of
        v = getattr(self.violation, "severity", None)
        if isinstance(v, str) and v.lower() in SEVERITY_LEVELS:
            return v.lower()
        return severity_of(self.detector_name)

    @property
    def confidence(self) -> str:
        """How likely this finding is a true positive (see
        :func:`tealql.security.confidence_of`)."""
        from . import confidence_of
        return confidence_of(self.detector_name)

    def format(self) -> str:
        """One-line greppable form:
        ``[SEVERITY] <rel_path>: sec-guide/<name>  <message>``. When the ABI
        method is known (source ``method`` info), it is named after the path."""
        loc = f"{self.rel_path} [{self.method_name}]" if self.method_name else self.rel_path
        return (f"[{self.severity.upper()}] {loc}: "
                f"sec-guide/{self.detector_name}  {self.violation.pretty()}")  # type: ignore[attr-defined]

    def to_finding(self):
        """Normalize to the structured :class:`tealql.security.findings.Finding` (the
        stable, versioned record every machine-readable output is built from —
        carries file + LINE + confidence + witness + method, not just prose)."""
        from .findings import normalize
        return normalize(
            self.violation, rule_id=self.detector_name,
            rel_path=self.rel_path, severity=self.severity,
            confidence=self.confidence, method=self.method_name,
        )

    def to_dict(self) -> dict:
        """The stable versioned finding record (schema in
        :mod:`tealql.security.findings`). ``rule_id`` is the kebab detector name;
        ``detector`` keeps the ``sec-guide/`` display form for back-compat."""
        d = self.to_finding().to_dict()
        d["detector"] = f"sec-guide/{self.detector_name}"
        return d


def scan(
    root: Path,
    config: ScanConfig = ScanConfig.empty(),
    *,
    detection_config: "Optional[DetectionConfig]" = None,
    options: "Optional[DetectionOptions]" = None,
    strict: bool = False,
    arc56=None,
) -> list[ScanFinding]:
    """Discover, reconstruct, and detect. Returns a flat list of findings
    sorted by ``(rel_path, detector_name)``.

    Pass a single unified ``options`` (:class:`DetectionOptions` from one YAML)
    for detector selection + mode scoping + per-detector severity (and it carries
    the ``fail_on`` threshold for :func:`failures`). The legacy ``config`` /
    ``detection_config`` pair still works and is used when ``options`` is None.

    A detector whose ``applies_to`` excludes a file's declared mode is skipped.
    A file with no declared mode is unfiltered (every selected detector runs)
    unless ``options.auto_mode`` is set, which classifies it by opcode.

    ``arc56`` (an :class:`tealql.tealtools.arc56.Arc56Spec`, or a path to one) is an
    OPTIONAL authoritative selector→method-name source, so findings keep their ABI
    method attribution even when the compiler's ``method "sig"`` comments were
    stripped from the source. Degrades cleanly when absent/unparseable.

    A file the grammar cannot fully parse is analyzed PARTIALLY with a
    warning (the unparsed spans are excluded — the scan may miss findings
    there); a file whose SSA cannot be reconstructed at all is skipped with
    a warning. ``strict=True`` turns both into a raised
    :class:`tealql.tealtools.errors.TealQLError` instead, so a CI scan can refuse
    to hand out a clean bill for input it could not actually analyze."""
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
        # The root exists but holds no TEAL. Reporting "(no findings)" for it is
        # true but misleading — nothing was analyzed — so say so, and let
        # --strict refuse to hand out the clean bill at all.
        msg = f"no .teal files found under {root} — nothing was analyzed"
        if strict:
            raise TealQLError(msg)
        logger.warning("%s", msg)
    findings: list[ScanFinding] = []
    for dir_path, teal_files in sorted(by_dir.items()):
        for teal in teal_files:
            rel = teal.relative_to(root)
            # ONE SSAProgram PER FILE. Each .teal is an independent program (the
            # AVM runs approval / clear-state programs separately), and a per-file
            # program keeps a per-file detector's cost from scaling with the whole
            # directory -- loading a directory of N contracts into one program made
            # the per-file detectors roughly O(N^2). Genuine cross-contract
            # analysis builds its own multi-program setup in `tealql.security.xcontract`;
            # it does not go through this single-contract scanner.
            try:
                # ONE preparation per program (see ``common.prepare``): the
                # detectors then all see the same resolved constants instead of
                # each one's inputs depending on which detector ran before it.
                from .common import prepare
                prog = prepare(SSAProgram(str(teal)))
            except Exception as e:                   # pragma: no cover
                if strict:
                    raise TealQLError(
                        f"could not reconstruct SSA for {rel}: {e}") from e
                logger.warning("could not reconstruct SSA for %s: %s", rel, e)
                continue
            diags = getattr(prog, "parse_diagnostics", ())
            if diags:
                if strict:
                    raise TealParseError(diags)
                logger.warning(
                    "%s: %d TEAL span(s) failed to parse and were EXCLUDED "
                    "from analysis — findings for this file may be "
                    "incomplete (first: %s)", rel, len(diags), diags[0])
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
            # OPTIONAL: map each finding's line to the ABI method it sits in, from
            # the source `method "sig"` router info. Empty (no attribution) on raw
            # bytecode / non-ABI code — findings just carry no method then.
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
                # The program holds exactly this file (keyed by basename); pass
                # it as the file filter so the detector scopes to it.
                sev = options.severity_for(name) if options is not None else None
                try:
                    # Construction AND detection are both guarded — a detector
                    # that does its analysis in __init__ (or crashes building)
                    # must not kill a whole corpus scan any more than one that
                    # crashes in detect(). Record it loudly and move on (strict
                    # mode refuses instead); the ERROR log keeps the crash
                    # visible so real bugs still get reported.
                    det = cls(prog, file=teal.name)
                    violations = list(det.detect())
                except Exception as e:
                    if strict:
                        raise TealQLError(
                            f"detector {name} crashed on {rel}: {e}") from e
                    logger.error(
                        "detector %s crashed on %s (skipped): %s", name, rel, e)
                    continue
                for v in violations:
                    findings.append(ScanFinding(
                        rel_path=rel, detector_name=name, violation=v,
                        severity_override=sev,
                        method_name=_method_at(method_ranges, v),
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
    """Versioned JSON envelope: ``{schema_version, tool, findings: [...]}`` where
    each finding is the stable :class:`tealql.security.findings.Finding` record (real
    ``file`` + ``line``, severity, confidence, structured witness)."""
    from .findings import SCHEMA_VERSION
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "tool": "tealql",
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def render_sarif(findings: list[ScanFinding]) -> str:
    """SARIF 2.1.0 — the format GitHub code scanning / most CI dashboards ingest.

    rules[] are the detectors that fired (id ``sec-guide/<name>``, level from
    severity, help text from the per-detector README when present); results[]
    carry a physicalLocation (file + 1-based region) and, when the IR taint road
    is available, a codeFlows entry from the finding's witness sources."""
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
            # Every threadFlowLocation carries a physicalLocation. Without one a
            # SARIF viewer (GitHub code scanning included) has nowhere to anchor
            # the step and drops the whole code flow, so the witness we went to
            # the trouble of computing never reached the user. The witness
            # sources are input-slot LABELS ("ApplicationArgs"), not lines, so
            # each step is anchored at the sink and the label carries in the
            # message; the final step is the sink itself.
            steps = [
                {"location": {"physicalLocation": physical,
                              "message": {"text": f"attacker input: {s}"}}}
                for s in fnd.witness["sources"]
            ]
            steps.append({"location": {"physicalLocation": physical,
                                       "message": {"text": "reaches this sink"}}})
            result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
        results.append(result)

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "tealql",
                "informationUri": "https://github.com/Argimirodelpozo/codeql-TEAL",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"tealqlSchemaVersion": SCHEMA_VERSION},
        }],
    }
    return json.dumps(doc, indent=2)
