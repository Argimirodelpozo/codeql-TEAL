"""The agent tool registry: typed, JSON-in / JSON-out wrappers over the analysis.

Each :class:`Tool` pairs a JSON-Schema ``input_schema`` with a function whose
keyword arguments are exactly that schema's properties. Arguments are validated
BEFORE the function runs (a malformed call is the caller's error, never a
crash), and every result is a JSON-serialisable ``dict``.

Two contracts the whole registry keeps, because an agent cannot see the log:

* **Completeness is data.** Any tool whose analysis can be partial returns the
  project's standard envelope — ``complete: bool`` plus ``notifications`` — so
  "no findings" and "never analyzed" are distinguishable in the payload.
* **Over-approximation is labelled.** Reachability tools say so in a
  ``semantics`` field; only the detectors (``analyze``) and ``verify_sinks``
  return verdicts.

Targets: every program-taking tool accepts ``target`` (a ``.teal`` file or a
directory of them) OR ``teal`` (inline source, materialised to a per-session
temp file so the whole pipeline, including the lift's source recovery, sees a
real path). Programs are cached per (path, mtime, size) so a conversation that
asks several questions about one contract rebuilds it once.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import tempfile
from collections import OrderedDict
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from tealql.tealtools.diagnostics.errors import TealQLError

logger = logging.getLogger("tealql.agent")


class ToolError(TealQLError):
    """A tool call that cannot be honoured as asked (bad argument, unusable
    target). Reported to the caller as the tool's error result, not a crash."""


# ---------------------------------------------------------------------------
# Registry + argument validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    fn: Callable[..., dict]
    read_only: bool = True
    #: Touches the network (chain fetch) — MCP ``openWorldHint``.
    network: bool = False
    #: MCP ``destructiveHint`` for a non-read-only tool; ``None`` = ``not
    #: read_only``. An ADDITIVE writer (the triage store) sets it False.
    destructive: Optional[bool] = None

    def call(self, arguments: Optional[dict] = None) -> dict:
        args = dict(arguments or {})
        validate_arguments(self.input_schema, args)
        return self.fn(**args)

    def mcp_descriptor(self) -> dict:
        """The ``tools/list`` entry for this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": (not self.read_only if self.destructive is None
                                    else self.destructive),
                "idempotentHint": True,
                "openWorldHint": self.network,
            },
        }


_JSON_TYPES = {
    "string": str, "integer": int, "number": (int, float), "boolean": bool,
    "array": list, "object": dict,
}


def validate_arguments(schema: dict, args: dict) -> None:
    """Minimal JSON-Schema check (types, enum, required, no unknown keys) —
    enough to turn a malformed agent call into a clear :class:`ToolError`."""
    props = schema.get("properties", {})
    unknown = sorted(set(args) - set(props))
    if unknown:
        raise ToolError(f"unknown argument(s) {unknown}; accepted: {sorted(props)}")
    missing = [k for k in schema.get("required", ()) if k not in args]
    if missing:
        raise ToolError(f"missing required argument(s) {missing}")
    for key, value in args.items():
        spec = props[key]
        if value is None:
            if spec.get("nullable", True):
                continue
        expected = spec.get("type")
        types = (expected,) if isinstance(expected, str) else tuple(expected or ())
        if types:
            py = tuple(t for name in types for t in
                       (_JSON_TYPES[name] if isinstance(_JSON_TYPES[name], tuple)
                        else (_JSON_TYPES[name],)))
            # bool is an int subclass in Python; JSON keeps them distinct.
            if isinstance(value, bool) and "boolean" not in types:
                raise ToolError(f"argument {key!r} must be {'/'.join(types)}, got boolean")
            if not isinstance(value, py):
                raise ToolError(f"argument {key!r} must be {'/'.join(types)}, "
                                f"got {type(value).__name__}")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"argument {key!r} must be one of {spec['enum']}, got {value!r}")
        if spec.get("type") == "array" and "items" in spec:
            item_t = _JSON_TYPES.get(spec["items"].get("type"))
            if item_t is not None and not all(isinstance(v, item_t) for v in value):
                raise ToolError(f"argument {key!r} items must be {spec['items']['type']}")
        if "minimum" in spec and isinstance(value, (int, float)) and value < spec["minimum"]:
            raise ToolError(f"argument {key!r} must be >= {spec['minimum']}")


def _schema(properties: dict, required: tuple = ()) -> dict:
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}


_TARGET_PROPS = {
    "target": {"type": "string",
               "description": "Path to a .teal file or a directory of .teal files."},
    "teal": {"type": "string",
             "description": "Inline TEAL source (alternative to `target`)."},
}
_FILE_PROP = {"file": {"type": "string",
                       "description": "For a directory target: the program (basename or "
                                      "relative path) the question is about."}}


# ---------------------------------------------------------------------------
# Targets + program cache
# ---------------------------------------------------------------------------


_INLINE_DIR: Optional[Path] = None
_PROGRAMS: "OrderedDict[tuple, Any]" = OrderedDict()
_PROGRAM_CACHE_SIZE = 16


def _inline_dir() -> Path:
    global _INLINE_DIR
    if _INLINE_DIR is None:
        _INLINE_DIR = Path(tempfile.mkdtemp(prefix="tealql-agent-"))
    return _INLINE_DIR


def resolve_target(target: Optional[str] = None, teal: Optional[str] = None,
                   *, name: str = "contract.teal") -> Path:
    """The path a tool analyses: ``target`` validated, or ``teal`` written to a
    content-addressed per-session temp file (so repeated calls hit the cache)."""
    if (target is None) == (teal is None):
        raise ToolError("give exactly one of `target` (path) or `teal` (inline source)")
    if teal is not None:
        if not name.endswith(".teal") or "/" in name or "\\" in name:
            raise ToolError("`name` must be a bare *.teal filename")
        digest = hashlib.sha1(teal.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        d = _inline_dir() / digest
        d.mkdir(exist_ok=True)
        p = d / name
        if not p.exists():
            p.write_text(teal)
        return p
    from tealql.tealtools._utils.targets import resolve_target as _resolve
    try:
        return _resolve(Path(target).expanduser())
    except FileNotFoundError as e:
        raise ToolError(str(e)) from e
    except ValueError as e:
        raise ToolError(str(e)) from e


def _teal_files(path: Path) -> list[Path]:
    from tealql.tealtools._utils.targets import _discover_teal_files
    return _discover_teal_files(path)


def load_program(path: Path):
    """A const-propagated :class:`SSAProgram` for ``path`` (file or directory),
    cached by path + mtime + size."""
    from tealql.tealtools.ssa import SSAProgram
    files = _teal_files(path)
    key = (str(path),) + tuple((str(f), f.stat().st_mtime_ns, f.stat().st_size)
                               for f in files)
    hit = _PROGRAMS.get(key)
    if hit is not None:
        _PROGRAMS.move_to_end(key)
        return hit
    prog = SSAProgram(str(path), strict=False)
    prog.propagate_constants()
    _PROGRAMS[key] = prog
    while len(_PROGRAMS) > _PROGRAM_CACHE_SIZE:
        _PROGRAMS.popitem(last=False)
    return prog


def _single_file(path: Path, file: Optional[str]) -> Path:
    """The one ``.teal`` a question is about: ``path`` itself, or ``file`` chosen
    from a directory target (basename or path relative to it)."""
    files = _teal_files(path)
    if path.is_file():
        return path
    if file is None:
        if len(files) == 1:
            return files[0]
        raise ToolError("directory target holds several programs; pass `file`: "
                        + ", ".join(str(f.relative_to(path)) for f in files))
    for f in files:
        if f.name == file or str(f.relative_to(path)) == file:
            return f
    raise ToolError(f"no program {file!r} under {path}; available: "
                    + ", ".join(str(f.relative_to(path)) for f in files))


def _file_filter(path: Path, teal: Path) -> Optional[str]:
    """The ``file=`` label detectors use to scope a directory program."""
    return None if path.is_file() else teal.name


def _health_dict(health) -> dict:
    return health.to_dict()


# ---------------------------------------------------------------------------
# Running CLI commands in-process (for the puya-gated / network ones)
# ---------------------------------------------------------------------------


def _cli_json(argv: list[str]) -> tuple[int, Any, str]:
    """Run a ``tealql`` subcommand in-process with ``--json`` and parse its
    stdout — reuse for the commands whose hazards (puya printing to stdout,
    network fetch + cache) the CLI already handles. Returns ``(rc, payload,
    stderr)``; a non-JSON payload comes back as ``None``."""
    from tealql.cli.main import main
    from tealql.cli._common import _configure_logging
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([*argv, "--json"])
    finally:
        # main() bound the tealql log handler to the redirected stderr; put it
        # back so a long-running server keeps logging to the real one.
        _configure_logging(0)
    text = out.getvalue().strip()
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = None
    return rc, payload, err.getvalue()


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def list_detectors() -> dict:
    """Every registered detector with its metadata."""
    from tealql.security import (DETECTORS, confidence_of, description_of, help_uri_of,
                                 severity_of)
    from tealql.security.run import _ON_DEMAND_ONLY
    from tealql.security.scan import SEVERITY_ORDER
    rows = []
    for name, cls in DETECTORS.items():
        applies = getattr(cls, "applies_to", frozenset({"app", "logicsig"}))
        rows.append({
            "name": name,
            "severity": severity_of(name),
            "confidence": confidence_of(name),
            "applies_to": sorted(applies),
            "in_default_run": name not in _ON_DEMAND_ONLY,
            "summary": description_of(name),
            "help_uri": help_uri_of(name),
        })
    return {"detectors": rows, "severity_order": list(SEVERITY_ORDER),
            "modes": ["app", "logicsig"]}


def _options(mode: Optional[str], detectors: Optional[list], fail_on: Optional[str]):
    from tealql.security import DETECTORS
    from tealql.security.config import DetectionConfig, ModeRule
    from tealql.security.scan import (
        DetectionOptions, SEVERITY_ORDER, _DetectorRule, _DetectorSelection,
    )
    if detectors:
        bad = [d for d in detectors if d not in DETECTORS]
        if bad:
            raise ToolError(f"unknown detector(s) {bad}; see list_detectors")
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        raise ToolError(f"fail_on must be one of {list(SEVERITY_ORDER)}")
    modes = (DetectionConfig((ModeRule(("*",), mode),))
             if mode in ("app", "logicsig") else DetectionConfig.empty())
    selection = (_DetectorSelection((_DetectorRule(("*",), only=tuple(detectors)),))
                 if detectors else _DetectorSelection.empty())
    return DetectionOptions(modes=modes, selection=selection,
                            fail_on=fail_on or "low",
                            auto_mode=(mode is None or mode == "auto"))


def analyze(target: Optional[str] = None, teal: Optional[str] = None, *,
            mode: Optional[str] = "auto", detectors: Optional[list] = None,
            fail_on: Optional[str] = None, arc56: Optional[str] = None) -> dict:
    """Run the detectors over a target; normalized findings + completeness."""
    from tealql.security import DETECTORS
    from tealql.security.findings import SCHEMA_VERSION
    from tealql.security.scan import SEVERITY_ORDER, failures, scan_target
    from tealql.security.suppress import fingerprints
    path = resolve_target(target, teal)
    options = _options(mode, detectors, fail_on)
    try:
        results = scan_target(path, options=options, strict=False, arc56=arc56)
    except TealQLError as e:
        raise ToolError(str(e)) from e

    base = path if path.is_dir() else path.parent
    # Which detectors actually RAN per file: the scan's own selection + mode
    # rule, replayed so a consumer can tell "ran and found nothing" from
    # "not applicable to this mode". A detector that crashed or degraded is in
    # `notifications`, never silently in this list as clean.
    ran: dict[str, dict] = {}
    for f in _teal_files(path):
        rel = str(f.relative_to(base))
        prog = load_program(f)
        try:
            resolved = options.mode_for(rel, prog=prog, file=f.name)
        except Exception:
            resolved = None
        names = []
        for name in options.detectors_for(rel):
            cls = DETECTORS.get(name)
            if cls is None:
                continue
            applies = getattr(cls, "applies_to", frozenset({"app", "logicsig"}))
            if resolved is None or resolved in applies:
                names.append(name)
        ran[rel] = {"mode": resolved, "detectors": names}

    rows = []
    by_sev: dict[str, int] = {}
    by_det: dict[str, int] = {}
    # `fingerprints` (not per-finding `fingerprint`): it assigns the ordinals
    # that disambiguate same-message findings, so this is the identity a
    # baseline and the triage store hold.
    for sf, fp in zip(results, fingerprints(results)):
        d = sf.to_dict()
        d["fingerprint"] = fp
        d["fails"] = options.is_failure(sf.severity)
        rows.append(d)
        by_sev[sf.severity] = by_sev.get(sf.severity, 0) + 1
        by_det[sf.detector_name] = by_det.get(sf.detector_name, 0) + 1
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda d: (-rank.get(d["severity"], -1), d["file"] or "",
                             d["line"] or 0, d["rule_id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "target": str(path),
        "complete": results.complete,
        "notifications": [n.to_dict() for n in results.notifications],
        "summary": {
            "total": len(rows),
            "failing": len(failures(results, options)),
            "fail_on": options.fail_on,
            "by_severity": {s: by_sev[s] for s in reversed(SEVERITY_ORDER) if s in by_sev},
            "by_detector": dict(sorted(by_det.items())),
        },
        "programs": ran,
        "findings": rows,
        "semantics": ("Each finding is a detector VERDICT: the sink is reached by "
                      "attacker-controlled data or an action is reachable, and the "
                      "detector found no recognised guard dominating it. `complete: "
                      "false` means part of the analysis did not run — absence of a "
                      "finding there is not evidence of safety."),
    }


def _hit_dicts(hits) -> list[dict]:
    return [h.to_dict() for h in hits]


def _node_dicts(q, nodes) -> list[dict]:
    out = []
    for n in nodes:
        d = {"file": n.file, "line": n.line, "node_class": n.node_class}
        op = q.g.op_of(n)
        if op:
            imm = q.g.immediates_of(n)
            d["op"] = f"{op} {imm}".strip() if imm else op
        out.append(d)
    return out


def taint_query(target: Optional[str] = None, teal: Optional[str] = None, *,
                file: Optional[str] = None, from_line: Optional[int] = None,
                to_line: Optional[int] = None, from_source: Optional[str] = None,
                inventory: Optional[str] = None, precise: bool = False) -> dict:
    """Open taint reachability (attacker inputs -> dangerous sinks)."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    path = resolve_target(target, teal)
    chosen = [x for x in (from_line, to_line, from_source, inventory) if x is not None]
    if len(chosen) > 1:
        raise ToolError("give at most one of from_line / to_line / from_source / inventory")
    prog = load_program(path)
    if file is not None:
        file = _single_file(path, file).name
    q = TaintQuery(prog, file=file)
    out: dict[str, Any] = {"target": str(path), "precise": precise,
                           **_health_dict(prog.health())}
    if from_line is not None:
        out["query"] = {"sinks_reachable_from_line": from_line}
        out["hits"] = _hit_dicts(q.sinks_from(line=from_line))
    elif from_source is not None:
        sf, _, sl = from_source.rpartition(":")
        if not sl.isdigit():
            raise ToolError("from_source expects '[FILE:]LINE' (a high-level source line)")
        candidates = q.source_files_matching(sf or None)
        if sf and len(candidates) > 1 and sf not in candidates:
            raise ToolError(f"from_source {sf!r} is ambiguous: {candidates}; give the "
                            "unique path suffix")
        out["query"] = {"sinks_reachable_from_source": from_source,
                        "source_files": candidates}
        out["teal_lines"] = q.teal_lines_for_source(sf or None, int(sl))
        out["hits"] = _hit_dicts(q.sinks_from(source_file=sf or None, source_line=int(sl)))
    elif to_line is not None:
        out["query"] = {"attacker_sources_reaching_line": to_line}
        out["sources"] = _node_dicts(q, q.sources_of(line=to_line))
    elif inventory == "sinks":
        out["query"] = {"inventory": "sinks"}
        out["hits"] = _hit_dicts(q.all_sinks())
    elif inventory == "sources":
        out["query"] = {"inventory": "sources"}
        out["sources"] = _node_dicts(q, q.all_sources())
    else:
        out["query"] = {"attack_surface": True}
        out["hits"] = _hit_dicts(q.tainted_sinks(precise=precise))
    out["semantics"] = (
        "Reachability OVER-approximates: a reachable sink may be validated on the "
        "way (sender gate, receiver pin, range check). Use verify_sinks for a "
        "guard-aware verdict. precise=true uses the lifted IR (interprocedural, "
        "fewer phantom edges) and falls back to the coarse graph if the program "
        "does not lift.")
    return out


def verify_sinks(target: Optional[str] = None, teal: Optional[str] = None, *,
                 file: Optional[str] = None, precise: bool = True) -> dict:
    """Attack surface with a per-sink guard-aware verdict."""
    from tealql.security.sink_verdict import verify_sinks as _verify
    path = resolve_target(target, teal)
    prog = load_program(path)
    if file is not None:
        file = _single_file(path, file).name
    verdicts = _verify(prog, file=file, precise=precise)
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    return {
        "target": str(path), "precise": precise,
        **_health_dict(prog.health()),
        "counts": counts,
        "verdicts": [v.to_dict() for v in verdicts],
        "semantics": {
            "CONFIRMED": "a guard-aware detector flagged this sink: attacker-controlled "
                         "data reaches it with no recognised dominating guard — treat as "
                         "a likely vulnerability, read the code to confirm",
            "NOT_FLAGGED": "a covering detector ran and did not flag it; this is NOT a "
                           "proof that a guard exists",
            "UNVERIFIED": "no detector covers this sink category, or the covering "
                          "detector could not run (degraded) — reachable, unjudged",
        },
    }


_TYPE_ENUM = {"1": "pay", "2": "keyreg", "3": "acfg", "4": "axfer", "5": "afrz", "6": "appl"}


def source_context(target: Optional[str] = None, teal: Optional[str] = None, *,
                   file: Optional[str] = None, line: int, before: int = 6,
                   after: int = 6) -> dict:
    """Everything the analysis knows about one TEAL line, for triage."""
    from tealql.tealtools.frontend.source_map import build_source_map
    from tealql.tealtools.metadata.abi import method_at_line, method_line_ranges
    from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    path = resolve_target(target, teal)
    teal_path = _single_file(path, file)
    text = teal_path.read_text(errors="replace")
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        raise ToolError(f"line {line} out of range 1..{len(lines)} for {teal_path.name}")
    lo, hi = max(1, line - before), min(len(lines), line + after)
    window = [{"line": n, "text": lines[n - 1], "focus": n == line}
              for n in range(lo, hi + 1)]

    prog = load_program(path)
    flt = _file_filter(path, teal_path)
    out: dict[str, Any] = {"target": str(path), "file": teal_path.name, "line": line,
                           "window": window}

    hl = build_source_map(text).get(line)
    out["high_level_source"] = f"{hl[0]}:{hl[1]}" if hl else None

    ranges = method_line_ranges(text)
    m = method_at_line(ranges, line)
    out["abi_method"] = ({"name": m.name, "signature": m.signature,
                          "selector": m.selector_hex} if m is not None else None)

    instr = [a for a in prog.assignments
             if a.location.line == line and (flt is None or a.location.file.endswith(teal_path.name))]
    out["instruction"] = ({"op": instr[0].op,
                           "outputs": [repr(o) for o in getattr(instr[0], "outputs", ()) or ()],
                           "operands": [repr(o) for o in getattr(instr[0], "operands", ()) or ()]}
                          if instr else None)

    # Path predicates of the basic block holding the line: what every path from
    # entry to here has already established (branch outcomes + assertions).
    preds: list[str] = []
    try:
        for blk in PathPredicateAnalysis(prog).to_dict().get("blocks", ()):
            if blk["first_line"] <= line <= blk["last_line"] and (
                    flt is None or str(blk.get("file", "")).endswith(teal_path.name)):
                preds = list(blk.get("predicates", ()))
                break
    except Exception as e:                  # a report failure must not hide the code
        out["path_predicates_error"] = f"{type(e).__name__}: {e}"
    out["path_predicates"] = preds

    try:
        q = TaintQuery(prog, file=flt)
        out["attacker_sources_reaching"] = _node_dicts(q, q.sources_of(line=line))
        out["sinks_reachable_from"] = _hit_dicts(q.sinks_from(line=line))
    except Exception as e:
        out["taint_error"] = f"{type(e).__name__}: {e}"
    out["semantics"] = ("path_predicates hold on EVERY path to this line (dominating "
                        "guards). attacker_sources_reaching / sinks_reachable_from are "
                        "coarse reachability (over-approximate).")
    return out


def methods(target: Optional[str] = None, teal: Optional[str] = None, *,
            arc56: Optional[str] = None) -> dict:
    """The ABI method table recovered from source comments or an ARC-56 spec."""
    from tealql.tealtools.metadata.abi import (
        abi_type_byte_length, extract_method_table, method_line_ranges,
    )
    path = resolve_target(target, teal)
    rows = []
    table = None
    if arc56:
        from tealql.tealtools.metadata import arc56 as _arc56
        try:
            spec = _arc56.load(arc56)
        except Exception as e:
            raise ToolError(f"could not read ARC-56 spec {arc56}: {e}") from e
        table = spec.method_table()
    for f in _teal_files(path):
        text = f.read_text(errors="replace")
        ranges = method_line_ranges(text, method_table=table)
        served = {m.selector: (s, e) for s, e, m in ranges}
        known = extract_method_table(text)
        if table:
            for sel, m in table.items():
                known.setdefault(sel, m)
        for m in known.values():
            span = served.get(m.selector)
            rows.append({
                "file": f.name, "selector": m.selector_hex, "name": m.name,
                "signature": m.signature, "arg_types": list(m.arg_types),
                "arg_names": list(m.arg_names), "return_type": m.return_type,
                "arg_byte_lengths": [abi_type_byte_length(a) for a in m.arg_types],
                "routable": (None if not served else span is not None),
                "lines": list(span) if span else None,
            })
    rows.sort(key=lambda r: (r["file"], r["name"]))
    return {"target": str(path), "methods": rows,
            "semantics": ("Recovered from `method \"sig\"` pseudo-ops / `// method` "
                          "comments or the ARC-56 spec; raw bytecode yields none. "
                          "routable=false marks ARC-28 event signatures or methods "
                          "this app CALLS on others (not attack surface); null = the "
                          "router shape was not recognised, so undetermined.")}


def storage_schema(target: Optional[str] = None, teal: Optional[str] = None, *,
                   arc56: Optional[str] = None) -> dict:
    """Recovered global/local/box storage schema (needs the puya lift extra)."""
    path = resolve_target(target, teal)
    argv = ["storage-schema", str(path)] + (["--arc56", arc56] if arc56 else [])
    rc, payload, err = _cli_json(argv)
    if rc == 2 or payload is None:
        return {"target": str(path), "complete": False, "entries": [],
                "notifications": [{"kind": "storage-schema-unavailable",
                                   "message": err.strip() or "storage-schema did not run",
                                   "file": None, "detector": None}]}
    notes = [{"kind": "lift-warning", "message": ln.strip(), "file": None, "detector": None}
             for ln in err.splitlines() if "did not lift" in ln]
    return {"target": str(path), "complete": not notes, "notifications": notes,
            "entries": payload}


def inner_transactions(target: Optional[str] = None, teal: Optional[str] = None, *,
                       file: Optional[str] = None) -> dict:
    """Every inner-transaction group the program can submit, with field values."""
    from tealql.tealtools.reporting.inner_transactions import InnerTxnReport
    path = resolve_target(target, teal)
    prog = load_program(path)
    if file is not None:
        prog = prog.for_file(_single_file(path, file).name, strict=False)
    report = InnerTxnReport(prog).to_dict()
    for g in report.get("groups", ()):
        for t in g.get("txns", ()):
            for fld in t.get("fields", ()):
                if fld.get("name") == "TypeEnum":
                    t["type"] = sorted({_TYPE_ENUM.get(str(v), str(v))
                                        for v in fld.get("possible_values", ())})
    return {"target": str(path), **_health_dict(prog.health()), **report}


def group_shape(target: Optional[str] = None, teal: Optional[str] = None, *,
                file: Optional[str] = None, per_exit: bool = True) -> dict:
    """The atomic-group shape the program forces on its approving exits."""
    from tealql.tealtools.cfg.group import analyze, analyze_layout, analyze_per_exit
    path = resolve_target(target, teal)
    prog = load_program(path)
    if file is not None:
        prog = prog.for_file(_single_file(path, file).name, strict=False)
    shape = (analyze_per_exit(prog) if per_exit else analyze(prog)).to_dict()
    try:
        layout = analyze_layout(prog).to_dict()
    except Exception as e:
        layout = {"error": f"{type(e).__name__}: {e}"}
    return {"target": str(path), **_health_dict(prog.health()),
            "shape": shape, "layout": layout,
            "semantics": ("Constraints every approving exit enforces on the group "
                          "(GroupSize, sibling fields). per_exit lists each exit's own "
                          "shape; a sibling the program trusts without pinning its "
                          "receiver to the app shows up in the "
                          "unvalidated-group-sibling detector.")}


def decompile(target: Optional[str] = None, teal: Optional[str] = None, *,
              view: str = "repr.pre_ir") -> dict:
    """A readable lifted/annotated representation (default: typed pre-IR)."""
    from tealql.tealtools.viz import CATALOG_BY_KEY, render_views
    path = resolve_target(target, teal)
    if view not in CATALOG_BY_KEY:
        raise ToolError(f"unknown view {view!r}; e.g. repr.pre_ir, repr.puya_ir, "
                        f"repr.ssa.presentation, analysis.path_predicates, "
                        f"analysis.authority, analysis.loop_bounds — run "
                        f"`tealql dump --list-views` for all {len(CATALOG_BY_KEY)}")
    rendered = render_views(str(path), keys=[view], graphs=False)[0]
    return {"target": str(path), "view": view, "title": rendered.spec.title,
            "complete": rendered.text_error is None,
            "notifications": ([{"kind": "view-failed", "message": rendered.text_error,
                                "file": None, "detector": None}]
                              if rendered.text_error else []),
            "text": rendered.text}


def audit_app(app_id: int, cache_dir: Optional[str] = None) -> dict:
    """Fetch a DEPLOYED app by ID and audit it (network: mainnet API + local algod)."""
    argv = ["audit", str(int(app_id))] + (["--cache-dir", cache_dir] if cache_dir else [])
    rc, payload, err = _cli_json(argv)
    if payload is None:
        raise ToolError(err.strip() or f"audit of app {app_id} produced no report")
    payload["exit_code"] = rc
    return payload


def brief(target: Optional[str] = None, teal: Optional[str] = None, *,
          file: Optional[str] = None, precise: bool = True,
          format: str = "json") -> dict:
    """The one-call contract brief (see :mod:`tealql.agent.brief`)."""
    from .brief import contract_brief, render_brief_markdown
    path = resolve_target(target, teal)
    teal_path = _single_file(path, file)
    data = contract_brief(teal_path, precise=precise)
    if format == "markdown":
        return {"target": str(teal_path), "complete": data["complete"],
                "notifications": data["notifications"],
                "markdown": render_brief_markdown(data)}
    return data


def _diff_key(finding: dict) -> str:
    """A revision-stable identity for a finding: rule + message with line numbers
    and the program's own file name neutralised, so renaming ``v1.teal`` to
    ``v2.teal`` or inserting lines above does not read as a new finding."""
    from tealql.security.suppress import normalize_message
    msg = normalize_message(finding["message"])
    fname = finding.get("file") or ""
    if fname:
        msg = msg.replace(fname, "<file>").replace(Path(fname).name, "<file>")
    return hashlib.sha256(f"{finding['rule_id']}\x00{msg}".encode()).hexdigest()[:16]


def diff(old: Optional[str] = None, new: Optional[str] = None, *,
         old_teal: Optional[str] = None, new_teal: Optional[str] = None,
         mode: Optional[str] = "auto", detectors: Optional[list] = None) -> dict:
    """Security diff between two revisions: findings added / removed, plus a
    bounded semantic-equivalence verdict when both are single programs."""
    before = analyze(target=old, teal=old_teal, mode=mode, detectors=detectors)
    after = analyze(target=new, teal=new_teal, mode=mode, detectors=detectors)
    old_keys = {_diff_key(f): f for f in before["findings"]}
    new_keys = {_diff_key(f): f for f in after["findings"]}
    added = [f for k, f in new_keys.items() if k not in old_keys]
    removed = [f for k, f in old_keys.items() if k not in new_keys]
    semantic: dict = {"status": "UNKNOWN",
                      "reason": "semantic comparison needs exactly one program on each side"}
    old_files, new_files = (_teal_files(Path(before["target"])),
                            _teal_files(Path(after["target"])))
    if len(old_files) == 1 and len(new_files) == 1:
        try:
            from tealql.security.semantic_compatibility import compare_programs
            result = compare_programs(load_program(old_files[0]), load_program(new_files[0]))
            semantic = result.to_dict()
        except Exception as e:                  # the diff must survive a comparator refusal
            semantic = {"status": "UNKNOWN", "reason": f"{type(e).__name__}: {e}"}
    return {
        "old": before["target"], "new": after["target"],
        "complete": before["complete"] and after["complete"],
        "notifications": before["notifications"] + after["notifications"],
        "summary": {"added": len(added), "removed": len(removed),
                    "unchanged": len(set(old_keys) & set(new_keys)),
                    "old_total": len(before["findings"]), "new_total": len(after["findings"])},
        "added": added, "removed": removed,
        "semantic_equivalence": semantic,
        "semantics": ("added/removed compare detector findings by a line- and "
                      "filename-insensitive identity (rule + message shape). "
                      "semantic_equivalence is the bounded revision comparator: PROVED "
                      "means canonical effects/traps agree under identical inputs and "
                      "state for a NoOp call on an existing app; UNKNOWN is not a "
                      "difference, REFUTED is a concrete constant-outcome difference."),
    }


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


def _tool(name, description, props, fn, *, required=(), network=False,
          read_only=True, destructive=None) -> Tool:
    return Tool(name=name, description=description, fn=fn,
                input_schema=_schema(props, required), network=network,
                read_only=read_only, destructive=destructive)


# Thin lazy wrappers: `triage` imports this module, so bind at call time.
def triage_queue(**kw) -> dict:
    from .triage import triage_queue as _q
    return _q(**kw)


def record_triage(**kw) -> dict:
    from .triage import record_triage as _r
    return _r(**kw)


def triage_report(**kw) -> dict:
    from .triage import triage_report as _r
    return _r(**kw)


_STORE_PROP = {"store": {"type": "string",
                         "description": "Triage store JSON path (default "
                                        "<scan root>/.tealql/triage.json)."}}
_MODE_PROP = {"mode": {"type": "string", "enum": ["auto", "app", "logicsig"],
                       "description": "Program kind; 'auto' infers from opcodes."}}


TOOLS: dict[str, Tool] = {t.name: t for t in (
    _tool("tealql_list_detectors",
          "List every security detector tealql can run, with severity, confidence, "
          "the mode it applies to (app / logicsig) and a one-paragraph summary.",
          {}, list_detectors),
    _tool("tealql_analyze",
          "Run the security detectors on a TEAL program (file, directory, or inline "
          "source) and return normalized findings (rule_id, severity, confidence, "
          "file, line, message, witness, fingerprint) plus a completeness envelope. "
          "This is the VERDICT surface: each finding is a guard-aware detector result. "
          "mode='auto' (default) classifies each program as app/logicsig by opcode so "
          "only applicable detectors run.",
          {**_TARGET_PROPS,
           "mode": {"type": "string", "enum": ["auto", "app", "logicsig"],
                    "description": "Program kind; 'auto' infers from opcodes."},
           "detectors": {"type": "array", "items": {"type": "string"},
                         "description": "Restrict to these detector names."},
           "fail_on": {"type": "string",
                       "enum": ["informational", "low", "medium", "high", "critical"],
                       "description": "Severity at/above which a finding counts as failing."},
           "arc56": {"type": "string", "description": "Optional ARC-56 app spec path "
                                                      "for ABI method attribution."}},
          analyze),
    _tool("tealql_verify_sinks",
          "Attack surface with verdicts: every dangerous sink (inner-txn Receiver/"
          "Amount/CloseRemainderTo/RekeyTo/Fee/ApplicationID, state-write keys, box "
          "ops, log) reachable from attacker input, each labelled CONFIRMED (a "
          "guard-aware detector flagged it), NOT_FLAGGED (covering detector ran, no "
          "finding) or UNVERIFIED (no detector covers it). Recommended first call for "
          "'is this contract exploitable?'.",
          {**_TARGET_PROPS, **_FILE_PROP,
           "precise": {"type": "boolean",
                       "description": "Use the lifted IR (interprocedural). Default true."}},
          verify_sinks),
    _tool("tealql_taint_query",
          "Open taint reachability (OVER-approximate, guard-blind): default = whole "
          "attack surface (attacker inputs -> dangerous sinks); from_line = sinks "
          "reachable from a TEAL line; to_line = attacker inputs reaching a sink line; "
          "from_source = sinks reachable from a high-level source line via the "
          "compiler's '// file.py:N' comments; inventory = 'sinks' or 'sources'.",
          {**_TARGET_PROPS, **_FILE_PROP,
           "from_line": {"type": "integer", "minimum": 1},
           "to_line": {"type": "integer", "minimum": 1},
           "from_source": {"type": "string", "description": "'[FILE:]LINE' high-level line"},
           "inventory": {"type": "string", "enum": ["sinks", "sources"]},
           "precise": {"type": "boolean"}},
          taint_query),
    _tool("tealql_source_context",
          "Explain one TEAL line: the numbered source window, the high-level source "
          "line it compiled from (if the compiler left '// file.py:N' comments), the "
          "ABI method it belongs to, the instruction's SSA form, the path predicates "
          "that hold on every path to it (dominating guards), the attacker inputs "
          "that reach it and the sinks it reaches. Use it to triage a finding.",
          {**_TARGET_PROPS, **_FILE_PROP,
           "line": {"type": "integer", "minimum": 1, "description": "1-based TEAL line"},
           "before": {"type": "integer", "minimum": 0},
           "after": {"type": "integer", "minimum": 0}},
          source_context, required=("line",)),
    _tool("tealql_methods",
          "The ABI method table (selector, signature, arg types/byte lengths, the "
          "TEAL line span each method owns, whether the router dispatches it).",
          {**_TARGET_PROPS, "arc56": {"type": "string"}}, methods),
    _tool("tealql_storage_schema",
          "Recovered storage schema: global/local/box keys and maps with recovered "
          "key/value types (composite keys included). Needs the optional puya lift "
          "backend; degrades to complete=false without it.",
          {**_TARGET_PROPS, "arc56": {"type": "string"}}, storage_schema),
    _tool("tealql_inner_transactions",
          "Every inner-transaction group the program can submit: per-txn type and "
          "the possible values of each field (Receiver, Amount, ApplicationID, ...).",
          {**_TARGET_PROPS, **_FILE_PROP}, inner_transactions),
    _tool("tealql_group_shape",
          "The atomic-group shape the program forces (GroupSize, sibling txn fields) "
          "per approving exit, plus the per-position layout.",
          {**_TARGET_PROPS, **_FILE_PROP, "per_exit": {"type": "boolean"}}, group_shape),
    _tool("tealql_decompile",
          "A readable representation of the program: default 'repr.pre_ir' (typed, "
          "Puya-shaped IR with named registers, blocks and calls — far easier to read "
          "than raw TEAL). Other views: repr.puya_ir, repr.ssa.presentation, "
          "analysis.path_predicates, analysis.authority, analysis.loop_bounds, "
          "analysis.storage, analysis.health (see `tealql dump --list-views`).",
          {**_TARGET_PROPS, "view": {"type": "string"}}, decompile),
    _tool("tealql_brief",
          "One-call contract brief for an auditor: version/mode, ABI methods, "
          "lifecycle (updatable/deletable and whether creator-gated), storage schema, "
          "inner transactions, forced group shape, attack surface with verdicts, "
          "detector findings, and analysis health. format='markdown' for a compact "
          "text rendering.",
          {**_TARGET_PROPS, **_FILE_PROP, "precise": {"type": "boolean"},
           "format": {"type": "string", "enum": ["json", "markdown"]}},
          brief),
    _tool("tealql_diff",
          "Security diff between two revisions of a program (paths or inline source): "
          "findings ADDED and REMOVED by a line- and filename-insensitive identity, "
          "plus a bounded semantic-equivalence verdict (PROVED / UNKNOWN / REFUTED) "
          "when both sides are single programs. Use it to review an upgrade or a PR.",
          {"old": {"type": "string", "description": "Old revision: .teal file or directory."},
           "new": {"type": "string", "description": "New revision: .teal file or directory."},
           "old_teal": {"type": "string"}, "new_teal": {"type": "string"},
           "mode": {"type": "string", "enum": ["auto", "app", "logicsig"]},
           "detectors": {"type": "array", "items": {"type": "string"}}},
          diff),
    _tool("tealql_audit_app",
          "Audit a DEPLOYED Algorand app by ID: fetch its approval program and "
          "cross-contract callees from chain (mainnet API + a local algod for "
          "disassembly; TEAL_ALGOD_* env), run every app-mode detector, return the "
          "consolidated report. NETWORK access; results cached under cache_dir.",
          {"app_id": {"type": "integer", "minimum": 1},
           "cache_dir": {"type": "string"}},
          audit_app, required=("app_id",), network=True),
    _tool("tealql_triage_queue",
          "The triage work queue: detector findings for a target that have NO triage "
          "record yet, highest severity/confidence first, each with its fingerprint "
          "and (for the first `limit`) the tealql_source_context payload for its line "
          "pre-joined — one call gives what is needed to judge a finding. Record each "
          "verdict with tealql_record_triage.",
          {**_TARGET_PROPS, **_STORE_PROP, **_MODE_PROP,
           "limit": {"type": "integer", "minimum": 0,
                     "description": "How many queue items carry source_context (default 10)."},
           "context": {"type": "boolean",
                       "description": "Pre-join source_context (default true)."}},
          triage_queue),
    _tool("tealql_record_triage",
          "Record a triage verdict (true_positive / false_positive / needs_context) "
          "for ONE current finding, by fingerprint, with a rationale and the TEAL "
          "evidence_lines it rests on (REQUIRED for false_positive: cite the guarding "
          "lines). Refuses fingerprints that are not current findings of the target. "
          "The verdict is stored as ADVICE beside the finding; it never changes the "
          "detector's verdict. Writes the triage store (additive; re-recording the "
          "same finding replaces its record).",
          {**_TARGET_PROPS, **_STORE_PROP, **_MODE_PROP,
           "fingerprint": {"type": "string",
                           "description": "The finding's fingerprint (from the queue)."},
           "verdict": {"type": "string",
                       "enum": ["true_positive", "false_positive", "needs_context"]},
           "rationale": {"type": "string",
                         "description": "Why: the guard found or the exploit path."},
           "evidence_lines": {"type": "array", "items": {"type": "integer"},
                              "description": "1-based TEAL lines the verdict rests on."},
           "reviewer": {"type": "string",
                        "description": "Who decided: a model name or a person."}},
          record_triage, required=("fingerprint", "verdict", "rationale"),
          read_only=False, destructive=False),
    _tool("tealql_triage_report",
          "Triage records joined to the CURRENT findings of a target: live records "
          "with their finding, STALE records whose fingerprint no longer appears "
          "(program or detector changed — re-triage), untriaged findings, and counts "
          "per verdict and per detector.",
          {**_TARGET_PROPS, **_STORE_PROP, **_MODE_PROP},
          triage_report),
)}


def call_tool(name: str, arguments: Optional[dict] = None) -> dict:
    """Invoke a registered tool by name with validated arguments."""
    tool = TOOLS.get(name)
    if tool is None:
        raise ToolError(f"unknown tool {name!r}; available: {sorted(TOOLS)}")
    return tool.call(arguments)


__all__ = ["Tool", "ToolError", "TOOLS", "call_tool", "validate_arguments",
           "resolve_target", "load_program", "list_detectors", "analyze",
           "verify_sinks", "taint_query", "source_context", "methods",
           "storage_schema", "inner_transactions", "group_shape", "decompile",
           "brief", "diff", "audit_app", "triage_queue", "record_triage",
           "triage_report"]
