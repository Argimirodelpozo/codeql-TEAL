"""Cross-contract analysis layer for TEAL `itxn_submit` app calls.

Slice 1: identification only. Walks a caller :class:`SSAProgram` for
`itxn_submit` groups whose first txn is an `appl` (TypeEnum == 6) with
a constant `ApplicationID` resolvable in a registry, and returns
:class:`AppcallSite` records describing the call.

Slice 2 (planned) extends :class:`PathPredicateAnalysis` with entry
seeds and computes an approving-exit summary on the callee. Slice 3
adds an :class:`XContractGraph` orchestrator and the first
cross-contract detector.

The substrate (``tealql.tealtools.ssa``) is *not* modified — this module only
consumes ``SSAProgram`` and ``InnerTxnReport``.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("tealql.tealtools.xcontract")

from .inner_txn_report import InnerTxn, InnerTxnReport
from .path_predicates import BranchCondition, PathPredicateAnalysis
from .ssa import Const, SSAProgram, const_bytes as _const_bytes, const_int

# TEAL TypeEnum integer for application calls. The assembler folds
# `int appl` and `byte "appl"` into the integer literal 6 before SSA.
TYPEENUM_APPL = "6"

Registry = dict[int, str]


@dataclass(frozen=True)
class AppcallSite:
    """One identified cross-contract call site in a caller program."""

    file: str
    submit_line: int
    app_id: int
    callee_source: Path
    # Constant ApplicationArgs by index. Non-constant args are absent;
    # consumers can still walk the underlying ``InnerTxn`` for
    # full operand info.
    const_args: dict[int, str] = field(default_factory=dict)

    def render(self, relative_to: Optional[Path] = None) -> str:
        if self.const_args:
            args = ", ".join(
                f"args[{i}]={v}"
                for i, v in sorted(self.const_args.items())
            )
        else:
            args = "(no constant args)"
        src = self.callee_source
        if relative_to is not None:
            try:
                src = src.relative_to(relative_to)
            except ValueError:
                pass
        return (
            f"{self.file}:L{self.submit_line}  "
            f"appl→{self.app_id}  ({src})  {args}"
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "submit_line": self.submit_line,
            "app_id": self.app_id,
            "callee_source": str(self.callee_source),
            "const_args": {str(i): v for i, v in sorted(self.const_args.items())},
        }


def load_registry(path: str | Path) -> Registry:
    """Load an AppID → ``.teal``-path mapping from a yaml file.

    Paths in the yaml are resolved relative to the yaml's parent dir
    so fixtures can carry self-contained registries.
    """
    p = Path(path).resolve()
    raw = yaml.safe_load(p.read_text()) or {}
    base = p.parent
    out: Registry = {}
    for app_id, src in raw.items():
        out[int(app_id)] = str((base / src).resolve())
    return out


def _const_only(values: list[str]) -> Optional[str]:
    """Return the single literal if ``values`` is exactly one literal,
    else ``None``. A literal is anything that didn't get prefixed with
    ``?`` (unresolved) or come back as a non-literal source-op
    description (containing whitespace or ``(``)."""
    if len(values) != 1:
        return None
    v = values[0]
    if v.startswith("?"):
        return None
    if " " in v or "(" in v:
        return None
    return v


def _is_appcall(txn: InnerTxn) -> bool:
    by_name = txn.fields_by_name()
    type_fields = by_name.get("TypeEnum") or []
    if not type_fields:
        return False
    # Every TypeEnum-set must agree on `appl`. If multiple sets
    # disagree (e.g. branchy code that sometimes makes pay sometimes
    # appl), be conservative and skip — we don't have a reliable
    # callee in that case.
    for f in type_fields:
        if _const_only(f.possible_values()) != TYPEENUM_APPL:
            return False
    return True


def _state_key(inputs) -> Optional[str]:
    """The constant bytes key among a state op's operands (the other being the
    app index for ``*_get_ex`` / the value for ``*_put``)."""
    for inp in inputs:
        kb = _const_bytes(inp)
        if kb is not None:
            return kb
    return None


# State scope -> the write op that stores into it. An ApplicationID stashed in any
# of the three persistent stores and read back to drive an inner appcall resolves
# the same way: prove EVERY write of the key agrees on one int constant.
_PUT_OP = {"global": "app_global_put", "local": "app_local_put", "box": "box_put"}


def _state_read(operand) -> Optional[tuple[str, str]]:
    """If ``operand`` reads a value out of THIS app's own persistent state under a
    constant key, return ``(scope, key)`` with ``scope`` in ``{"global", "local",
    "box"}``; else ``None``. Only reads that unambiguously target the running
    application's own state qualify:

    - ``app_global_get KEY`` / ``app_global_get_ex 0 KEY`` (foreign-app index 0 = self)
    - ``app_local_get ACCT KEY`` / ``app_local_get_ex ACCT 0 KEY``
    - ``btoi (box_get KEY)`` — box values are bytes, so an AppID read from a box is
      de-serialised with ``btoi``; only the whole-value ``box_get`` read is matched
      (a ``box_extract`` sub-slice can't be matched against a whole ``box_put``).

    The key is always the top-of-stack operand for a read, so ``_state_key``
    (first bytes const) picks it even when the account is itself an address const.
    """
    a = getattr(operand, "defined_by", None)
    if a is None:
        return None
    op = a.op
    if op == "app_global_get":
        key = _state_key(a.inputs)
        return ("global", key) if key is not None else None
    if op == "app_local_get":
        key = _state_key(a.inputs)
        return ("local", key) if key is not None else None
    # *_get_ex takes a foreign-apps index; index 0 is the running app's own state.
    if op in ("app_global_get_ex", "app_local_get_ex") and any(
        const_int(i) == 0 for i in a.inputs
    ):
        scope = "global" if op == "app_global_get_ex" else "local"
        key = _state_key(a.inputs)
        return (scope, key) if key is not None else None
    if op == "btoi" and len(a.inputs) == 1:
        src = getattr(a.inputs[0], "defined_by", None)
        if src is not None and src.op == "box_get":
            key = _state_key(src.inputs)
            return ("box", key) if key is not None else None
    return None


def _bytes_const_to_int(operand) -> Optional[int]:
    """Interpret a bytes-constant ``operand`` as the big-endian uint64 a ``btoi``
    would read from it — the value a ``box_put KEY, <=8-byte const`` stored. Only a
    <=8-byte constant is a valid ``btoi`` input; anything wider is rejected."""
    vb = _const_bytes(operand)
    if vb is None or not vb.startswith("0x"):
        return None
    if (len(vb) - 2) // 2 > 8:                # btoi panics on >8 bytes
        return None
    try:
        return int(vb, 16)                    # 0x-hex is big-endian, like btoi
    except ValueError:
        return None


def _itob_int(operand) -> Optional[int]:
    """The int a ``box_put KEY, (itob X)`` stores — ``X`` when it's a constant."""
    d = getattr(operand, "defined_by", None)
    if d is not None and d.op == "itob" and len(d.inputs) == 1:
        return const_int(d.inputs[0])
    return None


def _put_int_value(scope: str, inputs, key: str) -> Optional[int]:
    """The int constant a write op stores under ``key``, or ``None`` if the value
    isn't a statically-known int. A ``box`` value is bytes — a raw <=8-byte
    constant (decoded big-endian) or an ``itob`` of a constant. A ``global`` /
    ``local`` value is a uint64 pushed last, so it is the top-of-stack operand
    (``inputs[0]``, SSA inputs being top-first); the key (and, for local, the
    account) are lower operands."""
    if scope == "box":
        for inp in inputs:
            if _const_bytes(inp) == key:
                continue                      # the key operand, not the value
            iv = _bytes_const_to_int(inp)
            if iv is None:
                iv = _itob_int(inp)
            if iv is not None:
                return iv
        return None
    return const_int(inputs[0]) if inputs else None


def _resolve_state_app_id(prog: SSAProgram, operand) -> Optional[int]:
    """Resolve an ApplicationID read from THIS app's own persistent state —
    global, local, or box — when EVERY write of the key stores the SAME int
    constant. Sound-ish: a single non-constant or disagreeing write leaves it
    unresolved (no invented target). Covers the common router/factory pattern that
    stashes its target app id in state and reads it back to make the call."""
    read = _state_read(operand)
    if read is None:
        return None
    scope, key = read
    put_op = _PUT_OP[scope]
    vals: set[int] = set()
    for w in prog.assignments:
        if w.op != put_op:
            continue
        if all(_const_bytes(inp) != key for inp in w.inputs):
            continue                          # writes a different (or dynamic) key
        iv = _put_int_value(scope, w.inputs, key)
        if iv is None:
            return None                       # non-constant write: can't prove it
        vals.add(iv)
    return next(iter(vals)) if len(vals) == 1 else None


def _const_app_id(txn: InnerTxn, prog: Optional[SSAProgram] = None) -> Optional[int]:
    fields = txn.fields_by_name().get("ApplicationID") or []
    if not fields:
        return None
    seen: set[int] = set()
    for f in fields:
        v = _const_only(f.possible_values())
        if v is not None:                     # inline / propagated literal
            try:
                seen.add(int(v))
            except ValueError:
                return None
        else:                                 # dynamic: trace through persistent state
            rid = _resolve_state_app_id(prog, f.operand) if prog is not None else None
            if rid is None:
                return None
            seen.add(rid)
    return next(iter(seen)) if len(seen) == 1 else None


def _forwarded_apparg_index(operand) -> Optional[int]:
    """If ``operand`` is a direct ``txn`` / ``txna ApplicationArgs N`` read -- the
    program forwarding one of ITS OWN appcall args onward to a deeper callee --
    return ``N``. Lets a pin a caller placed on that arg propagate THROUGH this
    forwarding hop (transitive cross-contract suppression). Else ``None``."""
    d = getattr(operand, "defined_by", None)
    if d is None or d.op not in ("txn", "txna"):
        return None
    parts = (d.immediates or "").split()
    if len(parts) == 2 and parts[0] == "ApplicationArgs":
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def _const_args(txn: InnerTxn, incoming_pins: Optional[dict] = None) -> dict[int, str]:
    """Index the constant ApplicationArgs by their stack-set order.

    Each ``itxn_field ApplicationArgs`` op pushes one element onto the array;
    ``InnerTxnReport`` lists them in source order. ``incoming_pins`` are the
    constants a caller pinned on THIS program's own args (``{arg_index: const}``):
    an arg the program FORWARDS verbatim (a ``txna ApplicationArgs N`` read) is
    pinned to ``incoming_pins[N]`` if present, so a root-pinned value stays pinned
    across a proxy/forwarder hop."""
    incoming_pins = incoming_pins or {}
    fields = txn.fields_by_name().get("ApplicationArgs") or []
    out: dict[int, str] = {}
    for i, f in enumerate(fields):
        v = _const_only(f.possible_values())
        if v is not None:
            out[i] = v
            continue
        j = _forwarded_apparg_index(f.operand)
        if j is not None and j in incoming_pins:
            out[i] = incoming_pins[j]
    return out


def find_appcall_sites(prog: SSAProgram, registry: Registry,
                       incoming_pins: Optional[dict] = None) -> list[AppcallSite]:
    """Find every appcall itxn submit in ``prog`` whose ApplicationID
    is a constant present in ``registry``.

    Returns sites sorted by (file, submit_line) for deterministic
    output. Submits whose first txn isn't an appl, or whose AppID is
    non-constant or unregistered, are silently skipped — slice 1 is
    only about resolvable cross-contract calls.
    """
    report = InnerTxnReport(prog)
    sites: list[AppcallSite] = []
    for group in report.groups:
        if not group.txns:
            continue
        # An appcall group typically contains one txn; if more, the
        # appcall is whichever txn(s) had TypeEnum=appl. Emit one
        # site per appcall txn.
        for txn in group.txns:
            if not _is_appcall(txn):
                continue
            app_id = _const_app_id(txn, prog)
            if app_id is None or app_id not in registry:
                continue
            sites.append(
                AppcallSite(
                    file=group.file,
                    submit_line=group.submit_line,
                    app_id=app_id,
                    callee_source=Path(registry[app_id]),
                    const_args=_const_args(txn, incoming_pins),
                )
            )
    sites.sort(key=lambda s: (s.file, s.submit_line))
    return sites


# --- auto-discovery: build the registry by fetching callees from chain --------


def candidate_app_ids(prog: SSAProgram) -> list[int]:
    """Every appcall callee AppID resolvable from ``prog`` -- inline constant or
    state-backed (see :func:`_resolve_state_app_id`) -- regardless of any registry.
    The set :func:`discover_registry` would fetch. Deterministic order, deduped."""
    report = InnerTxnReport(prog)
    ids: list[int] = []
    seen: set[int] = set()
    for group in report.groups:
        for txn in group.txns:
            if not _is_appcall(txn):
                continue
            aid = _const_app_id(txn, prog)
            if aid is not None and aid not in seen:
                seen.add(aid)
                ids.append(aid)
    return ids


_DEFAULT_CALLEE_CACHE = Path.home() / ".cache" / "tealql" / "xcontract-callees"


def _default_chain_fetch(app_id: int):
    """Default fetcher: pull a deployed approval program off chain. Imported lazily
    so the analysis library doesn't hard-depend on the (network-touching) tool."""
    from ._utils.chain import fetch_approval
    return fetch_approval(app_id)


def discover_registry(
    prog: SSAProgram,
    *,
    cache_dir: "str | Path | None" = None,
    fetch=None,
    app_ids: Optional[list[int]] = None,
    max_depth: int = 4,
) -> Registry:
    """Build an xcontract registry by FETCHING each reachable callee's deployed
    approval program from chain into ``cache_dir`` -- no hand-written yaml.

    Discovery is TRANSITIVE: ``prog``'s callees are fetched, then parsed to find
    THEIR callees, and so on up to ``max_depth`` hops -- so an A->B->C chain
    pulls B and C. ``fetch(app_id) -> (teal_text, bytecode)`` defaults to
    :func:`_default_chain_fetch`; inject a stub to run offline. CACHED: an
    existing ``app_<id>.teal`` in ``cache_dir`` is reused. AppIDs that don't
    fetch (not found / network error) are skipped. Passing an explicit
    ``app_ids`` fetches exactly those (one level, no transitive walk). Returns
    ``{app_id: teal_path}``."""
    cache = Path(cache_dir) if cache_dir is not None else _DEFAULT_CALLEE_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    if fetch is None:
        fetch = _default_chain_fetch
    registry: Registry = {}

    def _fetch_one(aid: int) -> "Path | None":
        teal_path = cache / f"app_{aid}.teal"
        if not teal_path.exists():
            try:
                teal, _bytecode = fetch(aid)
            except Exception as e:
                # Unfetchable (not found / network / no local algod) -> skip, no
                # invented callee. Logged so an empty registry from a fetch
                # outage is distinguishable from "no cross-contract calls".
                logger.warning("could not fetch callee app %s: %s — skipped "
                               "(cross-contract coverage reduced)", aid, e)
                return None
            teal_path.write_text(teal)
        registry[aid] = str(teal_path)
        return teal_path

    if app_ids is not None:
        for aid in app_ids:
            _fetch_one(aid)
        return registry

    # Transitive BFS over the call graph: fetch each program's callees, parse
    # them, recurse into THEIR callees, deduped by AppID, bounded by max_depth.
    from collections import deque

    seen: set[int] = set()
    frontier: deque = deque([(prog, 0)])
    while frontier:
        p, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        for aid in candidate_app_ids(p):
            if aid in seen:
                continue
            seen.add(aid)
            teal_path = _fetch_one(aid)
            if teal_path is None:
                continue
            try:
                callee = SSAProgram(str(teal_path))
                callee.propagate_constants()
            except Exception:
                continue                   # unparseable callee -> registered, not walked
            frontier.append((callee, depth + 1))
    return registry


def render(sites: list[AppcallSite], relative_to: Optional[Path] = None) -> str:
    if not sites:
        return "(no cross-contract appcall sites)"
    return "\n".join(s.render(relative_to=relative_to) for s in sites)


# --- slice 2: seeded callee analysis ----------------------------------


def seeds_for_callee(
    callee: SSAProgram, site: AppcallSite
) -> frozenset[BranchCondition]:
    """Translate caller-side constant ApplicationArgs into entry
    predicates over the callee's ``txna ApplicationArgs N`` SSAVars.

    Conservative: emits one ``eq`` predicate per (index, constant)
    pair where the callee actually references that arg via ``txna``.
    Indices the callee never reads are dropped — they'd dangle on
    unreferenced SSAVars and pollute the predicate space.
    """
    if not site.const_args:
        return frozenset()
    seeds: set[BranchCondition] = set()
    for a in callee.assignments:
        # The current txn's args, indexed — both `txna ApplicationArgs N` (canonical)
        # and the `txn ApplicationArgs N` form. NOT `gtxn*`, which reads a group
        # sibling's args, not the ones this appcall passed.
        if a.op not in ("txn", "txna") or not a.outputs:
            continue
        parts = a.immediates.split()
        if len(parts) != 2 or parts[0] != "ApplicationArgs":
            continue
        try:
            idx = int(parts[1])
        except ValueError:
            continue
        if idx not in site.const_args:
            continue
        const = Const("bytes", site.const_args[idx])
        seeds.add(
            BranchCondition(value=a.outputs[0], kind="eq", args=(const,))
        )
    return frozenset(seeds)


@dataclass
class CalleeAnalysis:
    """Result of running the seeded path-predicate analysis on a
    callee, plus the approving-exit summary the caller can rely on."""

    site: AppcallSite
    analysis: PathPredicateAnalysis
    seeds: frozenset[BranchCondition]
    summary: frozenset[BranchCondition]


def analyze_callee(callee: SSAProgram, site: AppcallSite) -> CalleeAnalysis:
    seeds = seeds_for_callee(callee, site)
    analysis = PathPredicateAnalysis(callee, entry_seeds=seeds)
    return CalleeAnalysis(
        site=site,
        analysis=analysis,
        seeds=seeds,
        summary=analysis.approving_exit_summary(),
    )


def _fmt_preds(preds: frozenset[BranchCondition]) -> str:
    if not preds:
        return "(none)"
    return ", ".join(
        repr(p) for p in sorted(preds, key=lambda c: (c.kind, repr(c.value)))
    )


def render_xcontract(
    sites: list[AppcallSite],
    callee_analyses: dict[int, CalleeAnalysis],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    """Combined slice-1 + slice-2 rendering: each call site followed
    by the callee's seeded approving-exit summary."""
    if not sites:
        return "(no cross-contract appcall sites)"
    out: list[str] = []
    for site in sites:
        out.append("call site: " + site.render(relative_to=relative_to))
        ca = callee_analyses.get(site.app_id)
        if ca is None:
            out.append("  callee not analysed")
            continue
        out.append("  seeds:   " + _fmt_preds(ca.seeds))
        out.append("  summary: " + _fmt_preds(ca.summary))
    return "\n".join(out)


# --- slice 3: graph orchestrator + first cross-contract detector ------


@dataclass(frozen=True)
class AppcallEdge:
    """One appcall in the transitive graph: ``caller_app_id`` (``None`` =
    the root caller) makes ``site``, reaching callee ``site.app_id`` at
    ``depth`` hops from the root."""

    caller_app_id: Optional[int]
    site: AppcallSite
    depth: int

    def render(self) -> str:
        src = "root" if self.caller_app_id is None else f"app{self.caller_app_id}"
        return (f"{src} -> app{self.site.app_id} "
                f"@ {self.site.file}:{self.site.submit_line} (hop {self.depth + 1})")


@dataclass
class XContractGraph:
    """Caller + every TRANSITIVELY reachable callee (A->B->C->...), keyed by
    AppID, with each callee's seeded path-predicate analysis precomputed.

    ``callees`` / ``callee_sources`` / ``analyses`` span ALL hops, so a
    detector that iterates them (``cross_auth_findings``,
    ``cross_detection_findings``) gets multi-hop coverage for free.
    ``sites`` is just the ROOT caller's appcall sites (backward-compatible);
    ``edges`` is the full call graph (one :class:`AppcallEdge` per appcall).

    Owns no analysis logic itself — detectors are external functions that
    consume this graph, keeping detector composition explicit.
    """

    caller: SSAProgram
    sites: list[AppcallSite]
    callees: dict[int, SSAProgram]
    callee_sources: dict[int, Path]
    analyses: dict[int, CalleeAnalysis]
    edges: list[AppcallEdge] = field(default_factory=list)

    @classmethod
    def build(
        cls, caller: SSAProgram, registry: Registry, *, max_depth: int = 4,
    ) -> "XContractGraph":
        """Transitively walk appcall sites from ``caller`` through the
        ``registry``, up to ``max_depth`` hops. Each callee is loaded and
        seeded-analysed exactly once (keyed by AppID); a callee already in the
        graph (a shared callee or a cycle) still records an :class:`AppcallEdge`
        but is not re-analysed, so the walk always terminates."""
        from collections import deque

        root_sites = find_appcall_sites(caller, registry)
        callees: dict[int, SSAProgram] = {}
        callee_sources: dict[int, Path] = {}
        analyses: dict[int, CalleeAnalysis] = {}
        edges: list[AppcallEdge] = []
        # frontier item: (program, its AppID or None for the root, depth, the
        # pins a caller placed on THIS program's args -- so a forwarded arg keeps
        # the pin one hop deeper).
        frontier: deque = deque([(caller, None, 0, {})])
        while frontier:
            prog, prog_id, depth, incoming_pins = frontier.popleft()
            if depth >= max_depth:
                continue
            sites = (root_sites if prog is caller
                     else find_appcall_sites(prog, registry, incoming_pins))
            for site in sites:
                edges.append(AppcallEdge(prog_id, site, depth))
                if site.app_id in callees:
                    continue            # already analysed (dedup + cycle guard)
                callee = SSAProgram(str(site.callee_source))
                callees[site.app_id] = callee
                callee_sources[site.app_id] = site.callee_source
                analyses[site.app_id] = analyze_callee(callee, site)
                frontier.append((callee, site.app_id, depth + 1, dict(site.const_args)))
        return cls(
            caller=caller, sites=root_sites, callees=callees,
            callee_sources=callee_sources, analyses=analyses, edges=edges,
        )

    @classmethod
    def from_chain(
        cls, caller: SSAProgram, *, cache_dir=None, fetch=None, max_depth: int = 4,
    ) -> "XContractGraph":
        """Like :meth:`build`, but auto-discovers the registry transitively by
        fetching each reachable callee from chain (:func:`discover_registry`)."""
        registry = discover_registry(
            caller, cache_dir=cache_dir, fetch=fetch, max_depth=max_depth)
        return cls.build(caller, registry, max_depth=max_depth)

    def chains(self) -> list[list[int]]:
        """Every root -> ... -> leaf call path as a list of AppIDs, derived
        from :attr:`edges`. A cycle is cut at its first repeat."""
        by_caller: dict = {}
        for e in self.edges:
            by_caller.setdefault(e.caller_app_id, []).append(e.site.app_id)
        out: list[list[int]] = []

        def walk(node, path, seen):
            kids = by_caller.get(node)
            if not kids:
                if path:
                    out.append(path)
                return
            for k in kids:
                if k in seen:
                    out.append(path + [k])      # cycle: record + stop
                    continue
                walk(k, path + [k], seen | {k})

        walk(None, [], set())
        return out


@dataclass(frozen=True)
class CrossAuthFinding:
    """One auth-domination violation in a callee, surfaced via the
    cross-contract graph. Includes the calling AppID so the report
    can be grouped per callee."""

    app_id: int
    violation: "object"  # AuthViolation; avoid heavy import at module load

    def render(self, callee_source: Path, relative_to: Optional[Path] = None) -> str:
        src = callee_source
        if relative_to is not None:
            try:
                src = src.relative_to(relative_to)
            except ValueError:
                pass
        return f"{src}  {self.violation.pretty()}"  # type: ignore[attr-defined]

    def to_dict(self, callee_source: Optional[Path] = None) -> dict:
        out: dict = {
            "app_id": self.app_id,
            "violation": self.violation.to_dict(),  # type: ignore[attr-defined]
        }
        if callee_source is not None:
            out["callee_source"] = str(callee_source)
        return out


@dataclass(frozen=True)
class ForeignVar:
    """Tag wrapping a callee-side operand when it surfaces in a caller's
    predicate set after submit-feedback. Without this, callee
    SSAVars print as ``V#1@L4`` and collide visually with caller-side
    vars (both source files are typically named ``prog.teal``).

    ``inner`` is the original :class:`SSAVar` / :class:`Phi` from the
    callee; ``app_id`` is the AppID of the callee. Consts are not
    wrapped — they're literals with no provenance ambiguity.
    """

    inner: object
    app_id: int

    def __repr__(self) -> str:
        return f"app{self.app_id}:{self.inner!r}"


def _foreign_wrap(op: object, app_id: int) -> object:
    """Wrap callee-side operands; leave literals and primitives alone."""
    if isinstance(op, (Const, int, str)):
        return op
    return ForeignVar(inner=op, app_id=app_id)


def _wrap_callee_pred(pred: BranchCondition, app_id: int) -> BranchCondition:
    return BranchCondition(
        value=_foreign_wrap(pred.value, app_id),  # type: ignore[arg-type]
        kind=pred.kind,
        args=tuple(_foreign_wrap(a, app_id) for a in pred.args),
    )


def caller_feedback_bb_seeds(graph: XContractGraph) -> dict:
    """Map each caller BB containing an ``itxn_submit`` to the
    matching callee's approving-exit summary, with callee-side
    operands tagged via :class:`ForeignVar` so the renderer can
    disambiguate them from caller-side vars.

    Imprecision note: predicates land on the *whole* BB containing
    the submit, so any sink in that BB at a line *before* the submit
    will appear to have the summary in its predicate set. Most TEAL
    has control flow shortly after a submit, so this is rarely an
    issue in practice — but a sink-before-submit would be falsely
    over-guarded. A finer model would split the BB at the submit
    boundary; that's a follow-up.
    """
    seeds: dict = {}
    for site in graph.sites:
        ca = graph.analyses.get(site.app_id)
        if ca is None or not ca.summary:
            continue
        bb = graph.caller.block_containing(site.file, site.submit_line)
        if bb is None:
            continue
        wrapped = frozenset(
            _wrap_callee_pred(p, site.app_id) for p in ca.summary
        )
        existing = seeds.get(bb, frozenset())
        seeds[bb] = existing | wrapped
    return seeds


def caller_with_feedback(graph: XContractGraph) -> PathPredicateAnalysis:
    """Run :class:`PathPredicateAnalysis` on the caller with each
    submit-containing BB seeded with the matching callee's summary."""
    return PathPredicateAnalysis(
        graph.caller, bb_seeds=caller_feedback_bb_seeds(graph)
    )


def render_caller_feedback(
    graph: XContractGraph, *, relative_to: Optional[Path] = None
) -> str:
    """Render the caller's path predicates after callee-summary
    feedback. Only shows BBs that received feedback — the rest match
    a vanilla :class:`PathPredicateAnalysis`."""
    bb_seeds = caller_feedback_bb_seeds(graph)
    if not bb_seeds:
        return "(no callee-summary feedback to caller)"
    pp = caller_with_feedback(graph)
    out: list[str] = []
    for bb in sorted(bb_seeds.keys(), key=lambda b: (b.file, b.first_line)):
        preds = pp.bb_preds.get(bb, frozenset())
        out.append(
            f"caller {bb.file}:L{bb.first_line}-L{bb.last_line}  "
            + _fmt_preds(preds)
        )
    return "\n".join(out)


def cross_auth_findings(graph: XContractGraph) -> list[CrossAuthFinding]:
    """Run :class:`AuthDominationDetector` on every callee using its
    seeded :class:`PathPredicateAnalysis`. Returns one finding per
    sensitive sink that no recognised guard dominates.
    """
    from .auth_domination import AuthDominationDetector

    out: list[CrossAuthFinding] = []
    for app_id, callee in graph.callees.items():
        ca = graph.analyses[app_id]
        det = AuthDominationDetector(callee, path_predicates=ca.analysis)
        for v in det.detect():
            out.append(CrossAuthFinding(app_id=app_id, violation=v))
    return out


def render_findings(
    graph: XContractGraph,
    findings: list[CrossAuthFinding],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    if not findings:
        return "(no cross-contract auth-domination findings)"
    return "\n".join(
        f.render(graph.callee_sources[f.app_id], relative_to=relative_to)
        for f in findings
    )
