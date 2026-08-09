"""Cross-contract analysis layer for TEAL ``itxn_submit`` app calls.

Finds appcall sites with a resolvable callee AppID (:class:`AppcallSite`), walks
the transitive call graph (:class:`XContractGraph`), runs each callee under
caller-seeded path predicates, and feeds the callee's approving-exit summary
back to the caller. Consumes ``SSAProgram`` / ``InnerTxnReport`` only — the
substrate is never modified.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace as _dc_replace
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("tealql.tealtools.intercontract.analysis")

from ..reporting.inner_transactions import InnerTxn, InnerTxnReport
from ..cfg.path_predicates import BranchCondition, PathPredicateAnalysis
from ..ast.literals import render_byte_constant
from ..ssa import Const, SSAProgram, const_bytes as _const_bytes, const_int

# TypeEnum for appl: the assembler folds `int appl` to the literal 6 pre-SSA.
TYPEENUM_APPL = "6"

Registry = dict[int, str]


@dataclass(frozen=True)
class AppcallSite:
    """One identified cross-contract call site in a caller program."""

    file: str
    submit_line: int
    app_id: int
    callee_source: Path
    # Constant ApplicationArgs by index; non-constant args are absent (walk the
    # underlying ``InnerTxn`` for those).
    const_args: dict[int, str] = field(default_factory=dict)

    def render(self, relative_to: Optional[Path] = None) -> str:
        if self.const_args:
            args = ", ".join(
                f"args[{i}]={render_byte_constant(v)}"
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
    """Load an AppID → ``.teal``-path mapping from yaml; paths resolve relative
    to the yaml's parent dir, so a registry can be self-contained."""
    p = Path(path).resolve()
    raw = yaml.safe_load(p.read_text()) or {}
    base = p.parent
    out: Registry = {}
    for app_id, src in raw.items():
        out[int(app_id)] = str((base / src).resolve())
    return out


def _const_only(values: list[str]) -> Optional[str]:
    """The single literal in ``values``, else ``None`` — a literal being one that
    is neither ``?``-prefixed (unresolved) nor a source-op description."""
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
    # Every TypeEnum-set must agree on `appl`: if sets disagree (branchy code
    # that sometimes makes pay, sometimes appl) there is no reliable callee.
    for f in type_fields:
        if _const_only(f.possible_values()) != TYPEENUM_APPL:
            return False
    return True


def _state_key(inputs) -> Optional[str]:
    """The constant bytes KEY of a state READ, or ``None`` if the key isn't const.

    HAZARD: SSA inputs are TOP-FIRST, so the key is ``inputs[0]``
    (``[key, account?, app?]``). Scanning ALL inputs for the first bytes const
    instead takes a constant ACCOUNT address as the key when the key is dynamic —
    a wrong AppID resolution."""
    return _const_bytes(inputs[0]) if inputs else None


# State scope -> its write op. An AppID stashed in any persistent store and read
# back to drive an inner appcall resolves the same way: EVERY write of the key
# must agree on one int constant.
_PUT_OP = {"global": "app_global_put", "local": "app_local_put", "box": "box_put"}

#: Ops that MUTATE or REMOVE stored state without being a full ``*_put``.
#: HAZARD: the "every write agrees on one constant" proof must see these. A box
#: put with ``itob(123)`` and later ``box_replace``d to 456 otherwise resolves to
#: the stale 123, and the ENTIRE callee analysis — auth findings, summaries,
#: caller pins — runs against the wrong program. Any of these on the key makes
#: the value unprovable.
_MUTATE_OPS = {
    "global": frozenset({"app_global_del"}),
    "local": frozenset({"app_local_del"}),
    "box": frozenset({"box_replace", "box_splice", "box_resize", "box_del"}),
}


def _state_read(operand) -> Optional[tuple[str, str]]:
    """``(scope, key)`` if ``operand`` reads THIS app's own persistent state under
    a constant key (``scope`` in ``{"global", "local", "box"}``), else ``None``.

    Only unambiguously own-app reads qualify: ``app_global_get`` /
    ``app_local_get``, the ``*_get_ex`` forms with foreign-app index 0 (= self),
    and ``btoi (box_get KEY)`` — box values are bytes, and only the whole-value
    ``box_get`` is matched (a ``box_extract`` sub-slice can't be matched against
    a whole ``box_put``).
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
    # HAZARD: TOP-FIRST inputs — the app-reference is specifically inputs[1]
    # ([key, app] for global, [key, app, account] for local). Scanning ALL inputs
    # mis-classifies a FOREIGN app read whose account operand happens to be 0.
    if (op in ("app_global_get_ex", "app_local_get_ex") and len(a.inputs) >= 2
            and const_int(a.inputs[1]) == 0):
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
    """A bytes-constant ``operand`` as the big-endian uint64 a ``btoi`` would read
    from it. Wider than 8 bytes is rejected — ``btoi`` panics on those."""
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
    """The int constant a write op stores under ``key``, else ``None``. A ``box``
    value is bytes — a raw <=8-byte constant or an ``itob`` of a constant.

    HAZARD: a ``global``/``local`` value is a uint64 pushed LAST, so with
    TOP-FIRST SSA inputs it is ``inputs[0]``; the key (and, for local, the
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
    """Resolve an ApplicationID read back from THIS app's own state (global, local
    or box) when EVERY write of the key stores the SAME int constant.

    Errs unresolved: one non-constant or disagreeing write yields ``None`` rather
    than an invented target."""
    read = _state_read(operand)
    if read is None:
        return None
    scope, key = read
    put_op = _PUT_OP[scope]
    mutate_ops = _MUTATE_OPS[scope]
    vals: set[int] = set()
    for w in prog.assignments:
        if w.op in mutate_ops:
            # A partial update / delete of this key — or of an unresolvable key,
            # which MAY be this one — defeats the all-writes-agree proof.
            if any(_const_bytes(inp) == key for inp in w.inputs):
                return None
            if all(_const_bytes(inp) is None for inp in w.inputs):
                return None                   # dynamic key: can't rule it out
            continue
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
    """``N`` if ``operand`` is a direct ``txn``/``txna ApplicationArgs N`` read --
    the program forwarding one of ITS OWN args to a deeper callee, so a caller's
    pin on that arg propagates THROUGH the hop. Else ``None``."""
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
    """Constant ApplicationArgs indexed by stack-set order.

    Each ``itxn_field ApplicationArgs`` pushes one element; ``InnerTxnReport``
    lists them in source order. ``incoming_pins`` (``{arg_index: const}``) is what
    a caller pinned on THIS program's own args: an arg forwarded verbatim keeps
    its pin, so a root-pinned value survives a proxy/forwarder hop."""
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
    """Every appcall itxn submit in ``prog`` whose ApplicationID is a constant
    present in ``registry``, sorted by ``(file, submit_line)``.

    Submits that aren't appl, or whose AppID is non-constant or unregistered, are
    silently skipped — only resolvable cross-contract calls are reported.
    """
    report = InnerTxnReport(prog)
    sites: list[AppcallSite] = []
    for group in report.groups:
        if not group.txns:
            continue
        # A group is usually one txn; if more, emit one site per appcall txn.
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
    state-backed -- regardless of any registry; deterministic order, deduped."""
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
    """Pull a deployed approval program off chain; imported lazily so the analysis
    library doesn't hard-depend on the network-touching tool."""
    from .._utils.chain import fetch_approval
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

    TRANSITIVE: callees are fetched, parsed for THEIR callees, and so on up to
    ``max_depth`` hops. ``fetch(app_id) -> (teal_text, bytecode)`` defaults to
    :func:`_default_chain_fetch`; inject a stub to run offline. An existing
    ``app_<id>.teal`` is reused; unfetchable AppIDs are skipped. An explicit
    ``app_ids`` fetches exactly those, one level. Returns ``{app_id: teal_path}``."""
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
                # Unfetchable -> skip, no invented callee. Logged so an empty
                # registry from a fetch outage isn't read as "no xcontract calls".
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

    # Transitive BFS over the call graph, deduped by AppID, bounded by max_depth.
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


# --- seeded callee analysis -------------------------------------------


def seeds_for_callee(
    callee: SSAProgram, site: AppcallSite
) -> frozenset[BranchCondition]:
    """Translate a site's constant ApplicationArgs into ``eq`` entry predicates
    over the callee's ``txna ApplicationArgs N`` SSAVars.

    Indices the callee never reads are dropped — they'd dangle on unreferenced
    SSAVars and pollute the predicate space.
    """
    if not site.const_args:
        return frozenset()
    seeds: set[BranchCondition] = set()
    for a in callee.assignments:
        # This txn's args, both the `txna` and `txn` forms. NOT `gtxn*`: that
        # reads a group SIBLING's args, not the ones this appcall passed.
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
    """A callee's seeded path-predicate analysis plus its approving-exit summary."""

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
    """Each call site followed by its callee's seeded approving-exit summary."""
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


# --- graph orchestrator + cross-contract detector ---------------------


@dataclass(frozen=True)
class AppcallEdge:
    """One appcall in the transitive graph: ``caller_app_id`` (``None`` = the
    root caller) reaches ``site.app_id`` at ``depth`` hops from the root."""

    caller_app_id: Optional[int]
    site: AppcallSite
    depth: int

    def render(self) -> str:
        src = "root" if self.caller_app_id is None else f"app{self.caller_app_id}"
        return (f"{src} -> app{self.site.app_id} "
                f"@ {self.site.file}:{self.site.submit_line} (hop {self.depth + 1})")


@dataclass
class XContractGraph:
    """Caller + every TRANSITIVELY reachable callee, keyed by AppID, each with its
    seeded path-predicate analysis precomputed.

    ``callees`` / ``callee_sources`` / ``analyses`` span ALL hops, so a detector
    iterating them gets multi-hop coverage for free; ``sites`` is only the ROOT
    caller's appcall sites, while ``edges`` is the full call graph. Owns no
    analysis logic — detectors are external functions over this graph.
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
        """Transitively walk appcall sites from ``caller`` through ``registry``,
        up to ``max_depth`` hops.

        HAZARD: a callee is loaded once, but analysed under the INTERSECTION of
        arg pins across EVERY site calling it — a pin holds only if all callers
        agree. Letting the first caller's pins win would hand a second site
        (which leaves that arg attacker-controlled) the over-pinned analysis,
        silently suppressing a flow exploitable through it. Re-analysis on a
        weakened intersection is monotone, so the walk still terminates."""
        from collections import deque

        root_sites = find_appcall_sites(caller, registry)
        callees: dict[int, SSAProgram] = {}
        callee_sources: dict[int, Path] = {}
        analyses: dict[int, CalleeAnalysis] = {}
        merged_pins: dict[int, dict] = {}   # app_id -> intersected const_args used
        edges: list[AppcallEdge] = []
        edge_seen: set = set()              # (caller_id, app_id, file, line) dedup
        # frontier item: (program, its AppID or None for the root, depth, the pins
        # a caller placed on THIS program's args). A callee is re-enqueued when
        # its pins weaken, so the weakening reaches its own call sites.
        frontier: deque = deque([(caller, None, 0, {})])
        while frontier:
            prog, prog_id, depth, incoming_pins = frontier.popleft()
            if depth >= max_depth:
                continue
            sites = (root_sites if prog is caller
                     else find_appcall_sites(prog, registry, incoming_pins))
            for site in sites:
                ekey = (prog_id, site.app_id, site.file, site.submit_line)
                if ekey not in edge_seen:
                    edge_seen.add(ekey)
                    edges.append(AppcallEdge(prog_id, site, depth))
                if site.app_id not in callees:
                    callee = SSAProgram(str(site.callee_source))
                    # Resolve constants BEFORE walking the callee's own appcall
                    # sites: construction only tags direct pushes, so a callee
                    # whose target AppID needs propagation (folded arithmetic,
                    # dup/cover flow, phi) has ITS callees silently omitted.
                    callee.propagate_constants()
                    callees[site.app_id] = callee
                    callee_sources[site.app_id] = site.callee_source
                    merged_pins[site.app_id] = dict(site.const_args)
                    analyses[site.app_id] = analyze_callee(callee, site)
                    frontier.append((callee, site.app_id, depth + 1,
                                     dict(site.const_args)))
                else:
                    # Shared callee / cycle: intersect this site's pins with the
                    # merged set — keep only args both pin to the SAME constant.
                    cur = merged_pins[site.app_id]
                    new = {k: v for k, v in cur.items()
                           if site.const_args.get(k) == v}
                    if new != cur:                       # strictly weakened
                        merged_pins[site.app_id] = new
                        analyses[site.app_id] = analyze_callee(
                            callees[site.app_id],
                            _dc_replace(site, const_args=new))
                        frontier.append((callees[site.app_id], site.app_id,
                                         depth + 1, dict(new)))
        return cls(
            caller=caller, sites=root_sites, callees=callees,
            callee_sources=callee_sources, analyses=analyses, edges=edges,
        )

    @classmethod
    def from_chain(
        cls, caller: SSAProgram, *, cache_dir=None, fetch=None, max_depth: int = 4,
    ) -> "XContractGraph":
        """:meth:`build`, with the registry auto-discovered from chain."""
        registry = discover_registry(
            caller, cache_dir=cache_dir, fetch=fetch, max_depth=max_depth)
        return cls.build(caller, registry, max_depth=max_depth)

    def chains(self) -> list[list[int]]:
        """Every root -> ... -> leaf call path as AppIDs, from :attr:`edges`;
        a cycle is cut at its first repeat."""
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
    """One callee-side auth-domination violation, tagged with its AppID."""

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
    """Tags a callee-side operand surfacing in a caller's predicate set, so it
    prints as ``app<id>:V…`` instead of colliding visually with caller-side vars
    (both source files are typically named ``prog.teal``). Consts aren't wrapped.
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
    """Map each caller BB containing an ``itxn_submit`` to the matching callee's
    approving-exit summary, callee-side operands tagged :class:`ForeignVar`.

    HAZARD: the predicates land on the WHOLE BB containing the submit, so a sink
    earlier in that BB reads as over-guarded — an UNSOUND direction (missed
    finding). Splitting the BB at the submit boundary would fix it.
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
    """Caller path predicates, each submit BB seeded with its callee's summary."""
    return PathPredicateAnalysis(
        graph.caller, bb_seeds=caller_feedback_bb_seeds(graph)
    )


def render_caller_feedback(
    graph: XContractGraph, *, relative_to: Optional[Path] = None
) -> str:
    """The caller's path predicates after callee-summary feedback; only BBs that
    received feedback (the rest match a vanilla :class:`PathPredicateAnalysis`)."""
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
    """One finding per callee sink that no recognised guard dominates, using each
    callee's seeded :class:`PathPredicateAnalysis`.

    HAZARD: inside an appcall callee ``txn Sender`` is the CALLER APP's address,
    so a caller-side sender guard does NOT compose over the callee — never seed
    one into a callee's predicates. Cross-contract auth keys on ``global
    CallerApplicationID`` (see :mod:`.cfg.super_auth`).
    """
    from ..analysis.auth import AuthDominationDetector

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
