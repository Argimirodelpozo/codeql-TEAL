"""Ad-hoc taint reachability queries over the coarse :class:`TaintGraph`.

The detectors answer FIXED questions ("is this specific sink tainted?"). This is
the OPEN query layer: point at any source (a TEAL line, or every read of an input
slot) and ask "what dangerous sinks can this reach?", or the reverse ("what
attacker inputs reach this sink?"). It is the substrate a model/agent drives to
answer free-form security questions.

Two taxonomies, both consolidated here from what the detectors already encode:

* SOURCES — attacker-steerable inputs (``ApplicationArgs``, LogicSig ``arg``s).
* SINKS — operations whose attacker control is dangerous, tagged with a category
  and severity: inner-transaction fund / rekey / asset-admin / appcall fields
  (``itxn_field FIELD``), persistent-state and box writes, and ``log``.

Pure taint reachability over the SSA def-use graph (no lift needed); a hit means
"a value from the source flows into the sink", NOT "the sink is exploitable" —
guard/validation reasoning is the detectors' job. So this OVER-approximates by
design: it is a triage/exploration lens, not a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..avm import FUND_FIELDS, TXN_SOURCE_OPS
from .taint_graph import Node, TaintGraph

# --- sink taxonomy ----------------------------------------------------------

#: ``itxn_field FIELD`` -> (category, severity). Fund fields inherit their
#: severity from ``avm.FUND_FIELDS`` (single source); the rest are added here.
_ITXN_FIELD_SINKS: dict[str, tuple[str, str]] = {
    "CloseRemainderTo": ("inner-close-remainder", "critical"),
    "AssetCloseTo": ("inner-asset-close", "critical"),
    "RekeyTo": ("inner-rekey", "critical"),
    "Receiver": ("inner-payment-receiver", FUND_FIELDS["Receiver"].lower()),
    "AssetReceiver": ("inner-asset-receiver", FUND_FIELDS["AssetReceiver"].lower()),
    "Amount": ("inner-payment-amount", FUND_FIELDS["Amount"].lower()),
    "AssetAmount": ("inner-asset-amount", FUND_FIELDS["AssetAmount"].lower()),
    "Fee": ("inner-fee", "medium"),
    "ApplicationID": ("inner-appcall-target", "high"),
    "XferAsset": ("inner-asset-selector", "high"),
    "FreezeAsset": ("asset-freeze-target", "high"),
    "FreezeAssetAccount": ("asset-freeze-account", "high"),
    "ConfigAssetManager": ("asset-admin", "high"),
    "ConfigAssetClawback": ("asset-admin", "high"),
    "ConfigAssetFreeze": ("asset-admin", "high"),
    "ConfigAssetReserve": ("asset-admin", "high"),
}

#: Sinks identified by OPCODE alone (the danger is the op, not a field).
_OP_SINKS: dict[str, tuple[str, str]] = {
    "app_global_put": ("global-state-write", "high"),
    "app_local_put": ("local-state-write", "high"),
    "box_put": ("box-write", "high"),
    "box_create": ("box-write", "high"),
    "box_replace": ("box-write", "high"),
    "box_del": ("box-delete", "medium"),
    "log": ("log-emit", "low"),
}

#: Source opcodes carrying an attacker-steerable value — the full canonical
#: txn/gtxn read family (scalar `txn ApplicationArgs N` and array `txna …` forms
#: alike); ``is_source`` gates on the ``ApplicationArgs`` field so the scalar-read
#: ops only ever match an actual arg read.
_ARG_ARRAY_OPS = TXN_SOURCE_OPS
_LSIG_ARG_OPS = frozenset({"arg", "args", "arg_0", "arg_1", "arg_2", "arg_3"})


def classify_sink(op: Optional[str], immediates: Optional[str]
                  ) -> Optional[tuple[str, str]]:
    """``(category, severity)`` if ``(op, immediates)`` is a dangerous sink, else
    ``None``. ``itxn_field FIELD`` is classified by ``FIELD``; the state / box /
    log ops by opcode."""
    if op is None:
        return None
    if op == "itxn_field":
        field = (immediates or "").strip()
        return _ITXN_FIELD_SINKS.get(field)
    return _OP_SINKS.get(op)


def is_source(op: Optional[str], immediates: Optional[str]) -> bool:
    """``(op, immediates)`` reads an attacker-steerable input (``ApplicationArgs``
    array read, or a LogicSig ``arg``)."""
    if op is None:
        return False
    if op in _ARG_ARRAY_OPS and "ApplicationArgs" in (immediates or ""):
        return True
    return op in _LSIG_ARG_OPS


# --- query results ----------------------------------------------------------


@dataclass(frozen=True)
class SinkHit:
    """A dangerous sink and how severe it is. ``field`` is the ``itxn_field``
    field (or ``""`` for opcode sinks). ``source`` is the high-level
    ``file:line`` it compiled from, when a source map is available (else None)."""
    node: Node
    op: str
    field: str
    category: str
    severity: str
    source: Optional[str] = None

    @property
    def location(self) -> str:
        return f"{self.node.file}:{self.node.line}"

    def render(self) -> str:
        what = f"{self.op} {self.field}".strip()
        src = f"  <- {self.source}" if self.source else ""
        return (f"[{self.severity.upper():8}] {self.location:26} "
                f"{self.category:22} {what}{src}")

    def to_dict(self) -> dict:
        d = {"file": self.node.file, "line": self.node.line, "op": self.op,
             "field": self.field, "category": self.category,
             "severity": self.severity}
        if self.source:
            d["source"] = self.source
        return d


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sink_hit(g: TaintGraph, node: Node,
              srcmap: Optional[dict] = None) -> Optional[SinkHit]:
    op, imm = g.op_of(node), g.immediates_of(node)
    cls = classify_sink(op, imm)
    if cls is None:
        return None
    field = (imm or "").strip() if op == "itxn_field" else ""
    src = None
    if srcmap:
        hl = srcmap.get((node.file, node.line))
        if hl is not None:
            src = f"{hl[0]}:{hl[1]}"
    return SinkHit(node=node, op=op, field=field, category=cls[0],
                   severity=cls[1], source=src)


# --- the query surface ------------------------------------------------------


class TaintQuery:
    """Open taint-reachability queries over a program's coarse taint graph.

    Build once (``TaintQuery(prog)``), then ask any of:
      * :meth:`sinks_from` — dangerous sinks reachable from a source location;
      * :meth:`sources_of` — attacker inputs that reach a sink location;
      * :meth:`all_sinks` / :meth:`all_sources` — the full inventories.

    All results OVER-approximate (a reachable sink is not necessarily an
    exploitable one — the taint may be validated on the way); this is a triage
    lens, not a verdict.
    """

    def __init__(self, prog, *, file: Optional[str] = None):
        from ..source_map import source_map_for, reverse_file_source_map
        self.prog = prog
        self.g = TaintGraph.of(prog)
        # high-level <-> TEAL line map from the compiler's `// file.py:N` comments
        # (empty on raw bytecode — the query then works in TEAL lines only).
        # Keyed by (teal_file, line): a directory's programs don't clobber.
        src_path = str(getattr(prog, "source_path", "") or "")
        self.srcmap = source_map_for(src_path, file=file) if src_path else {}
        self._rev = reverse_file_source_map(self.srcmap)

    def _file_name(self) -> str:
        """The file label the coarse nodes carry (``a.location.file``), so precise
        IR hits render with the same ``file:line`` string as the coarse ones."""
        for a in getattr(self.prog, "assignments", ()) or ():
            loc = getattr(a, "location", None)
            if loc is not None and getattr(loc, "file", ""):
                return loc.file
        sp = getattr(self.prog, "source_path", None)
        return getattr(sp, "name", "") or "<program>"

    def _hits(self, nodes) -> list["SinkHit"]:
        hits = [h for n in nodes
                if (h := _sink_hit(self.g, n, self.srcmap)) is not None]
        return sorted(hits, key=lambda h: (_SEV_ORDER.get(h.severity, 9),
                                           h.node.file, h.node.line))

    def teal_lines_for_source(self, src_file: str, src_line: int) -> list[int]:
        """The TEAL lines a high-level ``src_file:src_line`` compiled to, or ``[]``
        (no source map / not that line)."""
        # _rev: (src_file, src_line) -> [(teal_file, teal_line), …]. Match the
        # source ref by exact path or basename, and return the bare TEAL lines.
        for (f, ln), tls in self._rev.items():
            if ln == src_line and (f == src_file or f.endswith("/" + src_file)
                                   or f.split("/")[-1] == src_file):
                return [tl for _tf, tl in tls]
        return []

    # -- source / sink location lookup ----------------------------------

    def _nodes(self, *, line: Optional[int] = None, op: Optional[str] = None,
               immediates: Optional[str] = None, file: Optional[str] = None
               ) -> list[Node]:
        return self.g.find(line=line, op=op, immediates=immediates, file=file)

    def all_sinks(self) -> list[SinkHit]:
        """Every dangerous sink in the program, most-severe first."""
        return self._hits(self.g.nodes())

    def all_sources(self) -> list[Node]:
        """Every attacker-input source node."""
        return sorted((n for n in self.g.nodes()
                       if is_source(self.g.op_of(n), self.g.immediates_of(n))),
                      key=lambda n: (n.file, n.line))

    # -- reachability ---------------------------------------------------

    def sinks_from(self, *, line: Optional[int] = None, op: Optional[str] = None,
                   immediates: Optional[str] = None, file: Optional[str] = None,
                   source_line: Optional[int] = None,
                   source_file: Optional[str] = None) -> list[SinkHit]:
        """The dangerous sinks a value defined at the given source location can
        reach (taint-forward). Point at a TEAL line, at every read of an input slot
        (``op="txna", immediates="ApplicationArgs 1"``), or at a HIGH-LEVEL line
        (``source_line=42`` [+ ``source_file``]) which resolves through the source
        map to the TEAL it compiled to."""
        srcs: list[Node] = []
        if any(x is not None for x in (line, op, immediates)):
            srcs += self._nodes(line=line, op=op, immediates=immediates, file=file)
        if source_line is not None:
            for tl in self.teal_lines_for_source(source_file or "", source_line):
                srcs += self._nodes(line=tl)
        reach: set = set()
        for src in srcs:
            reach |= self.g.reachable_from(src)
        return self._hits(reach)

    def sources_of(self, *, line: Optional[int] = None, file: Optional[str] = None
                   ) -> list[Node]:
        """The attacker-input sources that reach the sink at the given location
        (taint-backward). Answers "who can steer this sink?"."""
        if line is None and file is None:
            return []               # all-None find() returns EVERY node — refuse
        reach: set = set()
        for sink in self._nodes(line=line, file=file):
            reach |= self.g.reachable_to(sink)
        return sorted((n for n in reach
                       if is_source(self.g.op_of(n), self.g.immediates_of(n))),
                      key=lambda n: (n.file, n.line))

    def tainted_sinks(self, sources: Optional[Iterable[Node]] = None,
                      *, precise: bool = False) -> list[SinkHit]:
        """Every dangerous sink reachable from ANY attacker-input source — the
        program's attack surface in one call. ``sources`` overrides the default
        (all detected sources).

        ``precise=True`` backs reachability with the lifted Puya IR instead of the
        coarse SSA def-use graph: the IR's reaching-def / scratch / interprocedural
        summaries drop the phantom edges the coarse graph invents AND recover the
        across-``callsub`` flows it misses. It needs the lift (built + cached
        on-demand); when the contract doesn't lift it transparently falls back to
        the coarse graph. ``precise`` still reports GUARD-BLIND reachability (a
        triage lens) — run ``sink_verdict.verify_sinks`` for the guard-aware
        verdict. Passing an explicit ``sources`` set disables precise mode (the
        IR path computes the whole attack surface only)."""
        if precise and sources is None:
            from ..lift import build_lifter
            lifter = build_lifter(self.prog)
            if lifter is not None:
                return self._ir_sink_hits(lifter)
        srcs = list(sources) if sources is not None else self.all_sources()
        reach: set = set()
        for s in srcs:
            reach |= self.g.reachable_from(s)
        return self._hits(reach)

    def _ir_sink_hits(self, lifter) -> list[SinkHit]:
        """Attack-surface sinks from the lifted IR taint (see ``tainted_sinks``).
        Reuses the same fund-flow / state-write / log engine the ir-* detectors
        run on, so the reported lines match a subsequent detector verdict."""
        from ..lift import fund_flow as FF
        from ..lift.taint import user_input_taint
        fname = self._file_name()
        taint = user_input_taint(lifter)
        # fund_flow keys its internal sort by UPPERCASE severities; the SinkHit's
        # own category/severity come from ``classify_sink`` regardless.
        itxn_fields = {f: sev.upper() for f, (_c, sev) in _ITXN_FIELD_SINKS.items()}
        findings = (FF.tainted_itxn_flows(lifter, itxn_fields, taint=taint)
                    + FF.tainted_state_writes(lifter, taint=taint)
                    + FF.tainted_logs(lifter, taint=taint))
        hits: list[SinkHit] = []
        seen: set = set()
        for f in findings:
            if f.field in _ITXN_FIELD_SINKS:            # itxn_field FIELD sink
                op, imm = "itxn_field", f.field
            elif f.field in _OP_SINKS:                  # opcode sink (state / log)
                op, imm = f.field, ""
            else:
                continue
            cls = classify_sink(op, imm)
            if cls is None:
                continue
            key = (f.line, op, imm)
            if key in seen:
                continue
            seen.add(key)
            node = Node(file=fname, line=f.line, node_class="ir")
            hl = self.srcmap.get((fname, f.line)) if self.srcmap else None
            src = f"{hl[0]}:{hl[1]}" if hl else None
            hits.append(SinkHit(node=node, op=op, field=(imm if op == "itxn_field" else ""),
                                category=cls[0], severity=cls[1], source=src))
        return sorted(hits, key=lambda h: (_SEV_ORDER.get(h.severity, 9),
                                           h.node.file, h.node.line))
