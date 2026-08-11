"""The OPEN query layer over the coarse :class:`TaintGraph` — ask which dangerous
sinks a source reaches, or which attacker inputs reach a sink.

HAZARD: OVER-approximates by design. A hit means a value flows from source to
sink, NOT that the sink is exploitable — this layer does no guard reasoning at
all, so it is a triage lens and must never be reported as a verdict."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..language.avm import FUND_FIELDS, LSIG_ARG_OPS, TXN_SOURCE_OPS
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
    # Attacker-chosen program bytes on an inner app create/update deploy
    # arbitrary code under this app's authority.
    "ApprovalProgram": ("inner-program-code", "critical"),
    "ClearStateProgram": ("inner-program-code", "critical"),
    # ``AssetSender`` on an axfer is the CLAWBACK source — non-zero moves units
    # OUT of another account, so an app holding clawback that lets a caller
    # steer it can drain any holder. Deliberately NOT a fund-flow DETECTOR sink
    # (that needs clawback-authority reasoning to stay precise), so a verdict
    # reports it UNVERIFIED: reachable and unjudged.
    "AssetSender": ("asset-clawback-source", "critical"),
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

#: The whole txn/gtxn read family. HAZARD: these ops read any field, so
#: ``is_source`` must gate on ``ApplicationArgs`` or every txn read is a source.
_ARG_ARRAY_OPS = TXN_SOURCE_OPS
_LSIG_ARG_OPS = LSIG_ARG_OPS


def classify_sink(op: Optional[str], immediates: Optional[str]
                  ) -> Optional[tuple[str, str]]:
    """``(category, severity)`` if this is a dangerous sink, else ``None``."""
    if op is None:
        return None
    if op == "itxn_field":
        field = (immediates or "").strip()
        return _ITXN_FIELD_SINKS.get(field)
    return _OP_SINKS.get(op)


def is_source(op: Optional[str], immediates: Optional[str]) -> bool:
    """True if this reads an ``ApplicationArgs`` entry or a LogicSig ``arg``."""
    if op is None:
        return False
    if op in _ARG_ARRAY_OPS and "ApplicationArgs" in (immediates or ""):
        return True
    return op in _LSIG_ARG_OPS


# --- query results ----------------------------------------------------------


@dataclass(frozen=True)
class SinkHit:
    """A dangerous sink, its severity, and the high-level line it compiled from."""
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
    """Open taint-reachability queries over a program's coarse taint graph."""

    def __init__(self, prog, *, file: Optional[str] = None):
        from ..frontend.source_map import source_map_for, reverse_file_source_map
        self.prog = prog
        self.file = file
        self.g = TaintGraph.of(prog)
        self.health = prog.health(deep=True)
        # Keyed by (teal_file, line) so a directory's programs don't clobber;
        # empty on raw bytecode, where queries work in TEAL lines only.
        self.srcmap = source_map_for(prog, file=file)
        self._rev = reverse_file_source_map(self.srcmap)

    def _file_name(self) -> str:
        """The file label the coarse nodes carry, so IR hits render identically."""
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
        """The TEAL lines a high-level ``src_file:src_line`` compiled to, or ``[]``."""
        # _rev: (src_file, src_line) -> [(teal_file, teal_line), …]; the source
        # ref matches by exact path or basename.
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
        """Every attacker-input source node.

        Includes unknown-scratch loads: a load whose MAY value the SSA could
        not name is TOP for a conservative MAY analysis — it may return
        anything an attacker stored, so skipping it reads the unknown as
        clean."""
        return sorted((n for n in self.g.nodes()
                       if is_source(self.g.op_of(n), self.g.immediates_of(n))
                       or self.g.is_unknown_scratch(n)),
                      key=lambda n: (n.file, n.line))

    # -- reachability ---------------------------------------------------

    def sinks_from(self, *, line: Optional[int] = None, op: Optional[str] = None,
                   immediates: Optional[str] = None, file: Optional[str] = None,
                   source_line: Optional[int] = None,
                   source_file: Optional[str] = None) -> list[SinkHit]:
        """The dangerous sinks reachable from a TEAL line, an op/immediates match,
        or a HIGH-LEVEL line resolved through the source map."""
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
        """The attacker inputs that reach the sink at the given location."""
        if line is None and file is None:
            return []               # all-None find() returns EVERY node — refuse
        reach: set = set()
        for sink in self._nodes(line=line, file=file):
            reach |= self.g.reachable_to(sink)
        return sorted((n for n in reach
                       if is_source(self.g.op_of(n), self.g.immediates_of(n))
                       or self.g.is_unknown_scratch(n)),
                      key=lambda n: (n.file, n.line))

    def tainted_sinks(self, sources: Optional[Iterable[Node]] = None,
                      *, precise: bool = False) -> list[SinkHit]:
        """Every dangerous sink reachable from any attacker input — the attack
        surface in one call.

        ``precise=True`` uses the lifted IR, dropping phantom edges the coarse
        graph invents and recovering the across-``callsub`` flows it misses; it
        falls back silently when the contract doesn't lift, and is disabled by an
        explicit ``sources`` set.

        HAZARD: precise is still GUARD-BLIND. Only ``sink_verdict.verify_sinks``
        answers whether a reachable sink is actually unguarded."""
        if precise and sources is None:
            from ..lift import build_lifter
            lifter = build_lifter(self.prog, file=self.file)
            if lifter is not None:
                return self._ir_sink_hits(lifter)
        srcs = list(sources) if sources is not None else self.all_sources()
        reach: set = set()
        for s in srcs:
            reach |= self.g.reachable_from(s)
        return self._hits(reach)

    def _ir_sink_hits(self, lifter) -> list[SinkHit]:
        """Attack-surface sinks from the lifted IR taint.

        Reuses the same engine the ir-* detectors run on, so the lines reported
        here match a subsequent detector verdict."""
        from ..lift import fund_flow as FF
        from ..lift.taint import user_input_taint
        fname = self._file_name()
        taint = user_input_taint(lifter)
        # fund_flow sorts by UPPERCASE severities; SinkHit's own category and
        # severity still come from ``classify_sink``.
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
