"""Join the OPEN taint reachability (``TaintQuery``, which over-approximates: the
flow may be validated on the way) to the guard-aware detectors, for a per-sink
CONFIRMED / GUARDED / UNVERIFIED verdict.

HAZARD: GUARDED means a detector covering that category RAN and did not flag it,
UNVERIFIED means NO detector covers the category — reachable but unjudged, never
"safe". The join key is the source LINE, since the IR-taint detectors report at
the sink op's line, exactly the ``TaintQuery`` sink node's line.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tealql.tealtools.ssa import SSAProgram

#: sink category (from ``taint_query``) -> the detector(s) whose verdict covers it.
_CATEGORY_DETECTORS: dict[str, tuple[str, ...]] = {
    "inner-payment-receiver": ("ir-tainted-fund-flow",),
    "inner-payment-amount": ("ir-tainted-fund-flow",),
    "inner-asset-receiver": ("ir-tainted-fund-flow",),
    "inner-asset-amount": ("ir-tainted-fund-flow",),
    "inner-close-remainder": ("ir-tainted-fund-flow",),
    "inner-asset-close": ("ir-tainted-fund-flow",),
    # HAZARD: ir-tainted-fund-flow's FUND_FIELDS EXCLUDES RekeyTo, so listing it
    # here would make every itxn-rekey sink read GUARDED. inner-txn-close-rekey is
    # the detector that actually covers RekeyTo/CloseRemainderTo/AssetCloseTo.
    "inner-rekey": ("inner-txn-close-rekey",),
    "inner-fee": ("ir-tainted-fee",),
    "inner-appcall-target": ("ir-arbitrary-inner-appcall",),
    "inner-asset-selector": ("ir-arbitrary-inner-asset",),
    "asset-freeze-target": ("ir-tainted-freeze",),
    "asset-freeze-account": ("ir-tainted-freeze",),
    "asset-admin": ("ir-tainted-asset-admin",),
    "global-state-write": ("ir-tainted-state-write",),
    "local-state-write": ("ir-tainted-state-write",),
    "box-write": ("ir-tainted-state-write",),
    "box-delete": ("ir-tainted-state-write",),
    "log-emit": ("ir-tainted-log",),
}


@dataclass
class SinkVerdict:
    """A taint-reachable sink joined to the detectors' guard-aware verdict."""
    sink: object                       # taint_query.SinkHit
    confirmed_by: list = field(default_factory=list)   # detectors that flagged it
    covered_by: list = field(default_factory=list)     # detectors that CAN judge it

    @property
    def verdict(self) -> str:
        if self.confirmed_by:
            return "CONFIRMED"
        return "GUARDED" if self.covered_by else "UNVERIFIED"

    def render(self) -> str:
        tag = {"CONFIRMED": "CONFIRMED", "GUARDED": "guarded  ",
               "UNVERIFIED": "unverified"}[self.verdict]
        by = f" ({', '.join(self.confirmed_by)})" if self.confirmed_by else ""
        return f"{tag}  {self.sink.render()}{by}"

    def to_dict(self) -> dict:
        d = self.sink.to_dict()
        d["verdict"] = self.verdict
        d["confirmed_by"] = list(self.confirmed_by)
        return d


def verify_sinks(prog: SSAProgram, *, file: Optional[str] = None,
                 precise: bool = False) -> list[SinkVerdict]:
    """Every attacker-reachable dangerous sink with its verdict, running each
    relevant detector once; a detector crash leaves its sinks UNVERIFIED rather
    than failing the query. ``precise=True`` sources the reachable set from the
    lifted IR — a sharper sink set, same verdict layer."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    from tealql.security import DETECTORS
    from tealql.security.findings import violation_line

    if precise:
        # Pre-warm through the DETECTOR-grade builder so its coverage/crash
        # warnings fire (the query-side build is quiet) and the detectors below
        # reuse this one lift rather than building a second.
        from tealql.security.common import ir_lifter
        ir_lifter(prog, file)

    q = TaintQuery(prog, file=file)
    sinks = q.tainted_sinks(precise=precise)

    needed = {d for h in sinks for d in _CATEGORY_DETECTORS.get(h.category, ())}
    flagged: dict[str, set] = {}          # detector -> {flagged line}
    for det in needed:
        cls = DETECTORS.get(det)
        if cls is None:
            continue
        try:
            lines = {ln for v in cls(prog, file=file).detect()
                     if (ln := violation_line(v)) is not None}
        except Exception:
            continue                       # detector crash -> its sinks stay UNVERIFIED
        flagged[det] = lines

    out: list[SinkVerdict] = []
    for h in sinks:
        dets = _CATEGORY_DETECTORS.get(h.category, ())
        covered = [d for d in dets if d in flagged]          # actually ran
        confirmed = [d for d in covered if h.node.line in flagged[d]]
        out.append(SinkVerdict(sink=h, confirmed_by=confirmed, covered_by=covered))
    # CONFIRMED, then GUARDED, then UNVERIFIED; sink severity order is preserved.
    _rank = {"CONFIRMED": 0, "GUARDED": 1, "UNVERIFIED": 2}
    return sorted(out, key=lambda v: (_rank[v.verdict],))
