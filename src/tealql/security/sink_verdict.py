"""Chain the OPEN taint reachability (``TaintQuery``) to the guard-aware detectors
for a per-sink VERDICT.

``taint_query`` answers "can an attacker input REACH this sink?" (a triage lens
that over-approximates — the flow may be validated on the way). The detectors
answer "is a reach here actually UNGUARDED?" (the verdict, with sender-auth /
receiver-pin / group-index / type reasoning). This joins them: every
attacker-reachable dangerous sink, annotated with

  * CONFIRMED — a guard-aware detector flags it (a likely-real unguarded flow);
  * GUARDED   — a detector that covers this sink category RAN and did NOT flag it
    (its guard reasoning cleared the reach);
  * UNVERIFIED — no detector covers this sink category (reachable, unjudged).

The join key is the source LINE: the IR-taint detectors report at the sink op's
line, which is exactly the ``TaintQuery`` sink node's line.
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
    # ir-tainted-fund-flow's field set (FUND_FIELDS) EXCLUDES RekeyTo, so it can
    # never flag an itxn-rekey sink; inner-txn-close-rekey is the app-mode detector
    # that covers CloseRemainderTo/RekeyTo/AssetCloseTo inner-txn writes.
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
    """Every attacker-reachable dangerous sink with its detector verdict
    (CONFIRMED / GUARDED / UNVERIFIED). Runs each relevant detector once; a
    detector crash leaves its sinks UNVERIFIED rather than failing the query.

    ``precise=True`` sources the reachable set from the lifted IR (fewer phantom
    reaches, plus interprocedural ones the coarse graph misses) — see
    ``TaintQuery.tainted_sinks``. The verdict layer is unchanged; only the sink
    set it judges gets sharper."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    from tealql.security import DETECTORS
    from tealql.security.findings import violation_line

    if precise:
        # Pre-warm the shared lift through the detector-grade builder so its
        # coverage/crash warnings fire (the quiet query-side build would swallow
        # them); the detectors below then reuse this ONE lift, not a second.
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
    # CONFIRMED first, then GUARDED, then UNVERIFIED; keep the sink severity order.
    _rank = {"CONFIRMED": 0, "GUARDED": 1, "UNVERIFIED": 2}
    return sorted(out, key=lambda v: (_rank[v.verdict],))
