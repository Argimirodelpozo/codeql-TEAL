"""Join the OPEN taint reachability (``TaintQuery``, which over-approximates: the
flow may be validated on the way) to the guard-aware detectors, for a per-sink
CONFIRMED / NOT_FLAGGED / UNVERIFIED verdict.

NOT_FLAGGED means a covering detector completed without a matching finding.
It is not proof of a guard. A finding is joined by program, instruction and
operand role; incomplete detectors leave their sinks UNVERIFIED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tealql.tealtools.ssa import SSAProgram

#: sink category (from ``taint_query``) -> the detector(s) whose verdict covers it.
_CATEGORY_DETECTORS: dict[str, tuple[str, ...]] = {
    "inner-payment-receiver": ("tainted-fund-flow",),
    "inner-payment-amount": ("tainted-fund-flow",),
    "inner-asset-receiver": ("tainted-fund-flow",),
    "inner-asset-amount": ("tainted-fund-flow",),
    "inner-close-remainder": ("tainted-fund-flow",),
    "inner-asset-close": ("tainted-fund-flow",),
    # HAZARD: tainted-fund-flow's FUND_FIELDS EXCLUDES RekeyTo, so listing it
    # here would make every itxn-rekey sink read NOT_FLAGGED. inner-txn-close-rekey is
    # the detector that actually covers RekeyTo/CloseRemainderTo/AssetCloseTo.
    "inner-rekey": ("inner-txn-close-rekey",),
    "inner-fee": ("tainted-fee",),
    "inner-appcall-target": ("arbitrary-inner-appcall",),
    "inner-asset-selector": ("arbitrary-inner-asset",),
    "asset-freeze-target": ("tainted-freeze",),
    "asset-freeze-account": ("tainted-freeze",),
    "asset-admin": ("tainted-asset-admin",),
    "global-state-write": ("tainted-state-write",),
    "local-state-write": ("tainted-state-write",),
    "box-write": ("tainted-state-write",),
    "box-delete": ("tainted-state-write",),
    "log-emit": ("tainted-log",),
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
        return "NOT_FLAGGED" if self.covered_by else "UNVERIFIED"

    def render(self) -> str:
        tag = {"CONFIRMED": "CONFIRMED", "NOT_FLAGGED": "not flagged",
               "UNVERIFIED": "unverified"}[self.verdict]
        by = f" ({', '.join(self.confirmed_by)})" if self.confirmed_by else ""
        return f"{tag}  {self.sink.render()}{by}"

    def to_dict(self) -> dict:
        d = self.sink.to_dict()
        d["verdict"] = self.verdict
        d["confirmed_by"] = list(self.confirmed_by)
        d["covered_by"] = list(self.covered_by)
        return d


def verify_sinks(prog: SSAProgram, *, file: Optional[str] = None,
                 precise: bool = False) -> list[SinkVerdict]:
    """Every attacker-reachable dangerous sink with its verdict, running each
    relevant detector once; a detector crash leaves its sinks UNVERIFIED rather
    than failing the query. ``precise=True`` sources the reachable set from the
    lifted IR — a sharper sink set, same verdict layer."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    from tealql.security import DETECTORS
    from tealql.security.findings import violation_location
    from tealql.tealtools.diagnostics.location import InstructionPoint
    from tealql.tealtools.language.effects import STATE_EFFECTS

    if file is None and len(prog.source_files) > 1:
        out = [v for name in prog.source_files
               for v in verify_sinks(prog, file=name, precise=precise)]
        rank = {"CONFIRMED": 0, "NOT_FLAGGED": 1, "UNVERIFIED": 2}
        return sorted(out, key=lambda v: (rank[v.verdict], v.sink.node.file,
                                         v.sink.node.line))
    if file is not None:
        prog = prog.for_file(file, strict=False)

    if precise:
        # Pre-warm through the DETECTOR-grade builder so its coverage/crash
        # warnings fire (the query-side build is quiet) and the detectors below
        # reuse this one lift rather than building a second.
        from tealql.tealtools.lift import build_lifter
        build_lifter(prog, file)

    q = TaintQuery(prog, file=file)
    sinks = q.tainted_sinks(precise=precise)

    needed = {d for h in sinks for d in _CATEGORY_DETECTORS.get(h.category, ())}
    flagged: dict[str, set] = {}          # detector -> {InstructionPoint}
    for det in needed:
        cls = DETECTORS.get(det)
        if cls is None:
            continue
        try:
            inst = cls(prog, file=file)
            points = set()
            for violation in inst.detect():
                vf, line = violation_location(violation)
                role = getattr(violation, "field", "")
                if vf is None or line is None or not role:
                    continue
                op = role if role in STATE_EFFECTS or role == "log" else "itxn_field"
                points.add(InstructionPoint(vf, line, op,
                                            role if op == "itxn_field" else ""))
        except Exception:
            continue                       # detector crash -> its sinks stay UNVERIFIED
        if getattr(inst, "degraded", None):
            # A degraded detector (lift failed) returned [] WITHOUT raising —
            # counting that as "ran clean" flips every sink it covers to
            # NOT_FLAGGED. Its sinks stay UNVERIFIED, same as a crash.
            continue
        flagged[det] = points

    out: list[SinkVerdict] = []
    for h in sinks:
        dets = _CATEGORY_DETECTORS.get(h.category, ())
        covered = [d for d in dets if d in flagged]          # actually ran
        confirmed = [d for d in covered if h.point in flagged[d]]
        out.append(SinkVerdict(sink=h, confirmed_by=confirmed, covered_by=covered))
    # CONFIRMED, then NOT_FLAGGED, then UNVERIFIED; sink severity order is preserved.
    _rank = {"CONFIRMED": 0, "NOT_FLAGGED": 1, "UNVERIFIED": 2}
    return sorted(out, key=lambda v: (_rank[v.verdict],))
