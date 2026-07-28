"""App-state dataflow: a value read back out of global / local state reaching a
payment-routing or app-control sink without re-validation.

Taint-only on its own — compose with :mod:`.predicate_aware` to drop the flows a
dominating guard already constrains."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .engine import (
    ATTACKER_CONTROL_RULES, Sink, Source, TaintAnalysis, TaintedOperand,
    Violation,
)
from .box import APP_GLOBAL_PUT_VALUE_SINK, APP_LOCAL_PUT_VALUE_SINK, ITXN_FIELD_SENSITIVE_SINKS
from ..ssa import Assignment, Const, SSAProgram


# --- app-state read sources ------------------------------------------
#
# Output indices are 1-based and TOP-FIRST:
#   app_global_get     (1 -> 1): [value]            -> value = 1
#   app_local_get      (2 -> 1): [value]            -> value = 1
#   app_global_get_ex  (2 -> 2): [value, did_exist] -> value = 2
#   app_local_get_ex   (3 -> 2): [value, did_exist] -> value = 2
# The ``_ex`` forms leave ``did_exist`` ON TOP, so the stored value is the
# DEEPER output 2 — taking output 1 there taints a 0/1 flag instead.

APP_GLOBAL_GET_SOURCE = Source(
    name="app_global_get value",
    matches=lambda a: a.op == "app_global_get",
    tainted_outputs=lambda a: [1],
)

APP_LOCAL_GET_SOURCE = Source(
    name="app_local_get value",
    matches=lambda a: a.op == "app_local_get",
    tainted_outputs=lambda a: [1],
)

APP_GLOBAL_GET_EX_SOURCE = Source(
    name="app_global_get_ex value",
    matches=lambda a: a.op == "app_global_get_ex",
    tainted_outputs=lambda a: [2],
)

APP_LOCAL_GET_EX_SOURCE = Source(
    name="app_local_get_ex value",
    matches=lambda a: a.op == "app_local_get_ex",
    tainted_outputs=lambda a: [2],
)


DEFAULT_OUT_OF_STATE_SOURCES: list[Source] = [
    APP_GLOBAL_GET_SOURCE,
    APP_LOCAL_GET_SOURCE,
    APP_GLOBAL_GET_EX_SOURCE,
    APP_LOCAL_GET_EX_SOURCE,
]

# State-write sinks are included so a value laundered into a DIFFERENT slot is
# still reachable; they create no self-flows because a read's own output never
# feeds its own write input.
DEFAULT_OUT_OF_STATE_SINKS: list[Sink] = [
    *ITXN_FIELD_SENSITIVE_SINKS,
    APP_GLOBAL_PUT_VALUE_SINK,
    APP_LOCAL_PUT_VALUE_SINK,
]


def detect_out_of_state_flows(
    prog: SSAProgram,
    *,
    sources: Optional[Iterable[Source]] = None,
    sinks: Optional[Iterable[Sink]] = None,
) -> list[Violation]:
    """State values reaching sensitive consumers.

    HAZARD: EVERY state read is a source, so this is an attack-surface map, not
    a triage list — it cannot tell an attacker-writable slot from an admin-only
    one. Use :func:`detect_correlated_state_flows` for the latter."""
    return TaintAnalysis(
        prog,
        sources=list(sources) if sources is not None
        else DEFAULT_OUT_OF_STATE_SOURCES,
        sinks=list(sinks) if sinks is not None
        else DEFAULT_OUT_OF_STATE_SINKS,
        default_rules=ATTACKER_CONTROL_RULES,   # control question, not collision
    ).detect()


# --- correlated: attacker-written state, later read and used ---------
#
# Narrows the above to the actual round trip: find the state WRITES carrying
# attacker-tainted values, then treat only READS OF THOSE SAME SLOTS as sources.

#: Ops that write app state -> the input index holding the KEY.
#: TOP-FIRST: ``app_global_put`` is ``[value, key]`` and ``app_local_put`` is
#: ``[value, key, account]``, so on BOTH the value is index 0 and the key is 1.
#: HAZARD: READS put the key at index 0 instead (``_STATE_READ_KEY_IDX``). The
#: asymmetry is real — collapsing the two tables reads a value as a key.
_STATE_WRITE_KEY_IDX: dict[str, int] = {
    "app_global_put": 1,
    "app_local_put": 1,
}

#: Ops that read app state -> (key input index, 1-based output index of the
#: VALUE); the ``_ex`` forms put the value at the deeper output 2.
_STATE_READ_KEY_IDX: dict[str, tuple[int, int]] = {
    "app_global_get": (0, 1),
    "app_local_get": (0, 1),
    "app_global_get_ex": (0, 2),
    "app_local_get_ex": (0, 2),
}

_LOCAL_OPS = frozenset({"app_local_put", "app_local_get", "app_local_get_ex"})


def _state_slot_signature(a: Assignment) -> Optional[str]:
    """Syntactic identity of the storage slot a state op touches, or ``None``.

    HAZARD: scope, key AND account (local only) must all match for a write and a
    read to be the same storage — global ``"admin"`` is not local ``"admin"``,
    and ``app_local_put(A, k, v)`` is not ``app_local_get(B, k)``. Matching is
    syntactic, so two keys that agree at runtime by different routes do NOT
    match; that costs recall, never soundness."""
    from .box import _key_signature

    if a.op in _STATE_WRITE_KEY_IDX:
        key_idx = _STATE_WRITE_KEY_IDX[a.op]
        acct_idx = 2 if a.op in _LOCAL_OPS else None
    elif a.op in _STATE_READ_KEY_IDX:
        key_idx = _STATE_READ_KEY_IDX[a.op][0]
        # app_local_get [key, account]; app_local_get_ex [key, app, account]
        acct_idx = (len(a.inputs) - 1) if a.op in _LOCAL_OPS else None
    else:
        return None
    if key_idx >= len(a.inputs):
        return None
    scope = "local" if a.op in _LOCAL_OPS else "global"
    sig = f"{scope}:{_key_signature(a.inputs[key_idx])}"
    if acct_idx is not None:
        if acct_idx >= len(a.inputs):
            return None
        sig += f"@{_key_signature(a.inputs[acct_idx])}"
    return sig


@dataclass
class CorrelatedStateViolation:
    """The chain: external source → state write at slot S → read of S → sink."""

    initial_source: Assignment
    initial_source_name: str
    state_write: Assignment
    state_read: Assignment
    sink: Assignment
    sink_name: str
    sink_operand: TaintedOperand

    def pretty(self) -> str:
        return (
            f"{self.initial_source_name}@{self.initial_source.location}  →  "
            f"{self.state_write.op}@{self.state_write.location}  →  "
            f"{self.state_read.op}@{self.state_read.location}  →  "
            f"{self.sink_name}@{self.sink.location}  "
            f"(sink_value = {self.sink_operand!r})"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref, operand_repr
        return {
            "initial_source": {"name": self.initial_source_name,
                               **assignment_ref(self.initial_source)},
            "state_write": assignment_ref(self.state_write),
            "state_read": assignment_ref(self.state_read),
            "sink": {"name": self.sink_name, **assignment_ref(self.sink)},
            "operand": operand_repr(self.sink_operand),
        }


def detect_correlated_state_flows(
    prog: SSAProgram,
    *,
    initial_sources: Optional[Iterable[Source]] = None,
    sensitive_sinks: Optional[Iterable[Sink]] = None,
) -> list[CorrelatedStateViolation]:
    """Chain attacker-tainted state writes to later reads of the SAME slot."""
    from .box import DEFAULT_INTO_BOX_SOURCES

    init_sources = (list(initial_sources) if initial_sources is not None
                    else DEFAULT_INTO_BOX_SOURCES)
    sinks = (list(sensitive_sinks) if sensitive_sinks is not None
             else DEFAULT_OUT_OF_STATE_SINKS)

    write_sinks = [APP_GLOBAL_PUT_VALUE_SINK, APP_LOCAL_PUT_VALUE_SINK]
    pass1 = TaintAnalysis(prog, sources=init_sources, sinks=write_sinks,
                          default_rules=ATTACKER_CONTROL_RULES)
    tainted_ops, source_for = pass1._compute_taint()

    # slot signature → [(write, originating source assignment, source name)]
    clusters: dict[str, list[tuple[Assignment, Assignment, str]]] = {}
    for write in prog.assignments:
        if write.op not in _STATE_WRITE_KEY_IDX or not write.inputs:
            continue
        value_op = write.inputs[0]              # value is top on both put forms
        if isinstance(value_op, Const) or value_op not in tainted_ops:
            continue
        sig = _state_slot_signature(write)
        if sig is None:
            continue
        src_a, src_name = source_for[value_op]
        clusters.setdefault(sig, []).append((write, src_a, src_name))
    if not clusters:
        return []

    # Assignments are unhashable (unfrozen dataclass) — key by id().
    synth_sources: list[Source] = []
    read_to_cluster: dict[int, str] = {}
    for read in prog.assignments:
        if read.op not in _STATE_READ_KEY_IDX:
            continue
        sig = _state_slot_signature(read)
        if sig is None or sig not in clusters:
            continue
        read_to_cluster[id(read)] = sig
        out_idx = _STATE_READ_KEY_IDX[read.op][1]
        synth_sources.append(Source(
            name="state read of correlated slot",
            matches=lambda x, target=read: x is target,
            tainted_outputs=lambda x, oi=out_idx: [oi],
        ))
    if not synth_sources:
        return []

    out: list[CorrelatedStateViolation] = []
    for v in TaintAnalysis(prog, sources=synth_sources, sinks=sinks,
                           default_rules=ATTACKER_CONTROL_RULES).detect():
        cluster = read_to_cluster.get(id(v.source))
        if cluster is None:
            continue
        # Several writes may have stored it; one chain per (read, sink) pair
        # keeps the output bounded.
        write, init_a, init_name = clusters[cluster][0]
        if write is v.sink:
            continue        # the storing write itself is not an onward flow
        out.append(CorrelatedStateViolation(
            initial_source=init_a,
            initial_source_name=init_name,
            state_write=write,
            state_read=v.source,
            sink=v.sink,
            sink_name=v.sink_name,
            sink_operand=v.sink_operand,
        ))
    return out
