"""App-state dataflow detector.

Companion to :mod:`tealql.tealtools.dataflow.box`. Where box-out flow treats
box reads as sources, this treats *application-state reads*
(``app_global_get`` / ``app_local_get`` and their ``_ex`` variants) as
sources and looks for a stored value reaching a sensitive consumer
(payment-routing / app-control ``itxn_field`` sets, or another state
write) without validation.

The risk this models: a contract that trusts a value it previously
stored in global / local state -- a withdrawal address, an amount, an
admin app id -- and routes a payment or app call from it without
re-checking, so anyone who can influence that stored value (an earlier
unguarded write, a sibling app in the group) steers the outflow.

Same substrate and caveats as :mod:`tealql.tealtools.dataflow.box`: taint-only
(not predicate-aware on its own -- compose with
:mod:`tealql.tealtools.dataflow.predicate_aware` to drop guarded flows), stops
at BLOCK ops (arithmetic, ``btoi``), propagates through hash / slice /
concat-with-const.
"""
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
# Output-index conventions (1-based, top-first after the op runs; the
# arities live in tealql.tealtools.avm):
#   app_global_get     (1 -> 1): pushes [value]            -> value = 1
#   app_local_get      (2 -> 1): pushes [value]            -> value = 1
#   app_global_get_ex  (2 -> 2): pushes [value, did_exist] -> value = 2
#   app_local_get_ex   (3 -> 2): pushes [value, did_exist] -> value = 2
# The ``_ex`` variants leave ``did_exist`` on top (output 1); the stored
# value we care about is the deeper output 2 -- mirrors box_get/box_len.

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

# Payment-routing / app-control itxn fields are the high-value sinks
# (a stored address/amount steering an outflow). The state-write sinks
# are included so a state value laundered into a *different* state slot
# and then used downstream is still reachable; they don't create
# trivial self-flows because a read's own output never feeds its own
# write input.
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
    """Find app-state values reaching sensitive consumers without
    sanitisation. Treats *every* state read as a source; compose with
    :mod:`tealql.tealtools.dataflow.predicate_aware` to suppress flows a
    dominating guard already constrains."""
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
# ``detect_out_of_state_flows`` treats EVERY state read as a source, which
# answers "where does stored state steer an outflow" — an attack-surface map,
# not a triage list. It cannot tell a slot an attacker could have written from
# one only an admin path writes, so on a real contract it reports every
# config-read-then-route, which is most of them.
#
# This narrows it the same way :func:`tealql.tealtools.dataflow.box.
# detect_correlated_flows` narrows the box equivalent: first find the state
# WRITES that carry attacker-tainted values, then treat only READS OF THOSE
# SAME SLOTS as sources. The result is the actual round trip the module
# docstring describes as the risk — "anyone who can influence that stored
# value steers the outflow" — rather than every stored value.

#: Ops that write app state, and the input index holding the KEY.
#: Verified against the SSA (top-first): ``app_global_put`` is
#: ``[value, key]`` and ``app_local_put`` is ``[value, key, account]``, so on
#: BOTH the value is index 0 and the key is index 1. (Reads put the key at
#: index 0 — see ``_STATE_READ_KEY_IDX``. The asymmetry is real; do not
#: collapse the two tables.)
_STATE_WRITE_KEY_IDX: dict[str, int] = {
    "app_global_put": 1,
    "app_local_put": 1,
}

#: Ops that read app state -> (key input index, 1-based output index of the
#: VALUE). The ``_ex`` forms leave ``did_exist`` on top, so the stored value
#: is the deeper output 2.
_STATE_READ_KEY_IDX: dict[str, tuple[int, int]] = {
    "app_global_get": (0, 1),
    "app_local_get": (0, 1),
    "app_global_get_ex": (0, 2),
    "app_local_get_ex": (0, 2),
}

_LOCAL_OPS = frozenset({"app_local_put", "app_local_get", "app_local_get_ex"})


def _state_slot_signature(a: Assignment) -> Optional[str]:
    """A syntactic identity for the storage slot a state op touches, or
    ``None`` when the shape doesn't fit.

    Three components, because all three have to match for a write and a read
    to be the same storage:

    * **scope** — global ``"admin"`` and local ``"admin"`` are different slots.
    * **key** — via :func:`tealql.tealtools.dataflow.box._key_signature`, the
      same syntactic-equivalence used for box keys.
    * **account**, for local state only — ``app_local_put(A, k, v)`` and
      ``app_local_get(B, k)`` are different storage unless ``A`` is ``B``.

    Syntactic, like the box version: two forms that resolve to the same bytes
    at runtime by different routes are NOT matched (that needs semantic
    equality, which isn't modelled). Being strict here costs recall, not
    soundness — an unmatched pair simply isn't reported as a correlated flow,
    and ``detect_out_of_state_flows`` still covers it.
    """
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
    """End-to-end chain: external source → state write at slot S →
    state read at slot S → sensitive sink."""

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
    """Two-pass analysis chaining attacker-tainted state writes to later reads
    of the SAME slot.

    Pass 1: ``initial_sources`` (default: external args) → state-write value
    positions. Records which ``app_global_put`` / ``app_local_put`` carry
    tainted values, keyed by slot signature, with the originating source.

    Pass 2: synthesises a per-read :class:`Source` for every state read whose
    slot signature matches a tainted-write cluster, and runs the detector with
    the sensitive sinks. Each :class:`Violation` is rebuilt as a
    :class:`CorrelatedStateViolation` carrying the whole chain.
    """
    from .box import DEFAULT_INTO_BOX_SOURCES

    init_sources = (list(initial_sources) if initial_sources is not None
                    else DEFAULT_INTO_BOX_SOURCES)
    sinks = (list(sensitive_sinks) if sensitive_sinks is not None
             else DEFAULT_OUT_OF_STATE_SINKS)

    write_sinks = [APP_GLOBAL_PUT_VALUE_SINK, APP_LOCAL_PUT_VALUE_SINK]
    pass1 = TaintAnalysis(prog, sources=init_sources, sinks=write_sinks,
                          default_rules=ATTACKER_CONTROL_RULES)
    # One fixpoint for every write below (it also yields the source-of map).
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
        # The write that STORED the attacker value. Several are possible; one
        # chain per (read, sink) pair keeps the output bounded, same as the
        # box version.
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
