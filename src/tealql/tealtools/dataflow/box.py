"""Box dataflow detectors: into-box, out-of-box, and the key-correlated round trip.

HAZARD: every sink/source index below encodes a TOP-FIRST stack layout. The box
KEY is pushed first and so is the DEEPEST input, and the ``_ex``-style two-output
reads leave the existence flag ON TOP. Reading these backwards taints a key or a
0/1 flag instead of the value.

Taint-only, not predicate-aware — ``assert(arg < 100)`` before the sink does not
break the chain. Compose with :mod:`.predicate_aware` for that."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .engine import (
    ATTACKER_CONTROL_RULES,
    TaintAnalysis,
    Sink,
    Source,
    TaintedOperand,
    Violation,
)
from ..language.avm import SENSITIVE_ITXN_FIELDS as _SENSITIVE_ITXN_FIELDS
from ..ssa import Assignment, Const, Phi, SSAProgram


# --- sources ---------------------------------------------------------


# ``txna ApplicationArgs N``: pushes 1 (the bytes for arg N).
EXTERNAL_ARG_SOURCE = Source(
    name="txna ApplicationArgs",
    matches=lambda a: a.op == "txna"
    and a.immediates.startswith("ApplicationArgs"),
    tainted_outputs=lambda a: [1],
)


# --- sinks -----------------------------------------------------------


# TEAL pushes the box key FIRST and the value second, so top-first ``inputs``
# is [value, key] — or [size, key] for ``box_create``.

BOX_PUT_VALUE_SINK = Sink(
    name="box_put value",
    matches=lambda a: a.op == "box_put",
    tainted_input_index=lambda a: 1,
)

# ``box_replace key start replacement`` — top-first: [replacement, start, key].
BOX_REPLACE_VALUE_SINK = Sink(
    name="box_replace value",
    matches=lambda a: a.op == "box_replace",
    tainted_input_index=lambda a: 1,
)

# ``box_create key size``: top-first inputs [size, key].
BOX_CREATE_SIZE_SINK = Sink(
    name="box_create size",
    matches=lambda a: a.op == "box_create",
    tainted_input_index=lambda a: 1,
)


DEFAULT_INTO_BOX_SOURCES: list[Source] = [EXTERNAL_ARG_SOURCE]
DEFAULT_INTO_BOX_SINKS: list[Sink] = [
    BOX_PUT_VALUE_SINK,
    BOX_REPLACE_VALUE_SINK,
    BOX_CREATE_SIZE_SINK,
]


# --- box-out sources -------------------------------------------------


# ``box_get key`` — top-first outputs [did_exist, value], so value is index 2.
BOX_GET_VALUE_SOURCE = Source(
    name="box_get value",
    matches=lambda a: a.op == "box_get",
    tainted_outputs=lambda a: [2],
)

# ``box_extract key start length`` — a single bytes output.
BOX_EXTRACT_SOURCE = Source(
    name="box_extract value",
    matches=lambda a: a.op == "box_extract",
    tainted_outputs=lambda a: [1],
)

# ``box_len key`` — top-first outputs [did_exist, length], so length is index 2.
BOX_LEN_SOURCE = Source(
    name="box_len value",
    matches=lambda a: a.op == "box_len",
    tainted_outputs=lambda a: [2],
)


# --- sensitive sinks for box-out flow --------------------------------


# State writes push keys/accounts first, so top-first the value is index 1.
APP_GLOBAL_PUT_VALUE_SINK = Sink(
    name="app_global_put value",
    matches=lambda a: a.op == "app_global_put",
    tainted_input_index=lambda a: 1,
)

# ``app_local_put account key value`` — top-first: [value, key, account].
APP_LOCAL_PUT_VALUE_SINK = Sink(
    name="app_local_put value",
    matches=lambda a: a.op == "app_local_put",
    tainted_input_index=lambda a: 1,
)


# Sensitive itxn_field sinks — arbitrary bytes into these steer payment routing
# or transfer app control.


def _itxn_field_sink(field_name: str) -> Sink:
    return Sink(
        name=f"itxn_field {field_name}",
        matches=lambda a, fn=field_name: (
            a.op == "itxn_field" and a.immediates.strip() == fn
        ),
        tainted_input_index=lambda a: 1,
    )


ITXN_FIELD_SENSITIVE_SINKS: list[Sink] = [
    _itxn_field_sink(f) for f in _SENSITIVE_ITXN_FIELDS
]


DEFAULT_OUT_OF_BOX_SOURCES: list[Source] = [
    BOX_GET_VALUE_SOURCE,
    BOX_EXTRACT_SOURCE,
    BOX_LEN_SOURCE,
]
DEFAULT_OUT_OF_BOX_SINKS: list[Sink] = [
    APP_GLOBAL_PUT_VALUE_SINK,
    APP_LOCAL_PUT_VALUE_SINK,
] + ITXN_FIELD_SENSITIVE_SINKS


# --- entry points: into-box and out-of-box ---------------------------


def detect_into_box_flows(
    prog: SSAProgram,
    *,
    sources: Optional[Iterable[Source]] = None,
    sinks: Optional[Iterable[Sink]] = None,
) -> list[Violation]:
    """Find external inputs reaching a box write without sanitisation."""
    return TaintAnalysis(
        prog,
        sources=list(sources) if sources is not None else DEFAULT_INTO_BOX_SOURCES,
        sinks=list(sinks) if sinks is not None else DEFAULT_INTO_BOX_SINKS,
        # HAZARD: this is a CONTROL question, so concat must propagate on ANY
        # tainted input. The collision-model default blocks taint whenever an
        # untainted non-const operand is present, silently losing
        # `concat(dynamic_prefix, user_arg)`.
        default_rules=ATTACKER_CONTROL_RULES,
    ).detect()


def detect_out_of_box_flows(
    prog: SSAProgram,
    *,
    sources: Optional[Iterable[Source]] = None,
    sinks: Optional[Iterable[Sink]] = None,
) -> list[Violation]:
    """Box-stored values reaching sensitive consumers.

    HAZARD: EVERY box read is a source, so this is an attack-surface map, not a
    triage list. :func:`detect_correlated_flows` restricts it to reads that
    demonstrably alias an attacker-tainted prior write."""
    return TaintAnalysis(
        prog,
        sources=list(sources) if sources is not None else DEFAULT_OUT_OF_BOX_SOURCES,
        sinks=list(sinks) if sinks is not None else DEFAULT_OUT_OF_BOX_SINKS,
        default_rules=ATTACKER_CONTROL_RULES,   # control question, not collision
    ).detect()


# --- key correlation -------------------------------------------------


def _key_signature(op, depth: int = 4) -> str:
    """Structural signature of a key operand; equal signatures mean SYNTACTIC
    equivalence only, so two forms yielding the same runtime bytes won't match."""
    if depth == 0:
        return "?"
    if isinstance(op, Const):
        return f"const:{op.value}"
    cv = getattr(op, "const_value", None)
    if isinstance(cv, Const):
        return f"const:{cv.value}"
    if isinstance(op, Phi):
        # A phi joins several paths, so give it its own cluster rather than
        # over-correlating keys that agree on only one arm.
        return f"phi:{id(op)}"
    a = getattr(op, "defined_by", None)
    if a is None:
        return f"opaque:{id(op)}"
    inputs_sig = ",".join(_key_signature(i, depth - 1) for i in a.inputs)
    return f"{a.op}[{a.immediates}]({inputs_sig})"


def _box_op_key(a: Assignment):
    """The key operand of a box op, or None if the shape doesn't fit."""
    # Every box op pushes the key first, so TOP-FIRST it is the DEEPEST input:
    # box_put [value, key]; box_create [size, key]; box_replace [replacement,
    # start, key]; box_extract [length, start, key]; box_get / box_len [key].
    if a.op in {"box_put", "box_create", "box_replace",
                "box_get", "box_extract", "box_len"}:
        if a.inputs:
            return a.inputs[-1]
    return None


@dataclass
class CorrelatedViolation:
    """The chain: external source → box write at key K → read of K → sink."""

    initial_source: Assignment
    initial_source_name: str
    box_write: Assignment
    box_read: Assignment
    sink: Assignment
    sink_name: str
    sink_operand: TaintedOperand

    def pretty(self) -> str:
        return (
            f"{self.initial_source_name}@{self.initial_source.location}  →  "
            f"{self.box_write.op}@{self.box_write.location}  →  "
            f"{self.box_read.op}@{self.box_read.location}  →  "
            f"{self.sink_name}@{self.sink.location}  "
            f"(sink_value = {self.sink_operand!r})"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref, operand_repr
        return {
            "initial_source": {"name": self.initial_source_name,
                               **assignment_ref(self.initial_source)},
            "box_write": assignment_ref(self.box_write),
            "box_read": assignment_ref(self.box_read),
            "sink": {"name": self.sink_name, **assignment_ref(self.sink)},
            "operand": operand_repr(self.sink_operand),
        }


def detect_correlated_flows(
    prog: SSAProgram,
    *,
    initial_sources: Optional[Iterable[Source]] = None,
    sensitive_sinks: Optional[Iterable[Sink]] = None,
) -> list[CorrelatedViolation]:
    """Chain attacker-tainted box writes to later reads of the same key cluster."""
    init_sources = (
        list(initial_sources) if initial_sources is not None
        else DEFAULT_INTO_BOX_SOURCES
    )
    sinks = (
        list(sensitive_sinks) if sensitive_sinks is not None
        else DEFAULT_OUT_OF_BOX_SINKS
    )

    # Pass 1: which box writes carry tainted values, keyed by signature.
    pass1 = TaintAnalysis(
        prog, sources=init_sources, sinks=DEFAULT_INTO_BOX_SINKS,
        default_rules=ATTACKER_CONTROL_RULES,   # control question, not collision
    )
    tainted_ops, source_for = pass1._compute_taint()
    # cluster_sig → list of (write, originating source assignment, source name)
    cluster_writes: dict[str, list[tuple[Assignment, Assignment, str]]] = {}
    for write in prog.assignments:
        # HAZARD: box_create is DELIBERATELY excluded. Its input 0 is the
        # allocation SIZE and it zero-fills, storing no attacker content, so
        # enrolling its key would make a later read of a zero-filled box look
        # attacker-controlled. Tainted sizes belong to BOX_CREATE_SIZE_SINK.
        if write.op not in {"box_put", "box_replace"}:
            continue
        if not write.inputs:
            continue
        value_op = write.inputs[0]           # value/replacement bytes (top of stack)
        if isinstance(value_op, Const) or value_op not in tainted_ops:
            continue
        key = _box_op_key(write)
        if key is None:
            continue
        sig = _key_signature(key)
        src_a, src_name = source_for[value_op]
        cluster_writes.setdefault(sig, []).append((write, src_a, src_name))
    if not cluster_writes:
        return []

    # Pass 2: synthesise a Source per matching box read. Assignments aren't
    # hashable (unfrozen dataclass), so the read→cluster map is keyed by id().
    synth_sources: list[Source] = []
    read_to_cluster: dict[int, str] = {}
    for read in prog.assignments:
        if read.op not in {"box_get", "box_extract", "box_len"}:
            continue
        key = _box_op_key(read)
        if key is None:
            continue
        sig = _key_signature(key)
        if sig not in cluster_writes:
            continue
        read_to_cluster[id(read)] = sig
        # box_get / box_len leave did_exist on top, so the value is output 2;
        # box_extract has a single output.
        out_idx = 1 if read.op == "box_extract" else 2
        synth_sources.append(Source(
            name="box read of correlated cluster",
            matches=lambda x, target=read: x is target,
            tainted_outputs=lambda x, oi=out_idx: [oi],
        ))
    if not synth_sources:
        return []
    pass2 = TaintAnalysis(prog, sources=synth_sources, sinks=sinks,
                          default_rules=ATTACKER_CONTROL_RULES)
    flat_violations = pass2.detect()

    out: list[CorrelatedViolation] = []
    for v in flat_violations:
        cluster = read_to_cluster.get(id(v.source))
        if cluster is None:
            continue
        # A cluster may hold several tainted writes; one chain per (read, sink)
        # pair keeps the output bounded.
        write, init_a, init_name = cluster_writes[cluster][0]
        out.append(CorrelatedViolation(
            initial_source=init_a,
            initial_source_name=init_name,
            box_write=write,
            box_read=v.source,
            sink=v.sink,
            sink_name=v.sink_name,
            sink_operand=v.sink_operand,
        ))
    return out
