"""Box dataflow detectors.

Configurations of :class:`tealql.tealtools.dataflow.TaintAnalysis` for three
box-related questions:

- **into-box** — external/attacker inputs reaching a box write
  (value or size), unsanitised. ``detect_into_box_flows``.
- **out-of-box** — values read out of a box reaching sensitive
  consumers (state writes, itxn fields). ``detect_out_of_box_flows``.
- **key-correlated** — two-pass: external → box write at key K, then
  read at key K → sensitive sink. ``detect_correlated_flows``.

Caveats inherited from the substrate:

- Taint stops at ops whose default decision is BLOCK (arithmetic,
  ``btoi``, etc.). Hash and slice ops *propagate* taint —
  attacker-controlled bytes hashed into a box value are still
  attacker-controlled.
- The detector is taint-only, not predicate-aware. ``assert(arg <
  100)`` before the sink doesn't break the chain — the value is
  still tainted at the sink. A predicate-aware variant would consult
  :class:`PathPredicateAnalysis` to check whether a dominating
  guard constrains the operand.
- Key correlation is *syntactic*: two keys are matched if their SSA
  expressions canonicalise to the same signature (recursively
  identical opcode + immediates + inputs, or both Consts with the
  same value). Different syntactic forms that happen to yield the
  same bytes at runtime are not matched.
"""
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
from ..avm import SENSITIVE_ITXN_FIELDS as _SENSITIVE_ITXN_FIELDS
from ..ssa import Assignment, Const, Phi, SSAProgram


# --- sources ---------------------------------------------------------


# ``txna ApplicationArgs N``: pops 0, pushes 1 (the bytes for arg N).
# Tainted output is index 1 (the only output).
EXTERNAL_ARG_SOURCE = Source(
    name="txna ApplicationArgs",
    matches=lambda a: a.op == "txna"
    and a.immediates.startswith("ApplicationArgs"),
    tainted_outputs=lambda a: [1],
)


# --- sinks -----------------------------------------------------------


# Stack convention: TEAL pushes the box key first, value second; the
# value sits on top after the pushes. Top-first ``inputs`` therefore
# has [value, key] (or [size, key] for ``box_create``).
#
# Per dataflow.Sink, this is the generic
# "input position to check for taint" — the framework predates the
# value-flow use case.

BOX_PUT_VALUE_SINK = Sink(
    name="box_put value",
    matches=lambda a: a.op == "box_put",
    tainted_input_index=lambda a: 1,
)

# ``box_replace key start replacement``: pushes name, then start,
# then replacement. Top-first inputs: [replacement, start, key].
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


# ``box_get key``: pops 1, pushes 2 (value, did_exist). Top-first
# outputs: [did_exist, value]. Value is output index 2.
BOX_GET_VALUE_SOURCE = Source(
    name="box_get value",
    matches=lambda a: a.op == "box_get",
    tainted_outputs=lambda a: [2],
)

# ``box_extract key start length``: pops 3, pushes 1 (bytes).
BOX_EXTRACT_SOURCE = Source(
    name="box_extract value",
    matches=lambda a: a.op == "box_extract",
    tainted_outputs=lambda a: [1],
)

# ``box_len key``: pops 1, pushes 2 (length, did_exist). Top-first
# outputs: [did_exist, length]. Length is output index 2.
BOX_LEN_SOURCE = Source(
    name="box_len value",
    matches=lambda a: a.op == "box_len",
    tainted_outputs=lambda a: [2],
)


# --- sensitive sinks for box-out flow --------------------------------


# State writes — value is at the top of the stack after the keys/
# accounts get pushed. Top-first inputs: value at 1.
APP_GLOBAL_PUT_VALUE_SINK = Sink(
    name="app_global_put value",
    matches=lambda a: a.op == "app_global_put",
    tainted_input_index=lambda a: 1,
)

# ``app_local_put account key value``: top-first inputs [value, key, account].
APP_LOCAL_PUT_VALUE_SINK = Sink(
    name="app_local_put value",
    matches=lambda a: a.op == "app_local_put",
    tainted_input_index=lambda a: 1,
)


# Sensitive itxn_field sinks (flowing arbitrary bytes into these governs payment
# routing or app control transfer) — canonical set in tealql.tealtools.avm, imported
# at the top of this module.


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
        # Attacker-CONTROL question → concat propagates on ANY tainted input.
        # The default (collision-model) concat rule blocked taint whenever a
        # non-const untainted operand was present — a silent false negative
        # for `concat(dynamic_prefix, user_arg)` flowing into the sink.
        default_rules=ATTACKER_CONTROL_RULES,
    ).detect()


def detect_out_of_box_flows(
    prog: SSAProgram,
    *,
    sources: Optional[Iterable[Source]] = None,
    sinks: Optional[Iterable[Sink]] = None,
) -> list[Violation]:
    """Find box-stored values reaching sensitive consumers (state
    writes, itxn fields) without sanitisation. Treats *every* box
    read as a source — pair with :func:`detect_correlated_flows` if
    you only want to flag reads that demonstrably alias an
    attacker-tainted prior write.
    """
    return TaintAnalysis(
        prog,
        sources=list(sources) if sources is not None else DEFAULT_OUT_OF_BOX_SOURCES,
        sinks=list(sinks) if sinks is not None else DEFAULT_OUT_OF_BOX_SINKS,
        default_rules=ATTACKER_CONTROL_RULES,   # control question, not collision
    ).detect()


# --- key correlation -------------------------------------------------


def _key_signature(op, depth: int = 4) -> str:
    """Recursive structural signature of a key operand. Two operands
    with the same signature are *syntactically* equivalent — same
    opcode + immediates + recursively-equal inputs, or both Consts
    with the same value. Different syntactic forms that resolve to
    the same bytes at runtime are not matched (that would need a
    semantic equality, not modelled here).

    ``depth`` caps recursion for cyclic phi structures; matches are
    conservative beyond that depth.
    """
    if depth == 0:
        return "?"
    if isinstance(op, Const):
        return f"const:{op.value}"
    cv = getattr(op, "const_value", None)
    if isinstance(cv, Const):
        return f"const:{cv.value}"
    if isinstance(op, Phi):
        # A phi joins multiple paths — conservatively treat each phi
        # as its own cluster (id-based) so we don't over-correlate.
        return f"phi:{id(op)}"
    a = getattr(op, "defined_by", None)
    if a is None:
        return f"opaque:{id(op)}"
    inputs_sig = ",".join(_key_signature(i, depth - 1) for i in a.inputs)
    return f"{a.op}[{a.immediates}]({inputs_sig})"


def _box_op_key(a: Assignment):
    """Return the key operand for a box op, or None if the shape doesn't fit."""
    # All five ops put the key as the deepest input (last in top-first
    # order). box_put: [value, key]; box_create: [size, key];
    # box_replace: [replacement, start, key]; box_get: [key];
    # box_extract: [length, start, key]; box_len: [key].
    if a.op in {"box_put", "box_create", "box_replace",
                "box_get", "box_extract", "box_len"}:
        if a.inputs:
            return a.inputs[-1]
    return None


@dataclass
class CorrelatedViolation:
    """End-to-end chain: external source → box write at key K →
    box read at key K → sensitive sink."""

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
    """Two-pass analysis chaining box writes to subsequent reads at
    the same key cluster.

    Pass 1: ``initial_sources`` (default: external args) → box writes
    (value position). Records which box_put/replace/create writes are
    tainted, plus their key signatures and originating sources.

    Pass 2: synthesises a per-read :class:`Source` for every box_get/
    extract/len whose key signature matches a tainted-write cluster.
    Runs the detector with these synthetic sources and the sensitive
    sinks. Each resulting :class:`Violation` is rebuilt as a
    :class:`CorrelatedViolation` carrying the full chain.
    """
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
    # Compute the taint fixpoint ONCE (it also yields the source-of map); the
    # per-write loop below used to re-run the full fixpoint on every iteration.
    tainted_ops, source_for = pass1._compute_taint()
    # cluster_sig → list of (write_assignment, originating_source_assignment, source_name)
    cluster_writes: dict[str, list[tuple[Assignment, Assignment, str]]] = {}
    for write in prog.assignments:
        # box_create is DELIBERATELY excluded: its input 0 is the allocation
        # SIZE, not attacker content — box_create zero-fills, storing no value.
        # A tainted size is a distinct concern owned by BOX_CREATE_SIZE_SINK;
        # enrolling the box's key here would falsely make a later box_get of a
        # zero-filled box read as attacker-controlled (wrong provenance chain).
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
        # Originating source from the precomputed source-of map (hoisted above).
        src_a, src_name = source_for[value_op]
        cluster_writes.setdefault(sig, []).append((write, src_a, src_name))
    if not cluster_writes:
        return []

    # Pass 2: synthesise a Source per matching box_get/extract/len.
    # Assignments aren't hashable (unfrozen dataclass), so key the
    # read→cluster map by id().
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
        # Output index: 2 for box_get/box_len (did_exist on top), 1 for box_extract.
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

    # Rebuild as chains. Each Violation's ``source`` is a synthetic
    # one (the box read); look up its cluster, take any tainted write
    # in that cluster as the chain's middle, and that write's
    # originating source as the chain's start.
    out: list[CorrelatedViolation] = []
    for v in flat_violations:
        cluster = read_to_cluster.get(id(v.source))
        if cluster is None:
            continue
        # Pick the first matching write — multiple are possible if the
        # cluster has several tainted writes; we report one chain per
        # (read, sink) pair to keep output bounded.
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
