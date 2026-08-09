"""Generic taint-flow framework: a detector supplies :class:`Source`,
:class:`Sink` and :class:`FlowRule` sets and runs :class:`TaintAnalysis`.

HAZARD: the default decision is BLOCK, so taint dies at any op no rule covers.
Every propagating op has to be enumerated below — a missing one is a silent
false negative, not a conservative answer. (``byte_taint`` defaults the other
way and has no such hole.)

Needs the phi structure intact to carry taint across BB joins."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Union

from ..ssa import (
    Assignment,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    _shuffle_mapping,
    is_const,
)
from ..passes.frame_flow import (
    frame_gap_sources,
    scratch_load_sources,
    scratch_unknown_loads,
)


Operand = Union[SSAVar, Phi, Const]
TaintedOperand = Union[SSAVar, Phi]  # Const never tainted.


# ---------------------------------------------------------------------------
# Source / Sink / FlowRule descriptors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """A taint source: assignments matching it seed their ``tainted_outputs``.

    HAZARD: output indices are 1-based and TOP-FIRST — output 1 is the topmost
    value after the op runs, so a two-output read's deeper value is index 2."""

    name: str
    matches: Callable[[Assignment], bool]
    tainted_outputs: Callable[[Assignment], list[int]] = field(
        default=lambda a: [1]
    )


@dataclass(frozen=True)
class Sink:
    """A taint sink: the operand at ``tainted_input_index`` is checked for taint.

    HAZARD: 1-based and TOP-FIRST, matching ``Assignment.inputs`` — input 1 is
    the topmost popped operand, not the leftmost in source order."""

    name: str
    matches: Callable[[Assignment], bool]
    tainted_input_index: Callable[[Assignment], int]


@dataclass(frozen=True)
class FlowRule:
    """Per-op decision for how taint flows.

    ``flows`` returns ``None`` to abstain, ``[]`` to block, or the 1-based output
    indices to taint. First non-``None`` answer wins, defaults consulted last."""

    name: str
    matches: Callable[[Assignment], bool]
    flows: Callable[[Assignment, list[int]], Optional[list[int]]]


# ---------------------------------------------------------------------------
# Built-in flow rules — ops that propagate taint without breaking the chain
# ---------------------------------------------------------------------------


_HASH_OPS = frozenset({"sha256", "keccak256", "sha512_256", "sha3_256"})

HASH_PROPAGATION_RULE = FlowRule(
    name="hash-of-tainted",
    matches=lambda a: a.op in _HASH_OPS,
    flows=lambda a, ti: [1] if 1 in ti else [],
)


_SLICE_OPS = frozenset({
    "extract", "extract3",
    "extract_uint16", "extract_uint32", "extract_uint64",
    "substring", "substring3",
    # getbyte returns a byte OF the value, so taint flows, and it has the same
    # operand shape as the extract family.
    "getbyte",
})

SLICE_PROPAGATION_RULE = FlowRule(
    name="slice-of-tainted",
    matches=lambda a: a.op in _SLICE_OPS,
    # TOP-FIRST: the sliced VALUE is the deepest operand, so its 1-based index
    # is ``len(a.inputs)``. Checking index 1 would test an offset instead.
    flows=lambda a, ti: [1] if len(a.inputs) in ti else [],
)


# itob / btoi re-encode the SAME value between uint64 and bytes, so taint
# passes straight through.
_TRANSCODE_OPS = frozenset({"itob", "btoi"})

TRANSCODE_PROPAGATION_RULE = FlowRule(
    name="transcode-of-tainted",
    matches=lambda a: a.op in _TRANSCODE_OPS,
    flows=lambda a, ti: [1] if 1 in ti else [],
)


def _concat_flows(a: Assignment, tainted_in: list[int]) -> Optional[list[int]]:
    """``concat`` propagates taint iff every non-tainted input is constant.

    HAZARD: this is the COLLISION model, not attacker-control. A dynamic prefix
    makes a box key unique, so taint is BLOCKED — correct for key collisions,
    wrong for "can the attacker influence this value", which needs
    :data:`CONCAT_ANY_PROPAGATION_RULE`. The two genuinely conflict on
    ``concat(dynamic, user)``; pick the rule set, never edit this one."""
    if a.op != "concat":
        return None
    for i, inp in enumerate(a.inputs):
        if (i + 1) in tainted_in:
            continue
        if not is_const(inp):
            return []
    return [1]


CONCAT_PROPAGATION_RULE = FlowRule(
    name="concat-of-tainted-and-const-or-tainted",
    matches=lambda a: a.op == "concat",
    flows=_concat_flows,
)


#: Ops whose output is a deterministic FUNCTION of their operands: control `x`
#: and you control `x + 1`.
#:
#: Metadata/boolean results stay included: an attacker who controls a value can
#: control its length, comparison outcome, and therefore any later value that
#: consumes that result. Likewise ``bzero(n)`` has fixed byte content but an
#: attacker-controlled length, which changes the bytes value / box key.
#:
#: Deliberately EXCLUDED, each for a reason:
#:   * the crypto VERIFY ops — a 0/1 validity flag.
#:   * state / txn-field reads — those are SOURCES; taint on a KEY operand does
#:     not make the stored value attacker-controlled.
_VALUE_TRANSFORM_OPS = frozenset({
    # uint64 arithmetic, incl. the wide (two-output) forms
    "+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr", "<<", ">>",
    "addw", "mulw", "expw", "divw", "divmodw",
    # bitwise
    "&", "|", "^", "~",
    # metadata, comparisons and boolean derivations
    "len", "bitlen",
    "==", "!=", "<", "<=", ">", ">=",
    "b==", "b!=", "b<", "b<=", "b>", "b>=",
    "!", "&&", "||",
    # single-bit read (the sibling of `getbyte`, which SLICE already covers)
    "getbit",
    # value transforms / derivations
    "bzero", "base64_decode", "mimc", "sumhash512", "json_ref", "bsqrt",
    "ecdsa_pk_decompress", "ecdsa_pk_recover",
})

VALUE_TRANSFORM_RULE = FlowRule(
    name="value-transform-of-tainted",
    matches=lambda a: a.op in _VALUE_TRANSFORM_OPS,
    # Any tainted operand taints EVERY output — on the multi-output forms
    # (`addw` hi/lo, `divmodw`, `ecdsa_pk_recover` X/Y) the attacker influences
    # both halves, so tainting only output 1 loses the flow.
    flows=lambda a, ti: [i + 1 for i in range(len(a.outputs))] if ti else [],
)


#: ``select A B C`` returns one of its two values, so taint on either flows
#: through. It is not a pure stack shuffle, so it needs an explicit rule.
SELECT_PROPAGATION_RULE = FlowRule(
    name="select-of-tainted",
    matches=lambda a: a.op == "select",
    # TOP-FIRST inputs: [0] = condition, [1] = B (returned when cond != 0),
    # [2] = A. A tainted CONDITION matters too: it lets the attacker choose
    # between two otherwise-clean constants, so the result is attacker-controlled.
    flows=lambda a, ti: [1] if ti else [],
)

#: Splice ops write a tainted value INTO a buffer, so the result carries the
#: attacker's bytes. ``byte_taint`` models these at byte granularity.
_SPLICE_OPS = frozenset({"setbyte", "setbit", "replace2", "replace3"})

SPLICE_PROPAGATION_RULE = FlowRule(
    name="splice-into-buffer",
    matches=lambda a: a.op in _SPLICE_OPS,
    flows=lambda a, ti: [1] if ti else [],
)

#: 512-bit byte arithmetic — a deterministic function of the operands, so
#: attacker influence carries through.
_BYTE_MATH_OPS = frozenset({
    "b+", "b-", "b*", "b/", "b%", "bsqrt",
    "b|", "b&", "b^", "b~",
})

BYTE_MATH_PROPAGATION_RULE = FlowRule(
    name="byte-math-of-tainted",
    matches=lambda a: a.op in _BYTE_MATH_OPS,
    flows=lambda a, ti: [1] if ti else [],
)


# ``loads`` returns the value selected by its popped slot index. Even when all
# stored values are otherwise clean, attacker control of that selector controls
# which value emerges. Stored-value dependencies themselves are bridged by the
# typed scratch MAY relation below.
SCRATCH_SELECT_PROPAGATION_RULE = FlowRule(
    name="dynamic-scratch-selector",
    matches=lambda a: a.op == "loads",
    flows=lambda a, ti: [1] if 1 in ti else [],
)


CONCAT_ANY_PROPAGATION_RULE = FlowRule(
    name="concat-of-any-tainted",
    matches=lambda a: a.op == "concat",
    # Attacker-CONTROL semantics: the output embeds every input byte-for-byte,
    # so it is influenced iff ANY input is.
    flows=lambda a, ti: [1] if ti else [],
)


DEFAULT_RULES: list[FlowRule] = [
    HASH_PROPAGATION_RULE,
    SLICE_PROPAGATION_RULE,
    TRANSCODE_PROPAGATION_RULE,
    VALUE_TRANSFORM_RULE,
    CONCAT_PROPAGATION_RULE,
    SELECT_PROPAGATION_RULE,
    SPLICE_PROPAGATION_RULE,
    BYTE_MATH_PROPAGATION_RULE,
    SCRATCH_SELECT_PROPAGATION_RULE,
]

# HAZARD: pick this set for "can the attacker influence the value reaching this
# sink". DEFAULT_RULES keeps the box-key COLLISION concat, which BLOCKS taint
# behind a dynamic prefix — correct only for the key-collision question.
ATTACKER_CONTROL_RULES: list[FlowRule] = [
    HASH_PROPAGATION_RULE,
    SLICE_PROPAGATION_RULE,
    TRANSCODE_PROPAGATION_RULE,
    VALUE_TRANSFORM_RULE,
    CONCAT_ANY_PROPAGATION_RULE,
    SELECT_PROPAGATION_RULE,
    SPLICE_PROPAGATION_RULE,
    BYTE_MATH_PROPAGATION_RULE,
    SCRATCH_SELECT_PROPAGATION_RULE,
]


# ---------------------------------------------------------------------------
# Violation
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    """A tainted operand reached a sink."""

    source: Assignment
    source_name: str
    sink: Assignment
    sink_name: str
    # The tainted operand consumed at the sink — an SSAVar, or a Phi when the
    # value crossed a BB join. Walk ``defined_by`` / ``args`` to rebuild the path.
    sink_operand: TaintedOperand

    @property
    def file(self) -> str:
        return self.sink.location.file

    @property
    def line(self) -> int:
        # The SINK is the violation point; pretty() names source AND sink.
        return self.sink.location.line

    def pretty(self) -> str:
        return (
            f"{self.source_name}@{self.source.location}  "
            f"→  {self.sink_name}@{self.sink.location}  "
            f"(operand = {self.sink_operand!r})"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref, operand_repr
        return {
            "source": {"name": self.source_name, **assignment_ref(self.source)},
            "sink": {"name": self.sink_name, **assignment_ref(self.sink)},
            "operand": operand_repr(self.sink_operand),
        }

    def __repr__(self) -> str:
        return f"Violation({self.pretty()})"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TaintAnalysis:
    """Forward taint propagation with pluggable Source / Sink / FlowRule sets.

    Does not mutate ``prog``. ``file`` scopes seeding and reporting to one source
    file, which fully isolates that program because SSAVars are never shared
    across files."""

    def __init__(
        self,
        prog: SSAProgram,
        *,
        sources: Iterable[Source],
        sinks: Iterable[Sink],
        rules: Optional[Iterable[FlowRule]] = None,
        default_rules: Optional[Iterable[FlowRule]] = None,
        file: Optional[str] = None,
        cross_state: bool = False,
    ):
        self.prog = prog
        self.file = file
        self.sources: list[Source] = list(sources)
        self.sinks: list[Sink] = list(sinks)
        # Custom rules consulted first, so they can pre-empt the defaults.
        self.rules: list[FlowRule] = list(rules) if rules is not None else []
        self.default_rules: list[FlowRule] = (
            list(default_rules) if default_rules is not None else list(DEFAULT_RULES)
        )
        # Opt-in taint through an app-global-state roundtrip; off by default
        # because most detectors do not want state to be a taint conduit.
        self.cross_state = cross_state

    # -- public ---------------------------------------------------------

    def _in_scope(self, a: Assignment) -> bool:
        """True if ``a`` is in the scoped file, or no scope was set."""
        return self.file is None or a.location.file == self.file

    def detect(self) -> list[Violation]:
        """Backward-compatible findings-only view; use :meth:`analyze` when
        an empty list must be distinguished from an incomplete model."""
        return self.analyze().value

    def analyze(self):
        """Findings plus standardized completeness/degradation metadata."""
        tainted, source_for = self._compute_taint()
        violations: list[Violation] = []
        for a in self.prog.assignments:
            if not self._in_scope(a):
                continue
            for sink in self.sinks:
                if not sink.matches(a):
                    continue
                idx = sink.tainted_input_index(a)
                if idx < 1 or idx > len(a.inputs):
                    continue
                op = a.inputs[idx - 1]
                if isinstance(op, Const) or op not in tainted:
                    continue
                source_a, source_name = source_for[op]
                violations.append(Violation(
                    source=source_a,
                    source_name=source_name,
                    sink=a,
                    sink_name=sink.name,
                    sink_operand=op,
                ))
        return self.prog.result(violations, deep=True)

    def tainted_operands(self) -> set[TaintedOperand]:
        """Every operand the propagation marked tainted — a diagnostic hook."""
        tainted, _ = self._compute_taint()
        return tainted

    # -- core -----------------------------------------------------------

    def _compute_taint(
        self,
    ) -> tuple[set[TaintedOperand], dict[TaintedOperand, tuple[Assignment, str]]]:
        # HAZARD: this must NOT be ``propagate_constants``. The rules read
        # ``const_value``, and `_ensure_identity_steps` restores exactly the
        # shuffle-passthrough + scratch const seeds construction used to set
        # eagerly. ``propagate_constants`` seeds extra phi/fold consts, which
        # would silently change which flows the concat rules block.
        self.prog._ensure_identity_steps()
        tainted: set[TaintedOperand] = set()
        source_for: dict[TaintedOperand, tuple[Assignment, str]] = {}

        # Step 1: seed from sources, scoped to the file under analysis.
        for a in self.prog.assignments:
            if not self._in_scope(a):
                continue
            for src in self.sources:
                if not src.matches(a):
                    continue
                for out_idx in src.tainted_outputs(a):
                    if not (1 <= out_idx <= len(a.outputs)):
                        continue
                    v = a.outputs[out_idx - 1]
                    if isinstance(v, Const):
                        continue
                    if v not in tainted:
                        tainted.add(v)
                        source_for[v] = (a, src.name)

        # An unnamed scratch value is TOP for a conservative MAY analysis. It
        # cannot inherit a real source Assignment, so anchor provenance at the
        # load itself and make incompleteness visible in the source name.
        for value in scratch_unknown_loads(self.prog):
            assignment = getattr(value, "defined_by", None)
            if assignment is None or not self._in_scope(assignment) or value in tainted:
                continue
            tainted.add(value)
            source_for[value] = (assignment, "unknown-scratch")

        # Only the frame edges absent from canonical SSA def-use.
        frame_src = frame_gap_sources(self.prog)
        scratch_src = scratch_load_sources(self.prog)

        # Step 2: fixpoint propagation.
        changed = True
        while changed:
            changed = False
            # 2a. Through assignments.
            for a in self.prog.assignments:
                tainted_in_idx = [
                    i + 1
                    for i, x in enumerate(a.inputs)
                    if not isinstance(x, Const) and x in tainted
                ]
                if not tainted_in_idx:
                    continue
                out_idxs = self._decide_flow(a, tainted_in_idx)
                if not out_idxs:
                    continue
                provenance = source_for[a.inputs[tainted_in_idx[0] - 1]]
                for out_idx in out_idxs:
                    if not (1 <= out_idx <= len(a.outputs)):
                        continue
                    v = a.outputs[out_idx - 1]
                    if isinstance(v, Const) or v in tainted:
                        continue
                    tainted.add(v)
                    source_for[v] = provenance
                    changed = True
            # 2b. Through phis. Any tainted arg taints the phi.
            for ph in self.prog.phis.values():
                if ph in tainted:
                    continue
                for arg in ph.args:
                    if isinstance(arg, Const):
                        continue
                    if arg in tainted:
                        tainted.add(ph)
                        source_for[ph] = source_for[arg]
                        changed = True
                        break
            # 2c. Through scratch (store N value -> load N output), shared with
            # byte_taint so the two agree on what reaches a load.
            for load_var, srcs in scratch_src.items():
                if load_var in tainted:
                    continue
                for src_var in srcs:
                    if src_var in tainted:
                        tainted.add(load_var)
                        source_for[load_var] = source_for[src_var]
                        changed = True
                        break
            # 2d. Through frame params (callee param <- caller args).
            for dig_out, args in frame_src.items():
                if dig_out in tainted:
                    continue
                for arg in args:
                    if not isinstance(arg, Const) and arg in tainted:
                        tainted.add(dig_out)
                        source_for[dig_out] = source_for[arg]
                        changed = True
                        break
            # 2e. Through app-global state (opt-in): a put's value re-emerges
            # tainted from a get of the same key. Key-aware when both keys are
            # static, else conservative — any tainted put may reach the get.
            if self.cross_state:
                changed = self._propagate_state(tainted, source_for) or changed
        return tainted, source_for

    def _propagate_state(self, tainted: set, source_for: dict) -> bool:
        """One round of the state taint bridge; True if anything became tainted."""
        from ..ssa import operand_const
        puts: list = []   # (key_const_or_None, value_var)
        for a in self.prog.assignments:
            if a.op == "app_global_put" and len(a.inputs) >= 2 and self._in_scope(a):
                val = a.inputs[0]
                if not isinstance(val, Const) and val in tainted:
                    puts.append((operand_const(a.inputs[1]), val))
        if not puts:
            return False
        changed = False
        for a in self.prog.assignments:
            if a.op != "app_global_get" or not a.outputs or not self._in_scope(a):
                continue
            out = a.outputs[0]
            if isinstance(out, Const) or out in tainted:
                continue
            get_key = operand_const(a.inputs[0]) if a.inputs else None
            for put_key, put_val in puts:
                # Matching const keys, or conservatively when either key is
                # not statically known.
                if put_key is None or get_key is None or put_key == get_key:
                    tainted.add(out)
                    source_for[out] = source_for[put_val]
                    changed = True
                    break
        return changed

    def _decide_flow(
        self, a: Assignment, tainted_input_indices: list[int]
    ) -> list[int]:
        """Which outputs taint: user rules, then defaults, then pure shuffles,
        then BLOCK — first non-``None`` decision wins."""
        for rule_list in (self.rules, self.default_rules):
            for rule in rule_list:
                if not rule.matches(a):
                    continue
                decision = rule.flows(a, list(tainted_input_indices))
                if decision is not None:
                    return list(decision)
        mapping = _shuffle_mapping(a)
        if mapping is not None:
            return [
                out_idx + 1
                for out_idx, in_idx in enumerate(mapping)
                if (in_idx + 1) in tainted_input_indices
            ]
        return []
