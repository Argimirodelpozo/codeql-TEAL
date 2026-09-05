"""Opcode-cost facts over the canonical AVM instruction stream."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..analysis import ValueFacts
    from ..ssa import Assignment, BasicBlock, SSAProgram


_MAX_BYTES_VALUE = 4096


@dataclass(frozen=True)
class CostFact:
    """A cost interval plus the evidence quality behind it.

    ``upper=None`` means the available language specification does not provide
    a finite static upper bound.  ``lower`` remains useful: shortest paths and
    loop iteration ceilings need a cost lower bound, and one is the AVM opcode
    floor.  Such a result is deliberately marked non-exact.
    """

    lower: int
    upper: Optional[int]
    exact: bool
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.lower < 0:
            raise ValueError("cost lower bound must be non-negative")
        if self.upper is not None and self.upper < self.lower:
            raise ValueError("cost upper bound is below lower bound")
        if self.exact != (self.upper is not None and self.lower == self.upper):
            raise ValueError("exact must agree with a singleton interval")

    @classmethod
    def known(cls, cost: int) -> "CostFact":
        return cls(cost, cost, True)

    @classmethod
    def unknown(cls, reason: str, *, lower: int = 1) -> "CostFact":
        return cls(lower, None, False, (reason,))

    @classmethod
    def bounded(cls, lower: int, upper: int, reason: str = "") -> "CostFact":
        """A finite interval, retaining why it is not exact when it has width."""
        exact = lower == upper
        return cls(lower, upper, exact, (() if exact or not reason else (reason,)))

    def __add__(self, other: "CostFact") -> "CostFact":
        upper = None if self.upper is None or other.upper is None else self.upper + other.upper
        reasons = tuple(dict.fromkeys((*self.reasons, *other.reasons)))
        return CostFact(
            self.lower + other.lower,
            upper,
            upper is not None and self.lower + other.lower == upper,
            reasons,
        )

    def scale(self, count: int) -> "CostFact":
        if count < 0:
            raise ValueError("cost multiplier must be non-negative")
        upper = None if self.upper is None else self.upper * count
        return CostFact(
            self.lower * count,
            upper,
            upper is not None and self.lower * count == upper,
            self.reasons,
        )

    @property
    def degraded(self) -> bool:
        return not self.exact


@dataclass(frozen=True)
class _CostTable:
    fixed: dict[str, int]
    dynamic: frozenset[str]


@lru_cache(maxsize=1)
def _spec_cost_table() -> _CostTable:
    from ..language.spec import SPECS, opcode_spec
    fixed, dynamic = {}, set()
    for name in SPECS:
        raw = opcode_spec(name).cost
        if raw.isdecimal():
            fixed[name] = int(raw)
        else:
            dynamic.add(name)
    return _CostTable(fixed, frozenset(dynamic))


def op_cost(op: str, immediates: str = "") -> CostFact:
    """Cost of one opcode execution, without pretending dynamic costs are exact."""
    table = _spec_cost_table()
    fixed = table.fixed.get(op)
    if fixed is not None:
        return CostFact.known(fixed)
    suffix = f" {immediates.strip()}" if immediates and immediates.strip() else ""
    # OUR tables answer before Puya's "dynamic" verdict: Puya marks an op
    # dynamic when its enum cannot express a per-immediate or per-length cost,
    # but the AVM spec still fixes the immediate-selected cost (``ecdsa_verify
    # Secp256k1`` = 1700) and the length-dependent FLOOR.  Answering
    # ``lower=1`` for those understated every path they sit on.  An opcode
    # Puya's table has not shipped yet (``sha512``) is served the same way.
    linear = _LENGTH_COSTS.get(op)
    if linear is not None:
        return CostFact.unknown(
            f"length-dependent cost for {op}{suffix}", lower=linear[0])
    by_field = _FIELD_COSTS.get(op) or _FIELD_LENGTH_COSTS.get(op)
    if by_field is not None:
        imm = immediates.split()[0] if immediates.strip() else ""
        sel = by_field.get(imm)
        if isinstance(sel, int):
            return CostFact.known(sel)
        if isinstance(sel, tuple):            # length-dependent for this field
            return CostFact.unknown(
                f"length-dependent cost for {op}{suffix}", lower=sel[0])
        floors = [v[0] if isinstance(v, tuple) else v for v in by_field.values()]
        return CostFact.unknown(
            f"immediate-selected cost for {op}{suffix}", lower=min(floors))
    if op in table.dynamic:
        return CostFact.unknown(f"dynamic cost for {op}{suffix}")
    # Source-level pseudo ops (``int``) and control terminators are lowered
    # away before Puya IR, so they do not occur in AVMOp even though their AVM
    # execution cost is the fixed floor.
    from ..language.avm import is_known_op
    if is_known_op(op):
        return CostFact.known(1)
    return CostFact.unknown(f"unknown opcode cost for {op}{suffix}")


# Immediate-selected costs from the AVM opcode specification.  Puya marks
# these opcodes as dynamic because its enum-level metadata cannot express a
# different fixed cost for each immediate.
_FIELD_COSTS: dict[str, dict[str, int]] = {
    "ecdsa_verify": {"Secp256k1": 1700, "Secp256r1": 2500},
    "ecdsa_pk_decompress": {"Secp256k1": 650, "Secp256r1": 2400},
    "ec_add": {
        "BN254g1": 125, "BN254g2": 170,
        "BLS12_381g1": 205, "BLS12_381g2": 290,
    },
    "ec_scalar_mul": {
        "BN254g1": 1810, "BN254g2": 3430,
        "BLS12_381g1": 2950, "BLS12_381g2": 6530,
    },
    "ec_subgroup_check": {
        "BN254g1": 20, "BN254g2": 3100,
        "BLS12_381g1": 1850, "BLS12_381g2": 2340,
    },
    "ec_map_to": {
        "BN254g1": 630, "BN254g2": 3300,
        "BLS12_381g1": 1950, "BLS12_381g2": 8150,
    },
}


# ``base + per_chunk * ceil(len(input[depth]) / chunk_size)``.  SSA inputs are
# TOP-FIRST, matching the AVM stack depth used by the protocol cost function.
_LENGTH_COSTS: dict[str, tuple[int, int, int, int]] = {
    "base64_decode": (1, 1, 16, 0),
    "json_ref": (25, 2, 7, 1),
    "mimc": (10, 550, 32, 0),
    "poseidon2": (7, 350, 32, 0),
    "sumhash512": (150, 7, 4, 0),
    "sha512": (15, 32, 2, 0),
}


# Immediate-selected versions of the same linear length formula.
_FIELD_LENGTH_COSTS: dict[str, dict[str, tuple[int, int, int, int]]] = {
    "ec_pairing_check": {
        "BN254g1": (8000, 7400, 64, 0),
        "BN254g2": (8000, 7400, 128, 0),
        "BLS12_381g1": (13000, 10000, 96, 0),
        "BLS12_381g2": (13000, 10000, 192, 0),
    },
    "ec_multi_scalar_mul": {
        "BN254g1": (3600, 90, 32, 0),
        "BN254g2": (7200, 270, 32, 0),
        "BLS12_381g1": (6500, 95, 32, 0),
        "BLS12_381g2": (14850, 485, 32, 0),
    },
}


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def terminator_op(bb: "BasicBlock") -> Optional[str]:
    """The control op ending ``bb``'s canonical stream, or ``None``.

    The ONE spelling of the control-op set — `loop_bounds` and the cost model
    each carried a verbatim copy, so a future control op would have to be
    remembered twice or the loop graph and the cost model silently disagree."""
    for assignment in reversed(canonical_assignments(bb)):
        if assignment.op in {
            "b", "bz", "bnz", "switch", "match", "callsub",
            "retsub", "return", "err",
        }:
            return assignment.op
    return None


class CostModel:
    """Program/version-aware opcode costs over immutable value facts.

    The module-level :func:`op_cost` remains the metadata-only query.  This
    model is the analysis query: it resolves immediate-selected costs, uses
    byte-length facts for linear dynamic costs, and applies historical opcode
    revisions selected by the program's AVM version.
    """

    def __init__(
        self,
        prog: "SSAProgram",
        *,
        avm_version: Optional[int] = None,
    ):
        from ..analysis import FactDomain
        from .context import infer_avm_version

        self.prog = prog
        self.avm_version = (
            infer_avm_version(prog) if avm_version is None else avm_version
        )
        self.facts: ValueFacts = prog.facts(
            FactDomain.CONSTANTS, FactDomain.BYTE_LENGTHS
        )
        self._assignment_cache: dict[Assignment, CostFact] = {}
        self._block_cache: dict[BasicBlock, CostFact] = {}
        self._execution_block_cache: dict[BasicBlock, CostFact] = {}
        self._subroutine_cache: dict[BasicBlock, CostFact] = {}
        self._subroutines = None

    def _byte_length_range(self, value) -> Optional[tuple[int, int]]:
        from ..ssa import const_byte_length

        constant = self.facts.constant(value)
        n = const_byte_length(constant if constant is not None else value)
        if n is not None:
            return n, n
        fact_type = self.facts.fact(value).type
        if fact_type is not None:
            if fact_type.byte_length is not None:
                return fact_type.byte_length, fact_type.byte_length
            if fact_type.byte_length_range is not None:
                r = fact_type.byte_length_range
                return r.lo, min(r.hi, _MAX_BYTES_VALUE)
            if fact_type.kind == "bytes":
                return 0, _MAX_BYTES_VALUE
        value_type = getattr(value, "type", None)
        if value_type is not None and value_type.kind == "bytes":
            return 0, _MAX_BYTES_VALUE
        return None

    def _linear_cost(
        self,
        assignment: "Assignment",
        spec: tuple[int, int, int, int],
    ) -> CostFact:
        base, per_chunk, chunk_size, depth = spec
        if depth >= len(assignment.inputs):
            return CostFact.unknown(
                f"dynamic cost input unavailable for {assignment.op}",
                lower=base,
            )
        bounds = self._byte_length_range(assignment.inputs[depth])
        if bounds is None:
            # Reaching a valid length-priced opcode proves that this operand is
            # a bytes value even when partial SSA recovery could not annotate
            # its type.  The AVM bytes-stack cap is therefore a sound fallback
            # upper bound; malformed programs never execute this operation.
            bounds = (0, _MAX_BYTES_VALUE)
        lo, hi = bounds
        lower = base + per_chunk * _ceil_div(lo, chunk_size)
        upper = base + per_chunk * _ceil_div(hi, chunk_size)
        return CostFact.bounded(
            lower,
            upper,
            f"dynamic cost bounded by byte length [{lo},{hi}] for {assignment.op}",
        )

    def _dynamic_cost(self, assignment: "Assignment") -> Optional[CostFact]:
        op = assignment.op
        immediate = (assignment.immediates or "").strip().split()
        field = immediate[0] if immediate else ""
        by_field = _FIELD_COSTS.get(op)
        if by_field is not None:
            cost = by_field.get(field)
            return (
                CostFact.known(cost) if cost is not None
                else CostFact.unknown(f"unknown cost immediate for {op} {field}".rstrip())
            )
        linear = _LENGTH_COSTS.get(op)
        if linear is not None:
            return self._linear_cost(assignment, linear)
        by_field_length = _FIELD_LENGTH_COSTS.get(op)
        if by_field_length is not None:
            linear = by_field_length.get(field)
            return (
                self._linear_cost(assignment, linear) if linear is not None
                else CostFact.unknown(f"unknown cost immediate for {op} {field}".rstrip())
            )
        return None

    def assignment_cost(self, assignment: "Assignment") -> CostFact:
        cached = self._assignment_cache.get(assignment)
        if cached is not None:
            return cached
        # Hash costs changed at AVM v2.  The dependency metadata exposes only
        # the latest value, so select the historical v1 costs here.
        if self.avm_version == 1 and assignment.op in {
            "sha256", "keccak256", "sha512_256",
        }:
            result = CostFact.known({
                "sha256": 7, "keccak256": 26, "sha512_256": 9,
            }[assignment.op])
        else:
            result = self._dynamic_cost(assignment) or assignment_cost(assignment)
        self._assignment_cache[assignment] = result
        return result

    def block_cost(self, bb: "BasicBlock") -> CostFact:
        cached = self._block_cache.get(bb)
        if cached is None:
            cached = sum_costs(
                self.assignment_cost(assignment)
                for assignment in canonical_assignments(bb)
            )
            self._block_cache[bb] = cached
        return cached

    _terminator = staticmethod(terminator_op)

    def _subroutine_info(self):
        if self._subroutines is None:
            from ..cfg.subroutines import identify_subroutines
            self._subroutines = identify_subroutines(self.prog)
        return self._subroutines

    def _subroutine_cost(
        self,
        entry: "BasicBlock",
        active: frozenset["BasicBlock"],
    ) -> CostFact:
        cached = self._subroutine_cache.get(entry)
        if cached is not None:
            return cached
        if entry in active:
            # Recursive calls execute at least their own ``callsub`` (already
            # in the caller block), but this summary cannot promise any
            # additional finite cost without solving the recursion.
            return CostFact.unknown(
                "recursive subroutine cost is unbounded", lower=0
            )

        import networkx as nx

        info = self._subroutine_info()
        body = set(info["bodies"].get(entry, ()))
        if not body:
            return CostFact.unknown("subroutine body is unavailable", lower=0)
        call_targets = info["callsub_target"]
        continuations = info["continuations"]
        next_active = active | {entry}

        costs: dict[BasicBlock, CostFact] = {}
        graph = nx.DiGraph()
        graph.add_nodes_from(body)
        for bb in body:
            fact = self.block_cost(bb)
            if self._terminator(bb) == "callsub":
                callee = call_targets.get(bb)
                if callee is not None:
                    fact = fact + self._subroutine_cost(callee, next_active)
                continuation = continuations.get(bb)
                if continuation in body:
                    graph.add_edge(bb, continuation)
            elif self._terminator(bb) != "retsub":
                for successor in bb.successors:
                    if successor in body:
                        graph.add_edge(bb, successor)
            costs[bb] = fact

        returns = [bb for bb in body if self._terminator(bb) == "retsub"]
        if not returns or entry not in graph:
            return CostFact.unknown("subroutine has no reachable retsub", lower=0)

        # Minimum returning cost.  Every node weight is non-negative, so one
        # Dijkstra from a synthetic source gives a witness-safe lower bound.
        source = object()
        weighted = nx.DiGraph()
        weighted.add_nodes_from(graph.nodes)
        weighted.add_node(source)
        weighted.add_edge(source, entry, weight=costs[entry].lower)
        for left, right in graph.edges:
            weighted.add_edge(left, right, weight=costs[right].lower)
        distances, paths = nx.single_source_dijkstra(weighted, source, weight="weight")
        reachable_returns = [bb for bb in returns if bb in distances]
        if not reachable_returns:
            return CostFact.unknown("subroutine has no reachable retsub", lower=0)
        cheapest_return = min(reachable_returns, key=distances.__getitem__)
        lower = distances[cheapest_return]
        lower_path = [bb for bb in paths[cheapest_return] if bb is not source]
        reasons = [reason for bb in lower_path for reason in costs[bb].reasons]

        # A finite upper bound exists only when every returning execution is
        # acyclic and every block on one has a finite upper cost.  Non-returning
        # branches do not poison a summary used after a successful return.
        can_return = set(reachable_returns)
        work = list(reachable_returns)
        while work:
            bb = work.pop()
            for predecessor in graph.predecessors(bb):
                if predecessor not in can_return:
                    can_return.add(predecessor)
                    work.append(predecessor)
        returning_graph = graph.subgraph(can_return).copy()
        if not nx.is_directed_acyclic_graph(returning_graph):
            upper = None
            reasons.append("cyclic subroutine has no finite upper cost")
        elif any(costs[bb].upper is None for bb in returning_graph.nodes):
            upper = None
            reasons.extend(
                reason for bb in returning_graph.nodes for reason in costs[bb].reasons
                if costs[bb].upper is None
            )
        else:
            upper_to_return: dict[BasicBlock, int] = {}
            for bb in reversed(list(nx.topological_sort(returning_graph))):
                tails = [
                    upper_to_return[successor]
                    for successor in returning_graph.successors(bb)
                    if successor in upper_to_return
                ]
                own = costs[bb].upper
                if bb in returns:
                    upper_to_return[bb] = own  # type: ignore[assignment]
                elif tails:
                    upper_to_return[bb] = own + max(tails)  # type: ignore[operator]
            upper = upper_to_return.get(entry)

        result = CostFact(
            lower,
            upper,
            upper is not None and lower == upper,
            tuple(dict.fromkeys(reasons)),
        )
        self._subroutine_cache[entry] = result
        return result

    def subroutine_cost(self, entry: "BasicBlock") -> CostFact:
        """Cost of one returning invocation, excluding the caller's callsub."""
        return self._subroutine_cost(entry, frozenset())

    def execution_block_cost(self, bb: "BasicBlock") -> CostFact:
        """Direct block cost plus the returning callee cost of its callsub."""
        cached = self._execution_block_cache.get(bb)
        if cached is not None:
            return cached
        fact = self.block_cost(bb)
        if self._terminator(bb) == "callsub":
            callee = self._subroutine_info()["callsub_target"].get(bb)
            if callee is not None:
                fact = fact + self.subroutine_cost(callee)
            else:
                fact = fact + CostFact.unknown(
                    "callsub target is unavailable", lower=0
                )
        self._execution_block_cache[bb] = fact
        return fact


def sum_costs(facts: Iterable[CostFact]) -> CostFact:
    total = CostFact.known(0)
    for fact in facts:
        total = total + fact
    return total


def canonical_assignments(bb: "BasicBlock") -> tuple["Assignment", ...]:
    """The opcodes the AVM executes, independent of presentation cleanup."""
    stream = bb.stack_assignments
    return tuple(stream) if stream else tuple(bb.assignments)


def assignment_cost(assignment: "Assignment") -> CostFact:
    return op_cost(assignment.op, assignment.immediates or "")


def block_cost(bb: "BasicBlock") -> CostFact:
    return sum_costs(assignment_cost(a) for a in canonical_assignments(bb))


def block_stack_delta(bb: "BasicBlock") -> Optional[int]:
    """Net stack delta, or ``None`` when the block crosses a call boundary.

    Canonical SSA records actual call arguments on ``callsub`` but return values
    at the callee's ``retsub``.  Treating either block in isolation would mix
    frames, so callers may only use stack bounds for call-free cycles.
    """
    assignments = canonical_assignments(bb)
    if any(a.op in {"callsub", "retsub"} for a in assignments):
        return None
    # SSA inputs/outputs describe what stack simulation RECOVERED.  In an
    # underflow or merge-refusal shape operands and dead outputs may be absent,
    # but the AVM still executes the opcode's language-specified stack effect.
    from ..language.avm import op_arity
    delta = 0
    for assignment in assignments:
        n_in, n_out = op_arity(assignment.op, assignment.immediates or "")
        delta += n_out - n_in
    return delta
