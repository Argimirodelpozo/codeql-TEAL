"""Immutable facts and isolated derived views over canonical SSA."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional, TYPE_CHECKING

from ..ssa import Const, IntRange, Phi, SSAVar, TealType

if TYPE_CHECKING:  # pragma: no cover
    from ..ssa import Assignment, BasicBlock, SSAProgram


ValueKey = tuple[str, str, int, int]
AliasTarget = ValueKey | Const


class FactDomain(str, Enum):
    CONSTANTS = "constants"
    RANGES = "ranges"
    BYTE_LENGTHS = "byte-lengths"
    BIGINT_RANGES = "bigint-ranges"


class DerivedProfile(str, Enum):
    VALUE = "value"
    GUARDED = "guarded"
    PRESENTATION = "presentation"


@dataclass(frozen=True)
class TypeFact:
    kind: str
    byte_length: Optional[int] = None
    byte_length_range: Optional[IntRange] = None
    int_value_range: Optional[IntRange] = None

    @classmethod
    def of(cls, value: Optional[TealType]) -> Optional["TypeFact"]:
        if value is None:
            return None
        return cls(
            value.kind,
            value.byte_length,
            value.byte_length_range,
            value.int_value_range,
        )


@dataclass(frozen=True)
class ValueFact:
    constant: Optional[Const] = None
    int_range: Optional[IntRange] = None
    type: Optional[TypeFact] = None


@dataclass(frozen=True)
class _RangeRefinement:
    value: ValueKey
    relation: str
    other: IntRange
    guard_block: tuple
    guard_line: int


def _value_key(value) -> Optional[ValueKey]:
    if isinstance(value, SSAVar):
        return ("var", value.file, value.line, value.index)
    if isinstance(value, Phi):
        return ("phi", value.file, value.line, value.stack_index)
    return None


def _lookup(prog: "SSAProgram", key: ValueKey):
    kind, file, line, index = key
    if kind == "var":
        return prog.vars.get((file, line, index))
    return prog.phis.get((file, line, index))


def _copy_program(prog: "SSAProgram") -> "SSAProgram":
    # The parsed graph is the immutable reconstruction boundary.  A graph copy
    # gives every derived view independent nodes/annotations while retaining
    # the source snapshot and parse diagnostics.
    return type(prog).from_graph(
        prog._graph.copy(), strict=bool(getattr(prog, "_strict", False))
    )


def _build_derived_program(
    prog: "SSAProgram", profile: DerivedProfile = DerivedProfile.VALUE
) -> "SSAProgram":
    """Build an isolated, annotated program for algorithms not yet fact-native.

    Value rewrites and cleanup are safe here because no object in the returned
    program is shared with ``prog``.  The canonical program remains suitable
    for cost, lifting, and later security analyses regardless of query order.
    """
    target = _copy_program(prog)
    target.propagate_constants()
    target.propagate_scratch_constants()
    from ._input_aliases import propagate_inputs
    from ._scratch import propagate_scratch_values
    from ._range_refinement import propagate_assert_ranges
    from ..ssa.presentation import cleanup_unused_ssavars
    from ..ssa.value_rewrite import propagate_stack_shuffles

    propagate_inputs(target)
    target._rebuild_uses()
    target._invalidate_value_relations()
    target._ensure_scratch_influence()
    propagate_scratch_values(target)
    target._rebuild_uses()
    propagate_stack_shuffles(target)
    target._rebuild_uses()
    target.propagate_ranges()
    target.propagate_range_arithmetic()
    if profile in {DerivedProfile.GUARDED, DerivedProfile.PRESENTATION}:
        propagate_assert_ranges(target)
    target.propagate_byte_lengths()
    target.propagate_bytemath_ranges()
    if profile is DerivedProfile.PRESENTATION:
        cleanup_unused_ssavars(target)
    target._derived_profile = profile
    # Derived normal forms are cached and therefore shared by every consumer
    # requesting the same profile.  Make the supported mutation entry points
    # reject further refinement: otherwise one accidental legacy pass would
    # make detector results order-dependent again.
    target._analysis_read_only = True
    return target


def derived_program(
    prog: "SSAProgram", profile: DerivedProfile = DerivedProfile.VALUE
) -> "SSAProgram":
    """Return the revision-scoped normal form for ``profile``.

    Normal forms are owned by the program's :class:`AnalysisContext`, not by a
    caller.  Consumers must treat them as read-only.  Sharing one normalized
    snapshot avoids rebuilding the entire SSA once per detector while keeping
    every rewrite off the canonical graph.
    """
    if getattr(prog, "_derived_profile", None) is profile:
        return prog
    return prog.analysis_context().derived(profile)


def _base_snapshot(prog: "SSAProgram", domains: frozenset[FactDomain]) -> "SSAProgram":
    target = _copy_program(prog)
    target.propagate_constants()
    target.propagate_scratch_constants()
    if FactDomain.RANGES in domains or FactDomain.BIGINT_RANGES in domains:
        target.propagate_ranges()
        target.propagate_range_arithmetic()
    if FactDomain.BYTE_LENGTHS in domains:
        target.propagate_byte_lengths()
    if FactDomain.BIGINT_RANGES in domains:
        target.propagate_bytemath_ranges()
    return target


def _alias_map(prog: "SSAProgram") -> dict[ValueKey, AliasTarget]:
    """Pure equivalence relation for stable inputs, shuffles, and scratch loads."""
    from ._input_aliases import _input_key
    from ..ssa import _STACK_SHUFFLE_OPS, _shuffle_mapping

    redirects: dict[ValueKey, AliasTarget] = {}
    canonical: dict[tuple, ValueKey] = {}
    for assignment in prog.assignments:
        if not assignment.outputs:
            continue
        output = assignment.outputs[0]
        output_key = _value_key(output)
        if output_key is None:
            continue
        semantic_key = _input_key(assignment)
        if semantic_key is not None:
            representative = canonical.setdefault(semantic_key, output_key)
            if representative != output_key:
                redirects[output_key] = representative

        if assignment.op not in _STACK_SHUFFLE_OPS:
            continue
        mapping = _shuffle_mapping(assignment)
        if mapping is None:
            continue
        for output_index, input_index in enumerate(mapping):
            if output_index >= len(assignment.outputs) or input_index >= len(assignment.inputs):
                continue
            key = _value_key(assignment.outputs[output_index])
            source = assignment.inputs[input_index]
            source_key = _value_key(source)
            if key is not None and (source_key is not None or isinstance(source, Const)):
                redirects[key] = source_key if source_key is not None else source

    def resolve(target: AliasTarget) -> AliasTarget:
        seen: set[ValueKey] = set()
        while isinstance(target, tuple) and target in redirects and target not in seen:
            seen.add(target)
            target = redirects[target]
        return target

    # Scratch reaching definitions are semantic facts, not a reason to rewrite
    # consumers.  Iterate because one agreed source may itself be an alias.
    prog._ensure_scratch_influence()
    changed = True
    while changed:
        changed = False
        for node in prog._graph.nodes:
            stores = prog._graph.nodes[node].get("scratch_stores")
            if not stores:
                continue
            load = prog.var(node.location.file, node.location.start_line, 1)
            load_key = _value_key(load)
            if load_key is None:
                continue
            sources: list[AliasTarget] = []
            for file, line, index in stores:
                source = prog.var(file, line, index)
                source_key = _value_key(source)
                if source_key is None:
                    sources = []
                    break
                sources.append(resolve(source_key))
            if not sources or not all(source == sources[0] for source in sources):
                continue
            representative = resolve(sources[0])
            if representative != load_key and redirects.get(load_key) != representative:
                redirects[load_key] = representative
                changed = True

    return {key: resolve(value) for key, value in redirects.items()}


def _operand_range(value) -> Optional[IntRange]:
    from ._range_arithmetic import _operand_range as impl
    return impl(value)


def _range_refinements(prog: "SSAProgram") -> tuple[_RangeRefinement, ...]:
    from ._range_refinement import _CMP, _SWAP
    from ..ssa import binary_operands

    out: list[_RangeRefinement] = []
    for guard in prog.assignments:
        if guard.op != "assert" or not guard.inputs or guard.basic_block is None:
            continue
        condition = guard.inputs[0]
        definition = getattr(condition, "defined_by", None)
        candidates = []
        if definition is not None and definition.op in _CMP and len(definition.inputs) == 2:
            lhs, rhs = binary_operands(definition)
            lhs_range, rhs_range = _operand_range(lhs), _operand_range(rhs)
            if _value_key(lhs) is not None and rhs_range is not None:
                candidates.append((lhs, definition.op, rhs_range))
            if _value_key(rhs) is not None and lhs_range is not None:
                candidates.append((rhs, _SWAP[definition.op], lhs_range))
        elif _value_key(condition) is not None:
            candidates.append((condition, "!=", IntRange(0, 0)))
        for value, relation, other in candidates:
            if relation in {"==", "!="} and getattr(value.type, "kind", None) == "bytes":
                continue
            key = _value_key(value)
            if key is not None:
                out.append(_RangeRefinement(
                    key,
                    relation,
                    other,
                    guard.basic_block._key(),
                    guard.location.line,
                ))
    return tuple(out)


class ValueFacts:
    """Immutable facts keyed by stable SSA identities."""

    def __init__(
        self,
        prog: "SSAProgram",
        facts: Mapping[ValueKey, ValueFact],
        aliases: Mapping[ValueKey, AliasTarget],
        refinements: tuple[_RangeRefinement, ...],
        domains: frozenset[FactDomain],
    ):
        self._prog = prog
        self._facts = MappingProxyType(dict(facts))
        self._aliases = MappingProxyType(dict(aliases))
        self._refinements = refinements
        self.domains = domains
        self.revision = getattr(prog, "_revision", 0)
        self._dominance = None

    @classmethod
    def build(
        cls,
        prog: "SSAProgram",
        domains: frozenset[FactDomain],
        *,
        annotated_snapshot: Optional["SSAProgram"] = None,
    ) -> "ValueFacts":
        # A derived normal form already carries every annotation and has its
        # identities rewritten locally.  Re-cloning it here used to turn one
        # byte-taint query into two complete SSA reconstructions.
        # Constants are unaffected by guard refinement, so a normalized view
        # can answer that domain directly.  Ranges and type facts cannot: a
        # GUARDED/PRESENTATION view intentionally carries assert-conditioned
        # annotations, while ValueFacts are unconditional unless range_at() is
        # requested.  Rebuild those domains from the parsed graph boundary.
        normalized = (
            getattr(prog, "_derived_profile", None) is not None
            and domains <= {FactDomain.CONSTANTS}
        )
        if annotated_snapshot is not None:
            if not domains <= {FactDomain.CONSTANTS}:
                raise ValueError(
                    "guarded annotations can only seed unconditional constants"
                )
            snapshot = annotated_snapshot
            # The snapshot's physical rewrites are private.  Resolve callers'
            # canonical operands through the canonical identity relation and
            # return canonical objects from ValueFacts.resolve().
            aliases = _alias_map(prog)
        else:
            snapshot = prog if normalized else _base_snapshot(prog, domains)
            aliases = {} if normalized else _alias_map(snapshot)
        facts: dict[ValueKey, ValueFact] = {}
        values = [*snapshot.vars.values(), *snapshot.phis.values()]
        for value in values:
            key = _value_key(value)
            if key is None:
                continue
            facts[key] = ValueFact(
                constant=value.const_value,
                int_range=value.range if FactDomain.RANGES in domains else None,
                # Guarded normal forms may carry assert-conditioned range/type
                # refinements.  A constants-only query must not expose those
                # through the otherwise unrelated ``type`` field.
                type=(TypeFact.of(value.type) if domains & {
                    FactDomain.BYTE_LENGTHS, FactDomain.BIGINT_RANGES,
                } else None),
            )
        refinements = (
            _range_refinements(snapshot)
            if FactDomain.RANGES in domains else ()
        )
        return cls(prog, facts, aliases, refinements, domains)

    @property
    def facts(self) -> Mapping[ValueKey, ValueFact]:
        return self._facts

    @property
    def aliases(self) -> Mapping[ValueKey, AliasTarget]:
        return self._aliases

    def resolve(self, value):
        """Resolve a proven identity without modifying a consumer operand."""
        if isinstance(value, Const):
            return value
        key = _value_key(value)
        if key is None:
            return value
        target = self._aliases.get(key, key)
        if isinstance(target, Const):
            return target
        return _lookup(self._prog, target) or value

    def _resolved_key(self, value) -> Optional[ValueKey]:
        if isinstance(value, Const):
            return None
        key = _value_key(value)
        if key is None:
            return None
        target = self._aliases.get(key, key)
        return target if isinstance(target, tuple) else None

    def fact(self, value) -> ValueFact:
        if isinstance(value, Const):
            return ValueFact(constant=value)
        key = self._resolved_key(value)
        own = self._facts.get(key) if key is not None else None
        if own is not None:
            return own
        direct = self._facts.get(_value_key(value))
        return direct or ValueFact()

    def constant(self, value) -> Optional[Const]:
        if isinstance(value, Const):
            return value
        resolved = self.resolve(value)
        if isinstance(resolved, Const):
            return resolved
        return self.fact(value).constant

    def int_range(self, value) -> Optional[IntRange]:
        return self.fact(value).int_range

    def range_at(
        self,
        value,
        target: "Assignment | tuple[BasicBlock, int]",
    ) -> Optional[IntRange]:
        """Range valid at one use, including dominating assert refinements."""
        current = self.int_range(value)
        key = self._resolved_key(value) or _value_key(value)
        if key is None:
            return current
        if hasattr(target, "basic_block"):
            block, line = target.basic_block, target.location.line
        else:
            block, line = target
        if block is None:
            return current
        if self._dominance is None:
            from ..cfg.dominance import AssertDominance
            self._dominance = AssertDominance(self._prog)
        from ._range_refinement import _apply
        for refinement in self._refinements:
            refined_key = self._aliases.get(refinement.value, refinement.value)
            if refined_key != key:
                continue
            guard_block = self._prog.blocks.get(refinement.guard_block)
            if guard_block is None or not self._dominance.dominates(
                guard_block, block, refinement.guard_line, line
            ):
                continue
            base = current or IntRange(0, (1 << 64) - 1)
            lo, hi = _apply(refinement.relation, base, refinement.other)
            if lo <= hi:
                current = IntRange(lo, hi)
        return current


class AnalysisContext:
    """Revision-keyed cache of immutable facts for one canonical program."""

    def __init__(self, prog: "SSAProgram"):
        self.prog = prog
        self._cache: dict[tuple[int, frozenset[FactDomain]], ValueFacts] = {}
        self._derived: dict[tuple[int, DerivedProfile], "SSAProgram"] = {}

    def derived(self, profile: DerivedProfile) -> "SSAProgram":
        revision = getattr(self.prog, "_revision", 0)
        key = (revision, profile)
        result = self._derived.get(key)
        if result is None:
            result = _build_derived_program(self.prog, profile)
            self._derived = {
                cached_key: cached
                for cached_key, cached in self._derived.items()
                if cached_key[0] == revision
            }
            self._derived[key] = result
        return result

    def facts(
        self,
        *domains: FactDomain,
    ) -> ValueFacts:
        selected = frozenset(domains or tuple(FactDomain))
        revision = getattr(self.prog, "_revision", 0)
        key = (revision, selected)
        result = self._cache.get(key)
        if result is None:
            # A fact set computed for a superset of domains is a valid answer
            # for a narrower query.  Keeping same-revision entries prevents
            # CONSTANTS and CONSTANTS+RANGES consumers from evicting and then
            # rebuilding one another's whole SSA snapshots.
            result = next(
                (
                    cached
                    for (cached_revision, cached_domains), cached in self._cache.items()
                    if cached_revision == revision and selected <= cached_domains
                ),
                None,
            )
        if result is None:
            build_domains = selected
            annotated_snapshot = None
            normalized_constants = (
                getattr(self.prog, "_derived_profile", None) is not None
                and selected <= {FactDomain.CONSTANTS}
            )
            if not normalized_constants and selected <= {
                FactDomain.CONSTANTS, FactDomain.RANGES,
            }:
                guarded = self._derived.get((revision, DerivedProfile.GUARDED))
                if selected <= {FactDomain.CONSTANTS} and guarded is not None:
                    # Assert refinement cannot change constants.  Reuse the
                    # already-built normal form, but keep canonical identities.
                    annotated_snapshot = guarded
                else:
                    # CONSTANTS is a strict subset of this common query.  Build
                    # the superset up front so query order cannot construct two
                    # whole SSA snapshots for the same contract.
                    build_domains = frozenset({
                        FactDomain.CONSTANTS, FactDomain.RANGES,
                    })
            result = ValueFacts.build(
                self.prog,
                build_domains,
                annotated_snapshot=annotated_snapshot,
            )
            self._cache = {
                cached_key: cached
                for cached_key, cached in self._cache.items()
                if cached_key[0] == revision
            }
            self._cache[(revision, build_domains)] = result
        return result
