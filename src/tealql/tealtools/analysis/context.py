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


_COMMON_FACT_DOMAINS = frozenset({FactDomain.CONSTANTS, FactDomain.RANGES})


def _normalize_value_program(target: "SSAProgram") -> "SSAProgram":
    """Turn a private fact snapshot into the reusable value normal form.

    Facts must be frozen before this step: the physical identity rewrites below
    deliberately improve legacy derived consumers, but unconditional fact
    answers retain the canonical, pre-rewrite semantics of ``_base_snapshot``.
    """
    from ._input_aliases import propagate_inputs
    from ._scratch import propagate_scratch_values
    from ..ssa.value_rewrite import propagate_stack_shuffles

    propagate_inputs(target)
    target._rebuild_uses()
    target._invalidate_value_relations()
    target._ensure_scratch_influence()
    propagate_scratch_values(target)
    target._rebuild_uses()
    propagate_stack_shuffles(target)
    target._rebuild_uses()
    # The fact snapshot already seeded ranges.  Re-run arithmetic after operand
    # rewrites so newly exposed scratch/shuffle sources reach derived consumers.
    target.propagate_range_arithmetic()
    return target


def _build_derived_program(
    prog: "SSAProgram",
    profile: DerivedProfile = DerivedProfile.VALUE,
    *,
    value_program: Optional["SSAProgram"] = None,
) -> tuple["SSAProgram", "ValueFacts"]:
    """Finish an isolated derived view and capture unconditional value facts.

    ``value_program`` is an unshared unconditional fact snapshot.  A facts-first
    query may have built it; consuming that seed here removes the last redundant
    SSA graph construction without exposing a mutable program to the caller.
    """
    from ._range_refinement import propagate_assert_ranges
    from ..ssa.presentation import cleanup_unused_ssavars

    target = value_program or _base_snapshot(prog, _COMMON_FACT_DOMAINS)
    unconditional = ValueFacts._from_snapshot(
        prog,
        _COMMON_FACT_DOMAINS,
        target,
        aliases=_alias_map(target),
    )
    _normalize_value_program(target)
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
    return target, unconditional


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
    """Pure equivalence relation for stable inputs, shuffles, joins, and scratch."""
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
        for phi in prog.phis.values():
            key = _value_key(phi)
            sources = [resolve(_value_key(arg)) for arg in phi.args]
            if (sources and sources[0] is not None and sources[0] != key
                    and all(source == sources[0] for source in sources)
                    and redirects.get(key) != sources[0]):
                redirects[key] = sources[0]
                changed = True
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


class ValueFacts:
    """Immutable facts keyed by stable SSA identities."""

    def __init__(
        self,
        prog: "SSAProgram",
        facts: Mapping[ValueKey, ValueFact],
        aliases: Mapping[ValueKey, AliasTarget],
        domains: frozenset[FactDomain],
    ):
        self._prog = prog
        self._facts = MappingProxyType(dict(facts))
        self._aliases = MappingProxyType(dict(aliases))
        self.domains = domains
        self.revision = getattr(prog, "_revision", 0)
        self._intervals = None
        self._congruences = None
        self._numeric_calls = None

    @classmethod
    def build(
        cls,
        prog: "SSAProgram",
        domains: frozenset[FactDomain],
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
        snapshot = prog if normalized else _base_snapshot(prog, domains)
        aliases = {} if normalized else _alias_map(snapshot)
        return cls._from_snapshot(prog, domains, snapshot, aliases=aliases)

    @classmethod
    def _from_snapshot(
        cls,
        prog: "SSAProgram",
        domains: frozenset[FactDomain],
        snapshot: "SSAProgram",
        *,
        aliases: Mapping[ValueKey, AliasTarget],
    ) -> "ValueFacts":
        """Freeze facts from an already annotated private snapshot."""
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
        return cls(prog, facts, aliases, domains)

    @property
    def facts(self) -> Mapping[ValueKey, ValueFact]:
        return self._facts

    @property
    def aliases(self) -> Mapping[ValueKey, AliasTarget]:
        return self._aliases

    def resolve(self, value):
        """Resolve a proven identity without modifying a consumer operand."""
        if getattr(self._prog, "_revision", 0) != self.revision:
            raise RuntimeError("stale facts: request facts again after changing the program")
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

    def congruence(self, value):
        """Inductive divisibility/residue facts, including loop-carried values."""
        from .congruences import CongruenceQuery
        if self._congruences is None:
            self._congruences = CongruenceQuery(self)
        return self._congruences.query(value)

    def call_result(self, call, slot=0):
        """Numeric result of one call site; slots are bottom-first ABI returns."""
        from .numeric_calls import NumericCalls
        if self._numeric_calls is None:
            self._numeric_calls = NumericCalls(self)
        return self._numeric_calls.query(call, slot)

    def range_at(
        self,
        value,
        target: "Assignment | tuple[BasicBlock, int]",
    ) -> Optional[IntRange]:
        """Range at a use, including branch predicates and bounded expression flow."""
        if FactDomain.RANGES not in self.domains:
            return None
        if self._intervals is None:
            from .intervals import IntervalQuery
            self._intervals = IntervalQuery(self)
        return self._intervals.range_at(value, target)


class AnalysisContext:
    """Revision-keyed cache of immutable facts for one canonical program."""

    def __init__(self, prog: "SSAProgram"):
        self.prog = prog
        self._cache: dict[tuple[int, frozenset[FactDomain]], ValueFacts] = {}
        self._derived: dict[tuple[int, DerivedProfile], "SSAProgram"] = {}
        # A facts-first query owns this private, mutable value normal form until
        # the first derived view consumes it.  No caller can observe the seed.
        self._value_seed: Optional[tuple[int, "SSAProgram"]] = None

    def derived(self, profile: DerivedProfile) -> "SSAProgram":
        revision = getattr(self.prog, "_revision", 0)
        key = (revision, profile)
        result = self._derived.get(key)
        if result is None:
            seed = None
            if self._value_seed is not None:
                seed_revision, seed = self._value_seed
                if seed_revision != revision:
                    seed = None
                self._value_seed = None
            result, unconditional = _build_derived_program(
                self.prog,
                profile,
                value_program=seed,
            )
            self._derived = {
                cached_key: cached
                for cached_key, cached in self._derived.items()
                if cached_key[0] == revision
            }
            self._derived[key] = result
            self._cache = {
                cached_key: cached
                for cached_key, cached in self._cache.items()
                if cached_key[0] == revision
            }
            self._cache.setdefault(
                (revision, _COMMON_FACT_DOMAINS), unconditional
            )
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
            normalized_constants = (
                getattr(self.prog, "_derived_profile", None) is not None
                and selected <= {FactDomain.CONSTANTS}
            )
            if not normalized_constants and selected <= {
                FactDomain.CONSTANTS, FactDomain.RANGES,
            }:
                # Freeze the common unconditional superset before physical
                # identity rewrites.  Retain its unshared working graph so a
                # later GUARDED view can normalize and finish it in place.
                build_domains = _COMMON_FACT_DOMAINS
                seed = _base_snapshot(self.prog, build_domains)
                result = ValueFacts._from_snapshot(
                    self.prog,
                    build_domains,
                    seed,
                    aliases=_alias_map(seed),
                )
                self._value_seed = (revision, seed)
            else:
                result = ValueFacts.build(self.prog, build_domains)
            self._cache = {
                cached_key: cached
                for cached_key, cached in self._cache.items()
                if cached_key[0] == revision
            }
            self._cache[(revision, build_domains)] = result
        return result
