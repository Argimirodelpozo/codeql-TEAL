"""One interprocedural service for positional returns and effect dependencies.

Parameter dependencies are namespaced per procedure and grow monotonically,
including across recursion. Assertion dependencies are evidence of a use, not
validation: consumers must establish a predicate appropriate to their policy.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ..diagnostics.evidence import GuardEvidence
from ..language.effects import STATE_EFFECTS
from . import pre_ir
from .taint_flow import (
    UNKNOWN_SOURCE, _intr, _invoke, _trusted_apparg, source_label, transfer_fixpoint,
    value_sources,
)


@dataclass(frozen=True)
class ValueDependency:
    internal_sources: frozenset = frozenset()
    passthrough: frozenset = frozenset()

    def apply(self, arg_sources) -> set:
        out = set(self.internal_sources)
        for i in self.passthrough:
            out.update(arg_sources[i] if i < len(arg_sources) else {UNKNOWN_SOURCE})
        return out


@dataclass(frozen=True)
class EffectDependency:
    op: str
    line: int
    operands: tuple[ValueDependency, ...]
    procedure: str = ''
    immediates: tuple = ()


@dataclass(frozen=True)
class SubSummary:
    results: tuple[ValueDependency, ...]
    assertions: tuple[GuardEvidence, ...] = ()
    effects: tuple[EffectDependency, ...] = ()

    @property
    def passthrough(self) -> frozenset:
        return frozenset(i for r in self.results for i in r.passthrough)

    @property
    def internal_sources(self) -> frozenset:
        return frozenset(s for r in self.results for s in r.internal_sources)

    @property
    def asserted_params(self) -> frozenset:
        """Parameters influencing entry assertions; no sanitizer claim."""
        return frozenset(int(e.subject) for e in self.assertions)

    def output_sources(self, arg_sources) -> tuple[set, ...]:
        return tuple(result.apply(arg_sources) for result in self.results)

    def result_sources(self, arg_sources) -> set:
        """Aggregate presentation view; use output_sources for call transfers."""
        return set().union(*self.output_sources(arg_sources))


def _dependency(markers, sub_id) -> ValueDependency:
    return ValueDependency(
        frozenset(m for m in markers if not isinstance(m, tuple)),
        frozenset(m[2] for m in markers if isinstance(m, tuple) and m[1] == sub_id),
    )


def compute_summaries(lifter, trusted_args=frozenset()) -> Mapping[str, SubSummary]:
    """Least fixed point of per-output and transitive effect dependencies."""
    cache_key = frozenset(trusted_args)
    cache = getattr(lifter, '_summary_cache', {})
    if getattr(lifter, '_analysis_frozen', False) and cache_key in cache:
        return cache[cache_key]
    subs = [s for s in lifter.subs if not s.is_main]
    taint = defaultdict(set)
    acc = {}
    for sub in subs:
        for i, param in enumerate(sub.parameters):
            taint[id(param.register)].add(("p", sub.id, i))
        arity = max([len(sub.returns)] + [len(b.terminator.result) for b in sub.body
                    if isinstance(b.terminator, pre_ir.SubroutineReturn)])
        acc[sub.id] = [set() for _ in range(arity)]

    def invoke(op, inv, reg_t):
        callee = lifter.name2sub.get(inv.target)
        args = [reg_t(a) for a in inv.args]
        if callee is None or callee.id not in acc:
            unknown = {UNKNOWN_SOURCE}.union(*args)
            return tuple(unknown for _ in getattr(op, "targets", ())), False
        return tuple(_dependency(m, callee.id).apply(args) for m in acc[callee.id]), False

    def refine(reg_t):
        changed = False
        for sub in subs:
            for block in sub.body:
                term = block.terminator
                if isinstance(term, pre_ir.SubroutineReturn):
                    for index, markers in enumerate(acc[sub.id]):
                        incoming = (reg_t(term.result[index]) if index < len(term.result)
                                    else {UNKNOWN_SOURCE})
                        if incoming - markers:
                            markers.update(incoming)
                            changed = True
        return changed

    transfer_fixpoint(lifter, taint,
                      seed_label=lambda s: None if _trusted_apparg(s, trusted_args) else source_label(s),
                      invoke_ins=invoke, per_round=refine, subs=subs)
    result = {}
    for sub in subs:
        assertions = set()
        effects = []
        for block in sub.body:
            for op in block.ops:
                if block is sub.body[0] and isinstance(op, pre_ir.Assert):
                    dep = _dependency(value_sources(op.condition, taint), sub.id)
                    assertions.update(GuardEvidence(str(i), "influences-assertion", scope=(sub.id,))
                                      for i in dep.passthrough)
                intr = _intr(op)
                if intr is not None and intr.op in STATE_EFFECTS.keys() | {"log", "itxn_field"}:
                    effects.append(EffectDependency(intr.op, intr.line,
                        tuple(_dependency(value_sources(a, taint), sub.id) for a in intr.args),
                        sub.id, tuple(intr.immediates)))
        result[sub.id] = SubSummary(
            tuple(_dependency(m, sub.id) for m in acc[sub.id]),
            tuple(sorted(assertions, key=lambda e: e.subject)), tuple(effects))
    # Merge by originating instruction, not by call path. Recursion can grow
    # dependencies only over the finite source/parameter universe.
    effect_maps = {s.id: {(e.procedure, e.line, e.op, e.immediates): e for e in result[s.id].effects}
                   for s in subs}
    changed = True
    while changed:
        changed = False
        for sub in subs:
            for block in sub.body:
                for op in block.ops:
                    call = _invoke(op)
                    if call is None:
                        continue
                    args = [value_sources(a, taint) for a in call.args]
                    called = effect_maps.get(call.target)
                    effects = tuple(called.values()) if called is not None else (
                        EffectDependency('unknown-call', 0, (), call.target),)
                    for effect in effects:
                        key = effect.procedure, effect.line, effect.op, effect.immediates
                        deps = tuple(_dependency(d.apply(args), sub.id) for d in effect.operands)
                        old = effect_maps[sub.id].get(key)
                        if old is not None:
                            deps = tuple(ValueDependency(a.internal_sources | b.internal_sources,
                                                         a.passthrough | b.passthrough)
                                         for a, b in zip(old.operands, deps))
                        new = EffectDependency(effect.op, effect.line, deps,
                                               effect.procedure, effect.immediates)
                        if new != old:
                            effect_maps[sub.id][key] = new
                            changed = True
    result = MappingProxyType({name: SubSummary(s.results, s.assertions,
                    tuple(effect_maps[name][k] for k in sorted(effect_maps[name])))
                              for name, s in result.items()})
    if getattr(lifter, '_analysis_frozen', False):
        cache[cache_key] = result
        lifter._summary_cache = cache
    return result
