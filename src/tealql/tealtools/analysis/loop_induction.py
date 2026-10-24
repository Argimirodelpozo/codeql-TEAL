"""Bounded induction certificates shared by interval and resource queries.

Every entry and backedge participates. Arithmetic describes successful uint64
operations; a trip cap does not promise normal termination or sufficient credit.
No SSA values or scratch aliases are rewritten by this analysis.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..cfg import CFG
from ..cfg.loops import _routine_graph, _loop_shapes, _dominators
from ..ssa import Phi, IntRange, binary_operands
from ..ssa.operands import canonical_assignments, imm0

MAX_UINT = (1 << 64) - 1
_FLIP = {'<': '>', '<=': '>=', '>': '<', '>=': '<=', '==': '==', '!=': '!='}
_NEGATE = {'<': '>=', '<=': '>', '>': '<=', '>=': '<', '==': '!=', '!=': '=='}


@dataclass(frozen=True)
class LoopInduction:
    region: object
    trip_bound: int | None = None
    counter: object = None
    initial: IntRange | None = None
    step: IntRange | None = None
    limit: IntRange | None = None
    limit_value: object = None
    relation: str = ''
    invariant: IntRange | None = None
    guard: object = None
    post_test: bool = False
    scratch_slot: int | None = None
    reason: str = 'no supported induction proof'

    @property
    def complete(self):
        return self.trip_bound is not None


class _Refused(Exception):
    pass


def _hull(values):
    values = list(values)
    if not values or any(v is None for v in values):
        raise _Refused('an entry, update or operand has unknown bounds')
    return IntRange.hull(values)


class _Proof:
    def __init__(self, analysis, region, counter, slot=None):
        self.analysis, self.region, self.counter, self.slot = analysis, region, counter, slot
        self.remaining = analysis.budget
        self.active = set()

    def tick(self):
        self.remaining -= 1
        if self.remaining < 0:
            raise _Refused('induction proof work budget exhausted')

    def bounds(self, value, use):
        self.tick()
        result = self.analysis.base.range_at(value, use)
        carried = self.analysis.carried_bounds(value, use)
        if carried is not None:
            if result is not None and max(result.lo, carried.lo) > min(result.hi, carried.hi):
                raise _Refused('inconsistent numeric premises')
            result = carried if result is None else IntRange(max(result.lo, carried.lo), min(result.hi, carried.hi))
        if result is None:
            raise _Refused('numeric operand bounds unavailable')
        return result

    def offset(self, value, use):
        """Represent a value as coefficient * header counter + bounded offset."""
        self.tick()
        facts = self.analysis.facts
        original = getattr(value, 'defined_by', None)
        if self.slot is not None and original is not None and original.op == 'load' and imm0(original) == self.slot:
            result = self.scratch(original.basic_block, original)
            if result is None:
                raise _Refused('scratch value cycle has no seed')
            return result
        value = facts.resolve(value)
        if self.slot is None and value == self.counter:
            return 1, IntRange(0, 0)
        key = ('value', id(value))
        if key in self.active or len(self.active) > 64:
            raise _Refused('cyclic or deep induction expression')
        self.active.add(key)
        try:
            source = getattr(value, 'defined_by', None)
            if self.slot is not None and source is not None and source.op == 'load' and imm0(source) == self.slot:
                result = self.scratch(source.basic_block, source)
                if result is None:
                    raise _Refused('scratch value cycle has no seed')
                return result
            if isinstance(value, Phi):
                if not value.partial and self.slot is None and self.copy_of_counter(value):
                    return 1, IntRange(0, 0)
            operands = binary_operands(source) if source is not None else None
            if operands is not None and source.op in {'+', '-'}:
                left, right = (self.offset(v, source) for v in operands)
                sign = 1 if source.op == '+' else -1
                lo = left[1].lo + (right[1].lo if sign == 1 else -right[1].hi)
                hi = left[1].hi + (right[1].hi if sign == 1 else -right[1].lo)
                return left[0] + sign * right[0], IntRange(lo, hi)
            return 0, self.bounds(value, use)
        finally:
            self.active.remove(key)

    def copy_of_counter(self, value):
        """Prove identity through physical phi edges, before leaf flattening.

        Matching leaf sets alone can equate different loop iterations. Every
        path here must carry the header phi itself, with no other value leaf.
        """
        from ..ssa.ssa import PyPhi
        prog = self.analysis.prog
        root, current = prog.pyphi_for_phi(self.counter), prog.pyphi_for_phi(value)
        if root is None or current is None:
            return False
        work, seen, seeded = [current], set(), False
        while work:
            self.tick()
            item = work.pop()
            if item is root:
                seeded = True
            elif id(item) not in seen:
                if not isinstance(item, PyPhi) or not item.args:
                    return False
                seen.add(id(item))
                work.extend(item.args)
        return seeded

    def scratch(self, block, before=None, *, initial=False):
        """Walk last writers, with the loop header as a symbolic entry cut."""
        self.tick()
        key = ('scratch', block, id(before), initial)
        if key in self.active:
            return None  # a writer-free CFG cycle preserves its incoming value
        if len(self.active) > 64:
            raise _Refused('scratch writer walk is too deep')
        self.active.add(key)
        try:
            stream = canonical_assignments(block)
            end = stream.index(before) if before is not None else len(stream)
            for assignment in reversed(stream[:end]):
                self.tick()
                if assignment.op in {'callsub', 'stores'}:
                    raise _Refused('call or dynamic store may change the scratch counter')
                if assignment.op == 'store' and imm0(assignment) == self.slot:
                    if not assignment.inputs:
                        raise _Refused('scratch store value is unavailable')
                    if initial:
                        return 0, self.bounds(assignment.inputs[0], assignment)
                    return self.offset(assignment.inputs[0], assignment)
            if not initial and block is self.region.header:
                return 1, IntRange(0, 0)
            if initial and block in self.analysis.roots:
                # Only the actual program entry has AVM zero-initialized scratch.
                if block not in self.analysis.cfg.entries:
                    raise _Refused('callee scratch entry is caller-dependent')
                seeds = [(0, IntRange(0, 0))]
            else:
                seeds = []
            for pred in self.analysis.graph.predecessors(block):
                if initial and pred in self.region.body:
                    raise _Refused('scratch initial value depends on a previous loop invocation')
                if not initial and pred not in self.region.body:
                    raise _Refused('scratch update has an unaccounted entry')
                incoming = self.scratch(pred, initial=initial)
                if incoming is not None:
                    seeds.append(incoming)
            if not seeds:
                return None
            if len({x[0] for x in seeds}) != 1:
                raise _Refused('scratch paths disagree on counter identity')
            return seeds[0][0], _hull(x[1] for x in seeds)
        finally:
            self.active.remove(key)


class LoopAnalysis:
    def __init__(self, facts, *, budget=2048):
        from .intervals import IntervalQuery
        from .loop_invariants import LoopInvariants
        self.facts, self.prog, self.budget = facts, facts._prog, budget
        self.base = IntervalQuery(facts, loop_invariants=False)
        self.invariants = LoopInvariants(self.base, max_nodes=min(budget, 128))
        self.cfg = CFG.of(self.prog)
        self.graph, self.roots = _routine_graph(self.prog, self.cfg, self.base.predicates)
        self.regions = _loop_shapes(self.graph, self.roots)
        self.canonical = {(r.header, r.body): r for r in self.regions}
        self.by_header = {}
        for region in self.regions:
            self.by_header.setdefault(region.header, []).append(region)
        self.dom = _dominators(self.graph, self.roots)
        self.cache = {}
        self.phis = {}
        for phi in self.prog.phis.values():
            if not phi.partial:
                self.phis.setdefault(phi.basic_block, []).append(phi)

    def summary(self, region):
        self.facts.resolve(None)  # enforce revision identity even on cached answers
        key = region.header, region.body
        if key not in self.cache:
            canonical = self.canonical.get(key)
            self.cache[key] = (self._summary(canonical) if canonical is not None else
                               LoopInduction(region, reason='region differs from the canonical loop graph'))
        return self.cache[key]

    def carried_bounds(self, value, use):
        """A bounded copy/phi fixed point, seeded by every non-phi leaf.

        Pure identity cycles preserve the hull of their seeds. Arithmetic is a
        leaf, never an omitted backedge; incomplete or unseeded webs refuse.
        """
        value = self.facts.resolve(value)
        if not isinstance(value, Phi):
            return None
        work, seen, seeds = [value], set(), []
        while work:
            if len(seen) >= min(self.budget, 256):
                return None
            current = self.facts.resolve(work.pop())
            key = id(current)
            if key in seen:
                continue
            seen.add(key)
            if isinstance(current, Phi):
                if current.partial or not current.args:
                    return None
                work.extend(current.args)
            else:
                bounds = self.base.range_at(current, use)
                if bounds is None:
                    return None
                seeds.append(bounds)
        return _hull(seeds) if seeds else None

    def _relation(self, region, block, op):
        labels = self.prog.edge_polarity
        inside, outside = set(), set()
        for successor in self.graph.successors(block):
            target = inside if successor in region.body else outside
            target.update(labels.get((block._key(), successor._key()), ()))
        if inside == {'true'} and outside == {'false'}:
            return op
        if inside == {'false'} and outside == {'true'}:
            return _NEGATE[op]
        return None

    def _summary(self, region):
        if region.kind != 'reducible':
            return LoopInduction(region, reason='irreducible region has no single induction header')
        refusals, proved = [], []
        for block in sorted(region.body, key=lambda b: (b.file, b.first_line)):
            if not all(block in self.dom[latch] for latch, _ in region.back_edges):
                continue
            stream = canonical_assignments(block)
            if not stream or stream[-1].op not in {'bz', 'bnz'} or not stream[-1].inputs:
                continue
            guard = stream[-1]
            condition = self.facts.resolve(guard.inputs[0])
            comparison = getattr(condition, 'defined_by', None)
            if comparison is None or comparison.op not in _FLIP:
                continue
            operands = binary_operands(comparison)
            if operands is None:
                continue
            for tested, limit, relation in ((operands[0], operands[1], comparison.op),
                                             (operands[1], operands[0], _FLIP[comparison.op])):
                relation = self._relation(region, block, relation)
                if relation is None:
                    continue
                candidates = [(phi, None) for phi in self.phis.get(region.header, ())]
                slots = {imm0(a) for b in region.body for a in canonical_assignments(b)
                         if a.op == 'load' and imm0(a) is not None}
                candidates.extend((None, slot) for slot in sorted(slots)[:32])
                for counter, slot in candidates:
                    try:
                        proved.append(self._prove(region, guard, tested, limit, relation, counter, slot))
                    except _Refused as error:
                        refusals.append(str(error))
        reasons = [r for r in dict.fromkeys(refusals) if r != 'guard does not test this induction counter']
        return min(proved, key=lambda p: p.trip_bound) if proved else LoopInduction(
            region, reason='; '.join(reasons[:3]) if reasons else 'no unavoidable supported counter guard')

    def _prove(self, region, guard, tested, limit, relation, counter, slot):
        proof = _Proof(self, region, counter, slot)
        if slot is None and region.header in self.roots:
            raise _Refused('header has an implicit stack entry')
        tested_coef, tested_offset = proof.offset(tested, guard)
        if tested_coef != 1:
            raise _Refused('guard does not test this induction counter')
        initials, steps, updates = [], [], []
        predecessors = set(self.graph.predecessors(region.header))
        if slot is None and predecessors != set(region.header.predecessors):
            raise _Refused('call-matched entry stack is unavailable')
        for pred in predecessors:
            if slot is None:
                incoming = pred.slot(counter.stack_index)
                if incoming is None:
                    raise _Refused('header phi has an unavailable incoming value')
                if pred not in region.body:
                    initials.append(proof.bounds(incoming, (pred, pred.last_line)))
                    continue
                coef, delta = proof.offset(incoming, (pred, pred.last_line))
                updates.append(self.facts.resolve(incoming))
            else:
                incoming = proof.scratch(pred, initial=pred not in region.body)
                if incoming is None:
                    raise _Refused('scratch value cycle has no seed')
                coef, delta = incoming
                if pred not in region.body:
                    initials.append(delta)
                    continue
            if coef != 1:
                raise _Refused('a backedge resets or changes the counter identity')
            steps.append(delta)
        if slot is not None and region.header in self.cfg.entries:
            initials.append(IntRange(0, 0))
        initial, step = _hull(initials), _hull(steps)
        if step.lo <= 0 <= step.hi:
            raise _Refused('a backedge may make zero or inconsistent progress')
        increasing = step.lo > 0
        if relation in {'<', '<='} and not increasing or relation in {'>', '>='} and increasing:
            raise _Refused('counter moves away from the exit')
        bound = proof.bounds(limit, guard)
        # A bound is useful even when it changes each lap, provided this range
        # holds at every test. The base query never consumes this certificate.
        post = guard.basic_block is not region.header or tested_offset != IntRange(0, 0)
        if post and not all(latch is guard.basic_block for latch, _ in region.back_edges):
            raise _Refused('post-test guard does not cover every latch')
        if post and tested_offset != step:
            raise _Refused('post-test value differs from the backedge update')
        if post and (slot is None and any(v != self.facts.resolve(tested) for v in updates)
                     or slot is not None and step.lo != step.hi):
            raise _Refused('post-test update identity is not exact')
        offset = tested_offset
        if relation in {'==', '!='}:
            if initial.lo != initial.hi or bound.lo != bound.hi or step.lo != step.hi:
                raise _Refused('equality exit needs an exact start, limit and stride')
            distance = bound.lo - initial.lo
            if relation == '!=' and (distance * step.lo < 0 or distance % step.lo):
                raise _Refused('stride does not reach the equality exit')
            cap = 1 if relation == '==' else distance // step.lo
            if post:
                if relation == '!=' and cap == 0:
                    raise _Refused('post-test counter already passed its equality exit')
                cap = max(1, cap) if relation == '!=' else 2
        elif increasing:
            distance = bound.hi - initial.lo - offset.lo + int(relation == '<=')
            cap = max(0, (distance + step.lo - 1) // step.lo) + int(post)
        else:
            stride = -step.hi
            distance = initial.hi + offset.hi - bound.lo + int(relation == '>=')
            cap = max(0, (distance + stride - 1) // stride) + int(post)
        if increasing:
            end = bound.hi + ((0 if post else step.hi) - int(relation == '<'))
            if relation == '!=':
                end = bound.hi
            invariant = IntRange(initial.lo, min(MAX_UINT, max(initial.hi, end)))
        else:
            end = bound.lo + ((0 if post else step.lo) + int(relation == '>'))
            if relation == '!=':
                end = bound.lo
            invariant = IntRange(max(0, min(initial.lo, end)), initial.hi)
        if relation == '==':
            invariant = IntRange(0, MAX_UINT)  # progress cap holds; no ordering invariant follows
        return LoopInduction(region, cap, counter, initial, step, bound, limit,
                             relation, invariant, guard, post, slot, '')

    def range_at(self, value, file, line):
        """Certified header invariants, plus scratch values at named uses."""
        value = self.facts.resolve(value)
        source = getattr(value, 'defined_by', None)
        if not isinstance(value, Phi) and not (source is not None and source.op == 'load'):
            return None
        regions = self.by_header.get(value.basic_block, ()) if isinstance(value, Phi) else self.regions
        if not regions:
            return None
        carried = self.carried_bounds(value, (self.prog.block_containing(file, line), line))
        invariant = self.invariants.query(value) if isinstance(value, Phi) else None
        results = [r for r in (carried, invariant) if r is not None]
        for region in regions:
            if region.header.file != file:
                continue
            if isinstance(value, Phi) and value.basic_block is not region.header:
                continue
            if source is not None and source.basic_block not in region.body:
                if not any(source.basic_block in self.graph.successors(b) for b in region.body):
                    continue
            result = self.summary(region)
            if not result.complete:
                continue
            if result.scratch_slot is None:
                if value == result.counter:
                    results.append(result.invariant)
            elif source is not None and source.op == 'load' and imm0(source) == result.scratch_slot:
                outside = source.basic_block not in region.body
                if outside and set(self.graph.predecessors(source.basic_block)) != {result.guard.basic_block}:
                    continue
                try:
                    coefficient, offset = _Proof(self, region, None, result.scratch_slot).offset(value, source)
                    if coefficient == 1:
                        bounds = result.invariant
                        from ._range_refinement import _apply
                        if not result.post_test and (outside or source.basic_block is not region.header):
                            relation = _NEGATE[result.relation] if outside else result.relation
                            lo, hi = _apply(relation, bounds, result.limit)
                            if lo > hi:
                                continue
                            bounds = IntRange(lo, hi)
                        results.append(IntRange(max(0, bounds.lo + offset.lo), min(MAX_UINT, bounds.hi + offset.hi)))
                except _Refused:
                    pass
        if not results:
            return None
        lo, hi = max(r.lo for r in results), min(r.hi for r in results)
        return IntRange(lo, hi) if lo <= hi else None
