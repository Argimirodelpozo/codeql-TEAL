"""Address authority through current-program storage writers.

Preservation is separate from initialization/history: inspecting an approval
program cannot establish the contents of an existing application's ledger.
Storage-backed guards therefore retain those premises even when every writer
preserves the authority invariant. Unknown writers never establish preservation.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from ..diagnostics.evidence import GuardEvidence
from ..diagnostics.health import AnalysisDegradation, AnalysisHealth, health_for
from ..diagnostics.location import InstructionPoint
from ..language.effects import STATE_EFFECTS
from ..ssa import Const, Phi, SSAVar, const_int, is_field_var
from ..ssa.producers import is_current_sender_var
from . import FactDomain


@dataclass(frozen=True)
class AddressAuthority:
    preserved: bool
    reason: str
    evidence: tuple[GuardEvidence, ...] = ()

    @property
    def assumptions(self):
        return tuple(sorted({a for e in self.evidence for a in e.assumptions}))

    @property
    def proved(self):
        return self.preserved and not self.assumptions


def literal_authority(value):
    raw = value.value.removeprefix('0x') if isinstance(value, Const) else ''
    if (isinstance(value, Const) and value.kind == 'bytes' and len(raw) == 64
            and set(raw) <= set('0123456789abcdefABCDEF')):
        return AddressAuthority(True, 'fixed address in the program', (GuardEvidence(
            str(value), 'authority-controlled', basis='constant'),))
    return AddressAuthority(False, 'not a constant address')


def authority_health(evidence) -> AnalysisHealth:
    notes = {}
    for result in evidence:
        for guard in result.evidence:
            if not guard.assumptions:
                continue
            point = guard.point
            message = '; '.join(guard.assumptions)
            key = (point.file if point else None, message)
            notes[key] = AnalysisDegradation('authority-assumption', message,
                point.file if point else None, point.line if point else None)
    return AnalysisHealth(tuple(notes.values()))


class AuthorityAnalysis:
    """A revision-scoped, bounded must-analysis shared by SSA and lifted guards."""

    def __init__(self, program, paths=None):
        self.program = program
        self.revision = program.revision
        self.facts = program.facts(FactDomain.CONSTANTS)
        # An invocation's caller/method seeds do not constrain every possible
        # writer invocation. Reuse only a whole-program predicate analysis.
        self._paths = _whole_program_paths(paths)
        self._cache = {}
        self._captures = []
        self._writes = {}
        self._dynamic = {}
        self.visits = 0
        self._complete = health_for(program, deep=True).complete
        for assignment in program.assignments:
            effect = STATE_EFFECTS.get(assignment.op)
            if effect is None or effect.storage not in {'global', 'local'}:
                continue
            key = self._constant_key(assignment, effect.key_index)
            owner = assignment.location.file, effect.storage
            if key is None:
                self._dynamic.setdefault(owner, []).append(assignment)
            else:
                self._writes.setdefault((*owner, key), []).append(assignment)

    @property
    def paths(self):
        if self._paths is None:
            from ..cfg.path_predicates import PathPredicateAnalysis
            self._paths = PathPredicateAnalysis(self.program)
        return self._paths

    @contextmanager
    def capture(self):
        used = {}
        self._captures.append(used)
        try:
            yield used
        finally:
            self._captures.pop()

    def record(self, result):
        for used in self._captures:
            used[result] = result
        return result

    def address(self, value):
        if self.program.revision != self.revision:
            raise RuntimeError('stale authority analysis: request it again after changing the program')
        key = value._key() if isinstance(value, (SSAVar, Phi)) else value
        key = type(value), key
        if key not in self._cache:
            self.visits = 0
            self._cache[key] = self._address(value, frozenset(), frozenset())
        return self.record(self._cache[key])

    def state_key(self, file, storage, key: bytes):
        """Preservation of a named key, even when this program never reads it."""
        if self.program.revision != self.revision:
            raise RuntimeError('stale authority analysis: request it again after changing the program')
        if file not in self.program.source_files or storage not in {'global', 'local'}:
            raise ValueError('authority keys require a source file and global/local storage')
        self.visits = 0
        slot = file, storage, '0x' + key.hex()
        return self.record(self._storage(f'{storage} key {slot[2]}', slot, frozenset(), frozenset()))

    def _constant_key(self, assignment, index):
        if index >= len(assignment.inputs):
            return None
        constant = self.facts.constant(assignment.inputs[index])
        return constant.value if isinstance(constant, Const) and constant.kind == 'bytes' else None

    def _field(self, value, family, field):
        return is_field_var(self.facts.resolve(value), family, field)

    def _current_app(self, value):
        if (const_int(self.facts.constant(value)) == 0
                or self._field(value, 'txn', 'ApplicationID')
                or self._field(value, 'global', 'CurrentApplicationID')
                or self._field(value, 'txna', 'Applications 0')):
            return True
        source = getattr(self.facts.resolve(value), 'defined_by', None)
        return (source is not None and source.op == 'txnas'
                and source.immediates.strip() == 'Applications' and len(source.inputs) == 1
                and const_int(self.facts.constant(source.inputs[0])) == 0)

    def _slot(self, value):
        assignment = getattr(value, 'defined_by', None)
        if assignment is None or assignment.op not in {
                'app_global_get', 'app_global_get_ex', 'app_local_get', 'app_local_get_ex'}:
            return None
        if assignment.op.endswith('_ex'):
            # Public outputs are top-first: existence flag, then stored value.
            if value.index != 2 or len(assignment.inputs) < 2:
                return None
            if not self._current_app(assignment.inputs[1]):
                return None
        key = self._constant_key(assignment, 0)
        storage = 'global' if assignment.op.startswith('app_global') else 'local'
        return (assignment.location.file, storage, key) if key is not None else None

    def _proof(self, value, reason, assumptions=()):
        assignment = getattr(value, 'defined_by', None)
        point = (InstructionPoint(assignment.location.file, assignment.location.line, assignment.op)
                 if assignment is not None else None)
        return AddressAuthority(True, reason, (GuardEvidence(
            str(value), 'authority-controlled', point=point,
            basis='verified-obligation' if assumptions else 'constant',
            assumptions=tuple(assumptions)),))

    def _unknown(self, value, reason):
        assignment = getattr(value, 'defined_by', None)
        point = (InstructionPoint(assignment.location.file, assignment.location.line, assignment.op)
                 if assignment is not None else None)
        return AddressAuthority(False, reason, (GuardEvidence(
            str(value), 'unproved-authority', point=point, basis='unknown'),))

    def _address(self, value, slots, active):
        self.visits += 1
        if self.visits > 256:
            return AddressAuthority(False, 'authority dependency is cyclic or exceeds the work budget')
        value = self.facts.constant(value) or self.facts.resolve(value)
        if id(value) in active and self._slot(value) is None:
            return AddressAuthority(False, 'authority value dependency is cyclic')
        if isinstance(value, Const):
            return literal_authority(value)
        if self._field(value, 'global', 'CreatorAddress'):
            return self._proof(value, 'immutable application creator')
        source = getattr(value, 'defined_by', None)
        if (source is not None and source.op == 'app_params_get'
                and source.immediates.strip() == 'AppCreator' and value.index == 2
                and len(source.inputs) == 1 and self._current_app(source.inputs[0])):
            return self._proof(value, 'immutable creator of the current application')
        if isinstance(value, Phi) and value.args:
            parts = [self._address(v, slots, active | {id(value)}) for v in value.args]
            return AddressAuthority(all(p.preserved for p in parts), 'all phi arms must preserve authority',
                tuple(e for p in parts for e in p.evidence))
        slot = self._slot(value)
        if slot is None:
            return self._unknown(value, 'address provenance is unsupported, dynamic, or foreign')
        return self._storage(value, slot, slots, active)

    def _storage(self, value, slot, slots, active):
        if not self._complete:
            return AddressAuthority(False, 'source analysis is incomplete')
        file, storage, key = slot
        assumptions = (f'initial {storage} key {key} in {file} contains the intended authority',
                       f'the supplied code governs {storage} state in {file}; other programs and upgrades preserve its authority invariant')
        if slot in slots:
            # Inductive preservation, explicitly conditional on the initial
            # invariant. This is never an inference of trusted initialization.
            return self._proof(value, 'authority rotation relies on the initial invariant', assumptions)
        writes = self._writes.get(slot, ())
        dynamic = self._dynamic.get((file, storage), ())
        evidence = []
        for writer in (*writes, *dynamic):
            safe = self._writer(writer, slots | {slot}, active | {id(value)})
            if not safe.preserved:
                return self._unknown(value,
                    f'{storage} writer at {writer.location} has no proved authority restriction')
            evidence.extend(safe.evidence)
        proof = self._proof(value, f'{len(writes)} static and {len(dynamic)} dynamic writers preserve authority', assumptions)
        return AddressAuthority(True, proof.reason, tuple(dict.fromkeys((*proof.evidence, *evidence))))

    def _writer(self, writer, slots, active):
        candidates = []
        for predicate in self.paths.predicates_at(writer.location.file, writer.location.line):
            left = predicate.value
            if ((predicate.kind == 'zero' and self._field(left, 'txn', 'ApplicationID'))
                    or (predicate.kind == 'eq' and predicate.args
                        and self._field(left, 'txn', 'ApplicationID')
                        and const_int(self.facts.constant(predicate.args[0])) == 0)):
                return AddressAuthority(True, 'creator chooses state during application creation')
            if predicate.kind == 'eq' and predicate.args:
                right = predicate.args[0]
                if is_current_sender_var(self.facts.resolve(left)):
                    candidates.append(right)
                elif is_current_sender_var(self.facts.resolve(right)):
                    candidates.append(left)
        effect = STATE_EFFECTS[writer.op]
        if effect.value_index is not None and effect.value_index < len(writer.inputs):
            # A fixed trusted replacement cannot give the caller a new
            # authority, even when the caller can trigger the replacement.
            candidates.append(writer.inputs[effect.value_index])
        # Prefer immutable roots before recursive state invariants. Predicate
        # set iteration order must not consume the work budget or introduce
        # extra assumptions before an available creator guard is considered.
        candidates.sort(key=lambda v: (
            not (self.facts.constant(v) is not None or self._field(v, 'global', 'CreatorAddress')),
            str(v)))
        conditional = []
        for value in candidates:
            result = self._address(value, slots, active)
            if result.proved:
                return result
            if result.preserved:
                conditional.append(result)
        if conditional:
            return min(conditional, key=lambda result: (len(result.assumptions), repr(result)))
        return AddressAuthority(False, 'writer is not guarded by an established authority')


def _whole_program_paths(paths):
    if paths is not None and not paths.entry_seeds and not paths.bb_seeds:
        return paths
    return None


def authority_for(program, *, paths=None):
    cached = getattr(program, '_authority_analysis', None)
    if cached is None or cached.revision != program.revision:
        cached = AuthorityAnalysis(program, paths)
        program._authority_analysis = cached
    elif cached._paths is None and paths is not None:
        cached._paths = _whole_program_paths(paths)
    return cached
