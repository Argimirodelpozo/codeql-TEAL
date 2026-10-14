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
from ..ssa.producers import (is_current_sender_var, is_fixed_caller_app_pin,
                             is_group_signer_var)
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

    # --- state-value provenance (the lifted ``StateValue`` taint seed) -------

    #: Own-state reads whose VALUE output can carry a written value, with the
    #: top-first index of their key operand. ``box_len`` is absent: a length
    #: is not the stored value.
    STATE_READS = {
        'app_global_get': ('global', 0), 'app_global_get_ex': ('global', 0),
        'app_local_get': ('local', 0), 'app_local_get_ex': ('local', 0),
        'box_get': ('box', 0), 'box_extract': ('box', 2),
    }

    def read_slot(self, assignment):
        """``(file, storage, key_hex)`` of an OWN-state read with a constant key,
        else ``None`` (dynamic key, foreign app via ``*_get_ex``, not a read)."""
        spec = self.STATE_READS.get(getattr(assignment, 'op', None))
        if spec is None:
            return None
        storage, index = spec
        if assignment.op.endswith('_ex') and (
                len(assignment.inputs) < 2 or not self._current_app(assignment.inputs[1])):
            return None
        key = self._constant_key(assignment, index)
        return (assignment.location.file, storage, key) if key is not None else None

    def write_slot(self, assignment):
        """``(file, storage, key_hex | None)`` of an own-state writer (``None``
        key = dynamic, may alias any key of that storage), else ``None``."""
        effect = STATE_EFFECTS.get(getattr(assignment, 'op', None))
        if effect is None or effect.owner_index is not None:
            return None
        return (assignment.location.file, effect.storage,
                self._constant_key(assignment, effect.key_index))

    def writer_authority(self, writer, slot=None):
        """Whether ``writer`` preserves authority — creation-only, under a sender
        pin to a preserved address, or writing a fixed trusted value. ``slot``
        (the writer's own constant slot) makes rotation by the slot's current
        holder inductive, exactly as :meth:`_storage` does."""
        if self.program.revision != self.revision:
            raise RuntimeError('stale authority analysis: request it again after changing the program')
        self.visits = 0
        return self.record(self._writer(
            writer, frozenset({slot}) if slot is not None else frozenset(), frozenset()))

    def signer_principal(self, value, _active=frozenset()):
        """``value`` is SHAPED as a signing principal: ``global CreatorAddress``,
        the current application's ``AppCreator``, or own state whose every
        writer stores the CURRENT sender or the creator (a key captured from
        whoever signed). Structural only — callers ALSO require the address
        to preserve authority (:meth:`address` / ``_address`` with their own
        inductive context), so this never re-enters the storage walk.

        HAZARD: a sibling-signer pin (``gtxn K Sender == X``) authorises only
        when ``X`` signs with a key. The escrow pattern pins a sibling's sender
        to a stored LOGICSIG address (``gtxn 3 Sender == app_global_get "E"``)
        — that "signature" is the escrow program's own logic, which typically
        just requires this app call, so anyone can produce it. An address the
        admin merely CHOSE (``txna Accounts 1``) or a constant may be such an
        escrow; an address captured from ``txn Sender`` signed something."""
        if self.program.revision != self.revision:
            raise RuntimeError('stale authority analysis: request it again after changing the program')
        value = self.facts.constant(value) or self.facts.resolve(value)
        if self._field(value, 'global', 'CreatorAddress'):
            return True
        source = getattr(value, 'defined_by', None)
        if (source is not None and source.op == 'app_params_get'
                and source.immediates.strip() == 'AppCreator' and value.index == 2
                and len(source.inputs) == 1 and self._current_app(source.inputs[0])):
            return True
        if isinstance(value, Phi):
            if id(value) in _active or len(_active) > 64:
                return False
            return bool(value.args) and all(
                self.signer_principal(v, _active | {id(value)}) for v in value.args)
        slot = self._slot(value)
        if slot is None or not self._complete:
            return False
        file, storage, _ = slot
        if self._dynamic.get((file, storage)):
            return False
        writes = self._writes.get(slot, ())
        if not writes:
            return False
        for writer in writes:
            effect = STATE_EFFECTS[writer.op]
            if effect.value_index is None or effect.value_index >= len(writer.inputs):
                return False
            written = self.facts.constant(writer.inputs[effect.value_index]) or \
                self.facts.resolve(writer.inputs[effect.value_index])
            if not (is_current_sender_var(written)
                    or self._field(written, 'global', 'CreatorAddress')):
                return False
        return True

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
        if (source is not None and source.op == 'app_params_get'
                and source.immediates.strip() == 'AppAddress' and value.index == 2
                and len(source.inputs) == 1):
            # Only that application's program can sign for its account.
            app = self._app_id(source.inputs[0], slots, active | {id(value)})
            if app.preserved:
                proof = self._proof(value, 'account of an authority-preserved application',
                    ('the application named by the preserved id signs only under its '
                     'program, which preserves the authority invariant',))
                return AddressAuthority(True, proof.reason,
                                        tuple(dict.fromkeys((*proof.evidence, *app.evidence))))
            return self._unknown(value, 'application address of an unproved application id')
        if (source is not None and source.op == 'app_global_get_ex' and value.index == 2
                and len(source.inputs) >= 2 and not self._current_app(source.inputs[1])):
            key = self._constant_key(source, 0)
            app = self._app_id(source.inputs[1], slots, active | {id(value)})
            if key is not None and app.preserved:
                proof = self._proof(value, f'key {key} of an authority-preserved foreign application',
                    (f'foreign key {key} is governed by its application, which preserves '
                     'the authority invariant',))
                return AddressAuthority(True, proof.reason,
                                        tuple(dict.fromkeys((*proof.evidence, *app.evidence))))
            return self._unknown(value, 'foreign state of an unproved application id')
        slot = self._slot(value)
        if slot is None:
            return self._unknown(value, 'address provenance is unsupported, dynamic, or foreign')
        return self._storage(value, slot, slots, active)

    def _app_id(self, value, slots, active):
        """Preservation of an APPLICATION ID: a non-zero constant, the current
        application, a phi of preserved ids, or own state whose every writer is
        creation-only / authority-gated / writes a preserved id."""
        self.visits += 1
        if self.visits > 256:
            return AddressAuthority(False, 'authority dependency is cyclic or exceeds the work budget')
        value = self.facts.constant(value) or self.facts.resolve(value)
        if id(value) in active and self._slot(value) is None:
            return AddressAuthority(False, 'authority value dependency is cyclic')
        k = const_int(value)
        if k is not None:
            if k == 0:
                return AddressAuthority(False, 'application id 0 names the current application only by convention')
            return AddressAuthority(True, 'fixed application id in the program', (GuardEvidence(
                str(value), 'authority-controlled', basis='verified-obligation',
                assumptions=(f'application {k} preserves the authority invariant',)),))
        if isinstance(value, Const):
            return AddressAuthority(False, 'not an application id')
        if self._current_app(value):
            return self._proof(value, 'the current application')
        if isinstance(value, Phi) and value.args:
            parts = [self._app_id(v, slots, active | {id(value)}) for v in value.args]
            return AddressAuthority(all(p.preserved for p in parts), 'all phi arms must preserve authority',
                tuple(e for p in parts for e in p.evidence))
        slot = self._slot(value)
        if slot is None:
            return self._unknown(value, 'application id provenance is unsupported, dynamic, or foreign')
        return self._storage(value, slot, slots, active, value_eval=self._app_id)

    def _storage(self, value, slot, slots, active, value_eval=None):
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
            safe = self._writer(writer, slots | {slot}, active | {id(value)}, value_eval)
            if not safe.preserved:
                return self._unknown(value,
                    f'{storage} writer at {writer.location} has no proved authority restriction')
            evidence.extend(safe.evidence)
        proof = self._proof(value, f'{len(writes)} static and {len(dynamic)} dynamic writers preserve authority', assumptions)
        return AddressAuthority(True, proof.reason, tuple(dict.fromkeys((*proof.evidence, *evidence))))

    def _writer(self, writer, slots, active, value_eval=None):
        candidates = []
        written = []
        for predicate in self.paths.predicates_at(writer.location.file, writer.location.line):
            left = predicate.value
            if ((predicate.kind == 'zero' and self._field(left, 'txn', 'ApplicationID'))
                    or (predicate.kind == 'eq' and predicate.args
                        and self._field(left, 'txn', 'ApplicationID')
                        and const_int(self.facts.constant(predicate.args[0])) == 0)):
                return AddressAuthority(True, 'creator chooses state during application creation')
            if predicate.kind == 'eq' and predicate.args:
                right = predicate.args[0]
                l_res = self.facts.resolve(left)
                r_res = self.facts.constant(right) or self.facts.resolve(right)
                if is_fixed_caller_app_pin(l_res, r_res):
                    app = const_int(r_res) if const_int(r_res) is not None else const_int(l_res)
                    return self._proof(l_res, 'only the fixed caller application can write',
                        (f'application {app} (the pinned CallerApplicationID) '
                         'preserves the authority invariant',))
                # A trusted signer of ANY fixed-position group member approved
                # this call (signatures cover the group id): `gtxn 1 Sender ==
                # Creator` is a creator-signed write.
                # A SIBLING signer counts only against a signing principal
                # (see `signer_principal`): an escrow lsig "signs" by logic.
                r_var = self.facts.resolve(right)
                if is_current_sender_var(l_res):
                    candidates.append(right)
                elif is_current_sender_var(r_var):
                    candidates.append(left)
                elif is_group_signer_var(l_res) and self.signer_principal(right):
                    candidates.append(right)
                elif is_group_signer_var(r_var) and self.signer_principal(left):
                    candidates.append(left)
        effect = STATE_EFFECTS[writer.op]
        if effect.value_index is not None and effect.value_index < len(writer.inputs):
            # A fixed trusted replacement cannot give the caller a new
            # authority, even when the caller can trigger the replacement.
            if value_eval is None:
                candidates.append(writer.inputs[effect.value_index])
            else:
                written.append(writer.inputs[effect.value_index])
        # Prefer immutable roots before recursive state invariants. Predicate
        # set iteration order must not consume the work budget or introduce
        # extra assumptions before an available creator guard is considered.
        candidates.sort(key=lambda v: (
            not (self.facts.constant(v) is not None or self._field(v, 'global', 'CreatorAddress')),
            str(v)))
        conditional = []
        evaluated = [(v, self._address) for v in candidates] + [(v, value_eval) for v in written]
        for value, evaluate in evaluated:
            result = evaluate(value, slots, active)
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
