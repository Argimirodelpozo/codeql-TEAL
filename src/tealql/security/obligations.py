"""Experimental, explicitly scoped policy obligations over one TEAL program.

These checks are opt-in. Missing evidence is UNKNOWN, never a clean bill of
health. An obligation concerns a selected instruction on paths reaching it;
it does not establish reachability or a whole-contract invariant.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.analysis.relations import DifferenceConstraints, affine
from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.diagnostics.evidence import GuardEvidence
from tealql.tealtools.diagnostics.health import health_for, AnalysisDegradation, AnalysisHealth
from tealql.tealtools.language.effects import STATE_EFFECTS
from tealql.tealtools.language.spec import opcode_spec
from tealql.tealtools.ssa import Const, SSAVar


@dataclass(frozen=True)
class ObligationResult:
    kind: str
    subject: str
    status: str
    reason: str
    evidence: tuple[GuardEvidence, ...] = ()
    assumptions: tuple[str, ...] = ()

    def to_dict(self):
        return asdict(self)


class ObligationContext:
    def __init__(self, program):
        if len(program.source_files) != 1:
            raise ValueError('obligations require one source file')
        self.program = program
        self.file = next(iter(program.source_files))
        self.facts = program.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
        self.paths = PathPredicateAnalysis(program)
        self.health = health_for(program, deep=True)
        if any(a.op in {'b==', 'b!=', 'b<', 'b<=', 'b>', 'b>='} for a in program.assignments):
            self.health = AnalysisHealth(self.health.degradations + (AnalysisDegradation(
                'unsupported-byte-comparison', 'numeric byte comparisons require explicit width semantics'),))
        self.by_line = {a.location.line: a for a in program.assignments}

    def expression(self, value, active=frozenset()):
        """Exact field identities and evaluated arithmetic; state reads stay distinct."""
        value = self.facts.constant(value) or self.facts.resolve(value)
        if isinstance(value, Const):
            return int(value.value) if value.kind == 'int' else 'bytes:' + value.value
        if not isinstance(value, SSAVar) or id(value) in active or len(active) >= 64:
            return None
        assignment = value.defined_by
        if assignment is None:
            return None
        op, imm = assignment.op, str(assignment.immediates).strip()
        if op in {'txn', 'global', 'gtxn', 'txna', 'gtxna'}:
            return op + ' ' + imm
        if op in {'+', '-', '*'} and len(assignment.inputs) == 2:
            left, right = [self.expression(v, active | {id(value)}) for v in reversed(assignment.inputs)]
            return (op, left, right) if left is not None and right is not None else None
        # A value identity is safe for exact comparisons. Different reads of
        # mutable storage, phi arms and opaque computations are not equated.
        return f'value:{value.file}:{value.line}:{value.index}'

    def annotation(self, expression):
        if type(expression) is int:
            return expression
        if isinstance(expression, str):
            if expression.startswith('bytes:0x'):
                value = expression[8:]
                if len(value) % 2 or any(c not in '0123456789abcdefABCDEF' for c in value):
                    raise ValueError('byte annotations require an even-length hexadecimal value')
                return 'bytes:0x' + value.lower()
            words = expression.split()
            if words and words[0] in {'txn', 'global', 'gtxn', 'txna', 'gtxna'}:
                spec = opcode_spec(words[0])
                valid = len(words) == len(spec.immediates) + 1
                for (role, _), word in zip(spec.immediates, words[1:]):
                    valid &= (word in spec.fields if role == 'F' else
                              word.isascii() and word.isdecimal() and 0 <= int(word) < (16 if role == 'T' else 256))
                if valid:
                    return ' '.join(words)
                raise ValueError(f'invalid field annotation: {expression!r}')
        if isinstance(expression, list) and len(expression) == 3 and expression[0] in {'+', '-', '*'}:
            return (expression[0], self.annotation(expression[1]), self.annotation(expression[2]))
        if isinstance(expression, dict) and set(expression) <= {'line', 'output'} and 'line' in expression:
            if type(expression['line']) is not int or type(expression.get('output', 1)) is not int:
                raise ValueError('instruction annotations require integer line and output indices')
            assignment = self.by_line.get(expression['line'])
            index = expression.get('output', 1) - 1
            if assignment is None or not 0 <= index < len(assignment.outputs):
                return None
            return self.expression(assignment.outputs[index])
        raise ValueError(f'unsupported expression annotation: {expression!r}')

    def premises(self, line):
        for p in self.paths.predicates_at(self.file, line):
            left = self.expression(p.value)
            if p.kind in {'zero', 'nonzero'}:
                yield left, 'eq' if p.kind == 'zero' else 'neq', 0
            elif p.kind in {'eq', 'neq', 'le', 'lt', 'ge', 'gt'} and p.args:
                yield left, p.kind, self.expression(p.args[0])

    def proves(self, line, left, relation, right):
        if not self.health.complete or left is None or right is None:
            return False
        premises = list(self.premises(line))
        solver = DifferenceConstraints(premises)
        if not solver.consistent or solver.truncated:
            return False
        if relation == 'neq':
            return ((left, 'neq', right) in premises or (right, 'neq', left) in premises
                    or solver.proves(left, 'lt', right) or solver.proves(left, 'gt', right))
        return solver.proves(left, relation, right)

    def result(self, kind, subject, line, ok, reason, assumptions=()):
        status = 'PROVED' if ok and self.health.complete and (line in self.by_line or kind == 'authority') else 'UNKNOWN'
        evidence = self.paths.evidence_at(self.file, line) if status == 'PROVED' else ()
        return ObligationResult(kind, subject, status, reason, evidence, tuple(assumptions))


def authority_provenance(context, keys, *, initial_keys=()):
    """Constant global-key writers, with an explicit trusted initial-state premise.

    Creator-only writers establish preservation; an unguarded or dynamic-key
    writer prevents that conclusion. Deletion counts as a writer too. This
    first fragment does not infer trusted initialization or authority cycles.
    """
    out = []
    writes = [a for a in context.program.assignments if a.op in {'app_global_put', 'app_global_del'}]
    for key in keys:
        normalized = 'bytes:0x' + key.encode().hex()
        matching, dynamic = [], False
        for assignment in writes:
            role = STATE_EFFECTS[assignment.op].key_index
            value = context.expression(assignment.inputs[role]) if len(assignment.inputs) > role else None
            if value is None or not isinstance(value, str) or not value.startswith('bytes:'):
                dynamic = True
            elif value == normalized:
                matching.append(assignment)
        guarded = all(context.proves(a.location.line, 'txn Sender', 'eq', 'global CreatorAddress')
                      for a in matching)
        ok = key in initial_keys and not dynamic and guarded
        assumptions = (f'initial global key {key!r} contains the intended authority',
                       'all code that can write this global state is included; upgrades preserve this contract')
        out.append(context.result('authority', key, matching[0].location.line if matching else 1,
                   ok, f'{len(matching)} static writers; dynamic-key alias={dynamic}; creator-guarded={guarded}',
                   assumptions))
    return out


def group_obligation(context, policy):
    """Conjunction of relational field obligations for a bounded group template."""
    line, size = policy['line'], policy['size']
    roles, relations = policy['members'], policy['relations']
    if not 1 <= size <= 16 or set(roles) != {str(i) for i in range(size)} or not relations:
        raise ValueError('group policy must describe every member and at least one relation')
    checks = [('global GroupSize', 'eq', size)]
    for index, fields in roles.items():
        if not fields or 'TypeEnum' not in fields:
            raise ValueError('each group member needs TypeEnum and its intended field bindings')
        checks.extend((context.annotation(f'gtxn {index} {field}'), 'eq', context.annotation(value))
                      for field, value in fields.items())
    checks.extend((context.annotation(a), relation, context.annotation(b)) for a, relation, b in relations)
    ok = line in context.by_line and all(context.proves(line, *check) for check in checks)
    return context.result('group', str(line), line, ok, f'{len(checks)} required field/amount relations',
                          ('the supplied template lists all application-specific obligations',))


def crypto_binding(context, policy):
    """Exact fields through concat/itob/hash, plus an asserted verification result.

    No substring, length-dependent encoding, or mere data dependency establishes
    binding. The policy declares fixed widths and cryptographic/replay assumptions.
    """
    verify = context.by_line.get(policy['verify_line'])
    line = policy['line']
    fields = policy['fields']
    leaves = []

    def flatten(value, active=frozenset()):
        value = context.facts.resolve(value)
        if id(value) in active or len(active) >= 64:
            return False
        assignment = getattr(value, 'defined_by', None)
        if assignment and assignment.op in {'sha256', 'sha512_256', 'keccak256', 'concat'}:
            return all(flatten(v, active | {id(value)}) for v in reversed(assignment.inputs))
        # itob is fixed-width and injective over uint64.
        expression = context.expression(value)
        width = 8 if assignment and assignment.op == 'itob' else None
        if width:
            expression = context.expression(assignment.inputs[0])
        else:
            fact = context.facts.constant(value)
            if fact is not None and fact.kind != 'int':
                width = len(fact.value.removeprefix('0x')) // 2
            elif expression in {'txn Sender', 'global CreatorAddress', 'global CurrentApplicationAddress'}:
                width = 32
        leaves.append((expression, width))
        return expression is not None and width is not None

    ok = bool(fields and policy.get('domain') and policy.get('assumptions') and policy.get('public_key'))
    if verify is None or verify.op not in {'ed25519verify', 'ed25519verify_bare'} or len(verify.inputs) != 3 or len(verify.outputs) != 1:
        ok = False
    else:
        ok &= context.proves(line, context.expression(verify.outputs[0]), 'neq', 0)
        ok &= bool(policy.get('public_key')) and context.proves(line,
            context.expression(verify.inputs[0]), 'eq', context.annotation(policy['public_key']))
        ok &= flatten(verify.inputs[2])
        expected = [(context.annotation(row['value']), row['width']) for row in fields]
        ok &= leaves == expected and context.annotation(policy.get('domain')) in [v for v, _ in leaves]
    return context.result('crypto-binding', str(policy['verify_line']), line, ok,
                          'exact ordered fixed-width preimage fields and accepted verification',
                          policy.get('assumptions', ()))


def lifecycle_obligation(context, policy):
    """Bind an upgrade to exact proposal reads and an elapsed proposal delay."""
    line, delay = policy['line'], policy['delay']
    if type(delay) is not int or delay < 0:
        raise ValueError('upgrade delay must be a nonnegative integer')
    reads = [context.by_line.get(policy[name]) for name in ('proposal_line', 'proposed_at_line')]
    static = all(a and a.op == 'app_global_get' and a.inputs
                 and isinstance(context.facts.constant(a.inputs[0]), Const) for a in reads)
    ok = False
    if static:
        proposal, proposed_at = (context.expression(a.outputs[0]) for a in reads)
        ok = all(context.proves(line, *relation) for relation in (
            ('txn OnCompletion', 'eq', 4),
            ('txn ApprovalProgram', 'eq', proposal),
            ('global LatestTimestamp', 'ge', ('+', proposed_at, delay)),
            ('txn Sender', 'eq', context.annotation(policy['authority'])),
        ))
    return context.result('lifecycle', str(line), line, ok,
        'upgrade action, proposal identity, elapsed delay, and sender authorization',
        ('proposal/time writes form an atomic trusted pair; clear program policy is external',))


def conservation_obligation(context, policy):
    """Prove a supplied linear identity; enumerate each uint64 division's loss."""
    line = policy['line']
    left, right = context.annotation(policy['left']), context.annotation(policy['right'])
    if not policy.get('unit'):
        raise ValueError('conservation policy must name the unit')
    difference = affine(('-', left, right))
    ok = difference == ({}, 0) or context.proves(line, left, 'eq', right)
    result = context.result('conservation', policy['unit'], line, ok,
                            'mathematical linear identity on successful evaluated operations',
                            ('units and the intended conservation equation are supplied by the user',))
    rounding = []
    for assignment in context.program.assignments:
        if assignment.op != '/' or len(assignment.inputs) != 2:
            continue
        divisor, dividend = assignment.inputs
        d = context.facts.range_at(divisor, assignment)
        n = context.facts.range_at(dividend, assignment)
        exact = bool(d and n and d.lo == d.hi and d.lo > 0 and
                     (d.lo == 1 or n.lo == n.hi and n.lo % d.lo == 0))
        rounding.append(context.result('rounding', str(assignment.location.line), assignment.location.line,
            exact, 'exact integer division' if exact else 'floor division; remainder lies in [0, divisor - 1] when divisor > 0',
            ('beneficiary and unit interpretation require application policy',)))
    return [result, *rounding]


def analyze_obligations(program, policy):
    allowed = {'authority', 'initial_authorities', 'groups', 'crypto', 'lifecycle', 'conservation'}
    if not isinstance(policy, dict) or set(policy) - allowed:
        raise ValueError('unknown obligation policy fields')
    context = ObligationContext(program)
    results = authority_provenance(context, policy.get('authority', ()),
                                   initial_keys=policy.get('initial_authorities', ()))
    for name, run in (('groups', group_obligation), ('crypto', crypto_binding),
                      ('lifecycle', lifecycle_obligation)):
        results.extend(run(context, row) for row in policy.get(name, ()))
    for row in policy.get('conservation', ()):
        results.extend(conservation_obligation(context, row))
    return {'schema': 1, 'experimental': True, 'file': context.file,
            'complete': bool(results) and context.health.complete and all(r.status != 'UNKNOWN' for r in results),
            'notifications': context.health.to_dict()['notifications'],
            'obligations': [r.to_dict() for r in results]}


def render_obligations(report):
    return json.dumps(report, sort_keys=True, indent=2)
