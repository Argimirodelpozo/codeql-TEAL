"""SDK-free execution observations and explicit comparison completeness.

Dryrun exposes logs and global/local deltas, but not inner transaction or box
changes. Those programs require a richer execution fixture; missing effects
produce INCONCLUSIVE. Equality is limited to the executed input matrix.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

_PC = re.compile(r"(app=\d+, )?pc=\d+")


def _delta(rows):
    def value(row):
        v = row['value']
        action = v['action']
        return (row['key'], action, v.get('bytes', '') if action == 1
                else v.get('uint', 0) if action == 2 else None)
    return sorted(value(row) for row in (rows or ()))


@dataclass(frozen=True)
class Observation:
    approved: bool
    detail: str
    effects: str
    available: frozenset[str]


def observe_dryrun(response: dict) -> Observation:
    if response.get('error') or len(response.get('txns', ())) != 1:
        raise ValueError('dryrun did not return one transaction result')
    txn = response['txns'][0]
    messages = txn.get('app-call-messages') or ()
    if not messages or messages[-1] == '?':
        raise ValueError('dryrun did not report an application outcome')
    approved = messages[-1] == 'PASS'
    effects = {
        'logs': txn.get('logs') or [],
        'global': _delta(txn.get('global-delta')),
        'local': sorted((d['address'], _delta(d['delta']))
                        for d in (txn.get('local-deltas') or ())),
    }
    return Observation(approved, _PC.sub('@', messages[-1]),
                       json.dumps(effects if approved else {}, sort_keys=True),
                       frozenset({'logs', 'global', 'local'}))


def required_effects(*programs: str) -> frozenset[str]:
    """Conservative observable inventory, independent of lift rewrites."""
    from tealql.tealtools.language.avm import is_known_op, AVM_LANGSPEC_VERSION
    required = {'logs', 'global', 'local'}
    for program in programs:
        for line in program.splitlines():
            words = line.split('//', 1)[0].split()
            if not words:
                continue
            if words[0] == '#pragma':
                version = len(words) == 3 and words[1] == 'version' and words[2].isdigit() and 1 <= int(words[2]) <= AVM_LANGSPEC_VERSION
                typetrack = len(words) == 3 and words[1] == 'typetrack' and words[2] in {'true', 'false'}
                if not version and not typetrack:
                    required.add('unsupported-semantics')
                continue
            if words[0].endswith(':'):
                words = words[1:]
            if not words:
                continue
            op = words[0]
            if not is_known_op(op) and op not in {'byte', 'addr', 'method'}:
                required.add('unsupported-semantics')
            if op.startswith(('box_', 'app_box_')):
                required.add('boxes')
            if op.startswith('app_box_'):
                required.add('foreign-boxes')
            if op == 'itxn_submit':
                required.add('inner-transactions')
            if op in {'store', 'stores'}:
                required.add('exported-scratch')
            if op == 'app_params_set':
                required.add('app-parameters')
    return frozenset(required)


def observe_simulate(response):
    """One app transaction, including recursive inner effects and final scratch.

    AVM 13 foreign-box owner identity is not encoded in the state-change row;
    those programs require a ledger snapshot adapter and remain inconclusive.
    """
    groups = response.get('txn-groups', ())
    if 'version' not in response or len(groups) != 1 or len(groups[0].get('txn-results', ())) != 1:
        raise ValueError('simulation did not return one complete transaction result')
    group = groups[0]
    approved = not group.get('failure-message') and not group.get('failed-at')
    config = response.get('exec-trace-config') or {}
    available = {'logs', 'global', 'local', 'inner-transactions'}
    trace_complete = config.get('enable') and config.get('scratch-change') and config.get('state-change')
    states, scratch = {}, {}

    def transaction(result, trace, path):
        nonlocal trace_complete
        body = (result.get('txn') or {}).get('txn', {})
        if not body.get('type') or (not path and body['type'] != 'appl'):
            raise ValueError('simulation omitted the application transaction body')
        app = body.get('apid') or result.get('application-index')
        inners = result.get('inner-txns') or ()
        inner_traces = trace.get('inner-trace') or ()
        if body.get('type') == 'appl' and not ('approval-program-trace' in trace or 'clear-state-program-trace' in trace):
            trace_complete = False
        if trace.get('clear-state-rollback'):
            trace_complete = False
        slots = {}
        seen = set()
        inner_effects = [None] * len(inners)
        for step in trace.get('approval-program-trace', trace.get('clear-state-program-trace', ())):
            for change in step.get('state-changes', ()):
                key = (app, change['app-state-type'], change.get('account', ''), change['key'])
                if app is None or change['operation'] not in {'w', 'd'}:
                    trace_complete = False
                states[key] = change.get('new-value') if change['operation'] == 'w' else None
            for change in step.get('scratch-changes', ()):
                slots[change['slot']] = change['new-value']
            for index in step.get('spawned-inners', ()):
                if type(index) is not int or not 0 <= index < len(inners) or index in seen:
                    raise ValueError('invalid inner trace index')
                seen.add(index)
                inner_effects[index] = transaction(inners[index], inner_traces[index] if index < len(inner_traces) else {}, path + (index,))
        for index, inner in enumerate(inners):
            if index not in seen:
                trace_complete = False
                inner_effects[index] = transaction(inner, {}, path + (index,))
        # Unwritten slots contain uint64 zero; writing zero does not change the
        # exported scratch state. Paths keep distinct transaction scratch banks.
        scratch[str(path)] = sorted((slot, value) for slot, value in slots.items()
                                   if value.get('type') != 2 or value.get('uint', 0) != 0)
        return {'txn': body if path else None, 'logs': result.get('logs') or [],
                'global': _delta(result.get('global-state-delta')),
                'local': sorted((d['address'], _delta(d['delta'])) for d in result.get('local-state-delta', ())),
                'inner': inner_effects, 'created-app': result.get('application-index'),
                'created-asset': result.get('asset-index')}

    root = group['txn-results'][0]
    if 'txn-result' not in root:
        raise ValueError('simulation omitted transaction result')
    effects = transaction(root['txn-result'], root.get('exec-trace') or {}, ())
    if trace_complete:
        available.update(('boxes', 'exported-scratch'))
        effects['states'] = sorted((str(k), v) for k, v in states.items())
        effects['scratch'] = scratch
    return Observation(approved, _PC.sub('@', group.get('failure-message') or 'PASS'),
                       json.dumps(effects if approved else {}, sort_keys=True), frozenset(available))


def compare_cases(cases, execute, *, required: frozenset[str]) -> dict:
    """execute(case) returns original/lifted observations from identical state."""
    result = dict(match=0, mech=0, diverge=0, approve=0, attempted=0,
                  completed=0, errors=0, incomplete=0, diffs=[])
    for case in cases:
        result['attempted'] += 1
        try:
            original, lifted = execute(case)
        except Exception as error:
            result['errors'] += 1
            if len(result['diffs']) < 8:
                result['diffs'].append(f'execution error: {type(error).__name__}: {error}')
            continue
        result['completed'] += 1
        missing = required - (original.available & lifted.available)
        if missing:
            result['incomplete'] += 1
            if len(result['diffs']) < 8:
                result['diffs'].append('unobserved effects: ' + ', '.join(sorted(missing)))
        if original.approved != lifted.approved or (original.approved and original.effects != lifted.effects):
            result['diverge'] += 1
            if len(result['diffs']) < 8:
                result['diffs'].append(f'outcome/effect mismatch for input {case!r}')
        elif original.approved:
            result['approve'] += 1
            result['match'] += 1
        elif original.detail != lifted.detail:
            result['mech'] += 1
        else:
            result['match'] += 1
    result['required_effects'] = sorted(required)
    result['status'] = ('DIVERGES' if result['diverge'] else
                        'INCONCLUSIVE' if result['errors'] or result['incomplete']
                        or not result['approve'] else 'FAITHFUL')
    return result
