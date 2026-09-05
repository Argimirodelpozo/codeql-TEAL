"""Content-addressed corpus enumeration and explicit completion baselines.

Regenerate deliberately with python -m tests.corpus_manifest. Normal tests read
this manifest and fail if a fixture cannot be analyzed as expected.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / 'corpus_status.json'
FAMILIES = ROOT / 'corpus_families.json'
_ARITY_SKIP = frozenset({'frame_dig', 'frame_bury', 'callsub', 'retsub', 'proto',
                        'intcblock', 'bytecblock', 'return', 'err'})


def distinct_files(root: Path, *, recursive=False):
    seen = {}
    files = root.rglob('*.teal') if recursive else root.glob('*.teal')
    for path in sorted(files):
        seen.setdefault(hashlib.sha256(path.read_bytes()).hexdigest()[:16], path)
    return sorted(seen.items())


def representation_metrics(prog):
    from tealql.tealtools.ssa.relations import unresolved_call_results, shared_execution_blocks
    from tealql.tealtools.language.avm import op_arity
    examined = missing = 0
    for assignment in prog.assignments:
        if assignment.op in _ARITY_SKIP:
            continue
        inputs, _ = op_arity(assignment.op, assignment.immediates)
        if inputs > 0:
            examined += 1
            missing += len(assignment.inputs) < inputs
    return dict(unresolved=len(unresolved_call_results(prog)), missing=missing,
                shared=len(shared_execution_blocks(prog)), examined=examined)


def load_manifest():
    return json.loads(MANIFEST.read_text())


def family_profile(source):
    """A conservative syntax family: normalize literals and label spelling.

    The partition is for future evaluation discipline. These existing fixtures
    have already influenced development and are not an independent holdout.
    """
    from tealql.tealtools.ast.literals import tokenize_operands
    rows = [tokenize_operands(line) for line in source.splitlines()]
    labels = dict.fromkeys(words[0][:-1] for words in rows if words and words[0].endswith(':'))
    label_ids = {name: f'label{index}' for index, name in enumerate(labels)}
    normalized, opcodes = [], set()
    version = 1
    for words in rows:
        if not words:
            continue
        if words[:2] == ['#pragma', 'version']:
            version = int(words[2])
            continue
        if words[0].endswith(':'):
            # Label numbering must follow declaration order, independent of names.
            normalized.append([label_ids[words[0][:-1]] + ':'])
            words = words[1:]
        if not words:
            continue
        opcodes.add(words[0])
        if words[0] in {'int', 'byte', 'addr', 'method', 'pushint', 'pushbytes', 'intcblock', 'bytecblock'}:
            normalized.append([words[0], 'literal'])
        else:
            normalized.append([label_ids.get(word, word) for word in words])
    family = hashlib.sha256(json.dumps(normalized, separators=(',', ':')).encode()).hexdigest()[:16]
    return {'family': family, 'partition': 'reserved' if int(family, 16) % 5 == 0 else 'development',
            'version': version, 'calls': 'proto' if 'proto' in opcodes else 'legacy' if 'callsub' in opcodes else 'none',
            'frame': bool(opcodes & {'frame_dig', 'frame_bury'}),
            'scratch': bool(opcodes & {'load', 'loads', 'store', 'stores'}),
            'router': 'switch' if 'switch' in opcodes else 'match' if 'match' in opcodes else 'branch'}


def family_inventory():
    return {content_hash: {'path': str(path.relative_to(ROOT)), **family_profile(path.read_text())}
            for content_hash, path in distinct_files(ROOT / 'mainnet-random-probes')}


def parse_status(path):
    from tealql.tealtools.frontend.graph import load_graph
    try:
        graph = load_graph(str(path))
    except Exception as error:
        return {'error': f'{type(error).__name__}: {error}'}
    diagnostics = graph.graph.get('parse_diagnostics', ()) or ()
    return {'diagnostics': [str(d) for d in diagnostics]}


def main():
    from tealql.tealtools.ssa import SSAProgram
    parsed = {}
    for content_hash, path in distinct_files(ROOT, recursive=True):
        parsed[content_hash] = {'path': str(path.relative_to(ROOT)), **parse_status(path)}
        assert parsed[content_hash].get('diagnostics') == [], parsed[content_hash]
    represented = {}
    for content_hash, path in distinct_files(ROOT / 'mainnet-random-probes'):
        # Unexpected load failures abort regeneration too; never turn them into
        # a smaller metric or an accepted baseline automatically.
        program = SSAProgram(str(path), strict=False)
        represented[content_hash] = {'path': str(path.relative_to(ROOT)),
                                    **representation_metrics(program)}
    totals = {key: sum(row[key] for row in represented.values())
              for key in ('unresolved', 'missing', 'shared', 'examined')}
    print('Representation totals:', totals, flush=True)
    assert totals['unresolved'] <= 15 and totals['missing'] <= 22 and totals['shared'] <= 10
    assert totals['examined'] > 50_000
    print('Parse cases:', len(parsed), 'expected errors:', sum('error' in r for r in parsed.values()), flush=True)
    MANIFEST.write_text(json.dumps({'parse': parsed, 'representation': represented},
                                  sort_keys=True, indent=1) + '\n')
    FAMILIES.write_text(json.dumps(family_inventory(), sort_keys=True, indent=1) + '\n')


if __name__ == '__main__':
    main()
