"""Extract mechanical metadata from a pinned go-algorand langspec directory.

Usage: python tools/generate_avm_spec.py /path/to/data/transactions/logic
The input must contain langspec_v1.json through langspec_v13.json from REVISION.
No network access or upstream code execution is performed by this generator.
"""
import argparse
import hashlib
import json
from pathlib import Path

REVISION = 'da5946a14568c0cbaa2c9daf4241882de12f3c16'
TARGET = Path(__file__).resolve().parents[1] / 'src/tealql/tealtools/language/op_specs.json'


def generate(root):
    variants = {}
    hashes = {}
    expected = json.loads(Path(__file__).with_name('avm_sources.sha256.json').read_text())
    for version in range(1, 14):
        path = root / f'langspec_v{version}.json'
        raw = path.read_bytes()
        hashes[path.name] = hashlib.sha256(raw).hexdigest()
        if hashes[path.name] != expected[path.name]:
            raise ValueError(f'{path.name} does not match the pinned revision')
        for op in json.loads(raw)['Ops']:
            record = {
                'args': op.get('Args', []), 'returns': op.get('Returns', []),
                'modes': op['Modes'], 'cost': op['DocCost'],
                'immediates': [[i['Name'], i['Encoding']] for i in op.get('ImmediateNote', [])],
                'fields': {f['Name']: [f.get('Type'), f.get('Version', 1),
                                      f.get('Modes', op['Modes']), f['ByteEncoding']]
                           for f in op.get('ArgDetails', [])},
            }
            previous = variants.setdefault(op['Name'], [])
            if previous and {k: v for k, v in previous[-1].items() if k != 'since'} == record:
                continue
            previous.append({'since': version, **record})
    doc = {'revision': REVISION, 'release': 'v5.0.0-stable', 'version': 13,
           'source_sha256': hashes, 'ops': variants}
    return json.dumps(doc, sort_keys=True, separators=(',', ':')) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.directory)
    if args.check:
        if TARGET.read_text() != generated:
            raise SystemExit('AVM metadata differs from pinned generator inputs')
    else:
        TARGET.write_text(generated)


if __name__ == '__main__':
    main()
