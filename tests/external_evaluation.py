"""Reproducible external evaluation with pinned downloads and retained unknowns.

Download only when explicitly requested with --fetch. Source stays in the given
directory; the repository records provenance and results, not upstream code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tests.corpus_manifest import ROOT, distinct_files, family_profile, parse_status, representation_metrics

MANIFEST = ROOT / 'external_evaluation_manifest.json'


def manifest():
    return json.loads(MANIFEST.read_text())


def verified_path(directory, row):
    path = Path(directory) / row['filename']
    if hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
        raise ValueError('external fixture hash mismatch: ' + row['filename'])
    return path


def fetch(directory):
    from urllib.request import urlopen
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    data = manifest()
    prefix = 'https://raw.githubusercontent.com/algorandfoundation/puya/' + data['revision'] + '/examples/'
    for row in data['programs']:
        if Path(row['filename']).name != row['filename'] or not row['url'].startswith(prefix):
            raise ValueError('external fixture is outside the pinned source')
        with urlopen(row['url'], timeout=30) as response:
            source = response.read()
        if hashlib.sha256(source).hexdigest() != row['sha256']:
            raise ValueError('download hash mismatch: ' + row['filename'])
        (directory / row['filename']).write_bytes(source)


def novelty(directory):
    previous = {family_profile(path.read_text())['family'] for _, path in distinct_files(ROOT, recursive=True)}
    rows = {}
    for row in manifest()['programs']:
        path = verified_path(directory, row)
        profile = family_profile(path.read_text())
        rows[path.name] = dict(profile, unseen_syntax_family=profile['family'] not in previous)
    return rows


def evaluate(path, *, backend=True):
    from tealql.security import DETECTORS
    from tealql.tealtools.diagnostics.health import health_for
    from tealql.tealtools.ssa import SSAProgram
    from tests.mainnet_ratchet import app_mode_detectors, encode_findings
    row = {'parse': parse_status(path)}
    try:
        prog = SSAProgram(str(path), strict=False)
        row['representation'] = representation_metrics(prog)
        row['health'] = health_for(prog, deep=True).to_dict()
    except Exception as error:
        row['load_error'] = f'{type(error).__name__}: {error}'
        return row
    detectors = {}
    for name in app_mode_detectors():
        try:
            detector = DETECTORS[name](prog, file=path.name)
            findings = list(detector.detect())
            detectors[name] = {'findings': encode_findings(findings),
                               'degraded': sorted(map(str, getattr(detector, 'degraded', ()) or ()))}
        except Exception as error:
            detectors[name] = {'error': f'{type(error).__name__}: {error}'}
    row['detectors'] = detectors
    if backend:
        from tealql.tealtools.lift.backend import lift_to_teal
        diagnostics = []
        try:
            code = lift_to_teal(str(path), diagnostics=diagnostics)
            row['backend'] = {'emitted': True, 'diagnostics': [str(d) for d in diagnostics],
                              'lines': len(code.splitlines())}
        except Exception as error:
            row['backend'] = {'emitted': False, 'diagnostics': [str(d) for d in diagnostics],
                              'error': f'{type(error).__name__}: {error}'}
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.fetch:
        fetch(args.directory)
    if args.output:
        profiles = novelty(args.directory)
        digest = hashlib.sha256()
        for path in sorted((ROOT.parent / 'src').rglob('*.py')):
            digest.update(str(path.relative_to(ROOT.parent)).encode() + b'\0' + path.read_bytes() + b'\0')
        results = {'source_digest': digest.hexdigest(), 'profiles': profiles, 'programs': {}}
        # Write incrementally; a later error cannot erase earlier attempted cases.
        for row in manifest()['programs']:
            path = verified_path(args.directory, row)
            results['programs'][path.name] = evaluate(path)
            args.output.write_text(json.dumps(results, sort_keys=True, indent=2) + '\n')
            print('Evaluated:', path.name, flush=True)


if __name__ == '__main__':
    main()
