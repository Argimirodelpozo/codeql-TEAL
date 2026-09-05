"""Pinned external inputs remain reproducible and evaluation errors stay visible."""
import json
import os
from pathlib import Path

import pytest

from tests.external_evaluation import ROOT, evaluate, manifest, novelty, verified_path


def test_external_manifest_pins_distinct_sources_and_first_run_evidence():
    data = manifest()
    rows = data['programs']
    assert len(rows) == len({row['sha256'] for row in rows}) == 6
    assert len(data['revision']) == 40
    for row in rows:
        assert len(row['sha256']) == 64 and Path(row['filename']).name == row['filename']
        assert '/' + data['revision'] + '/' + row['upstream_path'] == row['url'].split('/puya')[1]
    first = json.loads((ROOT / 'external_evaluation_first_attempt.json').read_text())
    completed = json.loads((ROOT / 'external_evaluation_results.json').read_text())
    # Only the evaluation adapter changed between these two recorded attempts.
    assert first['source_digest'] == completed['source_digest']
    assert set(first['programs']) == set(completed['programs']) == {row['filename'] for row in rows}
    assert all(profile['unseen_syntax_family'] for profile in first['profiles'].values())
    assert len({profile['family'] for profile in first['profiles'].values()}) == 6


def test_fixture_hash_mismatch_is_rejected_before_analysis(tmp_path):
    row = manifest()['programs'][0]
    (tmp_path / row['filename']).write_text('altered input')
    with pytest.raises(ValueError, match='hash mismatch'):
        verified_path(tmp_path, row)


def test_evaluation_distinguishes_detector_failure_from_optional_metadata(tmp_path, monkeypatch):
    from tealql.security import DETECTORS
    from tests import mainnet_ratchet
    class Empty:
        degraded = None
        def __init__(self, *_args, **_kwargs):
            pass
        def detect(self):
            return []
    class Failing(Empty):
        def detect(self):
            raise RuntimeError('test detector failure')
    monkeypatch.setitem(DETECTORS, 'test-empty', Empty)
    monkeypatch.setitem(DETECTORS, 'test-failure', Failing)
    monkeypatch.setattr(mainnet_ratchet, 'app_mode_detectors', lambda: ['test-empty', 'test-failure'])
    path = tmp_path / 'evaluation.teal'
    path.write_text('#pragma version 10\nint 1\nreturn\n')
    rows = evaluate(path, backend=False)['detectors']
    assert rows['test-empty'] == {'findings': '', 'degraded': []}
    assert rows['test-failure'] == {'error': 'RuntimeError: test detector failure'}


@pytest.mark.skipif(not os.environ.get('TEALQL_EXTERNAL_FIXTURES'), reason='requires explicitly fetched pinned external examples')
@pytest.mark.parametrize('row', manifest()['programs'], ids=lambda row: row['filename'])
def test_external_example_matches_reviewed_evaluation(row):
    directory = Path(os.environ['TEALQL_EXTERNAL_FIXTURES'])
    path = verified_path(directory, row)
    expected = json.loads((ROOT / 'external_evaluation_results.json').read_text())
    assert novelty(directory)[path.name] == expected['profiles'][path.name]
    assert evaluate(path) == expected['programs'][path.name]


@pytest.mark.skipif(os.environ.get('TEALQL_LOCALNET') != '1' or not os.environ.get('TEALQL_EXTERNAL_FIXTURES'),
                    reason='requires pinned examples and private node')
@pytest.mark.parametrize('row', manifest()['programs'], ids=lambda row: row['filename'])
def test_external_original_and_recompiled_programs_assemble(row):
    from tests.behavioral_lift.compare import _compile, PROTOCOL
    from tests.behavioral_lift.recompile import algod_client, lift_to_teal
    client = algod_client()
    assert client.status()['last-version'] == PROTOCOL
    path = verified_path(os.environ['TEALQL_EXTERNAL_FIXTURES'], row)
    assert _compile(client, path.read_text())
    assert _compile(client, lift_to_teal(str(path)))
