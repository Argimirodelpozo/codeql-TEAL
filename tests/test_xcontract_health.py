"""A missing cross-contract answer is observable even with zero findings."""
import json

import pytest

from helpers import make_xcontract
from tealql.cli.main import main
from tealql.security import DETECTORS
from tealql.security.xcontract import cross_detection_result
from tealql.tealtools.diagnostics.errors import TealQLError
from tealql.tealtools.intercontract.analysis import XContractGraph
from tealql.tealtools.intercontract.health import call_graph_health

CALLER = '''#pragma version 8
itxn_begin
int appl
itxn_field TypeEnum
int 555
itxn_field ApplicationID
itxn_submit
int 1
return
'''
CALLEE = '#pragma version 8\nint 1\nreturn\n'


@pytest.mark.parametrize('crash', [False, True])
def test_cross_detector_health_and_strict_mode_survive_empty_findings(tmp_path, monkeypatch, crash):
    class Detector:
        def __init__(self, program):
            self.degraded = 'authority history is unknown' if not crash else None

        def detect(self):
            if crash:
                raise ValueError('cannot analyze fixture')
            return []

    monkeypatch.setitem(DETECTORS, 'health-fixture', Detector)
    caller, registry = make_xcontract(tmp_path, CALLER, {555: CALLEE})
    graph = XContractGraph.build(caller, registry)
    result = cross_detection_result(graph, detector_names=['health-fixture'])
    assert result.value == [] and not result.complete
    note, = result.degradations
    assert note.code == ('detector-failed' if crash else 'detector-degraded')
    assert note.detector == 'health-fixture' and 'app555:' in note.message
    with pytest.raises(ValueError if crash else TealQLError):
        cross_detection_result(graph, detector_names=['health-fixture'], strict=True)


@pytest.mark.parametrize('target,depth,registered', [
    ('txna ApplicationArgs 0\nbtoi', 4, True),
    ('int 555', 0, True),
    ('int 555', 4, False),
])
def test_unresolved_missing_and_depth_limited_targets_are_incomplete(tmp_path, target, depth, registered):
    caller, registry = make_xcontract(tmp_path, CALLER.replace('int 555', target), {555: CALLEE})
    graph = XContractGraph.build(caller, registry if registered else {}, max_depth=depth)
    health = call_graph_health(graph)
    assert not health.complete
    note, = health.degradations
    assert note.code == 'unresolved-call' and note.line is not None


@pytest.mark.parametrize('json_output', [False, True])
def test_xcontract_cli_carries_incompleteness_without_detections(tmp_path, capsys, json_output):
    path = tmp_path / 'caller.teal'
    path.write_text(CALLER)
    registry = tmp_path / 'registry.yml'
    registry.write_text('{}\n')
    args = ['xcontract', str(path), '--registry', str(registry)]
    rc = main(args + (['--json'] if json_output else []))
    output = capsys.readouterr().out
    assert rc == 2
    if json_output:
        result = json.loads(output)
        assert not result['complete'] and result['notifications'][0]['kind'] == 'unresolved-call'
    else:
        assert 'INCOMPLETE' in output and '555' in output


def test_cached_audit_retains_detector_degradation(tmp_path, capsys, monkeypatch):
    class Detector:
        degraded = 'fixture requires missing state'

        def __init__(self, *args, **kwargs):
            pass

        def detect(self):
            return []

    monkeypatch.setitem(DETECTORS, 'rekey-to', Detector)
    (tmp_path / 'app_555.teal').write_text(CALLEE)
    assert main(['audit', '555', '--cache-dir', str(tmp_path), '--json']) == 2
    result = json.loads(capsys.readouterr().out)
    assert not result['complete']
    assert any(n['detector'] == 'rekey-to' for n in result['notifications'])
