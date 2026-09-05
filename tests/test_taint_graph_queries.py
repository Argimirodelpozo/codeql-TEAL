"""Graph-query contracts checked against an exhaustive, independent oracle."""
import itertools

import networkx as nx
import pytest

from tealql.tealtools.dataflow.taint_graph import Node, TaintGraph
from tealql.tealtools.ssa import SSAProgram


def _graph(edges):
    graph = nx.DiGraph()
    graph.add_nodes_from(range(5))
    graph.add_edges_from(edges)
    return TaintGraph(graph, None)


def test_cap_selects_shortest_paths_before_truncating():
    graph = _graph([(0, 1), (1, 2), (2, 3), (3, 4), (0, 4)])
    assert graph.paths(0, 4, max_paths=1) == [[0, 4]]
    assert graph.paths_between([0], [3, 4], max_paths=1) == [[0, 4]]
    assert graph.paths_between([1, 0], [4], max_paths=1) == [[0, 4]]


@pytest.mark.parametrize('cap', [0, 1, 3, 100])
@pytest.mark.parametrize('cutoff', [None, -1, 0, 2, 5])
def test_simple_path_results_match_exhaustive_permutation_oracle(cap, cutoff):
    graph = _graph([(0, 1), (0, 2), (1, 2), (2, 1), (2, 3), (1, 4), (3, 4)])
    expected = []
    for length in range(2, 6):
        for path in itertools.permutations(range(5), length):
            if path[0] not in (0, 2) or path[-1] not in (3, 4):
                continue
            if cutoff is not None and length - 1 > cutoff:
                continue
            if all(graph.g.has_edge(a, b) for a, b in itertools.pairwise(path)):
                expected.append(list(path))
    actual = graph.paths_between([0, 2, 0, 99], [3, 4, 3, 99], max_paths=cap, max_length=cutoff)
    assert len(actual) == min(cap, len(expected))
    assert len({tuple(path) for path in actual}) == len(actual)
    assert all(path in expected for path in actual)
    assert list(map(len, actual)) == sorted(map(len, expected))[:cap]


def test_missing_disconnected_and_identity_paths():
    graph = _graph([(0, 1)])
    assert graph.paths(1, 4) == graph.paths(9, 1) == []
    assert graph.paths(1, 1, max_length=0) == [[1]]
    assert graph.paths(0, 1, max_paths=-1) == []
    assert graph.paths_between([], [1]) == []


def test_flow_channels_survive_refinement_and_share_constant_facts():
    prog = SSAProgram.from_text('#pragma version 10\ntxna ApplicationArgs 0\nstore 4\nload 4\nlog\nint 1\nreturn', name='query.teal')
    graph = TaintGraph.of(prog)
    source, = graph.find(op='txna', immediates='ApplicationArgs 0', file='query.teal', line=2)
    sink, = graph.find(op='log')
    assert graph.paths(source, sink)
    assert sink in graph.reachable_from_any([source, Node('absent', 99, 'missing')])
    assert source in graph.reachable_to_any([sink])
    assert graph.edges_by_kind()['scratch']
    assert list(graph.edges_with_kind('scratch'))
    identity = graph.identity_subgraph()
    graph.annotate(lambda _u, _v, _data: {'reviewed': True})
    assert all(data['reviewed'] for _, _, data in graph.edges())
    assert all('reviewed' not in data for _, _, data in identity.edges())
    before = len(identity.g.edges)
    graph.prune(lambda _u, _v, data: 'scratch' in data['kinds'])
    assert not list(graph.edges_with_kind('scratch'))
    assert len(identity.g.edges) == before
    absent = Node('absent', 99, 'missing')
    assert not graph.const_values_at(absent) and not graph.is_const_at(absent)
    assert not graph.is_unknown_scratch(absent)
