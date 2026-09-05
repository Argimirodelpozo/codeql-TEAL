"""Corpus gates cannot become green by losing their inputs or failing to load."""
from tests.corpus_manifest import ROOT, distinct_files, load_manifest, parse_status


def test_manifest_accounts_for_every_distinct_program():
    manifest = load_manifest()
    for name, folder, recursive, floor in (
        ('parse', ROOT, True, 800),
        ('representation', ROOT / 'mainnet-random-probes', False, 200),
    ):
        files = distinct_files(folder, recursive=recursive)
        assert len(files) >= floor
        assert set(manifest[name]) == {h for h, _ in files}
        assert {h: str(p.relative_to(ROOT)) for h, p in files} == {
            h: row['path'] for h, row in manifest[name].items()}
    assert all(row.get('diagnostics') == [] for row in manifest['parse'].values())
    assert sum(row['examined'] for row in manifest['representation'].values()) > 50_000


def test_failed_load_is_a_failure_status(monkeypatch):
    from tealql.tealtools.frontend import graph
    def fail(_):
        raise ValueError('test loader failure')
    monkeypatch.setattr(graph, 'load_graph', fail)
    assert parse_status('unused.teal') == {'error': 'ValueError: test loader failure'}


def test_template_families_never_cross_evaluation_partitions():
    import json
    from tests.corpus_manifest import FAMILIES, family_inventory, family_profile
    inventory = family_inventory()
    assert inventory == json.loads(FAMILIES.read_text())
    families = {}
    for row in inventory.values():
        families.setdefault(row['family'], set()).add(row['partition'])
    assert all(len(partitions) == 1 for partitions in families.values())
    assert {r['partition'] for r in inventory.values()} == {'development', 'reserved'}
    a = family_profile('#pragma version 8\nbyte "literal//data"\nlog\nint 1\nreturn')
    b = family_profile('#pragma version 8\nbyte "different"\nlog\nint 2\nreturn')
    assert a['family'] == b['family']
