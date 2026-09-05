"""The visualization surface is complete, executable, and non-tautological."""
from __future__ import annotations

import inspect
from pathlib import Path
import shutil

import pytest

from tealql.cli.main import main
from tealql.tealtools._utils.dot import render as render_dot
from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.lift import transforms
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.viz import CATALOG, CATALOG_BY_KEY, ViewKind, dump_all, render_views
from tealql.tealtools.viz.coverage import MODULE_VIEW_COVERAGE, NON_PRODUCT_MODULES


SOURCE = {
    "approval.teal": """#pragma version 8
txna ApplicationArgs 0
len
int 4
>=
assert
int 7
itob
pop
int 0
store 1
load 1
bz done
itxn_begin
txn Sender
itxn_field Receiver
itxn_submit
done:
int 1
return
""",
}

TEALTOOLS_ROOT = Path(__file__).resolve().parents[1] / "src" / "tealql" / "tealtools"


def test_every_catalog_entry_makes_an_explicit_graph_decision():
    """A new view cannot silently become a text-only omission."""
    keys = [view.key for view in CATALOG]
    assert len(keys) == len(set(keys))
    assert CATALOG_BY_KEY == {view.key: view for view in CATALOG}
    for view in CATALOG:
        prefix = {
            ViewKind.REPRESENTATION: "repr.",
            ViewKind.ANALYSIS: "analysis.",
            ViewKind.PASS: "pass.",
        }[view.kind]
        assert view.key.startswith(prefix)
        assert view.description.strip()
        assert callable(view.text)
        assert (view.dot is None) != (view.graph_reason is None), view.key


def test_catalog_covers_fact_profiles_and_public_pass_entry_points():
    """Discoverable pass/fact APIs require a maintained catalog entry."""
    for domain in FactDomain:
        assert f"analysis.facts.{domain.value}" in CATALOG_BY_KEY
    for profile in ("canonical", "value", "guarded", "presentation"):
        assert f"repr.ssa.{profile}" in CATALOG_BY_KEY

    # Method names differ only where the architectural operation has a more
    # precise catalog name (inputs are aliases; range propagation is seeding).
    aliases = {
        "propagate_inputs": "input_aliases",
        "propagate_ranges": "range_seeds",
    }
    methods = {
        name for name, member in inspect.getmembers(SSAProgram, inspect.isfunction)
        if name.startswith("propagate_") or name == "cleanup_unused_ssavars"
    }
    for method in methods:
        pass_name = aliases.get(method, method.removeprefix("propagate_"))
        assert f"pass.ssa.{pass_name}" in CATALOG_BY_KEY, method
    assert "pass.ssa.run_all" in CATALOG_BY_KEY

    public_transforms = {
        name for name, member in inspect.getmembers(transforms, inspect.isfunction)
        if not name.startswith("_") and member.__module__ == transforms.__name__
    }
    for transform in public_transforms:
        assert f"pass.lift.{transform}" in CATALOG_BY_KEY, transform


def test_every_tealtools_module_has_a_visualization_decision():
    """A new representation/analysis module cannot bypass catalog review."""
    discovered = set()
    for path in TEALTOOLS_ROOT.rglob("*.py"):
        relative = path.relative_to(TEALTOOLS_ROOT)
        if path.name == "__init__.py" or relative.parts[0] in {"_utils", "viz"}:
            continue
        discovered.add(".".join(relative.with_suffix("").parts))

    classified = set(MODULE_VIEW_COVERAGE) | set(NON_PRODUCT_MODULES)
    assert not (set(MODULE_VIEW_COVERAGE) & set(NON_PRODUCT_MODULES))
    assert discovered == classified
    for module, keys in MODULE_VIEW_COVERAGE.items():
        assert keys, module
        for key in keys:
            assert key in CATALOG_BY_KEY, (module, key)
    assert all(reason.strip() for reason in NON_PRODUCT_MODULES.values())


def test_every_view_renders_annotated_text_and_every_applicable_graph():
    """Break any builder, annotation bridge, or DOT adapter and this goes red."""
    import importlib.util
    has_compiler = importlib.util.find_spec('puya') is not None
    compiler_views = {'repr.puya_ir', 'analysis.abi', 'analysis.storage'}
    rendered = render_views(SOURCE)
    assert len(rendered) == len(CATALOG)
    for view in rendered:
        if not has_compiler and view.spec.key in compiler_views:
            assert view.text_error == "ModuleNotFoundError: No module named 'puya'"
        else:
            assert view.text_error is None, (view.spec.key, view.text_error)
        assert view.text.strip(), view.spec.key
        if (view.spec.has_graph and not view.spec.requires_registry
                and not view.spec.requires_group):
            assert view.graph_error is None, (view.spec.key, view.graph_error)
            assert view.dot is not None and view.dot.lstrip().startswith("digraph ")
        elif view.spec.requires_registry or view.spec.requires_group:
            assert view.dot is None

    # Semantic pins, not merely "returned a string": immutable facts must be
    # inside the graph, PySSA must expose phis/ops, and pre-IR must expose real
    # block topology.
    facts = next(v for v in rendered if v.spec.key == "analysis.facts.byte-lengths")
    assert "len=8" in facts.text
    assert "len=8" in facts.dot
    pyssa = next(v for v in rendered if v.spec.key == "repr.pyssa")
    assert "construction SSA" in pyssa.dot and "itxn_field Receiver" in pyssa.dot
    pre_ir = next(v for v in rendered if v.spec.key == "repr.pre_ir")
    assert "block@" in pre_ir.text and " -> " in pre_ir.dot
    constant_pass = next(v for v in rendered if v.spec.key == "pass.ssa.constants")
    assert "changed at this boundary:" in constant_pass.text
    assert "isolated construction copy" in constant_pass.text
    range_pass = next(v for v in rendered if v.spec.key == "pass.ssa.range_seeds")
    assert constant_pass.dot != range_pass.dot


@pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz is optional")
def test_every_emitted_dot_graph_compiles():
    """Balanced braces are insufficient: Graphviz must accept every artifact."""
    for view in render_views(SOURCE):
        if view.dot is not None:
            assert bytes(render_dot(view.dot)).startswith(b"<?xml"), view.spec.key


def test_dump_selection_writes_stable_annotated_report_and_graph(tmp_path):
    text = dump_all(
        SOURCE,
        tmp_path,
        svg=False,
        views=["analysis.path_predicates", "pass.ssa.assert_ranges"],
    )
    assert "[analysis] analysis.path_predicates" in text
    assert "[pass] pass.ssa.assert_ranges" in text
    assert (tmp_path / "contract.txt").read_text() == text
    assert (tmp_path / "analysis-path_predicates.dot").is_file()
    assert (tmp_path / "pass-ssa-assert_ranges.dot").is_file()
    assert not (tmp_path / "repr-cfg.dot").exists()


def test_contextual_group_analysis_renders_when_ordered_members_are_supplied():
    members = [
        {"m0.teal": "#pragma version 8\ntxna ApplicationArgs 0\nstore 2\nint 1\nreturn\n"},
        {"m1.teal": "#pragma version 8\ngload 0 2\nlog\nint 1\nreturn\n"},
    ]
    (view,) = render_views(
        members[0],
        keys=["analysis.group_taint"],
        group_members=members,
    )
    assert view.text_error is None
    assert view.graph_error is None
    assert view.dot is not None
    assert "cross-member atomic-group taint" in view.dot
    assert "gload" in view.dot


def test_policy_views_render_conditional_evidence_and_numeric_results():
    source = {'policy.teal': '#pragma version 13\nbyte "owner"\napp_global_get\npop\n'
              'global CreatorAddress\npop\ntxn Fee\nint 4\n*\npop\nint 3\ncallsub increment\nreturn\n'
              'increment:\nproto 1 1\nframe_dig -1\nint 1\n+\nretsub'}
    views = {v.spec.key: v for v in render_views(source, keys=[
        'analysis.authority', 'analysis.congruences', 'analysis.numeric_calls'])}
    assert all(v.text_error is None for v in views.values())
    authority = views['analysis.authority'].text
    assert 'PROVED' in authority and 'CONDITIONAL' in authority and 'assumptions=' in authority
    assert 'modulus=4, residue=0' in views['analysis.congruences'].text
    calls = views['analysis.numeric_calls'].text
    assert 'slot=0' in calls and 'complete=True' in calls and 'residue=4' in calls


def test_resource_view_and_call_health_keep_missing_environment_visible():
    views = {v.spec.key: v for v in render_views(
        {'simple.teal': '#pragma version 13\nint 1\nreturn'},
        keys=['analysis.resource_bounds', 'analysis.xcontract_health'])}
    assert all(v.text_error is None for v in views.values())
    assert '"required": 4' in views['analysis.resource_bounds'].text
    assert '"available": null' in views['analysis.resource_bounds'].text
    assert '"status": "UNKNOWN"' in views['analysis.resource_bounds'].text
    assert 'UNKNOWN' in views['analysis.xcontract_health'].text
    unresolved = {'caller.teal': '#pragma version 13\nitxn_begin\nint appl\nitxn_field TypeEnum\n'
                  'int 7\nitxn_field ApplicationID\nitxn_submit\nint 1\nreturn'}
    view, = render_views(unresolved, keys=['analysis.xcontract_health'], registry={})
    assert view.text_error is None
    assert 'was not traversed' in view.text


def test_dump_cli_lists_and_selects_views(tmp_path, capsys):
    assert main(["dump", "--list-views"]) == 0
    listing = capsys.readouterr().out
    assert "repr.pyssa" in listing
    assert "analysis.byte_taint" in listing
    assert "pass.lift.prune_dead_phis" in listing

    source = tmp_path / "p.teal"
    source.write_text(SOURCE["approval.teal"])
    assert main(["dump", str(source), "--view", "analysis.health"]) == 0
    output = capsys.readouterr().out
    assert "analysis.health" in output
    assert "repr.cfg" not in output

    assert main(["dump", str(source), "--view", "analysis.nope"]) == 2
    assert "dump --list-views" in capsys.readouterr().err
