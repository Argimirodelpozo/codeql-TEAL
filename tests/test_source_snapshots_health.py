"""Immutable source identity and standardized analysis completeness."""
from __future__ import annotations

from tealql.security import DETECTORS
from tealql.tealtools.dataflow.engine import Sink, Source, TaintAnalysis
from tealql.tealtools.analysis import DerivedProfile, derived_program
from tealql.tealtools.lift import lift
from tealql.tealtools.lift.teal_const import _load_src
from tealql.tealtools.source_map import source_map_for
from tealql.tealtools.sources import ProgramSources
from tealql.tealtools.ssa import SSAProgram


def test_in_memory_program_has_no_fake_filesystem_path():
    prog = SSAProgram.from_text(
        "#pragma version 8\nint 1\nreturn\n", name="memory.teal"
    )
    assert prog.source_path is None
    assert prog.sources.names == ("memory.teal",)
    assert "exit 1u" in lift(prog).render()


def test_source_recovery_uses_construction_snapshot_after_file_edit(tmp_path):
    path = tmp_path / "p.teal"
    original = "#pragma version 8\n// original.py:10\nint 1\nreturn\n"
    path.write_text(original)
    prog = SSAProgram(str(path))
    digest = prog.sources.digest

    path.write_text("#pragma version 8\n// changed.py:99\nint 0\nreturn\n")

    assert prog.sources.digest == digest
    assert _load_src(prog)["p.teal"][1] == "// original.py:10"
    assert source_map_for(prog)[("p.teal", 3)] == ("original.py", 10)
    assert "exit 1u" in lift(prog).render()


def test_nested_duplicate_basenames_keep_exact_source_maps(tmp_path):
    for folder, src, line, value in (("a", "a.py", 11, 1), ("b", "b.py", 22, 0)):
        directory = tmp_path / folder
        directory.mkdir()
        (directory / "prog.teal").write_text(
            f"#pragma version 8\n// {src}:{line}\nint {value}\nreturn\n"
        )
    prog = SSAProgram(str(tmp_path))
    a = source_map_for(prog, file="a/prog.teal")
    b = source_map_for(prog, file="b/prog.teal")
    assert a[("a/prog.teal", 3)] == ("a.py", 11)
    assert b[("b/prog.teal", 3)] == ("b.py", 22)
    assert not ({file for file, _line in a} & {file for file, _line in b})
    projected = prog.for_file("a/prog.teal")
    assert projected.sources.names == ("a/prog.teal",)
    assert projected.source_path == tmp_path.resolve() / "a/prog.teal"

    # Source identity is construction-time metadata too, not a later fs probe.
    (tmp_path / "a/prog.teal").unlink()
    assert projected.sources.physical_path("a/prog.teal") == projected.source_path


def test_in_memory_path_aliases_cannot_silently_replace_a_program():
    """Mapping keys are source identities even when ``Path`` normalizes alike."""
    approve = b"#pragma version 8\nint 1\nreturn\n"
    reject = b"#pragma version 8\nint 0\nreturn\n"
    supplied = {"./approval.teal": approve, "approval.teal": reject}

    sources = ProgramSources.load(supplied)
    assert len(sources.files) == 2
    assert {file.raw for file in sources.files} == {approve, reject}
    assert len(set(sources.names)) == 2

    # Pin the consuming path too: retaining bytes only in snapshot metadata is
    # insufficient if parsing later collapses the reported file identities.
    prog = SSAProgram(supplied)
    returns = [assignment for assignment in prog.assignments
               if assignment.op == "return"]
    assert len(returns) == 2
    assert len({assignment.location.file for assignment in returns}) == 2


def test_assert_refined_in_memory_program_rebuilds_from_snapshot():
    src = """#pragma version 8
txna ApplicationArgs 0
btoi
dup
int 10
<
assert
int 20
<
assert
int 1
return
"""
    fresh = SSAProgram.from_text(src, name="fresh.teal")
    expected = [v.pretty() for v in DETECTORS["constant-condition"](fresh).detect()]
    refined = derived_program(
        SSAProgram.from_text(src, name="refined.teal"), DerivedProfile.GUARDED
    )
    actual = [v.pretty() for v in DETECTORS["constant-condition"](refined).detect()]
    # File labels differ; the semantic violation kinds/messages do not.
    assert [v.split(":", 1)[-1] for v in actual] == [v.split(":", 1)[-1] for v in expected]


def test_partial_analysis_result_cannot_masquerade_as_clean():
    prog = SSAProgram.from_text(
        "#pragma version 8\nint 1\nnot_a_real_opcode\nreturn\n",
        name="partial.teal",
        strict=False,
    )
    analysis = TaintAnalysis(
        prog,
        sources=[Source("none", lambda _a: False)],
        sinks=[Sink("none", lambda _a: False, lambda _a: 1)],
    ).analyze()
    assert analysis.value == []
    assert not analysis.complete
    assert {item.code for item in analysis.degradations} >= {"parse-diagnostic"}


def test_unknown_scratch_is_reported_in_deep_health():
    prog = SSAProgram.from_text(
        "#pragma version 8\nint 1\nstore 0\nload 0\npop\nint 1\nreturn\n",
        name="scratch.teal",
    )
    store = next(a for a in prog.assignments if a.op == "store")
    store.inputs = []  # emulate a value the reconstruction could not name
    prog._invalidate_value_relations()
    health = prog.health(deep=True)
    assert not health.complete
    assert "unknown-scratch-value" in {item.code for item in health.degradations}
