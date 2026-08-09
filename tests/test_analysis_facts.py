"""Query-scoped value facts do not mutate canonical SSA."""
from __future__ import annotations

import pytest

from tealql.tealtools.analysis import (
    DerivedProfile,
    FactDomain,
    derived_program,
)
from tealql.tealtools.ssa import SSAProgram


def _program(source: str) -> SSAProgram:
    return SSAProgram.from_text(source, strict=False)


def test_aliases_resolve_without_rewriting_consumer_inputs():
    prog = _program(
        "#pragma version 8\ntxn Fee\ntxn Fee\n==\nreturn\n"
    )
    comparison = next(a for a in prog.assignments if a.op == "==")
    original = tuple(comparison.inputs)
    facts = prog.facts(FactDomain.CONSTANTS)

    assert facts.resolve(original[0]) is facts.resolve(original[1])
    assert tuple(comparison.inputs) == original
    assert original[0] is not original[1]
    assert prog.revision == 0


def test_assert_refinement_is_scoped_to_the_dominated_use():
    prog = _program(
        "#pragma version 8\n"
        "txn OnCompletion\n"
        "dup\npop\n"
        "dup\nint 3\n<\nassert\n"
        "int 1\n+\nreturn\n"
    )
    source = next(a for a in prog.assignments if a.op == "txn").outputs[0]
    before = next(a for a in prog.assignments if a.op == "pop")
    after = next(a for a in prog.assignments if a.op == "+")
    facts = prog.facts(FactDomain.CONSTANTS, FactDomain.RANGES)

    assert (facts.int_range(source).lo, facts.int_range(source).hi) == (0, 5)
    assert (facts.range_at(source, before).lo, facts.range_at(source, before).hi) == (0, 5)
    assert (facts.range_at(source, after).lo, facts.range_at(source, after).hi) == (0, 2)
    # The value object itself never receives the guarded fact.
    assert source.range is None


def test_shift_ranges_use_canonical_avm_names():
    prog = _program("#pragma version 8\nint 1\nint 2\nshl\nreturn\n")
    output = next(a for a in prog.assignments if a.op == "shl").outputs[0]
    result = prog.facts(FactDomain.CONSTANTS, FactDomain.RANGES).int_range(output)
    assert result is not None and (result.lo, result.hi) == (4, 4)


def test_presentation_view_is_isolated_and_repeatable():
    prog = _program(
        "#pragma version 8\ntxn Fee\ntxn Fee\n==\npop\nint 1\nreturn\n"
    )
    before = prog.functional(resolve_consts=False, propagate_consts=False)
    revision = prog.revision
    first = derived_program(prog, DerivedProfile.PRESENTATION).functional()
    second = derived_program(prog, DerivedProfile.PRESENTATION).functional()
    assert first == second
    assert prog.functional(resolve_consts=False, propagate_consts=False) == before
    assert prog.revision == revision


def test_fact_cache_is_revision_scoped():
    prog = _program("#pragma version 8\nint 1\nreturn\n")
    first = prog.facts(FactDomain.CONSTANTS)
    assert prog.facts(FactDomain.CONSTANTS) is first
    prog.propagate_constants()
    assert prog.facts(FactDomain.CONSTANTS) is not first


def test_fact_superset_and_derived_views_are_reused():
    prog = _program("#pragma version 8\ntxn Fee\nint 1\n+\nreturn\n")
    broad = prog.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
    assert prog.facts(FactDomain.CONSTANTS) is broad

    first = derived_program(prog, DerivedProfile.GUARDED)
    assert derived_program(prog, DerivedProfile.GUARDED) is first
    # Facts on a normal form are copied directly; they do not recursively
    # reconstruct another SSA graph.
    assert first.facts(FactDomain.CONSTANTS).constant(
        next(a for a in first.assignments if a.op == "int").outputs[0]
    ) is not None


def test_cached_derived_view_rejects_supported_mutation_entry_points():
    prog = _program("#pragma version 8\nint 1\nreturn\n")
    view = derived_program(prog, DerivedProfile.GUARDED)

    with pytest.raises(RuntimeError, match="read-only"):
        view.propagate_constants()
