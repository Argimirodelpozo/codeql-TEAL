"""Pins for the small 2026-09-02 fix-pass leftovers (findings.md §7.3, §7.10).

One test per defect; the control (the accepted spelling) is asserted in the
same test so the boundary the fix draws is what is pinned."""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

from tealql.tealtools.ssa import SSAProgram, const_int


def _prog(tmp_path: Path, src: str, name: str = "t.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text("#pragma version 8\n" + src)
    prog = SSAProgram(str(p), strict=False)
    prog.propagate_constants()
    return prog


def test_unknown_named_int_is_a_diagnostic_not_a_phantom_push(tmp_path):
    """``int Foo`` is rejected by the assembler; recovering it as a const-free
    ``int`` minted an operand the program never has, with NO diagnostic.
    It must stay an excluded span (visible degradation). Control: the real
    named constant ``int pay`` still resolves to its value."""
    bad = _prog(tmp_path, "int Foo\nreturn\n", "bad.teal")
    assert bad.parse_diagnostics, "int Foo must be reported as unparsed"
    assert not [a for a in bad.assignments if a.op == "int"], \
        "no phantom `int` push for an unknown identifier"

    good = _prog(tmp_path, "int pay\nreturn\n", "good.teal")
    assert not good.parse_diagnostics
    ints = [a for a in good.assignments if a.op == "int"]
    assert len(ints) == 1 and const_int(ints[0].outputs[0]) == 1


def test_cli_health_check_surfaces_non_parse_degradations(tmp_path, caplog):
    """``multiple-constant-blocks`` (every ``intc_*`` left unresolved) was
    reachable through ``prog.health()`` only; the CLI's parse-health check
    must warn about it like it warns about unparsed spans. Control: a single
    block emits no such warning."""
    from tealql.cli._common import _check_parse_health

    two = _prog(tmp_path, "intcblock 1 2\nintcblock 3 4\nintc_0\nreturn\n", "two.teal")
    with caplog.at_level(logging.WARNING, logger="tealql"):
        _check_parse_health(two, SimpleNamespace(strict=False))
    assert any("multiple-constant-blocks" in r.getMessage() for r in caplog.records)

    caplog.clear()
    one = _prog(tmp_path, "intcblock 1 2\nintc_0\nreturn\n", "one.teal")
    with caplog.at_level(logging.WARNING, logger="tealql"):
        _check_parse_health(one, SimpleNamespace(strict=False))
    assert not any("multiple-constant-blocks" in r.getMessage() for r in caplog.records)
