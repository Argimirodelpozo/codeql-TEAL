"""SSA / analysis from in-memory TEAL source -- no filesystem.

``graphs.load_graph`` accepts a ``{name: text}`` mapping, and
``SSAProgram.from_text`` wraps it -- so editor integrations, fuzzing, and tests
can run the whole pipeline without writing temp files.
"""
from tealtools.ssa import SSAProgram
from tealtools.graphs import load_graph
from tealtools.detections import DETECTORS

_TEAL = """#pragma version 10
    itxn_begin
    txn ApplicationArgs 0
    itxn_field Receiver
    int 1000
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def test_from_text_builds_ssa():
    prog = SSAProgram.from_text(_TEAL)
    assert prog.assignments
    assert {a.location.file for a in prog.assignments} == {"contract.teal"}


def test_from_text_custom_name():
    prog = SSAProgram.from_text(_TEAL, name="vault.teal")
    assert {a.location.file for a in prog.assignments} == {"vault.teal"}


def test_detector_runs_in_memory():
    prog = SSAProgram.from_text(_TEAL)
    findings = DETECTORS["tainted-fund-flow"](prog).detect()
    assert any("Receiver" in f.pretty() for f in findings)


def test_mapping_equivalent_to_file(tmp_path):
    p = tmp_path / "c.teal"
    p.write_text(_TEAL)
    from_file = SSAProgram(str(p))
    from_mem = SSAProgram.from_graph(load_graph({"c.teal": _TEAL}))
    assert len(from_file.assignments) == len(from_mem.assignments)
    assert len(from_file.blocks) == len(from_mem.blocks)


def test_load_graph_accepts_bytes_values():
    g = load_graph({"c.teal": _TEAL.encode("utf-8")})
    assert g.number_of_nodes() > 0
    assert g.graph["source"] == "<memory>"
