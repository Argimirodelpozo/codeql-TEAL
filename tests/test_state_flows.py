"""Tests for the app-state taint sources / out-of-state flow
(``tealtools.dataflow.state``).

Two layers:
  - pure (no CodeQL DB): the Source output-index conventions, which are
    the easy thing to get wrong (the ``_ex`` variants leave did_exist on
    top, so the *value* is the deeper output 2).
  - fixture-based: end-to-end seeding against a real program that reads
    app state; skipped if the fixture DB can't be built.
"""
import pytest

from tealtools.ssa import Assignment, Location, SSAVar
from tealtools.dataflow.state import (
    APP_GLOBAL_GET_SOURCE,
    APP_GLOBAL_GET_EX_SOURCE,
    APP_LOCAL_GET_SOURCE,
    APP_LOCAL_GET_EX_SOURCE,
    DEFAULT_OUT_OF_STATE_SOURCES,
    detect_out_of_state_flows,
)
from tealtools.dataflow.engine import Sink, TaintAnalysis


def _assign(op: str, n_out: int) -> Assignment:
    outs = [SSAVar("f.teal", 1, k) for k in range(1, n_out + 1)]
    return Assignment(
        outputs=outs, op=op, immediates="", inputs=[],
        location=Location("f.teal", 1), ast_code=op, const=None,
        basic_block=None,
    )


class TestSourceConventions:
    def test_plain_gets_taint_output_1(self):
        # app_global_get / app_local_get push only the value.
        assert APP_GLOBAL_GET_SOURCE.matches(_assign("app_global_get", 1))
        assert APP_GLOBAL_GET_SOURCE.tainted_outputs(_assign("app_global_get", 1)) == [1]
        assert APP_LOCAL_GET_SOURCE.tainted_outputs(_assign("app_local_get", 1)) == [1]

    def test_ex_gets_taint_output_2_the_value_not_did_exist(self):
        # _ex variants push [value, did_exist] -> did_exist on top (1),
        # value is the deeper output 2. Tainting 1 would track the
        # exists-flag instead of the data, a silent miss.
        assert APP_GLOBAL_GET_EX_SOURCE.tainted_outputs(_assign("app_global_get_ex", 2)) == [2]
        assert APP_LOCAL_GET_EX_SOURCE.tainted_outputs(_assign("app_local_get_ex", 2)) == [2]

    def test_sources_do_not_cross_match(self):
        assert not APP_GLOBAL_GET_SOURCE.matches(_assign("app_global_get_ex", 2))
        assert not APP_GLOBAL_GET_EX_SOURCE.matches(_assign("app_global_get", 1))
        assert not APP_GLOBAL_GET_SOURCE.matches(_assign("app_local_get", 1))


@pytest.fixture(scope="module")
def updatable_prog():
    """SSAProgram for a fixture that reads app state. Skips if the DB
    isn't available in this environment."""
    from pathlib import Path
    from tealtools.ssa import SSAProgram

    db = (Path(__file__).resolve().parent
          / "tealtools/sec_guide/is_updatable/gabe_vuln")
    if not db.exists():
        pytest.skip(f"fixture DB not present: {db}")
    try:
        return SSAProgram(str(db))
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")


class TestEndToEnd:
    def test_state_reads_are_seeded_tainted(self, updatable_prog):
        ta = TaintAnalysis(
            updatable_prog,
            sources=DEFAULT_OUT_OF_STATE_SOURCES,
            sinks=[Sink("none", lambda a: False, lambda a: 1)],
        )
        tainted = ta.tainted_operands()
        seeded = [
            v for v in tainted
            if isinstance(v, SSAVar) and v.defined_by is not None
            and v.defined_by.op in (
                "app_global_get", "app_local_get",
                "app_global_get_ex", "app_local_get_ex",
            )
        ]
        # The fixture has app_global_get_ex reads; their value outputs
        # must be seeded (proves source match + correct output index).
        assert seeded, "no app-state read value output was seeded as tainted"
        for v in seeded:
            assert v.index == (2 if v.defined_by.op.endswith("_ex") else 1)

    def test_detector_runs_and_returns_list(self, updatable_prog):
        # No payment/itxn sink reached from state on this fixture, so the
        # expected result is no violations (and notably no false positive).
        viols = detect_out_of_state_flows(updatable_prog)
        assert isinstance(viols, list)
        assert viols == []
