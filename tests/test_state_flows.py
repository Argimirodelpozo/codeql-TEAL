"""Tests for the app-state taint sources / out-of-state flow
(``tealql.tealtools.dataflow.state``).

Two layers:
  - pure (no CodeQL DB): the Source output-index conventions, which are
    the easy thing to get wrong (the ``_ex`` variants leave did_exist on
    top, so the *value* is the deeper output 2).
  - fixture-based: end-to-end seeding against a real program that reads
    app state; skipped if the fixture can't be built.
"""
import pytest

from tealql.tealtools.ssa import Assignment, Location, SSAProgram, SSAVar
from tealql.tealtools.dataflow.state import (
    APP_GLOBAL_GET_SOURCE,
    APP_GLOBAL_GET_EX_SOURCE,
    APP_LOCAL_GET_SOURCE,
    APP_LOCAL_GET_EX_SOURCE,
    DEFAULT_OUT_OF_STATE_SOURCES,
    detect_out_of_state_flows,
)
from tealql.tealtools.dataflow.engine import (
    ATTACKER_CONTROL_RULES, Sink, Source, TaintAnalysis,
)


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


class TestGenericEngineDependencies:
    """Direct data dependencies must survive the engine's block-by-default policy."""

    @staticmethod
    def _reaches_log(body: str) -> bool:
        prog = SSAProgram.from_text(
            f"#pragma version 8\n{body}\nlog\nint 1\nreturn\n",
            name="t.teal",
        )
        analysis = TaintAnalysis(
            prog,
            sources=[Source("arg", lambda a: a.op == "txna")],
            sinks=[Sink("log", lambda a: a.op == "log", lambda a: 1)],
            default_rules=ATTACKER_CONTROL_RULES,
        )
        return bool(analysis.detect())

    @pytest.mark.parametrize("derived", ("len\nitob", "btoi\nint 10\n<\nitob", "btoi\nbzero"))
    def test_metadata_boolean_and_length_derived_values_propagate(self, derived):
        assert self._reaches_log(f"txna ApplicationArgs 0\n{derived}")

    def test_tainted_select_condition_controls_clean_constant_result(self):
        # TOP-FIRST select inputs are condition, B, A. The attacker chooses
        # which otherwise-clean byte constant reaches the sink.
        assert self._reaches_log(
            "byte 0x00\nbyte 0x01\n"
            "txna ApplicationArgs 0\nbtoi\nselect"
        )


@pytest.fixture(scope="module")
def updatable_prog():
    """SSAProgram for a fixture that reads app state. Skips if the fixture
    isn't available in this environment."""
    from pathlib import Path
    from tealql.tealtools.ssa import SSAProgram

    contract = (Path(__file__).resolve().parent
          / "tealtools/sec_guide/is_updatable/gabe_vuln")
    if not contract.exists():
        pytest.skip(f"fixture not present: {contract}")
    # A construction failure IS a test failure — never skip on it.
    return SSAProgram(str(contract))


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
