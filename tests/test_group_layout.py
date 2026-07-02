"""Tests for the group size + layout report
(``tealtools.group_reasoning.analyze_layout`` / GroupLayout).

Reuses the existing group_shape fixtures (no new DB). Skips cleanly if
the fixture DB isn't available.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/group_shape"


def _prog(case: str):
    db = FIX / case
    if not db.exists():
        pytest.skip(f"fixture DB not present: {db}")
    from tealtools.ssa import SSAProgram
    try:
        return SSAProgram(str(db))
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"could not build SSAProgram: {e}")


class TestForcedLayout:
    def test_render_groups_size_index_and_position(self):
        from tealtools.group_reasoning import analyze_layout
        text = analyze_layout(_prog("forced")).render()
        # Size + this-txn index surface as their own lines.
        assert "group size : == 2" in text
        assert "GroupIndex == 1" in text
        # gtxn[0]'s two requirements are grouped under one position header,
        # incl. the cross-ref flipped so the slot field reads on the left.
        assert "gtxn[0]:" in text
        assert "Receiver == Global.CurrentApplicationAddress" in text
        assert "TypeEnum == 1" in text

    def test_to_dict_structure(self):
        from tealtools.group_reasoning import analyze_layout
        d = analyze_layout(_prog("forced")).to_dict()
        assert d["group_size"] == ["== 2"]
        assert d["this_index"] == ["== 1"]
        assert "0" in d["positions"]
        assert any("Receiver" in s for s in d["positions"]["0"])
        assert any("TypeEnum == 1" == s for s in d["positions"]["0"])


class TestNoneLayout:
    def test_unconstrained_program(self):
        from tealtools.group_reasoning import analyze_layout
        text = analyze_layout(_prog("none")).render()
        assert "no group-shape constraints" in text


class TestCli:
    def test_cli_group_layout_json(self, capsys):
        import json
        from cli.main import main

        db = FIX / "forced"
        if not db.exists():
            pytest.skip("fixture DB not present")
        rc = main(["group-layout", str(db), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["group_size"] == ["== 2"]
        assert "0" in data["positions"]
