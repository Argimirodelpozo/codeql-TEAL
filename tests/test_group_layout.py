"""Tests for the group size + layout report
(``tealql.tealtools.cfg.group.analyze_layout`` / GroupLayout).

Reuses the existing group_shape fixtures (no new fixture). Skips cleanly if
the fixture isn't available.
"""
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "tealtools/group_shape"


def _prog(case: str):
    contract = FIX / case
    if not contract.exists():
        pytest.skip(f"fixture not present: {contract}")
    from tealql.tealtools.ssa import SSAProgram
    # A construction failure IS a test failure — never skip on it.
    return SSAProgram(str(contract))


class TestForcedLayout:
    def test_render_groups_size_index_and_position(self):
        from tealql.tealtools.cfg.group import analyze_layout
        text = analyze_layout(_prog("forced")).render()
        # Size + this-txn index surface as their own lines.
        assert "group size : == 2" in text
        assert "GroupIndex == 1" in text
        # gtxn[0]'s two requirements are grouped under one position header,
        # incl. the cross-ref flipped so the slot field reads on the left.
        assert "gtxn[0]:" in text
        assert "Receiver == Global.CurrentApplicationAddress" in text
        assert "TypeEnum == pay" in text   # enum-symbolised, matching the shape view

    def test_to_dict_structure(self):
        from tealql.tealtools.cfg.group import analyze_layout
        d = analyze_layout(_prog("forced")).to_dict()
        assert d["group_size"] == ["== 2"]
        assert d["this_index"] == ["== 1"]
        assert "0" in d["positions"]
        assert any("Receiver" in s for s in d["positions"]["0"])
        assert any("TypeEnum == pay" == s for s in d["positions"]["0"])


class TestNoneLayout:
    def test_unconstrained_program(self):
        from tealql.tealtools.cfg.group import analyze_layout
        text = analyze_layout(_prog("none")).render()
        assert "no group-shape constraints" in text


class TestCli:
    def test_cli_group_layout_json(self, capsys):
        import json
        from tealql.cli.main import main

        contract = FIX / "forced"
        if not contract.exists():
            pytest.skip("fixture not present")
        rc = main(["group-layout", str(contract), "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["group_size"] == ["== 2"]
        assert "0" in data["positions"]
