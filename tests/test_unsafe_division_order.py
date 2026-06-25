"""sec-guide/unsafe-division-order: divide-before-multiply precision loss.

AVM integer division truncates, so ``(a / b) * c`` loses the remainder before
scaling — a systematic value leak in DeFi rate/share math. Def-use shape match: a
multiply whose operand is produced directly by a divide.
"""
from pathlib import Path

from tealtools.ssa import SSAProgram
from security import DETECTORS

_DET = DETECTORS["unsafe-division-order"]

_TAIL = """
    itxn_begin
    int pay
    itxn_field TypeEnum
    itxn_field Amount
    itxn_submit
    int 1
    return
"""


def _detect(expr: str, tmp_path: Path):
    p = tmp_path / "prog.teal"
    p.write_text("#pragma version 10\n" + expr + _TAIL)
    return _DET(SSAProgram(str(p), verbose=False)).detect()


def test_registered():
    assert "unsafe-division-order" in DETECTORS
    assert "app" in getattr(_DET, "applies_to", frozenset())


_DIV_THEN_MUL = """    txna ApplicationArgs 0
    btoi
    txna ApplicationArgs 1
    btoi
    /
    txna ApplicationArgs 2
    btoi
    *"""


def test_divide_before_multiply_flagged(tmp_path):
    vs = _detect(_DIV_THEN_MUL, tmp_path)
    assert len(vs) == 1
    assert vs[0].div.op == "/"
    assert vs[0].mul.op == "*"


_MUL_THEN_DIV = """    txna ApplicationArgs 0
    btoi
    txna ApplicationArgs 2
    btoi
    *
    txna ApplicationArgs 1
    btoi
    /"""


def test_multiply_before_divide_clean(tmp_path):
    assert _detect(_MUL_THEN_DIV, tmp_path) == []


_DIV_BY_ONE = """    txna ApplicationArgs 0
    btoi
    int 1
    /
    txna ApplicationArgs 2
    btoi
    *"""


def test_divide_by_one_clean(tmp_path):
    assert _detect(_DIV_BY_ONE, tmp_path) == []


_BYTEMATH = """    txna ApplicationArgs 0
    txna ApplicationArgs 1
    b/
    txna ApplicationArgs 2
    b*
    btoi"""


def test_bytemath_divide_before_multiply_flagged(tmp_path):
    vs = _detect(_BYTEMATH, tmp_path)
    assert len(vs) == 1
    assert vs[0].div.op == "b/"
    assert vs[0].mul.op == "b*"
