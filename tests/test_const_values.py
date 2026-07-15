"""Integer immediate resolution (`tealtools.const_values`).

`goal` / puya accept `0x` / `0o` / `0b` prefixed int literals (`int 0x10`), so the
extractor must resolve them — a decimal-only parse silently dropped every hex
constant, blinding downstream const propagation.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from tealql.tealtools.const_values import _resolve_int_immediate, _to_int
from tealql.tealtools.ssa import SSAProgram


class TestResolveInt:
    def test_decimal(self):
        assert _to_int("16") == 16
        assert _resolve_int_immediate("16") == 16

    def test_hex(self):
        assert _to_int("0x10") == 16
        assert _to_int("0xDEAD") == 0xDEAD
        assert _resolve_int_immediate("0x10") == 16

    def test_octal_and_binary(self):
        assert _to_int("0o17") == 15
        assert _to_int("0b1010") == 10

    def test_named_constant_still_resolves(self):
        assert _resolve_int_immediate("pay") == 1
        assert _resolve_int_immediate("DeleteApplication") == 5

    def test_garbage_is_none(self):
        assert _to_int("TMPL_X") is None
        assert _resolve_int_immediate("not_a_const") is None


def _const_of(src: str, op: str):
    d = tempfile.mkdtemp()
    Path(d, "p.teal").write_text(src)
    p = SSAProgram(d)
    p.propagate_constants()
    assert not getattr(p, "parse_diagnostics", ()), "hex int must not parse-error"
    a = [x for x in p.assignments if x.op == op][0]
    cv = a.outputs[0].const_value
    return int(cv.value) if cv is not None else None


def test_hex_int_folds_end_to_end():
    # The grammar's numeric_argument is decimal-only, so `int 0x10` parses as
    # `int 0` + a bogus label tail; the parser recovers it and const_values
    # resolves the full literal. Covers int / pushint / intcblock (label + ERROR
    # split shapes).
    assert _const_of("#pragma version 10\nint 0x10\npop\nint 1\nreturn\n", "int") == 16
    assert _const_of("#pragma version 10\npushint 0xFF\npop\nint 1\nreturn\n",
                     "pushint") == 255
    assert _const_of("#pragma version 10\nintcblock 0x10 5\nintc_0\npop\nint 1\nreturn\n",
                     "intc_0") == 16
    assert _const_of("#pragma version 10\nintcblock 0x10 5\nintc_1\npop\nint 1\nreturn\n",
                     "intc_1") == 5


def test_plain_int_followed_by_label_not_merged():
    # a real `int 0` then a separate label must NOT be swallowed by the recovery.
    assert _const_of(
        "#pragma version 10\nint 0\nbnz skip\nskip:\nint 1\nreturn\n", "int") == 0
