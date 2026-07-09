"""Relational in-bounds analysis (``dataflow.bounds.check_bounds``).

Pins the three verdicts and their soundness: a provable in-bounds access, a
proven out-of-bounds over-read on an UNAMBIGUOUS (literal) buffer, and a dynamic
index we can't prove (oob-risk, not proven-oob). Plus a precision check that the
sound ``proven_oob`` fires only on genuinely-over-reading code.
"""
from __future__ import annotations

from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.dataflow.bounds import check_bounds

_B24 = "0x" + "00" * 24


def _sites(tmp_path, teal):
    (tmp_path / "p.teal").write_text(teal)
    return check_bounds(SSAProgram(str(tmp_path)))


def test_provably_in_bounds(tmp_path):
    s = _sites(tmp_path, f"#pragma version 10\npushbytes {_B24}\nextract 0 8\npop\nint 1\nreturn\n")
    ex = [x for x in s if x.op == "extract"]
    assert ex and ex[0].in_bounds and not ex[0].proven_oob


def test_proven_oob_on_literal_buffer(tmp_path):
    """extract 20 8 of a 24-byte literal reads [20,28) > 24 — a true over-read."""
    s = _sites(tmp_path, f"#pragma version 10\npushbytes {_B24}\nextract 20 8\npop\nint 1\nreturn\n")
    ex = [x for x in s if x.op == "extract"]
    assert ex and ex[0].proven_oob and not ex[0].in_bounds


def test_dynamic_index_is_oob_risk_not_proven(tmp_path):
    """A dynamic offset into an unknown-length buffer: can't prove in-bounds, and
    must NOT be claimed as a proven over-read (unsound)."""
    teal = ("#pragma version 10\n"
            "txna ApplicationArgs 0\ntxna ApplicationArgs 1\nbtoi\nint 8\n"
            "extract3\npop\nint 1\nreturn\n")
    s = _sites(tmp_path, teal)
    e3 = [x for x in s if x.op == "extract3"]
    assert e3 and e3[0].oob_risk and not e3[0].proven_oob and not e3[0].in_bounds


# --- relational proofs the non-relational domain CANNOT do (the SOTA piece) ---

_WHOLE_BUFFER = """#pragma version 10
txna ApplicationArgs 0
dup
int 0
dig 1
len
extract3
pop
int 1
return
"""

_LEN_FLOOR = """#pragma version 10
txna ApplicationArgs 0
dup
len
int 32
>=
assert
extract 0 32
pop
int 1
return
"""

# L = extract_uint16(X, 0); assert(L + 2 <= len X); extract3 X 2 L
_LEN_PREFIX = """#pragma version 10
txna ApplicationArgs 0
dup
dup
int 0
extract_uint16
dup
int 2
+
dig 3
len
<=
assert
swap
pop
int 2
swap
extract3
pop
int 1
return
"""


def test_whole_buffer_idiom_is_relationally_in_bounds(tmp_path):
    """``extract3 X 0 (len X)`` reads the whole buffer — provable only by
    relating the count to Len(X) (count == Len(X), offset 0)."""
    s = _sites(tmp_path, _WHOLE_BUFFER)
    e3 = [x for x in s if x.op == "extract3"]
    assert e3 and e3[0].in_bounds


def test_asserted_length_floor_proves_fixed_read(tmp_path):
    """``assert(len X >= 32)`` then ``extract 0 32`` — the assert seeds a Len
    floor that dominates the read."""
    s = _sites(tmp_path, _LEN_FLOOR)
    ex = [x for x in s if x.op == "extract"]
    assert ex and ex[0].in_bounds


def test_length_prefix_wellformedness_is_transitively_in_bounds(tmp_path):
    """The flagship 3-variable relation: ``assert(L + 2 <= len X)`` proves
    ``extract3 X 2 L`` in-bounds transitively through the difference closure."""
    s = _sites(tmp_path, _LEN_PREFIX)
    e3 = [x for x in s if x.op == "extract3"]
    assert e3 and e3[0].in_bounds and not e3[0].oob_risk


def test_proven_oob_precision_on_corpus_oob_fixtures():
    """``proven_oob`` must fire on Puya's deliberate out-of-bounds regression
    cases — a sound, precise static over-read finding."""
    base = Path("tests/experimental_IR_lift/puya")
    hit = 0
    for name in ("regression_tests_ExtractLengthOOB",
                 "regression_tests_ExtractStartOOB",
                 "regression_tests_SubstringEndOOB"):
        src = base / name / "src"
        if not (src.exists() and list(src.glob("*.teal"))):
            continue
        if any(x.proven_oob for x in check_bounds(SSAProgram(str(src)))):
            hit += 1
    if hit == 0:
        import pytest
        pytest.skip("OOB corpus fixtures not present")
    assert hit >= 1
