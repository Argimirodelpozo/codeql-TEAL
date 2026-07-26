"""Gate: our decoded constants must equal the REAL assembler's.

See :mod:`tests.assembler_differential` for the method. In short: algod is the
reference implementation, so ``compile`` then ``disassemble`` gives ground truth
for what a program's constants ARE, and we compare our own decode against it.

This closes the one gap nothing else in the suite covered. Every other gate
answers "did we crash / drop / change shape"; the failure mode that actually hurt
was a SILENTLY WRONG VALUE — a ``b64(..)`` decoded to its own ASCII text, a
comment swallowed into a string constant, ``gaid``/``itxna`` losing the index
that says which transaction. None of those crash, raise a diagnostic, or move a
golden; a guard comparing against such a constant just never matches.

Network-gated (a reachable algod, ``TEAL_ALGOD_LOCAL``, default ``:4001``) and
sampled by default. ``ASSEMBLER_DIFF_CORPUS=1`` runs the whole corpus.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest

from assembler_differential import (  # noqa: E402
    algod_available, compare, constant_sets, run,
)

pytestmark = pytest.mark.skipif(
    not algod_available(),
    reason="needs a reachable algod (TEAL_ALGOD_LOCAL, default :4001)",
)

TESTS = Path(__file__).resolve().parent

#: Sampled by default so a normal run stays quick; the full sweep is opt-in,
#: mirroring LIFT_SEMANTICS_CORPUS.
_SAMPLE = 60


def _corpus() -> list:
    files = sorted(glob.glob(str(TESTS / "**" / "*.teal"), recursive=True))
    if os.environ.get("ASSEMBLER_DIFF_CORPUS"):
        return files
    return files[:: max(1, len(files) // _SAMPLE)]


def test_decoded_constants_match_the_assembler():
    """The gate itself."""
    res = run(_corpus())
    assert res.divergences == [], "\n".join(d.render() for d in res.divergences)
    # SILENCE IS NOT SUCCESS: zero divergences means nothing if nothing was
    # checked. A broken harness (every program failing to assemble, a network
    # fault swallowed) would otherwise read as a clean pass forever.
    assert res.checked >= 10, (
        f"only {res.checked} program(s) were actually compared "
        f"({res.skipped_unassemblable} were not assemblable) — the gate is vacuous"
    )


@pytest.mark.parametrize("source,expected_hex", [
    ('#pragma version 10\nbyte b64(SGVsbG8=)\npop\nint 1\nreturn\n', "48656c6c6f"),
    ('#pragma version 10\nbyte base64(SGVsbG8=)\npop\nint 1\nreturn\n', "48656c6c6f"),
    ('#pragma version 10\nbyte b32(NBSWY3DP)\npop\nint 1\nreturn\n', "68656c6c6f"),
    ('#pragma version 10\nbyte "Hello"\npop\nint 1\nreturn\n', "48656c6c6f"),
    ('#pragma version 10\npushbytes 0x48656c6c6f\npop\nint 1\nreturn\n', "48656c6c6f"),
])
def test_every_byte_literal_spelling_agrees_with_the_chain(source, expected_hex):
    """Five spellings of the same constant. The assembler is the arbiter, so
    this pins the decode against the chain rather than against our own opinion
    of what it should be."""
    assert compare(source, "t.teal") == []
    _, ours = constant_sets(source)
    assert expected_hex in ours


def test_a_comment_containing_quotes_does_not_enter_the_constant():
    """The grammar's string tokenizer ran past `//` when the comment held a
    quote, so the comment text became part of the constant."""
    src = ('#pragma version 10\npushbytes "asa_"   // [name, "asa_"]\n'
           "pop\nint 1\nreturn\n")
    assert compare(src, "t.teal") == []


def test_an_unassemblable_program_is_counted_not_passed():
    """An un-instantiated `TMPL_` template is not assemblable TEAL at all, so
    the assembler rejects it. That must be COUNTED as unchecked — reporting it
    as a pass would be the same silent-clean failure this gate exists to stop."""
    src = "#pragma version 10\npushint TMPL_DELETABLE\npop\nint 1\nreturn\n"
    assert compare(src, "t.teal") is None


def test_the_gate_catches_a_reintroduced_decode_bug(monkeypatch):
    """NON-VACUITY. Restore the pre-fix decoder (no `b64(..)` / `b32(..)`
    parenthesised forms) and confirm the differential fires — otherwise this
    whole file could pass while checking nothing real."""
    import tealql.tealtools.ast.literals as L

    def _pre_fix(v: str):
        v = v.strip()
        if v.startswith("0x"):
            return bytes.fromhex(v[2:]), "base16"
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            return L._teal_str_bytes(v[1:-1]), "utf8"
        if v.startswith(("b64 ", "base64 ")):
            return L._b64(v.split(None, 1)[1]), "base64"
        try:
            return bytes.fromhex(v), "base16"
        except ValueError:
            return v.encode("utf-8"), "utf8"      # <- the bug: b64(..) lands here

    src = '#pragma version 10\nbyte b64(SGVsbG8=)\npop\nint 1\nreturn\n'
    assert compare(src, "t.teal") == []           # clean as shipped
    monkeypatch.setattr(L, "decode_byte_literal", _pre_fix)
    found = compare(src, "t.teal")
    assert found, "the differential failed to catch a known decode bug"
    assert found[0].kind == "bytes"
