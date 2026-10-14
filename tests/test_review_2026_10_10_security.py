"""Pins for the 2026-10-10 security-layer review defects the ground-truth
benchmark cannot express (every verdict-level defect of that review is pinned
as a `tests/benchmark/<detector>/{vuln,safe}` fixture instead). One test per
DEFECT, controls folded in as further assertions in the same test.

The dominant class this round, again: a verdict read at a JOIN (the exit's
entry predicates are the INTERSECTION over incoming paths) where the question
was per-EDGE — the action guard, the selector scope — and a caller-blind
credit of a callee's verdict."""
from __future__ import annotations

from pathlib import Path

from tealql.security import DETECTORS
from tealql.tealtools.ssa import SSAProgram

_V = "#pragma version 8\n"


def _prog(tmp_path: Path, src: str, name: str = "t.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text(_V + src if not src.startswith("#pragma") else src)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return prog


def _findings(det: str, prog: SSAProgram) -> list:
    return DETECTORS[det](prog).detect()


# ---------------------------------------------------------------------------
# Output review §B12 — an ABSENCE detector needs an approving exit, and the
# group-sibling finding carries a structured anchor
# ---------------------------------------------------------------------------


def test_absence_finding_needs_an_approving_exit_and_sibling_finding_has_a_line(tmp_path):
    """``asset-close-to`` claims "all asset units can be drained" — on a
    program whose only exit is ``int 0; return`` nothing is ever approved, so
    the absent check protects nothing and is not a finding (it was, and made
    ``tealql all`` exit 1 on a reject-only program). Control: the same program
    approving stays flagged. And ``UnvalidatedGroupSiblingViolation`` carried
    only a ``location`` STRING, so SARIF rendered every one at line 1: it now
    exposes ``file``/``line`` from the offending read, mirroring ``location``."""
    reject_only = _prog(tmp_path, "int 0\nreturn\n", "r.teal")
    assert _findings("asset-close-to", reject_only) == []
    approves = _prog(tmp_path, "int 1\nreturn\n", "a.teal")
    assert len(_findings("asset-close-to", approves)) == 1

    sibling = _prog(tmp_path, (
        "gtxn 0 Amount\n"
        "pop\n"
        "int 1\n"
        "return\n"
    ), "s.teal")
    (v,) = _findings("unvalidated-group-sibling", sibling)
    assert v.file == "s.teal" and v.line == 2          # the `gtxn 0 Amount` read
    assert v.location == "s.teal:2"
    d = v.to_dict()
    assert (d["file"], d["line"]) == ("s.teal", 2)


# ---------------------------------------------------------------------------
# Review 7 — the selector scope is decided per EDGE, not at the exit's join
# ---------------------------------------------------------------------------


def test_abi_selector_scope_is_per_edge(tmp_path):
    """A shared epilogue reached from a MATCHED method arm and from the BARE
    (``NumAppArgs == 0``) create arm: at the join the entry predicates are the
    intersection — neither the selector pin nor the bare proof survives — yet
    every edge into it carries one, so the exit is out of scope. Control: the
    same router whose bare arm is dispatched WITHOUT the ``NumAppArgs`` test
    (any arg-carrying call reaches it) stays flagged at that shared exit."""
    shared = (
        "txn NumAppArgs\n"
        "bz bare\n"
        "txna ApplicationArgs 0\n"
        "method \"hello()void\"\n"
        "==\n"
        "bnz hello\n"
        "err\n"
        "hello:\n"
        "byte \"k\"\n"
        "app_global_get\n"
        "pop\n"
        "b done\n"
        "bare:\n"
        "txn Fee\n"      # NOT a create path: a create call is never
        "itob\n"         # method-dispatched (2026-10-10 precision pass),
        "log\n"          # so `ApplicationID == 0` would close the walk
        "done:\n"
        "int 1\n"
        "return\n"
    )
    assert _findings("abi-method-selector", _prog(tmp_path, shared, "ok.teal")) == []

    unchecked_bare = shared.replace("txn NumAppArgs\nbz bare\n",
                                    "txn OnCompletion\nbz bare\n")
    (v,) = _findings("abi-method-selector", _prog(tmp_path, unchecked_bare, "bad.teal"))
    assert v.line == 20                     # the shared `return` (after the pragma)
