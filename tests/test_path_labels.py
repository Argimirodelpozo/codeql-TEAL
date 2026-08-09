"""puya-sol full-path subroutine labels must not break the parse.

puya-sol emits the full source path as a subroutine label (``callsub
/home/dev/contracts/Token.sol.transfer``). The tree-sitter-teal grammar's label
token stops at the first ``/``, so the target truncated to ``/home``, the rest of
the path parsed as a run of bare ``/`` division opcodes, and the subroutine was
never resolved — 5 parse diagnostics and an EMPTY label set on well-formed TEAL.

Salvaged from the unmerged ``ssa-migration-wip-local-backup`` branch (commit
90bdc577) during the 2026-07-25 review, with a collision guard added.
"""
from __future__ import annotations

from tealql.tealtools.frontend.graph import _sanitize_path_labels
from tealql.tealtools.ssa import SSAProgram

_PATH_LABELS = """#pragma version 10
txn NumAppArgs
callsub /home/dev/contracts/Token.sol.transfer
return

/home/dev/contracts/Token.sol.transfer:
proto 1 1
frame_dig -1
int 1
+
retsub
"""


def _prog(tmp_path, src, name="prog.teal"):
    p = tmp_path / name
    p.write_text(src)
    return SSAProgram(str(p))


def test_path_label_program_parses_cleanly(tmp_path):
    prog = _prog(tmp_path, _PATH_LABELS)
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []


def test_path_label_subroutine_resolves(tmp_path):
    prog = _prog(tmp_path, _PATH_LABELS)
    labels = [c.rstrip(":").strip() for _, _, c in prog.labels]
    assert labels == ["_home_dev_contracts_Token_sol_transfer"]
    targets = [a.immediates.strip() for a in prog.assignments if a.op == "callsub"]
    assert targets == ["_home_dev_contracts_Token_sol_transfer"]
    # the callee's body is reachable, i.e. the sub really was wired up
    assert any(a.op == "frame_dig" for a in prog.assignments)


def test_rename_is_length_preserving():
    """Column spans on every node must stay valid, so the mangle is
    char-for-char: one ``/`` or ``.`` becomes exactly one ``_``."""
    out = _sanitize_path_labels(_PATH_LABELS)
    for before, after in zip(_PATH_LABELS.split("\n"), out.split("\n")):
        assert len(before) == len(after)


def test_ordinary_labels_are_untouched():
    src = "#pragma version 10\nmain:\nint 1\nb main\n"
    assert _sanitize_path_labels(src) == src


def test_division_opcode_is_not_mangled():
    """``/`` as an opcode sits on a line that is neither a label definition nor
    a label reference, so it must survive verbatim."""
    src = ("#pragma version 10\n"
           "a/b:\nint 6\nint 2\n/\nb a/b\n")
    out = _sanitize_path_labels(src)
    assert "a_b:" in out and "b a_b" in out
    assert "\n/\n" in out           # the divide op is still a bare `/`


def test_colliding_labels_are_left_alone():
    """``a/b`` and ``a.b`` both mangle to ``a_b``. Renaming them would MERGE two
    distinct blocks — far worse than the truncation this works around — so the
    colliding renames are dropped instead."""
    src = "#pragma version 10\na/b:\nint 1\nreturn\na.b:\nint 2\nreturn\n"
    assert _sanitize_path_labels(src) == src
