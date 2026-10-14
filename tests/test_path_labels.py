"""puya-sol full-path subroutine labels must not break the parse.

puya-sol emits the full source path as a subroutine label (``callsub
/home/dev/contracts/Token.sol.transfer``). The tree-sitter-teal grammar's label
token used to stop at the first ``/``, so the target truncated to ``/home``, the
rest of the path parsed as a run of bare ``/`` division opcodes, and the
subroutine was never resolved — 5 parse diagnostics and an EMPTY label set on
well-formed TEAL. tree-sitter-teal 0.2 accepts the path in both positions, so
the label keeps its real name (no mangling rename).

Salvaged from the unmerged ``ssa-migration-wip-local-backup`` branch (commit
90bdc577) during the 2026-07-25 review, with a collision guard added.
"""
from __future__ import annotations

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
    assert labels == ["/home/dev/contracts/Token.sol.transfer"]
    targets = [a.immediates.strip() for a in prog.assignments if a.op == "callsub"]
    assert targets == ["/home/dev/contracts/Token.sol.transfer"]
    # the callee's body is reachable, i.e. the sub really was wired up
    assert any(a.op == "frame_dig" for a in prog.assignments)


def test_division_opcode_next_to_a_path_label(tmp_path):
    """``/`` as an opcode and ``a/b`` as a label share a character; the label
    token needs a name character after the slash, so the bare divide survives."""
    prog = _prog(tmp_path, "#pragma version 10\nb a/b\na/b:\nint 6\nint 2\n/\nreturn\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert "/" in [a.op for a in prog.assignments]
    assert [c.rstrip(":") for _, _, c in prog.labels] == ["a/b"]


def test_labels_differing_only_in_separator_stay_distinct(tmp_path):
    """``a/b`` and ``a.b`` are two labels. A mangling rename mapped both to
    ``a_b`` and had to refuse; keeping the real names needs no such guard."""
    prog = _prog(tmp_path, "#pragma version 10\nint 1\nbnz a.b\nb a/b\n"
                           "a/b:\nint 1\nreturn\na.b:\nint 2\nreturn\n")
    assert list(getattr(prog, "parse_diagnostics", ()) or []) == []
    assert sorted(c.rstrip(":") for _, _, c in prog.labels) == ["a.b", "a/b"]
