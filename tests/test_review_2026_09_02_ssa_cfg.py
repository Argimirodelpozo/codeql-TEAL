"""Pins for the 2026-09-02 audit's SSA/CFG substrate defects. One test per
defect, controls folded in (findings.md 1.2, 1.3, 1.10, 3.1, 3.6)."""
from __future__ import annotations

import pytest

from tealql.tealtools.ssa import SSAProgram


def _prog(tmp_path, src: str, name: str = "t.teal") -> SSAProgram:
    p = tmp_path / name
    p.write_text(src)
    prog = SSAProgram(str(p), strict=False)
    prog.propagate_constants()
    return prog


def _exit_lines(prog, classify) -> set[int]:
    return {bb.last_line for bb in prog.blocks.values() if classify(bb)}


# --- 1.2: off-end exits -----------------------------------------------------

_OC_UPDATE = "txn OnCompletion\nint UpdateApplication\n==\n"


def test_off_end_exits_classified_as_approval_or_rejection(tmp_path):
    """The AVM terminates at ``pc == len(program)`` with the stack top as its
    verdict. Three spellings never reached ``is_approval_exit``: v1 fall-off,
    a branch to a label at EOF, and ``callsub`` as the last instruction (its
    ``retsub`` resumes at EOF). Controls: the same programs with an explicit
    ``return`` (same exit set, shifted to the ``return`` line), an ``int 0``
    off-end twin (rejection, not approval), and ``retsub`` staying no exit."""
    from tealql.tealtools.cfg.cfg import CFG
    from tealql.tealtools.cfg.exits import is_approval_exit, is_rejection_exit
    from tealql.security._program_shape import approving_exits

    # (a) v1 fall-off: the `==` result IS the verdict.
    v1 = _prog(tmp_path, "#pragma version 2\n" + _OC_UPDATE, "v1.teal")
    assert _exit_lines(v1, is_approval_exit) == {4}
    assert _exit_lines(v1, is_rejection_exit) == set()
    assert [bb.last_line for bb in approving_exits(v1)] == [4]

    # (b) branch to a label at EOF — the block has OTHER successors, so only
    # the construction flag can name it.
    bnz = ("#pragma version 10\nint 1\n" + _OC_UPDATE +
           "bnz end\nint 0\nreturn\nend:\n")
    p = _prog(tmp_path, bnz, "bnz.teal")
    assert _exit_lines(p, is_approval_exit) == {6}
    assert _exit_lines(p, is_rejection_exit) == {8}
    assert {bb.last_line for bb in CFG.of(p).exits} == {6, 8}
    ctrl = _prog(tmp_path, bnz + "return\n", "bnz_ctrl.teal")
    assert _exit_lines(ctrl, is_approval_exit) == {10}
    assert _exit_lines(ctrl, is_rejection_exit) == {8}
    # `int 0` off-end twin: provably zero on top → rejection, not approval.
    zero = _prog(tmp_path, bnz.replace("int 1\n", "int 0\n", 1), "bnz0.teal")
    assert _exit_lines(zero, is_approval_exit) == set()
    assert _exit_lines(zero, is_rejection_exit) == {6, 8}

    # (c) callsub as the last instruction: retsub returns to pc == len.
    cs = ("#pragma version 10\nb main\napprove:\nint 1\nretsub\nreject:\nerr\n"
          "main:\n" + _OC_UPDATE + "bz reject\ncallsub approve\n")
    p = _prog(tmp_path, cs, "cs.teal")
    assert p.off_end_exits == {("cs.teal", 13, 13)}
    assert _exit_lines(p, is_approval_exit) == {13}
    assert _exit_lines(p, is_rejection_exit) == {7}
    # `retsub` is NEVER an exit — the successor-less retsub block stays out.
    retsub_bb = next(bb for bb in p.blocks.values()
                     if bb.assignments[-1].op == "retsub")
    assert not retsub_bb.successors
    assert not is_approval_exit(retsub_bb) and not is_rejection_exit(retsub_bb)
    ctrl = _prog(tmp_path, cs + "return\n", "cs_ctrl.teal")
    assert ctrl.off_end_exits == set()
    assert _exit_lines(ctrl, is_approval_exit) == {14}

    # Detector-level: every variant is an unguarded UpdateApplication approval.
    from tealql.security import DETECTORS
    for name, src in (("v1d.teal", "#pragma version 2\n" + _OC_UPDATE),
                      ("bnzd.teal", bnz), ("csd.teal", cs)):
        prog = _prog(tmp_path, src, name)
        assert DETECTORS["unprotected-updatable"](prog).detect(), name


# --- 1.3: switch/match arm predicates ----------------------------------------

def _preds(prog, first_line: int, file: str = "t.teal") -> set[str]:
    from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
    return {repr(p) for p in PathPredicateAnalysis(prog).predicates_at(file, first_line)}


def test_switch_match_arms_refuse_missing_operands_and_resolve_aliased_labels(tmp_path):
    """(a) ``match`` reads its candidates POSITIONALLY off ``inputs``, which
    DROP an unresolved cell — here the unsafe proto'd callee ``outer`` withdraws
    the ``int 4`` candidate — so the ``t0`` arm (reached iff GroupSize == 4) was
    credited ``GroupSize == 5``: a fabricated guard. Refuse when the op's arity
    is not met. Control: the same program with ``leg`` proto'd (nothing
    withdrawn) keeps ``t0: GroupSize == 4`` and ``t1: GroupSize == 5``.
    (b) an EMPTY label aliased onto the next one owns no block, so matching the
    arm target by LINE found no successor and the NoOp arm carried the
    fall-through's ``not in [0..1]`` (``OnCompletion >= CloseOut`` on the NoOp
    path). Resolve targets to BLOCKS. Controls: the non-aliased switch keeps
    ``key == 0``; ``switch a a`` (same block twice) still refuses."""
    body = ("int 4\nint 7\ncallsub outer\npop\nint 5\nglobal GroupSize\n"
            "match t0 t1\nerr\nt0:\nint 1\nreturn\nt1:\nint 1\nreturn\n"
            "outer:\nproto 1 1\nframe_dig -1\ncallsub leg\nretsub\nleg:\n")
    withdrawn = _prog(tmp_path, "#pragma version 10\n" + body + "int 2\n+\nretsub\n")
    m = next(a for a in withdrawn.assignments if a.op == "match")
    assert len(m.inputs) == 2, "premise: the withdrawn candidate is dropped"
    assert _preds(withdrawn, 10) == set()          # t0 arm: refused, not `== 5`
    assert _preds(withdrawn, 13) == set()
    assert _preds(withdrawn, 9) == set()           # fall-through refused too
    ctrl = _prog(tmp_path, "#pragma version 10\n" + body +
                 "proto 1 1\nframe_dig -1\nint 2\n+\nretsub\n")
    assert _preds(ctrl, 10) == {"(V#1@L7 == 4)"}
    assert _preds(ctrl, 13) == {"(V#1@L7 == 5)"}

    alias = _prog(tmp_path, "#pragma version 10\ntxn OnCompletion\n"
                  "switch on_noop on_optin\nerr\non_noop:\nreal_noop:\n"
                  "int 1\nreturn\non_optin:\nint 1\nreturn\n")
    assert _preds(alias, 6) == {"(V#1@L2 == 0)"}
    assert _preds(alias, 9) == {"(V#1@L2 == 1)"}
    assert _preds(alias, 4) == {"(V#1@L2 not in [0..1])"}
    plain = _prog(tmp_path, "#pragma version 10\ntxn OnCompletion\n"
                  "switch on_noop on_optin\nerr\non_noop:\n"
                  "int 1\nreturn\non_optin:\nint 1\nreturn\n")
    assert _preds(plain, 5) == {"(V#1@L2 == 0)"}
    twice = _prog(tmp_path, "#pragma version 10\ntxn OnCompletion\n"
                  "switch on_noop real_noop on_optin\nerr\non_noop:\nreal_noop:\n"
                  "int 1\nreturn\non_optin:\nint 1\nreturn\n")
    assert _preds(twice, 6) == set()               # disjunction of keys: refused
    assert _preds(twice, 9) == {"(V#1@L2 == 2)"}


# --- 1.10: concat past MaxStringSize -----------------------------------------

def test_concat_does_not_fold_past_max_string_size(tmp_path):
    """``concat`` PANICS when the result exceeds 4096 bytes; folding it turned
    a halting program into a constant approval (``len`` → 8192, ``==`` → 1,
    ``return (1)``). Control: 4096 exactly still folds."""
    from tealql.tealtools.ssa import const_int

    def _ret(n_a: int, n_b: int):
        prog = _prog(tmp_path, f"#pragma version 10\nint {n_a}\nbzero\nint {n_b}\n"
                     f"bzero\nconcat\nlen\nint {n_a + n_b}\n==\nreturn\n",
                     f"c{n_a}_{n_b}.teal")
        ret = next(a for a in prog.assignments if a.op == "return")
        return const_int(ret.inputs[0])

    assert _ret(4096, 4096) is None        # would panic: nothing to fold
    assert _ret(4095, 2) is None           # 4097: one past the cap
    assert _ret(4095, 1) == 1              # exactly 4096: legal, folds
