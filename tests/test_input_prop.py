"""`passes.input_prop` — unify execution-stable input reads WITHOUT merging reads
that pop distinct indices off the stack."""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram


def _consumer_inputs(tmp_path, teal, consumer_op):
    (tmp_path / "p.teal").write_text(teal)
    p = SSAProgram(str(tmp_path / "p.teal"))
    p.propagate_constants()
    p.propagate_inputs()
    for a in p.assignments:
        if a.op == consumer_op:
            return a.inputs
    return []


H = "#pragma version 8\n"


def test_imm_only_reads_unify(tmp_path):
    ins = _consumer_inputs(tmp_path, H + "txn NumAppArgs\ntxn NumAppArgs\n==\nreturn\n", "==")
    assert len(ins) == 2 and ins[0] is ins[1]


def test_args_distinct_index_not_unified(tmp_path):
    # `args` pops the arg index off the stack; args[0] and args[1] are DIFFERENT
    # values and must not be merged (was: all `args` reads unified — unsound).
    ins = _consumer_inputs(tmp_path, H + "int 0\nargs\nint 1\nargs\n==\nreturn\n", "==")
    assert len(ins) == 2 and ins[0] is not ins[1]


def test_args_same_index_unified(tmp_path):
    ins = _consumer_inputs(tmp_path, H + "int 0\nargs\nint 0\nargs\n==\nreturn\n", "==")
    assert len(ins) == 2 and ins[0] is ins[1]


def test_gtxnas_distinct_array_index_not_unified(tmp_path):
    # gtxnas pops the ARRAY index (txn index is immediate) — was wrongly imm-only.
    ins = _consumer_inputs(
        tmp_path,
        H + "int 0\ngtxnas 0 ApplicationArgs\nint 1\ngtxnas 0 ApplicationArgs\n==\nreturn\n",
        "==")
    assert len(ins) == 2 and ins[0] is not ins[1]


def test_gtxnsas_second_index_matters(tmp_path):
    # gtxnsas pops BOTH the txn index and the array index; a differing txn index
    # must keep the reads distinct (was: only the first popped operand keyed).
    ins = _consumer_inputs(
        tmp_path,
        H + "int 0\nint 0\ngtxnsas ApplicationArgs\n"
            "int 1\nint 0\ngtxnsas ApplicationArgs\n==\nreturn\n",
        "==")
    assert len(ins) == 2 and ins[0] is not ins[1]


def test_opcode_budget_not_unified(tmp_path):
    # global OpcodeBudget decreases as the program runs — two reads can differ.
    ins = _consumer_inputs(
        tmp_path, H + "global OpcodeBudget\nglobal OpcodeBudget\n==\nreturn\n", "==")
    assert len(ins) == 2 and ins[0] is not ins[1]
