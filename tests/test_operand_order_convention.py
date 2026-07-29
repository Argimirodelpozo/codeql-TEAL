"""One name, one meaning: ``inputs`` is TOP-FIRST, everywhere, always.

Operand order is the single most re-found defect in this codebase — it is the
dominant finding in two separate full reviews (const_fold and range_arith
reversed for non-commutative ops; bytemath ``b/`` and byte_length_prop wrong in
both directions; a comparator inversion in path_predicates and group_reasoning).

The root cause was never the top-first convention itself. It was that
``const_fold`` reversed its list and kept the name ``inputs``, so the identical
expression ``inputs[0]`` meant the topmost popped value everywhere in the tree
and the deepest one inside that module — a difference visible only by reading a
docstring in a third file. Two conventions, one spelling.

So the rule these tests enforce is a NAMING rule, which is the only kind a
reader can check locally:

    ``inputs``  is always Assignment.inputs order: TOP-first.
    ``operands`` is always SOURCE order: what the programmer wrote.

Use :func:`binary_operands` / :func:`source_operands` to cross between them.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from tealql.tealtools.ssa import (
    SSAProgram, binary_operands, const_bytes, const_int, source_operands,
)

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"


def _value(x):
    i = const_int(x)
    return i if i is not None else const_bytes(x)


@pytest.fixture(scope="module")
def prog() -> SSAProgram:
    """`extract3` takes `buf start len` and `-` is non-commutative, so both
    orders are observable in one program."""
    teal = ('#pragma version 10\n'
            'byte "abcdef"\nint 1\nint 2\nextract3\nlen\n'
            'int 7\nint 3\n-\n+\nreturn\n')
    p = SSAProgram.from_text(teal)
    p.propagate_constants()
    return p


def _op(prog, name):
    return next(a for a in prog.assignments if a.op == name)


# ---------------------------------------------------------------------------
# The convention, pinned executably rather than in prose
# ---------------------------------------------------------------------------


def test_inputs_are_top_first(prog):
    """`byte "abcdef"; int 1; int 2; extract3` pushes buf, start, len — so the
    LAST one pushed is inputs[0]."""
    a = _op(prog, "extract3")
    assert [_value(i) for i in a.inputs] == [2, 1, "0x616263646566"]


def test_source_operands_is_source_order(prog):
    a = _op(prog, "extract3")
    assert [_value(i) for i in source_operands(a)] == ["0x616263646566", 1, 2]


def test_binary_operands_agrees_with_source_operands(prog):
    """The 2-input helper and the n-ary one must not disagree — two spellings
    of the same swap is how the codebase got here in the first place."""
    a = _op(prog, "-")
    lhs, rhs = binary_operands(a)
    assert (lhs, rhs) == source_operands(a)
    # `int 7; int 3; -` is 7 - 3, NOT 3 - 7
    assert (_value(lhs), _value(rhs)) == (7, 3)
    assert _value(a.inputs[0]) == 3, "inputs[0] must be the TOP of the stack"


# ---------------------------------------------------------------------------
# The structural gate
# ---------------------------------------------------------------------------


def _reversal_bindings(tree) -> list:
    """Lines binding the name ``inputs`` to a REVERSED sequence, or reversing it
    in place — i.e. rebinding the top-first name to source order."""
    def _is_reversal(node) -> bool:
        # reversed(x) / list(reversed(x)) / tuple(reversed(x))
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                if fn.id == "reversed":
                    return True
                if fn.id in ("list", "tuple") and node.args:
                    return _is_reversal(node.args[0])
            return False
        # x[::-1]
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            step = node.slice.step
            return (isinstance(step, ast.UnaryOp)
                    and isinstance(step.op, ast.USub)
                    and isinstance(step.operand, ast.Constant)
                    and step.operand.value == 1)
        return False

    bad = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            names = [t.id for t in n.targets if isinstance(t, ast.Name)]
            if "inputs" in names and _is_reversal(n.value):
                bad.append((n.lineno, "bound to a reversed sequence"))
        elif isinstance(n, ast.Call):
            fn = n.func
            if (isinstance(fn, ast.Attribute) and fn.attr == "reverse"
                    and isinstance(fn.value, ast.Name) and fn.value.id == "inputs"):
                bad.append((n.lineno, "reversed in place"))
    return bad


def test_no_module_rebinds_inputs_to_source_order():
    """``inputs`` must never hold source order. If you need it, call
    ``source_operands`` and name the result ``operands``."""
    offenders = []
    for py in sorted(SRC.rglob("*.py")):
        for lineno, why in _reversal_bindings(ast.parse(py.read_text())):
            offenders.append(f"{py.relative_to(SRC)}:{lineno} — inputs {why}")
    assert not offenders, (
        "the name `inputs` is TOP-FIRST everywhere; rebinding it to source "
        "order is the defect this project keeps re-finding:\n  "
        + "\n  ".join(offenders))


def test_the_gate_catches_every_reversal_spelling():
    """Non-vacuity. A structural gate that matches nothing is decoration, and
    this one has four shapes to cover."""
    for snippet in (
        "inputs = reversed(a.inputs)",
        "inputs = list(reversed(a.inputs))",
        "inputs = tuple(reversed(a.inputs))",
        "inputs = a.inputs[::-1]",
        "inputs = []\ninputs.reverse()",
    ):
        assert _reversal_bindings(ast.parse(snippet)), f"missed: {snippet!r}"
    # ...and does not fire on the legitimate spellings
    for ok in (
        "operands = list(reversed(a.inputs))",
        "operands = a.inputs[::-1]",
        "inputs = a.inputs",
        "inputs = [x for x in a.inputs]",
    ):
        assert not _reversal_bindings(ast.parse(ok)), f"false positive: {ok!r}"


def test_const_fold_folders_take_operands_not_inputs():
    """The specific regression: every ``_fold_*`` helper reads SOURCE order, so
    naming its parameter ``inputs`` is what made ``inputs[0]`` ambiguous."""
    tree = ast.parse((SRC / "tealql/tealtools/ssa/const_fold.py").read_text())
    bad = [n.name for n in ast.walk(tree)
           if isinstance(n, ast.FunctionDef) and n.name.startswith("_fold_")
           and any(a.arg == "inputs" for a in n.args.args)]
    assert not bad, f"source-order folders must not name the parameter 'inputs': {bad}"
