"""The ONE coverage-semantics guard walker (`analysis/guard_coverage.py`).

Two halves. A TABLE of abstract condition trees -> expected coverage pins the
rules representation-free (a toy model: no pre-IR, no SSA). Then MUTATION
GATES: each shared rule is broken in the walker and the benchmark fixture that
pins it must flip — through BOTH engines that now consume the walker, so a
rule nobody's corpus exercises shows up here as a survivor, not as a silent
FP/FN later."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tealql.security import DETECTORS
from tealql.tealtools.analysis import guard_coverage as gc
from tealql.tealtools.ssa import SSAProgram

_BENCH = Path(__file__).resolve().parent / "benchmark"


# --- a toy representation ----------------------------------------------------


class N:
    """A condition-tree node: ``N(op, *args)``; ints are uint64 literals."""

    def __init__(self, op, *args, name=None):
        self.op, self.args, self.name = op, args, name or op

    def __repr__(self):
        return self.name


X, Y = N("txna", name="x"), N("txna", name="y")       # attacker inputs (leaves)
S = N("txn", name="Sender")                           # the current sender
C = N("global", name="Creator")                       # a trusted identity


class Toy:
    def is_node(self, v):
        return isinstance(v, N)

    def definition(self, v):
        if v.op == "phi":
            return "phi", None, v.args
        return "op", v.op, v.args

    def returns(self, v):
        return ()

    def arm_value(self, v):
        return v if isinstance(v, (N, int)) else gc.OPAQUE

    def literal_int(self, v):
        return v if isinstance(v, int) else None

    def leaf_credit(self, v, op, self_truthy, sender_ok):
        out = gc.NO_COVERAGE
        if v in (X, Y) and not self_truthy:
            out = gc.Coverage(True, False, frozenset({v.name}))
        if v is S and sender_ok:
            out = gc.Coverage(sender=True)
        return out

    def pins_sender(self, v):
        return S in v.args and C in v.args

    def dependent(self, v, state_ok):
        return v in (X, Y) or (isinstance(v, N) and any(self.dependent(a, state_ok)
                                                        for a in v.args))

    def counterpart_ok(self, pinned, other):
        return True

    def arm_dead(self, v, sense):
        return False


def cover(tree, sense=True):
    return gc.CoverageWalker(Toy()).cover(tree, sense)


def leaves(tree, sense=True):
    return set(cover(tree, sense).leaves)


_TABLE = [
    # (condition, sense, constrained leaves, sender pinned, excluded seen)
    ("x <= 100", N("<=", 100, X), True, {"x"}, False, False),
    ("x + y <= 100 (value position: + is arithmetic)",
     N("<=", 100, N("+", Y, X)), True, {"x", "y"}, False, False),
    ("conjunction = union", N("&&", N("<=", 5, Y), N("<=", 9, X)), True, {"x", "y"}, False, False),
    ("join = intersection: || of different leaves",
     N("||", N("<=", 5, Y), N("<=", 9, X)), True, set(), False, False),
    ("|| of a constant set pins the key", N("||", N("==", 2, X), N("==", 1, X)),
     True, {"x"}, False, False),
    ("boolean | is a join", N("|", N("<=", 5, Y), N("<=", 9, X)), True, set(), False, False),
    ("boolean + is a join", N("+", N("<=", 5, X), N("<=", 9, X)), True, {"x"}, False, False),
    # TOP-FIRST: args[0] is the (attacker-steered) selector.
    ("select: live constant arm is a bypass", N("select", Y, N("<=", 9, X), 1),
     True, set(), False, False),
    ("select: both arms check x", N("select", Y, N("<=", 1, X), N("<=", 9, X)),
     True, {"x"}, False, False),
    ("select: a dead constant arm is no bypass", N("select", Y, N("<=", 9, X), 0),
     True, {"x"}, False, False),
    ("De Morgan: !(a || b) forces both", N("!", N("||", N("<", 5, Y), N("<", 9, X))),
     True, {"x", "y"}, False, False),
    ("x != 5 only excludes", N("!=", 5, X), True, set(), False, True),
    ("!(x != 5) pins", N("!", N("!=", 5, X)), True, {"x"}, False, False),
    ("x > 0 only excludes", N(">", 0, X), True, set(), False, True),
    ("x >= 2 bounds", N(">=", 2, X), True, {"x"}, False, False),
    ("1 <= x only excludes", N("<=", X, 1), True, set(), False, True),
    ("input vs input is no check", N("==", Y, X), True, set(), False, False),
    ("x - x is vacuous", N("<=", 3, N("-", X, X)), True, set(), False, False),
    ("x % 1 is vacuous", N("%", 1, X), True, set(), False, False),
    ("len(x) bounds a length, not x", N("==", 8, N("len", X)), True, set(), False, False),
    ("bare truthiness of x credits nothing", X, True, set(), False, False),
    ("!x pins x to zero", N("!", X), True, {"x"}, False, False),
    ("value used as predicate guarantees nothing below", N("btoi", N("<=", 3, X)),
     True, set(), False, False),
    ("Sender == Creator pins", N("==", C, S), True, set(), True, False),
    ("Sender != Creator truthy does not pin", N("!=", C, S), True, set(), False, True),
    ("Sender != Creator falsy pins", N("!=", C, S), False, set(), True, False),
    ("every || arm pins", N("||", N("==", C, S), N("==", S, C)), True, set(), True, False),
    ("one || arm free", N("||", N("==", C, S), N("<=", 5, X)), True, set(), False, False),
    ("phi with a dead 0 arm", N("phi", N("==", C, S), 0), True, set(), True, False),
    ("phi with a live 1 arm", N("phi", N("==", C, S), 1), True, set(), False, False),
    ("(Sender == Creator) ^ 1 is a value", N("^", 1, N("==", C, S)), True, set(), False, False),
]


@pytest.mark.parametrize("what,tree,sense,want_leaves,want_sender,want_excl",
                         _TABLE, ids=[row[0] for row in _TABLE])
def test_coverage_table(what, tree, sense, want_leaves, want_sender, want_excl):
    got = cover(tree, sense)
    assert (set(got.leaves), got.sender, got.excluded) == (
        want_leaves, want_sender, want_excl), what


def test_join_needs_an_arm():
    assert not gc.every([]) and gc.every([True]) and not gc.every([True, False])
    assert gc.join([None, None]) == gc.NO_COVERAGE


# --- mutation gates: each shared rule, both engines ---------------------------


def _fires(det: str, kind: str, name: str) -> bool:
    prog = SSAProgram(str(_BENCH / det / kind / name))
    prog.propagate_constants()
    return bool(DETECTORS[det](prog).detect())


def _patch_everywhere(monkeypatch, name, replacement):
    """`from x import y` binds locally — patch every loaded holder."""
    holders = [m for m in list(sys.modules.values())
               if getattr(m, "__name__", "").startswith("tealql")
               and getattr(m, name, None) is getattr(gc, name)]
    assert gc in holders
    for mod in holders:
        monkeypatch.setattr(mod, name, replacement)


def _union(credits):
    live = [c for c in credits if c is not None]
    out = gc.NO_COVERAGE
    for c in live:
        out = gc.conjoin(out, c)
    return out


# (rule, patch, [(detector, kind, fixture)] whose verdict must flip)
_MUTATIONS = {
    "join -> union": (
        lambda mp: _patch_everywhere(mp, "join", _union),
        [("tainted-fund-flow", "vuln", "bitor_constant_bypass.teal"),
         ("tainted-fund-flow", "vuln", "plus_constant_bypass.teal"),
         ("tainted-fund-flow", "vuln", "select_constant_arm_bypass.teal"),
         # the SSA engine's sender-pin join (survived until this fixture)
         ("unprotected-updatable", "vuln", "sender_pin_or_caller_flag.teal")]),
    "drop input-vs-input": (
        lambda mp: _patch_everywhere(mp, "counterpart_credits", lambda *a, **k: True),
        [("tainted-fund-flow", "vuln", "input_vs_input_equality.teal"),
         ("tainted-fund-flow", "vuln", "input_bounded_by_input.teal"),
         ("abi-method-selector", "vuln", "selector_vs_other_app_arg.teal")]),
    "select as conjunction": (
        lambda mp: mp.setattr(gc.CoverageWalker, "_select", lambda self, args, sense, flags, depth:
                              gc.conjoin(self.visit(args[1], *flags, depth=depth),
                                         self.visit(args[2], *flags, depth=depth))),
        [("tainted-fund-flow", "vuln", "select_constant_arm_bypass.teal")]),
    "credit `> 0`": (
        lambda mp: _patch_everywhere(
            mp, "comparison_excludes",
            lambda op, sense, lhs, rhs: (op in gc.NEQ_OPS and sense)
            or (op in gc.EQ_OPS and not sense)),
        [("tainted-fund-flow", "vuln", "amount_gt_zero_only.teal")]),
    # Comparison SENSE is enforced twice — `comparison_pins` for the sender
    # and the exclusion withdrawing `input_ok` (which also gates the sender
    # leaf) — so only breaking both is observable; each alone is masked.
    "comparison sense ignored": (
        lambda mp: (_patch_everywhere(mp, "comparison_pins",
                                      lambda op, sense: op in gc.EQ_OPS | gc.NEQ_OPS),
                    _patch_everywhere(mp, "comparison_excludes", lambda *a: False)),
        [("tainted-fund-flow", "vuln", "sender_guard_inverted.teal"),
         ("tainted-fund-flow", "vuln", "receiver_only_not_zero.teal"),
         ("unprotected-updatable", "vuln", "inverted_creator_guard_branch.teal")]),
}


@pytest.mark.parametrize("rule", sorted(_MUTATIONS))
def test_walker_mutation_flips_its_fixtures(monkeypatch, rule):
    apply, fixtures = _MUTATIONS[rule]
    fixtures = [f for f in fixtures if (_BENCH / f[0] / f[1] / f[2]).exists()]
    assert fixtures, f"{rule}: no fixture on disk pins it"
    before = {f: _fires(*f) for f in fixtures}
    assert all(v == (f[1] == "vuln") for f, v in before.items()), before
    apply(monkeypatch)
    after = {f: _fires(*f) for f in fixtures}
    survived = [f for f in fixtures if after[f] == before[f]]
    assert not survived, f"MUTATION SURVIVED ({rule}) on {survived}"
