"""The unified subroutine-partition module: cross-policy invariants.

``tealql.tealtools.subroutines`` hosts three deliberately different policies
(corrected / sound / construction — see its docstring). These tests pin the
relationships MEASURED over the full fixture universe (490 programs, ~25k
callsubs) when the module was unified, so silent drift between the policies
can't creep back in:

  * the SOUND policy never disagrees with the CORRECTED policy where it
    resolves (it is a soundness-narrowed subset, 0 disagreements measured);
  * every CONSTRUCTION-policy subroutine root is a CORRECTED-policy entry
    (the corrected policy additionally label-resolves dangling callsub
    edges, so it may know MORE entries — never fewer);
  * the naive construction continuation and the corrected continuation
    genuinely DIVERGE (353/24,965 callsubs measured) — pinned here on a real
    contract so nobody "fixes" one policy into the other without noticing
    (that is a semantic change; gate it with tests/subroutines_differential.py,
    the lift corpus, and the behavioural gate).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.ssa import PySSA
from tealql.tealtools.subroutines import (
    identify_subroutines,
    pyblock_partition,
    sound_return_targets,
)

REPO = Path(__file__).resolve().parent.parent
CONTRACTS = sorted(
    d for d in (REPO / "tests" / "contracts").iterdir() if d.is_dir()
)


def _bb_key(bb):
    if bb.assignments:
        loc = bb.assignments[0].location
        return f"{loc.file}:{loc.line}"
    return f"{bb.file}:{bb.first_line}"


def _py_key(b):
    if b.ops:
        return f"{b.ops[0].file}:{b.ops[0].line}"
    return f"<empty:{b.key}>"


@pytest.mark.parametrize("contract", CONTRACTS, ids=lambda d: d.name)
def test_sound_targets_agree_with_corrected_continuations(contract):
    prog = SSAProgram(str(contract))
    info = identify_subroutines(prog)
    _, return_target_of = sound_return_targets(prog)
    corrected = {_bb_key(c): (None if t is None else _bb_key(t))
                 for c, t in info["continuations"].items()}
    for cs, tgt in return_target_of.items():
        assert corrected.get(_bb_key(cs)) == _bb_key(tgt), (
            f"sound target {_bb_key(tgt)} for callsub {_bb_key(cs)} "
            f"disagrees with the corrected continuation "
            f"{corrected.get(_bb_key(cs))}"
        )


@pytest.mark.parametrize("contract", CONTRACTS, ids=lambda d: d.name)
def test_construction_roots_are_corrected_entries(contract):
    prog = SSAProgram(str(contract))
    entries = {_bb_key(e) for e in identify_subroutines(prog)["entries"]}
    py = PySSA._construct(SSAProgram(str(contract)))
    bb_to_sub = pyblock_partition(py.blocks)
    assert bb_to_sub, "partition must be non-empty"
    # Every block is owned.
    assert set(bb_to_sub) == set(py.blocks)
    sub_roots = {_py_key(r) for b, r in bb_to_sub.items()
                 if r.preds}  # roots WITH preds = callsub entries, not mains
    missing = sub_roots - entries
    assert not missing, (
        f"construction roots not known to the corrected policy: {missing}"
    )


def test_policies_deliberately_diverge_on_never_returning_callee():
    """folks-xgov-registry: the callee entered from the callsub at line 24
    never retsubs, so the CORRECTED policy assigns NO continuation, while the
    CONSTRUCTION policy's naive next-op heuristic picks line 28. Both are
    pinned: this divergence is a policy difference, not a bug in either."""
    contract = REPO / "tests" / "contracts" / "folks-xgov-registry"
    prog = SSAProgram(str(contract))
    info = identify_subroutines(prog)
    corrected = {_bb_key(c): (None if t is None else _bb_key(t))
                 for c, t in info["continuations"].items()}
    cs_key = "xgov_registry_approval_program.teal:24"
    assert corrected.get(cs_key, "<missing>") is None

    from tealql.tealtools.subroutines import _pyblock_return_point
    py = PySSA._construct(SSAProgram(str(contract)))
    rps = {_py_key(b): (None if rp is None else _py_key(rp))
           for b, rp in _pyblock_return_point(py.blocks).items()}
    assert rps.get(cs_key) == "xgov_registry_approval_program.teal:28"
