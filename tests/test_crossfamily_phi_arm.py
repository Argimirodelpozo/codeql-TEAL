"""A phi arm from the other AVM family must not reach puya unreconciled.

One stack cell can hold a uint64 on one path and a byteslice on another. The phi's type is settled by
a majority vote over its arms, and when the families TIE it is broken arbitrarily (`conc[0]`). The
arm-materialising loop then began:

    for arg in ph.args:
        if isinstance(arg.value, pre_ir.Register):
            continue

so a REGISTER arm was skipped unconditionally — including the cross-family ones, which are the only
arms that cannot work. The vote had already seen the disagreement; it is what made the count a tie.
Puya then rejects the result outright:

    InternalError: Phi node (tmp%893#0) received arguments with unexpected type(s)

and the ENTIRE lift dies — no IR, no lowering, no analysis, for a 6258-line contract.

The arm becomes an explicit unknown of the phi's own type, matching the policy already applied to
non-register arms: coercing (itob/btoi) would assert a plausible WRONG value on a path that may be
live, and failing the lift costs every analysis downstream.

WHY THE FIXTURE IS A REAL CONTRACT. Every synthetic shape tried lifts without touching this path —
constant arms are handled by the existing branches, and register arms from `txn`/`txna`, through
scratch, or kept live past the join all agree on family. The real case pairs a DEPTH-DIVERGENT join
(which is what synthesises the `pc%` placeholder cell) with a value of the other family arriving on
the other edge. It is kept whole rather than trimmed to something that might stop reproducing.

The fixture is Reti's ValidatorRegistry with its labels and integer separators already normalised, so
it depends only on the change under test and not on the parse fixes that were needed to read the
original artifact.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import to_puya                # noqa: E402
from tealql.tealtools.ssa import SSAProgram              # noqa: E402

CONTRACT = Path(__file__).resolve().parent / "contracts" / "reti-crossfamily-phi" / "approval.teal"


def _prog():
    prog = SSAProgram(str(CONTRACT), strict=False)
    assert not prog.parse_diagnostics, f"fixture no longer parses: {prog.parse_diagnostics[:2]}"
    return prog


def test_the_contract_lifts():
    """Before this, the lift raised and produced nothing for the whole contract."""
    main, subs = to_puya(_prog())
    assert main is not None, "lift produced no main"
    assert len(subs) > 40, f"degenerate lift — only {len(subs)} subroutines"
    assert len(main.body) > 40, f"degenerate lift — only {len(main.body)} main blocks"


def test_exactly_one_arm_is_given_up(caplog):
    """The reconciliation must stay SURGICAL, and must announce itself.

    One arm of one phi in 6258 lines. If this number climbs, the lift is discarding values it could
    have kept, and the warning is the only thing separating "reconciled one genuinely two-typed
    cell" from "quietly stopped modelling a lot of the contract".
    """
    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.lift"):
        to_puya(_prog())
    lost = [r for r in caplog.records if "cross-family" in r.getMessage()]
    assert len(lost) == 1, (f"expected exactly 1 cross-family arm, got {len(lost)}: "
                            f"{[r.getMessage()[:70] for r in lost]}")


def test_same_family_arms_are_untouched(tmp_path, caplog):
    """A phi whose arms agree must not be disturbed — nothing replaced, nothing warned."""
    p = tmp_path / "t.teal"
    p.write_text("#pragma version 11\n\ttxn NumAppArgs\n\tbnz other\n\ttxn NumAppArgs\n\tb merge\n"
                 "other:\n\ttxn NumAssets\n"
                 "merge:\n\tpop\n\tint 1\n\treturn\n")
    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.lift"):
        main, _ = to_puya(SSAProgram(str(p), strict=False))
    assert main is not None
    assert not [r for r in caplog.records if "cross-family" in r.getMessage()], \
        "same-family phi should need no reconciliation"
