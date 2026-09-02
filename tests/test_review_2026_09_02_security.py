"""Pins for the 2026-09-02 audit's security-layer defects (findings.md §1.6,
§2.1–§2.6, §2.9). One test per DEFECT, controls folded in as further
assertions in the same test — a pin whose control is elsewhere proves nothing
about the boundary the fix draws.

The dominant class this round: the approving ``return``'s own operand and
EDGE-level predicates were never consulted as guards, and a ``||`` whose every
arm is a pin was read as no pin at all."""
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


def _flags(det: str, prog: SSAProgram) -> bool:
    return bool(DETECTORS[det](prog).detect())


def _lifecycle(prog: SSAProgram) -> set[str]:
    """Which of the four lifecycle verdicts fire — the informational ``is-*``
    pair and the HIGH ``unprotected-*`` pair are asserted separately below."""
    return {d for d in ("is-updatable", "is-deletable",
                        "unprotected-updatable", "unprotected-deletable")
            if _flags(d, prog)}


_CREATOR_CMP = "txn Sender\nglobal CreatorAddress\n==\n"
_ADMIN_CMP = "txn Sender\nbyte \"admin\"\napp_global_get\n==\n"
_NO_UNPROTECTED = {"is-updatable", "is-deletable"}
_ALL_FOUR = {"is-updatable", "is-deletable",
             "unprotected-updatable", "unprotected-deletable"}


# ---------------------------------------------------------------------------
# 2.1 — an approving `return V` is an `assert V` edge
# ---------------------------------------------------------------------------


def test_returned_comparison_is_the_approval_guard(tmp_path):
    """PyTeal ``Return(Txn.sender() == Global.creator_address())`` compiles to
    ``==; return``: the exit approves ONLY when the check holds, yet the exit's
    entry predicates carry nothing and it read as "updatable by anyone". Same
    for the Puya top-level ``callsub main; return`` (the retsub value is the
    comparison), ``select`` with a constant-0 arm, and a returned ``&&`` of
    ``!OC`` and ``!ApplicationID`` (approves NoOp-on-create only, so every
    lifecycle action is excluded). Controls: ``int 1; return`` and a ``select``
    whose 0 arm is the TAKEN one (approves when the check FAILS) stay flagged."""
    ret_cmp = _prog(tmp_path, _CREATOR_CMP + "return\n", "a.teal")
    assert _lifecycle(ret_cmp) == _NO_UNPROTECTED

    via_sub = _prog(tmp_path, "callsub main\nreturn\nmain:\nproto 0 1\n"
                    + _CREATOR_CMP + "retsub\n", "b.teal")
    assert _lifecycle(via_sub) == _NO_UNPROTECTED

    select = _prog(tmp_path, "int 0\nint 1\n" + _CREATOR_CMP + "select\nreturn\n",
                   "c.teal")
    assert _lifecycle(select) == _NO_UNPROTECTED

    and_zero = _prog(tmp_path, "txn OnCompletion\n!\ntxn ApplicationID\n!\n&&\n"
                     "return\n", "d.teal")
    assert _lifecycle(and_zero) == set()

    # Controls.
    const_true = _prog(tmp_path, "int 1\nreturn\n", "e.teal")
    assert _lifecycle(const_true) == _ALL_FOUR
    inverted_select = _prog(tmp_path, "int 1\nint 0\n" + _CREATOR_CMP
                            + "select\nreturn\n", "f.teal")
    assert _lifecycle(inverted_select) == _ALL_FOUR


# ---------------------------------------------------------------------------
# 2.3 — `||` whose EVERY leaf is a trusted-sender pin is a guard
# ---------------------------------------------------------------------------


def test_all_trusted_disjunction_is_a_sender_guard(tmp_path):
    """``Sender == creator || Sender == admin_state; assert`` authorises: whichever
    arm holds, the sender is one the contract trusts (NFT-marketplace template,
    ~10 mainnet contracts). Also through ``return``. Control: a ``||`` with ONE
    caller-supplied leaf (``Sender == ApplicationArgs[0]``) authorises nothing
    and stays flagged — the all-arms rule must fail closed."""
    asserted = _prog(tmp_path, _CREATOR_CMP + _ADMIN_CMP + "||\nassert\nint 1\nreturn\n",
                     "a.teal")
    assert _lifecycle(asserted) == _NO_UNPROTECTED
    returned = _prog(tmp_path, _CREATOR_CMP + _ADMIN_CMP + "||\nreturn\n", "b.teal")
    assert _lifecycle(returned) == _NO_UNPROTECTED

    bypass = _prog(tmp_path, _CREATOR_CMP + "txn Sender\ntxna ApplicationArgs 0\n==\n"
                   "||\nassert\nint 1\nreturn\n", "c.teal")
    assert _lifecycle(bypass) == _ALL_FOUR


# ---------------------------------------------------------------------------
# 2.4 — truthy `||` of `OC == k_i` is set-membership
# ---------------------------------------------------------------------------


def test_oncompletion_disjunction_is_set_membership(tmp_path):
    """PyTeal ``Cond([Or(OC == OptIn, OC == NoOp), handler])`` compiles to
    ``==; ==; ||; bnz handler`` (or ``bz reject``). On the surviving edge OC is
    in {0, 1}, which excludes Update and Delete outright — no creator guard is
    even needed, so all four lifecycle verdicts must be silent. Control: a set
    CONTAINING Update (``Or(OC == NoOp, OC == Update)``) keeps the Update
    verdicts and drops only the Delete ones."""
    members = "txn OnCompletion\nint OptIn\n==\ntxn OnCompletion\nint NoOp\n==\n||\n"
    bnz = _prog(tmp_path, members + "bnz handler\nint 0\nreturn\nhandler:\nint 1\nreturn\n",
                "a.teal")
    assert _lifecycle(bnz) == set()
    bz = _prog(tmp_path, members + "bz reject\nint 1\nreturn\nreject:\nint 0\nreturn\n",
               "b.teal")
    assert _lifecycle(bz) == set()

    with_update = ("txn OnCompletion\nint NoOp\n==\ntxn OnCompletion\n"
                   "int UpdateApplication\n==\n||\n")
    ctrl = _prog(tmp_path, with_update + "bnz handler\nint 0\nreturn\nhandler:\n"
                 "int 1\nreturn\n", "c.teal")
    assert _lifecycle(ctrl) == {"is-updatable", "unprotected-updatable"}


# ---------------------------------------------------------------------------
# 2.5 — a sender guard proven on the EDGE into a shared approve block
# ---------------------------------------------------------------------------


def test_sender_guard_on_edge_into_shared_approve_block(tmp_path):
    """``OC == Update && Sender == Creator; bnz approve`` proves the guard on the
    TAKEN edge only; a NoOp path (``OC == NoOp; assert``) also falls into
    ``approve``, and the intersection at the join drops the guard from the
    block's entry set (mainnet app_900070460). Controls: the same conjunction
    asserted inline (no join) was already clean; the same dispatch whose
    fall-through approves UNGUARDED must stay flagged — the edge rule closes
    one edge, not the block."""
    conj = "txn OnCompletion\nint UpdateApplication\n==\n" + _CREATOR_CMP + "&&\n"
    joined = _prog(tmp_path, conj + "bnz approve\ntxn OnCompletion\nint NoOp\n==\n"
                   "assert\napprove:\nint 1\nreturn\n", "a.teal")
    assert not _flags("unprotected-updatable", joined)

    inline = _prog(tmp_path, conj + "assert\nint 1\nreturn\n", "b.teal")
    assert not _flags("unprotected-updatable", inline)

    leaky = _prog(tmp_path, conj + "bnz approve\nint 1\nreturn\napprove:\nint 1\n"
                  "return\n", "c.teal")
    assert _flags("unprotected-updatable", leaky)


# ---------------------------------------------------------------------------
# 2.6 — `txna Accounts 0` / `int 0; txnas Accounts` ARE the sender
# ---------------------------------------------------------------------------


def test_accounts_zero_is_the_current_sender(tmp_path):
    """The AVM defines ``Accounts[0] == Sender``; fund-flow already credits it,
    the lifecycle guards read it as an unrelated address (one program, two
    verdicts — mainnet app_900397491). Controls: ``txna Accounts 1`` is a
    CALLER-named address and ``txn AssetSender`` is an axfer field the caller
    sets on their own txn — neither authorises anything."""
    for spelling in ("txna Accounts 0\n", "int 0\ntxnas Accounts\n"):
        prog = _prog(tmp_path, spelling + "global CreatorAddress\n==\nassert\n"
                     "int 1\nreturn\n", f"{len(spelling)}.teal")
        assert _lifecycle(prog) == _NO_UNPROTECTED, spelling

    for spelling in ("txna Accounts 1\n", "txn AssetSender\n", "int 1\ntxnas Accounts\n"):
        prog = _prog(tmp_path, spelling + "global CreatorAddress\n==\nassert\n"
                     "int 1\nreturn\n", f"c{len(spelling)}.teal")
        assert _lifecycle(prog) == _ALL_FOUR, spelling


# ---------------------------------------------------------------------------
# 2.2 — an ORDERED comparison rejecting on TRUE is a bound
# ---------------------------------------------------------------------------


def test_ordered_compare_rejecting_on_true_is_credited(tmp_path):
    """``Fee > 1000; bnz reject`` pins ``Fee <= 1000`` on every approving path —
    the complement of an ordered comparison is itself a bound, and the SAME
    check spelled ``<=; assert`` was always credited, so the verdict depended
    on the spelling. Covers the whole field family (lsig ``fee-validation``
    here), the TealScript ``if (x > y) throw`` shape (``>; bz ok; err``), a
    rejecting ``int 0; return``, a scratch round-trip before the branch, and
    the app-mode consumer ``group-size-check``. Controls: ``==; bnz reject`` IS
    the inverted-check antipattern (rejects only fee==0) and must stay flagged,
    in both families; the already-credited spellings stay clean."""
    fee = "txn Fee\nint 1000\n"
    clean = {
        "gt_bnz": fee + ">\nbnz reject\nint 1\nreturn\nreject:\nint 0\nreturn\n",
        "gt_bz_err": fee + ">\nbz ok\nerr\nok:\nint 1\nreturn\n",
        "ge_bnz_err": "txn Fee\nint 1001\n>=\nbnz reject\nint 1\nreturn\nreject:\nerr\n",
        "stored": fee + ">\nstore 1\nload 1\nbnz reject\nint 1\nreturn\nreject:\nerr\n",
        "le_assert": fee + "<=\nassert\nint 1\nreturn\n",           # already credited
        "lt_bz": "txn Fee\nint 1001\n<\nbz reject\nint 1\nreturn\nreject:\nerr\n",
    }
    for name, body in clean.items():
        assert not _flags("fee-validation", _prog(tmp_path, body, f"{name}.teal")), name
    inverted = _prog(tmp_path, "txn Fee\nint 0\n==\nbnz reject\nint 1\nreturn\n"
                     "reject:\nerr\n", "inv.teal")
    assert _flags("fee-validation", inverted)

    gs = "global GroupSize\nint 2\n"
    gs_gt = _prog(tmp_path, gs + ">\nbnz reject\ngtxn 0 Amount\npop\nint 1\nreturn\n"
                  "reject:\nerr\n", "gs1.teal")
    assert not _flags("group-size-check", gs_gt)
    gs_eq_inverted = _prog(tmp_path, gs + "==\nbnz reject\ngtxn 0 Amount\npop\nint 1\n"
                           "return\nreject:\nerr\n", "gs2.teal")
    assert _flags("group-size-check", gs_eq_inverted)
