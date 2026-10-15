"""A key-PREFIX exclusion is a state-write key check when its namespace holds
every slot the program reads (``lift/key_namespace.py``).

The registry idiom (NFD-style apps, 33 labelled FP cells of
``tainted-state-write`` on the mainnet corpus): callers may write any global /
box key EXCEPT the reserved ``i.`` namespace, enforced by ``extract 0 2 != "i."``
inside a validation subroutine. The guard walker gives a disequality no input
credit — it excludes ONE value — so the write read as an unchecked
attacker-chosen slot, while the sibling handler that lacks the prefix check
(a real TP on the same contract) read identically.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift.lift import _Lifter
from tealql.tealtools.lift.fund_flow import tainted_state_writes

_HELPER = """
is_internal:
    proto 1 1
    frame_dig -1
    byte "i."
    ==
    retsub
check_key:
    proto 1 1
    frame_dig -1
    extract 0 2
    byte "i."
    ==
    bnz reject
    int 1
    retsub
reject:
    int 0
    return
internal_unless_creator:
    proto 1 1
    txn Sender
    global CreatorAddress
    ==
    bnz bypass
    frame_dig -1
    extract 0 2
    byte "i."
    ==
    retsub
bypass:
    int 0
    retsub
either_internal:
    proto 1 1
    txn NumAppArgs
    int 4
    ==
    bnz other
    frame_dig -1
    extract 0 2
    byte "i."
    ==
    retsub
get_key:
    proto 0 1
    load 7
    int 1
    +
    store 7
    load 7
    txnas ApplicationArgs
    retsub
other:
    txna ApplicationArgs 3
    extract 0 2
    byte "i."
    ==
    retsub
"""

#: The canonical write: the helper's verdict on arg 1's 2-byte prefix is
#: asserted false, then arg 1 is the global key.
_ASSERT_HELPER = """
    txna ApplicationArgs 1
    extract 0 2
    callsub is_internal
    !
    assert
"""


def _program(check: str, reads: str = '    byte "i.owner"\n    app_global_get\n    pop\n',
             write: str = "    txna ApplicationArgs 1\n    txna ApplicationArgs 2\n"
                          "    app_global_put\n") -> str:
    return ("#pragma version 10\n    txn ApplicationID\n    bz create\n"
            + check + write + reads
            + "    int 1\n    return\ncreate:\n    int 1\n    return\n" + _HELPER)


_LOOP_BOX = """#pragma version 10
    int 1
    store 0
loop:
    load 0
    txn NumAppArgs
    <
    bz done
    load 0
    txnas ApplicationArgs
    callsub check_key
    assert
    load 0
    txnas ApplicationArgs
    byte "v"
    box_put
    load 0
    int 1
    +
    store 0
    b loop
done:
    byte "i.cfg"
    box_get
    pop
    pop
    int 1
    return
""" + _HELPER


_CASES = {
    # --- credited: the namespace holds every slot the program reads -------
    "helper-asserted-false": (_program(_ASSERT_HELPER), False),
    "validation-sub-rejects": (_program(
        "    txna ApplicationArgs 1\n    callsub check_key\n    pop\n"), False),
    "loop-index-reread-box": (_LOOP_BOX, False),
    # The index is re-stored between the check and the write: arg 0 (never
    # checked) is written on the first iteration.
    "loop-index-restored-between": (_LOOP_BOX.replace(
        "    callsub check_key\n    assert\n",
        "    callsub check_key\n    assert\n    load 0\n    int 1\n    -\n    store 0\n").replace(
        "    int 1\n    +\n    store 0\n    b loop", "    int 2\n    +\n    store 0\n    b loop"),
        True),
    "foreign-app-read-outside": (_program(_ASSERT_HELPER, reads=(
        '    int 123\n    byte "price"\n    app_global_get_ex\n    pop\n    pop\n')), False),
    "other-storage-read-outside": (_program(_ASSERT_HELPER, reads=(
        '    byte "i.owner"\n    app_global_get\n    pop\n'
        '    byte "cfg"\n    box_get\n    pop\n    pop\n')), False),
    # --- controls: the finding must stand --------------------------------
    # A helper answering "not internal" on a bypass arm (join = OR).
    "helper-bypass-arm": (_program(
        "    txna ApplicationArgs 1\n    callsub internal_unless_creator\n    !\n    assert\n"),
        True),
    # Two calls of an impure key getter return different args: checking the
    # first call's key says nothing about the second's.
    "two-calls-of-a-key-getter": (_program(
        "    callsub get_key\n    extract 0 2\n    callsub is_internal\n    !\n    assert\n",
        write="    callsub get_key\n    txna ApplicationArgs 2\n    app_global_put\n"), True),
    # Each return arm checks a DIFFERENT value: no arm-common fact.
    "helper-arms-check-different-values": (_program(
        "    txna ApplicationArgs 1\n    callsub either_internal\n    !\n    assert\n"),
        True),
    "no-check": (_program(""), True),
    "own-read-outside-namespace": (_program(_ASSERT_HELPER, reads=(
        '    byte "admin"\n    app_global_get\n    pop\n')), True),
    "own-app-get-ex-outside": (_program(_ASSERT_HELPER, reads=(
        '    int 0\n    byte "price"\n    app_global_get_ex\n    pop\n    pop\n')), True),
    "dynamic-own-read": (_program(_ASSERT_HELPER, reads=(
        '    txn Sender\n    app_global_get\n    pop\n')), True),
    "checks-another-arg": (_program(_ASSERT_HELPER.replace(
        "ApplicationArgs 1", "ApplicationArgs 3")), True),
    "prefix-width-mismatch": (_program(_ASSERT_HELPER.replace(
        "extract 0 2", "extract 0 3")), True),
    "asserts-inside-namespace": (_program(_ASSERT_HELPER.replace("    !\n", "")), True),
    "check-on-one-branch-only": (_program(
        "    txn NumAppArgs\n    int 3\n    ==\n    bz skip\n" + _ASSERT_HELPER
        + "skip:\n"), True),
    "box-write-under-global-namespace": (_program(_ASSERT_HELPER, write=(
        "    txna ApplicationArgs 1\n    txna ApplicationArgs 2\n    box_put\n"),
        reads='    byte "i.owner"\n    app_global_get\n    pop\n'
              '    byte "cfg"\n    box_get\n    pop\n    pop\n'), True),
}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_key_prefix_exclusion_is_a_key_check_only_over_the_read_namespace(name, tmp_path: Path):
    teal, flagged = _CASES[name]
    p = tmp_path / "prog.teal"
    p.write_text(teal)
    lifter = _Lifter(SSAProgram(str(p)))
    lifter.build()
    unguarded = [f for f in tainted_state_writes(lifter) if not f.guarded]
    assert bool(unguarded) is flagged, (name, [f.pretty() for f in tainted_state_writes(lifter)])
    if not flagged:
        credited = [g for f in tainted_state_writes(lifter) for g in f.guards
                    if g.kind == "key-namespace"]
        assert credited and all(g.checks_input and not g.checks_sender for g in credited)
