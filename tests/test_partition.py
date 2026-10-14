"""Trace partitioning of path predicates (``cfg/partition.py``)."""
from __future__ import annotations

from tealql.tealtools.cfg.partition import COLLAPSED, ROOT, PartitionedPredicates
from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
from tealql.tealtools.metadata.abi import method_at_line_or_partition
from tealql.tealtools.ssa import SSAProgram

# ARC-4 router: `match` on the selector, a bare-create arm, and ONE shared
# `done: return` that every arm jumps to (Puya's shared-exit shape).
ROUTER = """#pragma version 10
txn NumAppArgs
bz create
method "a()void"
method "b()void"
txna ApplicationArgs 0
match route_a route_b
err
route_a:
txn Fee
int 1000
<=
assert
callsub helper
int 1
b done
route_b:
txn RekeyTo
global ZeroAddress
==
assert
callsub helper
int 1
b done
create:
txn ApplicationID
!
assert
int 1
b done
done:
return
helper:
txn Sender
global CreatorAddress
==
assert
retsub
"""
SHARED_RETURN_LINE = 32
# `int 1; b done` of route_a — the return target of a helper SHARED with
# route_b, so only the call-site check keeps method=b from leaking in.
ROUTE_A_TAIL_LINE = 15


def _prog(src):
    return SSAProgram({"approval.teal": src})


def _block(prog, line):
    return prog.block_containing("approval.teal", line)


def _labelled(pp, bb):
    names = {k: m.name for k, m in pp.method_names.items()}
    return {p.label(names): {repr(c) for c in pp.predicates_at(bb, p)}
            for p in pp.partitions_at(bb)}


def test_selector_partitions_keep_each_arm_at_the_shared_exit():
    prog = _prog(ROUTER)
    base = PathPredicateAnalysis(prog)
    pp = PartitionedPredicates(prog, key="method", base=base)
    done = _block(prog, SHARED_RETURN_LINE)
    at_exit = _labelled(pp, done)
    assert set(at_exit) == {"<undispatched>", "method=a", "method=b"}
    # Each arm's selector equality AND its own guard survive the shared join…
    assert any("== 0x" in c for c in at_exit["method=a"])
    assert any("<= 1000" in c for c in at_exit["method=a"])
    assert any("== 0x0000" in c for c in at_exit["method=b"])
    assert not any("<= 1000" in c for c in at_exit["method=b"])
    # …which the unpartitioned intersection loses entirely.
    assert not any("<= 1000" in repr(c) for c in base.bb_preds[done])
    # Partitioning never knows LESS than the plain analysis anywhere.
    for bb in prog.blocks.values():
        assert base.bb_preds[bb] <= pp.merged_at(bb)
    exits = pp.exits_by_partition()
    assert {p.method is not None for p in exits} == {True, False}
    assert all(list(blocks) == [done] for blocks in exits.values())
    d = pp.to_dict()
    assert d["key"] == "method" and d["collapsed_blocks"] == []
    assert {e["method"] for e in d["exits_by_partition"]} == {None, "a", "b"}


def test_oncompletion_partitions_on_a_switch():
    prog = _prog("""#pragma version 10
txn OnCompletion
switch noop optin
err
noop:
txn Fee
int 1000
<=
assert
b done
optin:
txn RekeyTo
global ZeroAddress
==
assert
done:
int 1
return
""")
    pp = PartitionedPredicates(prog, key="oncompletion")
    done = _block(prog, 17)
    assert [p.oncompletion for p in pp.partitions_at(done)] == [0, 1]
    at_exit = _labelled(pp, done)
    assert any("<= 1000" in c for c in at_exit["oc=NoOp"])
    assert not any("<= 1000" in c for c in at_exit["oc=OptIn"])
    # Selector dispatch is not a key in this mode.
    assert all(p.method is None for p in pp.partitions_at(done))


def test_budget_overflow_collapses_and_is_recorded():
    prog = _prog(ROUTER)
    pp = PartitionedPredicates(prog, key="method", budget=2)
    done = _block(prog, SHARED_RETURN_LINE)
    assert done in pp.collapsed_blocks
    assert pp.partitions_at(done) == [COLLAPSED]
    # A collapsed block is the plain meet: no arm's guard survives.
    assert pp.predicates_at(done, COLLAPSED) == PathPredicateAnalysis(prog).bb_preds[done]
    assert pp.to_dict()["collapsed_blocks"] == [
        {"file": "approval.teal", "first_line": done.first_line}]
    assert pp.method_at("approval.teal", SHARED_RETURN_LINE) is None
    # Blocks under budget stay partitioned.
    assert len(pp.partitions_at(_block(prog, ROUTE_A_TAIL_LINE))) == 1


def test_method_attribution_fallback_single_partition_only():
    prog = _prog(ROUTER)
    pp = PartitionedPredicates(prog, key="method")
    # Line spans found nothing (ranges=[]): the partition decides.
    hit = method_at_line_or_partition([], ROUTE_A_TAIL_LINE, partitions=pp,
                                      file="approval.teal")
    assert hit is not None and hit.name == "a"
    # The shared return is reached by several partitions: never attributed.
    assert method_at_line_or_partition([], SHARED_RETURN_LINE, partitions=pp,
                                       file="approval.teal") is None
    # The bare-create arm is reached only by the undispatched path.
    assert pp.method_at("approval.teal", 26) is None
    # A line-span hit always wins over the fallback.
    sentinel = object()
    assert method_at_line_or_partition(
        [(1, 50, sentinel)], SHARED_RETURN_LINE, partitions=pp,
        file="approval.teal") is sentinel


def test_no_router_program_matches_the_unpartitioned_result():
    prog = _prog("""#pragma version 10
txn Fee
int 1000
<=
bz fail
callsub check
txn RekeyTo
global ZeroAddress
==
assert
int 1
return
fail:
int 0
return
check:
txn Sender
global CreatorAddress
==
assert
retsub
""")
    base = PathPredicateAnalysis(prog)
    for key in ("method", "oncompletion", "both"):
        pp = PartitionedPredicates(prog, key=key, base=base)
        assert not pp.collapsed_blocks
        for bb in prog.blocks.values():
            if base.bb_preds[bb] or bb.predecessors:
                assert pp.partitions_at(bb) in ([ROOT], [])
            assert pp.predicates_at(bb, ROOT) == base.bb_preds[bb]
