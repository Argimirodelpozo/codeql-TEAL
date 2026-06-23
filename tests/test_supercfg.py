"""The cross-contract super-CFG (:class:`tealtools.cfg.SuperCFG`) splices typed
appcall call/return edges into one BB graph spanning a caller and its transitive
callees, so reachability / dominance / paths cross the contract boundary.

Built on the foundation that ``itxn_submit`` ends a basic block, so the submit
BB is a clean boundary and the continuation BB is its intra successor.
"""
from tealtools.cfg import SuperCFG
from helpers import make_xcontract


# A (root) calls B (app 100); B calls C (app 200). Each forwards arg 0.
_FWD = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int {app}
itxn_field ApplicationID
txna ApplicationArgs 0
itxn_field ApplicationArgs
itxn_submit
int 1
return
"""
# Leaf: a guard (assert) dominating a payment, no further appcall.
_LEAF = """#pragma version 10
txna ApplicationArgs 0
btoi
int 100
>=
assert
itxn_begin
txna ApplicationArgs 0
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
int 1
return
"""


def _build(tmp_path, **kw):
    caller, registry = make_xcontract(
        tmp_path, _FWD.format(app=100),
        {100: _FWD.format(app=200), 200: _LEAF})
    return SuperCFG.build(caller, registry, **kw)


def test_spans_all_contracts(tmp_path):
    sc = _build(tmp_path)
    scopes = {sb.app_id for sb in sc.blocks()}
    assert scopes == {None, 100, 200}


def test_call_and_return_edges_present(tmp_path):
    sc = _build(tmp_path)
    kinds = {e.kind for e in sc.inter_edges}
    assert kinds == {"call", "return"}
    # a call edge leaves the ROOT submit BB into app 100's entry...
    call_hops = {(e.src.app_id, e.dst.app_id) for e in sc.inter_edges if e.kind == "call"}
    assert (None, 100) in call_hops      # A -> B
    assert (100, 200) in call_hops       # B -> C
    # ...and a return edge comes back from the callee into its caller.
    ret_hops = {(e.src.app_id, e.dst.app_id) for e in sc.inter_edges if e.kind == "return"}
    assert (200, 100) in ret_hops        # C -> B
    assert (100, None) in ret_hops       # B -> A


def test_call_edge_targets_callee_entry(tmp_path):
    sc = _build(tmp_path)
    for e in sc.inter_edges:
        if e.kind == "call" and e.dst.app_id == 100:
            # callee entry is the top of B (the program start), with a
            # predecessor only via this call edge.
            assert e.dst.bb.first_line <= 3
            assert sc.predecessors(e.dst) == [e.src]
            return
    raise AssertionError("no call edge into app 100")


def test_interprocedural_reachability_root_to_leaf_sink(tmp_path):
    sc = _build(tmp_path)
    root = sc.root_entry
    assert root is not None and root.app_id is None
    reach = sc.reachable_from(root)
    # the leaf C's payment sink (itxn in C) is reachable from the ROOT entry,
    # two contracts away — that's the cross-boundary reachability.
    leaf_blocks = [sb for sb in reach if sb.app_id == 200]
    assert leaf_blocks, "leaf contract unreachable from root entry"


def test_root_entry_dominates_everything_reachable(tmp_path):
    sc = _build(tmp_path)
    root = sc.root_entry
    # the single program entry dominates every reachable block, including
    # callee blocks across the boundary (interprocedural dominance).
    callee_block = next(sb for sb in sc.blocks() if sb.app_id == 200)
    assert sc.dominates(root, callee_block)


def test_callee_entry_not_a_super_entry(tmp_path):
    sc = _build(tmp_path)
    # only the root program entry is a super-entry; callee entries gain the
    # call-edge predecessor, so they're no longer predecessor-less.
    entry_scopes = {sb.app_id for sb in sc.entries}
    assert entry_scopes == {None}


def test_depth_cap_stops_before_leaf(tmp_path):
    sc = _build(tmp_path, max_depth=1)
    scopes = {sb.app_id for sb in sc.blocks()}
    assert scopes == {None, 100}     # C (2 hops) absent
    assert all(e.dst.app_id != 200 for e in sc.inter_edges)


def test_dot_renders_clusters_and_typed_edges(tmp_path):
    sc = _build(tmp_path)
    dot = sc.to_dot()
    assert "subgraph cluster_root" in dot
    assert "subgraph cluster_app100" in dot
    assert "color=blue" in dot           # call edges
    assert "color=red" in dot            # return edges
