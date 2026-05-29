"""Out-of-SSA phi materialization for SSAProgram.

Replaces each live Phi with a synthetic MatPhiVar, inserting copy assignments
``mat_phi_k = leaf_ssavar`` at each reachable SSAVar leaf's def site, then
rewrites consumers (Phi -> MatPhiVar) and prunes the phis. Transitive leaves
are computed via SCC condensation of the phi-arg graph (O(N+E); a naive DFS is
O(N^2) on the giant cyclic SCCs PySSA produces at constant-stack loops).

Bridged from ``SSAProgram.materialize_phis`` (which keeps the idempotency
guard + state flag).
"""
from __future__ import annotations

from ..ssa import (
    Assignment,
    Location,
    MatPhiVar,
    Operand,
    Phi,
    SSAProgram,
    SSAVar,
)


def materialize_phis(prog: SSAProgram) -> None:
    # Transitive SSAVar leaves per phi via SCC condensation of the phi-arg
    # graph (all phis in one SCC share the same leaf set).
    import networkx as nx
    _args_graph = nx.DiGraph()
    _args_graph.add_nodes_from(prog.phis.values())
    for _phi in prog.phis.values():
        for _arg in _phi.args:
            if isinstance(_arg, Phi):
                _args_graph.add_edge(_phi, _arg)
    _sccs = list(nx.strongly_connected_components(_args_graph))
    _scc_of: dict[Phi, int] = {}
    for _i, _scc in enumerate(_sccs):
        for _phi in _scc:
            _scc_of[_phi] = _i
    _scc_succs: list[set[int]] = [set() for _ in _sccs]
    for _u, _v in _args_graph.edges:
        _su, _sv = _scc_of[_u], _scc_of[_v]
        if _su != _sv:
            _scc_succs[_su].add(_sv)
    _scc_direct: list[list[SSAVar]] = [[] for _ in _sccs]
    for _phi in prog.phis.values():
        _s = _scc_of[_phi]
        for _arg in _phi.args:
            if isinstance(_arg, SSAVar):
                _scc_direct[_s].append(_arg)
    _cond_dag = nx.DiGraph()
    _cond_dag.add_nodes_from(range(len(_sccs)))
    for _u, _succs_set in enumerate(_scc_succs):
        for _v in _succs_set:
            _cond_dag.add_edge(_u, _v)
    _scc_leaves: list[list[SSAVar]] = [[] for _ in _sccs]
    for _s in reversed(list(nx.topological_sort(_cond_dag))):
        _seen: set[int] = set()
        _out: list[SSAVar] = []
        for _v in _scc_direct[_s]:
            _key = id(_v)
            if _key not in _seen:
                _seen.add(_key)
                _out.append(_v)
        for _succ in _scc_succs[_s]:
            for _v in _scc_leaves[_succ]:
                _key = id(_v)
                if _key not in _seen:
                    _seen.add(_key)
                    _out.append(_v)
        _scc_leaves[_s] = _out

    def _leaf_ssavars(phi: Phi) -> list[SSAVar]:
        return _scc_leaves[_scc_of[phi]]

    # Deterministic ordering so mat_phi indices are stable across runs.
    sorted_phis = sorted(
        prog.phis.values(),
        key=lambda p: (p.file, p.line, p.kind, p.stack_index),
    )

    phi_to_mat: dict[Phi, MatPhiVar] = {}
    next_idx = 0

    # Pass A: allocate mat vars (DirectPhi + multi-arg IndirectPhi: fresh).
    for phi in sorted_phis:
        if phi.kind == "DirectPhi":
            next_idx += 1
            mv = MatPhiVar(next_idx)
            phi_to_mat[phi] = mv
            prog.mat_phis.append(mv)
        elif phi.kind == "IndirectPhi" and len(phi.args) >= 2:
            next_idx += 1
            mv = MatPhiVar(next_idx)
            phi_to_mat[phi] = mv
            prog.mat_phis.append(mv)

    # IndirectPhi with exactly 1 arg: alias its root's mat var if possible.
    for phi in sorted_phis:
        if phi.kind != "IndirectPhi" or len(phi.args) != 1:
            continue
        parent = phi.args[0]
        if isinstance(parent, Phi) and parent in phi_to_mat:
            phi_to_mat[phi] = phi_to_mat[parent]
        else:
            next_idx += 1
            mv = MatPhiVar(next_idx)
            phi_to_mat[phi] = mv
            prog.mat_phis.append(mv)

    # Pass B: insert copy assignments at each reachable leaf's def site.
    seen_owned: set[MatPhiVar] = set()
    new_copies: list[Assignment] = []
    for phi in sorted_phis:
        mv = phi_to_mat.get(phi)
        if mv is None or mv in seen_owned:
            continue
        if phi.kind == "IndirectPhi" and len(phi.args) == 1:
            continue
        seen_owned.add(mv)
        for leaf in _leaf_ssavars(phi):
            producer = leaf.defined_by
            if producer is None:
                continue
            copy = Assignment(
                outputs=[mv],
                op="=",
                immediates="",
                inputs=[leaf],
                location=Location(producer.location.file, producer.location.line),
                ast_code=f"mat_phi_{mv.index} = {leaf.identifier}",
                const=None,
                basic_block=producer.basic_block,
            )
            new_copies.append(copy)
            leaf.uses.append(copy)
            if producer.basic_block is not None:
                producer.basic_block.assignments.append(copy)

    # Pass C: rewrite every Assignment's inputs — phis → mat vars.
    for a in prog.assignments:
        new_inputs: list[Operand] = []
        for inp in a.inputs:
            if isinstance(inp, Phi) and inp in phi_to_mat:
                new_inputs.append(phi_to_mat[inp])
            else:
                new_inputs.append(inp)
        a.inputs = new_inputs

    prog.assignments.extend(new_copies)
    prog.assignments.sort(key=lambda a: (a.location.file, a.location.line))
    for bb in prog.blocks.values():
        bb.assignments.sort(key=lambda a: a.location.line)

    # Pass D: prune the original phis (now structurally unreachable).
    prog.phis = {}
    for bb in prog.blocks.values():
        bb.phis = []
