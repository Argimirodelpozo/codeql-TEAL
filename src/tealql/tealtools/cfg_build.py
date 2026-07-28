"""Derive the control-flow graph -- edges and basic blocks -- from the AST.

Emits ``(pred.startLine, succ.startLine, successorType)`` per edge, plus the
basic-block ranges; node/edge identity is ``(file, startLine)``. Consumes the
AST nodes and the source text (operands / label names), nothing else.

HAZARD: exactly three successor-type strings exist, and their boolean POLARITY
is what downstream guard reasoning reads off an edge:

* ``NormalSuccessor``        -- linear fall-through, ``b``/``callsub`` jumps,
                                ``switch``/``match`` arms (incl. fall-through),
                                ``retsub`` returns.
* ``BooleanSuccessor(true)``  -- ``bnz``->target, ``bz``->fall-through,
                                ``assert``->fall-through.
* ``BooleanSuccessor(false)`` -- ``bnz``->fall-through, ``bz``->target.

Exit completions (``return``/``err``/assert-false) have no matching successor
type and so produce no edge.
"""
from __future__ import annotations

from dataclasses import dataclass
NORMAL = "NormalSuccessor"
BOOL_TRUE = "BooleanSuccessor(true)"
BOOL_FALSE = "BooleanSuccessor(false)"

# Control-flow opcode classes (by their ``node_class`` name).
_RETURN = "ReturnOpcode"
_ERR = "ErrOpcode"
_ASSERT = "AssertOpcode"
_B = "BOpcode"
_CALLSUB = "CallsubOpcode"
_RETSUB = "RetsubOpcode"
_BNZ = "BnzOpcode"
_BZ = "BzOpcode"
_SWITCH = "SwitchOpcode"
_MATCH = "MatchOpcode"
# Ends a basic block (the boundary the xcontract supergraph splices call/return
# edges at) but NOT control flow — it keeps its NormalSuccessor edge, like assert.
_ITXN_SUBMIT = "InnerTransactionSubmit"
_LABEL = "Label"

_MULTI = frozenset({_SWITCH, _MATCH})
_EXIT = frozenset({_RETURN, _ERR})
# Opcodes that terminate the subroutine-local walk (getNextNode_subroutineAux).
_AUX_STOP = frozenset({_RETURN, _ERR, _RETSUB})


@dataclass
class _Node:
    """One program child (an AST line) as the CFG sees it."""
    file: str
    line: int          # source start line  -> edge identity
    col: int           # source start column-> child ordering tiebreak
    cls: str           # node-type string
    code: str          # source text of the line (operands, label name)
    ast: object = None  # the AstNode this wraps, so edges/blocks come back as objects

    def operand(self) -> str:
        """First whitespace-separated operand (branch/callsub target)."""
        parts = self.code.split()
        return parts[1] if len(parts) > 1 else ""

    def operands(self) -> list[str]:
        """All operands (switch/match target list)."""
        return self.code.split()[1:]

    def label_name(self) -> str:
        """Bare label name (identifier before the ``:``)."""
        return self.code.split(":", 1)[0].strip()


def _children(nodes) -> dict[str, list[_Node]]:
    """Group AstNodes into per-program child lists ordered by ``(line, col)``.

    The ``Source`` root is dropped; exact-duplicate locations (a node matching
    two leaf types, e.g. ``==`` -> IntegerEquals + EqualsComparison) collapse to
    one child, keeping the first object but preferring a control-flow type.
    """
    by_file: dict[str, dict[tuple[int, int], _Node]] = {}
    for node in nodes:
        cls = node.node_class
        if cls == "Source":
            continue
        loc = node.location
        sl, sc = loc.start_line, loc.start_column
        slot = by_file.setdefault(loc.file, {})
        existing = slot.get((sl, sc))
        if existing is None:
            slot[(sl, sc)] = _Node(loc.file, sl, sc, cls, node.code, node)
        elif existing.cls not in _CF_CLASSES and cls in _CF_CLASSES:
            existing.cls = cls          # keep existing.ast (the first object)
    return {
        f: [slot[k] for k in sorted(slot)]
        for f, slot in by_file.items()
    }


_CF_CLASSES = frozenset(
    {_RETURN, _ERR, _ASSERT, _B, _CALLSUB, _RETSUB, _BNZ, _BZ, _SWITCH, _MATCH, _LABEL}
)


def _aux_succ(n: _Node, nxt: _Node | None, labels: dict[str, _Node]) -> list[_Node]:
    """``getNextNode_subroutineAux``: subroutine-local successors of ``n``.

    Branches follow their target(s); ``callsub`` continues at the next line
    (never descends into the callee); ``return``/``err``/``retsub`` stop.
    ``switch``/``match`` follow BOTH their arms and the fall-through -- the arms
    are sub-local dispatch, so a ``retsub`` reached only through an arm still
    belongs to the sub's body. Fall-through only would orphan such arm-retsubs
    from their entry, their return edge to the caller's continuation would never
    be predicted, and the nested-call reachability chain unravels.
    """
    if n.cls in _AUX_STOP:
        return []
    if n.cls == _B:
        tgt = labels.get(n.operand())
        return [tgt] if tgt else []
    if n.cls in (_BZ, _BNZ):
        tgt = labels.get(n.operand())
        return [x for x in (tgt, nxt) if x is not None]
    if n.cls in _MULTI:                       # switch/match: arms + fall-through
        arms = (labels.get(name) for name in n.operands())
        return [x for x in (*arms, nxt) if x is not None]
    # callsub and everything else (assert/normal/label).
    return [nxt] if nxt is not None else []


def build_cfg_edges(nodes) -> list:
    """The CFG edges as ``(pred_AstNode, succ_AstNode, successorType)``.

    Candidate edges are pruned to those whose predecessor is reachable from the
    program entry — dropping, e.g., the ``retsub`` of a sub only ever reached
    through a ``callsub`` to a sibling that exits via ``return`` (control never
    flows back).
    """
    edges: list = []
    for _file, kids in _children(nodes).items():
        if not kids:
            continue
        cand, reachable, idx_of = _program_cfg(kids)
        for p, s, t in cand:
            if idx_of[id(p)] in reachable:
                edges.append((p.ast, s.ast, t))
    return edges


def _program_cfg(
    kids: list[_Node],
) -> tuple[list[tuple[_Node, _Node, str]], set[int], dict[int, int]]:
    """One program's candidate CFG edges + reachable-node set.

    ``(cand, reachable, idx_of)``: candidate ``(pred, succ, type)`` edges, the
    child indices reachable from the entry (``getChild(0)``), and node identity
    -> child index. Shared by :func:`build_cfg_edges` and
    :func:`build_basic_blocks` so both see exactly the same reachability.
    """
    cand: list[tuple[_Node, _Node, str]] = []
    # retsub-return candidates, deferred so the fixpoint below can gate them on
    # their callsub being reachable.
    retsub_cand: list[tuple[_Node, _Node, _Node]] = []   # (retsub, cont, callsub)

    def emit(pred: _Node, succ: _Node, t: str) -> None:
        cand.append((pred, succ, t))

    nxt_of: dict[int, _Node | None] = {
        i: (kids[i + 1] if i + 1 < len(kids) else None) for i in range(len(kids))
    }
    # FIRST definition wins on a duplicate label (only reachable on adversarial /
    # hand-written source — the assembler rejects duplicates). Taking the LAST
    # would branch past the first definition's code and prune it as unreachable:
    # a confidently wrong graph.
    labels: dict[str, _Node] = {}
    for k in kids:
        if k.cls == _LABEL:
            labels.setdefault(k.label_name(), k)
    idx_of = {id(k): i for i, k in enumerate(kids)}

    # --- subroutine-local containment + retsub return prediction -----------
    # Entries = labels targeted by some callsub; each one's body is its closure
    # under _aux_succ. A retsub's predicted returns are the lines after every
    # callsub to the entries whose body contains it.
    callsubs_to: dict[str, list[_Node]] = {}
    for k in kids:
        if k.cls == _CALLSUB and (tgt := labels.get(k.operand())):
            callsubs_to.setdefault(tgt.label_name(), []).append(k)

    entry_body: dict[str, set[int]] = {}
    for name in callsubs_to:
        seen: set[int] = set()
        stack = [labels[name]]
        while stack:
            cur = stack.pop()
            ci = idx_of[id(cur)]
            if ci in seen:
                continue
            seen.add(ci)
            stack.extend(_aux_succ(cur, nxt_of[ci], labels))
        entry_body[name] = seen

    def retsub_returns(rn: _Node) -> list[tuple[_Node, _Node]]:
        ri = idx_of[id(rn)]
        outs: list[tuple[_Node, _Node]] = []
        for name, body in entry_body.items():
            if ri in body:
                for c in callsubs_to[name]:
                    nx = nxt_of[idx_of[id(c)]]
                    if nx is not None:
                        outs.append((nx, c))      # (continuation, its callsub)
        return outs

    # --- build candidate edges ---------------------------------------------
    for i, n in enumerate(kids):
        nxt = nxt_of[i]

        if n.cls in _EXIT:
            continue  # return/err -> program exit; no matching succ type

        if n.cls == _ASSERT:
            if nxt is not None:
                emit(n, nxt, BOOL_TRUE)
            continue

        if n.cls == _B:
            if (t := labels.get(n.operand())) is not None:
                emit(n, t, NORMAL)
            continue

        if n.cls == _CALLSUB:
            if (t := labels.get(n.operand())) is not None:
                emit(n, t, NORMAL)
            continue

        if n.cls == _BNZ:
            if (t := labels.get(n.operand())) is not None:
                emit(n, t, BOOL_TRUE)
            if nxt is not None:
                emit(n, nxt, BOOL_FALSE)
            continue

        if n.cls == _BZ:
            if (t := labels.get(n.operand())) is not None:
                emit(n, t, BOOL_FALSE)
            if nxt is not None:
                emit(n, nxt, BOOL_TRUE)
            continue

        if n.cls in _MULTI:
            if nxt is not None:  # arm 0 = fall-through
                emit(n, nxt, NORMAL)
            for name in n.operands():
                if (t := labels.get(name)) is not None:
                    emit(n, t, NORMAL)
            continue

        if n.cls == _RETSUB:
            for r, c in retsub_returns(n):
                retsub_cand.append((n, r, c))     # gated on reachability below
            continue

        # Normal flow (ordinary opcode, label, pragma): fall through.
        if nxt is not None:
            emit(n, nxt, NORMAL)

    # --- reachability from the entry (getChild(0)) -------------------------
    # HAZARD: a `retsub` is context-INSENSITIVE -- it fans a return edge out to
    # EVERY caller's continuation. When a callsub is itself unreachable, its
    # `callsub -> callee` edge is pruned (unreachable predecessor) but the
    # matching `retsub -> continuation` edge would survive (the retsub IS
    # reachable, from live sites), leaving that continuation reachable only via a
    # return-with-no-reachable-call. That phantom inflates the callee's return
    # count past its reachable call count and corrupts the lift. So keep a
    # retsub-return live only while its callsub is reachable, to a fixpoint:
    # dropping one can make a downstream callsub in a dead call chain
    # unreachable, cascading until the whole dead region is gone.
    def _reach(live_retsub: list[tuple[_Node, _Node, _Node]]) -> set[int]:
        adj: dict[int, list[_Node]] = {}
        for p, s, _t in cand:
            adj.setdefault(idx_of[id(p)], []).append(s)
        for rn, r, _c in live_retsub:
            adj.setdefault(idx_of[id(rn)], []).append(r)
        seen: set[int] = set()
        stack2 = [kids[0]]
        while stack2:
            cur = stack2.pop()
            ci = idx_of[id(cur)]
            if ci in seen:
                continue
            seen.add(ci)
            stack2.extend(adj.get(ci, ()))
        return seen

    live = retsub_cand
    reachable = _reach(live)
    while True:
        nxt_live = [(rn, r, c) for (rn, r, c) in live if idx_of[id(c)] in reachable]
        if len(nxt_live) == len(live):
            break
        live = nxt_live
        reachable = _reach(live)
    for rn, r, _c in live:
        emit(rn, r, NORMAL)

    return cand, reachable, idx_of


# Opcode classes that END a codeblock (as does any node followed by a label).
_ENDS_CLASSES = frozenset(
    {_B, _CALLSUB, _RETSUB, _BZ, _BNZ, _SWITCH, _MATCH, _RETURN, _ERR, _ASSERT,
     _ITXN_SUBMIT}
)


def build_basic_blocks(nodes) -> list:
    """Basic blocks as ``(AstNode, bbFirstLine, bbLastLine)``, one per reachable node.

    In TEAL a basic block coincides exactly with a codeblock (the maximal
    straight-line region between labels / branch boundaries): every join, branch
    successor and boolean-edge target already starts one. So the partition is
    structural and is only intersected with CFG reachability.
    """
    rows: list = []
    for _file, kids in _children(nodes).items():
        if not kids:
            continue
        _cand, reachable, _idx = _program_cfg(kids)

        def ends_codeblock(i: int) -> bool:
            if kids[i].cls in _ENDS_CLASSES:
                return True
            return i + 1 < len(kids) and kids[i + 1].cls == _LABEL

        # Partition the child sequence into codeblocks [first .. last].
        start = 0
        for i in range(len(kids)):
            if ends_codeblock(i) or i == len(kids) - 1:
                first_ln, last_ln = kids[start].line, kids[i].line
                for m in range(start, i + 1):
                    if m in reachable:
                        rows.append((kids[m].ast, first_ln, last_ln))
                start = i + 1
    return rows

