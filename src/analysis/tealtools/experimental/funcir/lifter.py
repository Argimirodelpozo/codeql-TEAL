"""Lift a TEAL :class:`SSAProgram` + its control tree into the
structured IR.

Process:

1. Materialise phis (the SSA layer already supports this — turns
   phi-merges at joins into ``mat_phi_k = arg`` copy assignments,
   so the lifter doesn't have to invent loop-carried state).
2. Build the control tree.
3. Recursively lift each region:

   - :class:`BlockR` → a chain of :class:`Let` / :class:`Assign` /
     :class:`Assert` / :class:`Return` / :class:`Halt` / :class:`Call`
     statements. The terminal branch op (``bnz`` / ``bz`` / ``b`` /
     ``switch`` / ``match`` / ``callsub``) is consumed by the parent
     region and doesn't appear in the IR Block directly.
   - :class:`SequenceR` → a Block of the lifted children.
   - :class:`IfR` / :class:`IfElseR` → ``If`` / ``IfElse`` with the
     cond expression extracted from the cond block's terminal
     branch op.
   - :class:`SwitchR` → ``Switch`` with the selector and N arms.
   - :class:`GuardR` → :class:`Guard` (early-exit pattern).
   - :class:`LoopR` → :class:`Loop` containing the body with an
     explicit ``If(not back_edge_cond, Break)`` at the end of the
     back-edge BB. Phis at the loop header have already become
     ``Assign`` to ``mat_phi_k`` vars, so the loop body just looks
     like a normal sequence with re-assignments inside.
   - :class:`ImproperR` → :class:`Unstructured` (best-effort dump).
   - :class:`ProgramR` → :class:`Prog` with one main per program +
     a dict of subroutines.
"""
from __future__ import annotations

from typing import Optional

from ...control_tree import (
    BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR,
    ImproperR, ProgramR, SubroutineR, Region, build_control_tree,
)
from ...ssa import (
    BasicBlock, Assignment, SSAProgram, SSAVar, MatPhiVar, Const, Phi,
)
from . import ir


# Ops that end a BB's contribution to forward control flow.
# These are absorbed by parent regions (If/IfElse/Switch/Loop/Guard).
# We don't emit them as Block-internal statements — the structure they
# encode is already represented by the surrounding region.
_BRANCH_OPS = frozenset({"bnz", "bz", "b", "switch", "match"})
# Terminator ops that translate to specific IR statements.
_TERMINATOR_TO_IR = {
    "return": ir.Return,
    "retsub": ir.Return,
    "err": ir.Halt,
}
# Stack-manipulation ops whose SSA representation carries the full
# stack as inputs and produces a slightly-larger stack as outputs.
# For decompilation we suppress the noisy stack-snapshot args, show
# only the immediate, and keep just the "newly-pushed" output (the
# last entry in ``outputs``).
_STACK_OPS = frozenset({
    "frame_dig", "frame_bury", "dup", "dup2", "dupn", "swap",
    "cover", "uncover", "bury", "popn", "select", "proto",
})


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


_used_names: set[str] = set()           # populated per ``lift()`` call
_alias_map: dict = {}                   # MatPhiVar → resolved source Operand


def _collect_used_names(prog: SSAProgram) -> set[str]:
    """Walk every assignment and collect the names of every operand
    that's *consumed*. Outputs whose names don't appear in this set
    are dead — safe for the lifter to drop in the printed IR. Used
    primarily to clean up stack-snapshot outputs of ``frame_dig``,
    ``dup``, etc. that the SSA layer produces but nothing reads."""
    used: set[str] = set()
    for bb in prog.blocks.values():
        for a in bb.assignments:
            for inp in a.inputs:
                used.add(_var_name(inp))
    return used


def _build_alias_map(prog: SSAProgram) -> dict:
    """Single-assignment alias collapse.

    ``materialize_phis`` introduces ``mat_phi_k = leaf_ssavar`` copy
    assignments at every phi leaf. When a particular ``mat_phi_k``
    has exactly one such assignment, it's just an alias for that
    leaf — substituting the leaf at every use of the mat_phi and
    dropping the copy keeps the IR semantics identical and removes
    a lot of cosmetic noise (see the xgov L323 / consensus_v3 cases
    where one input ``intc_0`` fans out to dozens of mat_phi copies
    that are each then read once).

    We only substitute when the source is a *direct* value
    (``SSAVar`` / ``MatPhiVar`` / ``Const``) — never an ``App``
    expression — so we never duplicate side-effecting ops or change
    evaluation cardinality. Aliases chain transitively
    (``mat_phi_a = mat_phi_b = mat_phi_c = X`` collapses to
    ``mat_phi_a → X``)."""
    counts: dict = {}
    sources: dict = {}
    for bb in prog.blocks.values():
        for a in bb.assignments:
            if getattr(a, "shuffled", False):
                continue
            if a.op != "=" or len(a.outputs) != 1 or not a.inputs:
                continue
            out = a.outputs[0]
            if not isinstance(out, MatPhiVar):
                continue
            counts[out] = counts.get(out, 0) + 1
            sources[out] = a.inputs[0]
    alias: dict = {}
    for mp, c in counts.items():
        if c != 1:
            continue
        src = sources[mp]
        if isinstance(src, (SSAVar, MatPhiVar, Const)):
            alias[mp] = src
    # Transitive resolution — collapse alias chains.
    resolved: dict = {}
    for mp in alias:
        cur = alias[mp]
        seen = {mp}
        while isinstance(cur, MatPhiVar) and cur in alias and cur not in seen:
            seen.add(cur)
            cur = alias[cur]
        resolved[mp] = cur
    return resolved


def lift(prog: SSAProgram) -> ir.Prog:
    """Lift ``prog`` into a :class:`ir.Prog`.

    Runs the standard SSA-cleanup pipeline before lifting (every pass
    is idempotent):

    1. :meth:`SSAProgram.propagate_constants` — set ``const_value`` on
       SSAVars whose producer is a literal-pushing op so consumers can
       inline the constant instead of an SSA name.
    2. :meth:`SSAProgram.propagate_stack_shuffles` — rewrite every
       consumer of a pure stack-shuffle op (``frame_dig``, ``dup``,
       ``swap``, ...) to read the source input directly. Eliminates
       the stack-snapshot noise; the shuffle assignments themselves
       are marked ``shuffled=True`` and ignored at lift time.
    3. :meth:`SSAProgram.materialize_phis` — turn live phis into
       :class:`MatPhiVar` copy assignments so the lifter doesn't
       need an extra phi/loop-carried-state pass.

    We deliberately skip ``eliminate_dead_constants`` here — it
    inlines constant SSAVars into phi args, which then have no
    def-site for ``materialize_phis`` to anchor a copy assignment
    on, dropping loop-counter initialisations. The const inlining
    is partially achieved anyway by ``propagate_constants`` +
    :meth:`Assignment.functional`'s ``resolve_consts`` flag.
    """
    prog.propagate_constants()
    prog.propagate_stack_shuffles()
    prog.materialize_phis()
    global _used_names, _alias_map
    _alias_map = _build_alias_map(prog)
    # Recompute used names *after* alias inlining — once a mat_phi is
    # aliased away its name no longer counts as "used".
    _used_names = _collect_used_names(prog) - {_var_name(mp) for mp in _alias_map}
    tree = build_control_tree(prog)

    if isinstance(tree, ProgramR):
        mains: list[ir.Stmt] = []
        subs: dict[str, ir.Sub] = {}
        # Stable naming: subroutines are sub_<file>_<line> of the entry BB.
        for entry_bb, body_region in tree.subroutines.items():
            name = _sub_name(entry_bb)
            params = _sub_params(entry_bb)
            subs[name] = ir.Sub(
                name=name, params=params, body=_lift_region(body_region)
            )
        for prog_region in tree.programs:
            mains.append(_lift_region(prog_region))
        return ir.Prog(mains=mains, subs=subs)

    # Single-program DB, no subroutines.
    return ir.Prog(mains=[_lift_region(tree)], subs={})


# ---------------------------------------------------------------------------
# Region → Stmt dispatch
# ---------------------------------------------------------------------------


def _lift_region(region: Region) -> ir.Stmt:
    if isinstance(region, BlockR):
        return _lift_block(region.bb)
    if isinstance(region, SequenceR):
        parts = [_lift_region(p) for p in region.parts]
        return ir.Block(_flatten(parts))
    if isinstance(region, IfR):
        return _lift_if(region)
    if isinstance(region, IfElseR):
        return _lift_ifelse(region)
    if isinstance(region, SwitchR):
        return _lift_switch(region)
    if isinstance(region, GuardR):
        return _lift_guard(region)
    if isinstance(region, LoopR):
        return _lift_loop(region)
    if isinstance(region, ImproperR):
        return _lift_improper(region)
    if isinstance(region, SubroutineR):
        return _lift_region(region.body)
    # ProgramR shouldn't reach here in single-region contexts.
    return ir.Block([ir.Unstructured(label=f"<{type(region).__name__}>", body=[])])


# ---------------------------------------------------------------------------
# Block lifting (the workhorse)
# ---------------------------------------------------------------------------


def _lift_block(bb: BasicBlock, *, include_terminal: bool = False) -> ir.Stmt:
    """Lift a BB to a Block of statements. By default, the BB's
    terminal branch op (bnz/bz/b/switch/match) is *omitted* — the
    parent If/IfElse/Switch/Loop/Guard region encodes it.

    Stack-shuffle assignments whose outputs were already
    copy-propagated by ``propagate_stack_shuffles`` (and so are
    marked ``shuffled=True``) are skipped — they're no-ops at this
    point, only kept on the SSA for inspection.

    ``include_terminal=True`` forces all assignments to be lifted —
    useful when the BB has *no* terminal branch (e.g., the last BB
    of an Improper sequence)."""
    stmts: list[ir.Stmt] = []
    for i, a in enumerate(bb.assignments):
        is_last = i == len(bb.assignments) - 1
        if getattr(a, "shuffled", False):
            continue  # already copy-propagated into consumers
        if is_last and not include_terminal and a.op in _BRANCH_OPS:
            # Branch absorbed by parent region.
            continue
        if a.op in _TERMINATOR_TO_IR:
            stmts.append(_lift_terminator(a))
            continue
        if a.op == "assert":
            stmts.append(ir.Assert(value=_operand_expr(a.inputs[0]) if a.inputs else ir.Lit(0)))
            continue
        if a.op == "callsub":
            stmts.append(_lift_callsub(a, bb))
            continue
        stmts.append(_lift_assignment(a))
    # Drop empty-Block placeholders that the dead-mat-phi filter left.
    stmts = [s for s in stmts if not _is_empty_block(s)]
    if len(stmts) == 1:
        return stmts[0]
    return ir.Block(stmts)


def _lift_assignment(a: Assignment) -> ir.Stmt:
    """Lift a non-branch, non-terminator op to a statement.

    Output selection: outputs whose SSA names appear in
    :data:`_used_names` are kept; ones that nothing reads downstream
    are dropped (these are typically stack-snapshot carry-throughs
    that the SSA layer produces for ``frame_dig`` / ``dup`` /
    ``frame_bury`` etc.). If *no* outputs are used, the last one is
    kept as the "interesting" one (and the assignment is shown so
    the side effect / stack push is visible).

    For known stack-manipulation ops (:data:`_STACK_OPS`), the input
    args (which would be a noisy stack snapshot) are suppressed —
    these ops carry their meaning entirely in their immediates."""
    # Fast path: drop the copy if the target was alias-collapsed or
    # is genuinely dead. ``materialize_phis`` inserts
    # ``mat_phi_k = leaf_ssavar`` at every leaf — once we've inlined
    # single-assignment aliases at every use, or if the target was
    # never read anywhere, the copy itself is no-op.
    if (
        a.op == "="
        and len(a.outputs) == 1
        and isinstance(a.outputs[0], MatPhiVar)
        and (
            a.outputs[0] in _alias_map
            or _var_name(a.outputs[0]) not in _used_names
        )
    ):
        return ir.Block([])  # printed as nothing; flattens away
    suppress_args = a.op in _STACK_OPS
    if suppress_args:
        # Keep the *value* arg for frame_bury (inputs[0] is the value
        # being buried; the rest is stack-frame carry-through). Other
        # stack ops genuinely have no useful arg to keep.
        if a.op == "frame_bury" and a.inputs:
            args: list[ir.Expr] = [_operand_expr(a.inputs[0])]
        else:
            args = []
    else:
        args = [_operand_expr(o) for o in a.inputs]
    expr = ir.App(op=a.op, immediates=a.immediates or "", args=args)
    if not a.outputs:
        return ir.Let(targets=[], value=expr)
    # Use-analysis filtering of outputs.
    target_names = [_var_name(o) for o in a.outputs]
    relevant_idx = [i for i, t in enumerate(target_names) if t in _used_names]
    if not relevant_idx:
        relevant_idx = [len(target_names) - 1]
    kept_targets = [target_names[i] for i in relevant_idx]
    # If the only kept output is a MatPhiVar, emit Assign.
    if (
        len(kept_targets) == 1
        and isinstance(a.outputs[relevant_idx[0]], MatPhiVar)
    ):
        return ir.Assign(target=kept_targets[0], value=expr)
    return ir.Let(targets=kept_targets, value=expr)


def _lift_terminator(a: Assignment) -> ir.Stmt:
    """``return`` / ``retsub`` / ``err`` → IR statement."""
    if a.op == "err":
        return ir.Halt()
    val = _operand_expr(a.inputs[0]) if a.inputs else None
    kind = "retsub" if a.op == "retsub" else "return"
    return ir.Return(value=val, kind=kind)


def _lift_callsub(a: Assignment, bb: BasicBlock) -> ir.Stmt:
    """``callsub target`` — emit ``Call(name, args, results)``.
    Resolves the target via the BB's successor (the SSA already
    points the BB at the sub entry)."""
    args = [_operand_expr(o) for o in a.inputs]
    results = [_var_name(o) for o in a.outputs]
    sub_name = (a.immediates or "").strip() or _sub_name_from_succ(bb)
    return ir.Call(sub_name=sub_name, args=args, results=results)


def _sub_name_from_succ(bb: BasicBlock) -> str:
    if bb.successors:
        return _sub_name(bb.successors[0])
    return "<unknown>"


# ---------------------------------------------------------------------------
# Control-flow region lifters
# ---------------------------------------------------------------------------


def _extract_cond(cond_region: Region) -> tuple[ir.Stmt, ir.Expr, bool]:
    """Lift the cond region to a Stmt and extract the cond expression
    + negation flag from its terminal branch op (bnz/bz). Returns
    ``(prelude_stmt, cond_expr, negated)``. ``negated`` is True for
    ``bz`` (we want ``cond_expr`` to read as "true → take the arm";
    ``bz target`` means "jump if zero", so the cond is effectively
    ``not value``)."""
    # Find the *last* BB in cond_region — that's where the branch is.
    last_bb = _last_bb(cond_region)
    if last_bb is None or not last_bb.assignments:
        return _lift_region(cond_region), ir.Lit(0), False
    branch_op = last_bb.assignments[-1]
    if branch_op.op not in _BRANCH_OPS or not branch_op.inputs:
        return _lift_region(cond_region), ir.Lit(0), False
    cond_expr = _operand_expr(branch_op.inputs[0])
    negated = branch_op.op == "bz"
    return _lift_region(cond_region), cond_expr, negated


def _last_bb(region: Region) -> Optional[BasicBlock]:
    """The last BB in source order within this region — where the
    branch op lives, if any."""
    bbs = list(region.basic_blocks())
    if not bbs:
        return None
    return max(
        bbs,
        key=lambda b: (
            (b.assignments[-1].location.file, b.assignments[-1].location.line)
            if b.assignments else ("", 0)
        ),
    )


def _branch_target_bb(cond_region: Region) -> Optional[BasicBlock]:
    """The BB the cond's bnz/bz jumps to on its *taken* path. For bnz
    this is the labelled successor (jump on nonzero); for bz it's
    likewise the labelled successor (jump on zero). Used to figure
    out which of an IfElseR's two arms is the structural ``then``."""
    last_bb = _last_bb(cond_region)
    if last_bb is None or not last_bb.assignments:
        return None
    last_op = last_bb.assignments[-1]
    if last_op.op not in ("bnz", "bz") or not last_bb.successors:
        return None
    # The branch target's label is in immediates; we resolve by
    # finding whichever successor's first assignment's line matches
    # the labelled target. As a simple heuristic, the branch target
    # is the successor whose entry line is *not* the source-order
    # next BB after the cond. We pick whichever successor's first
    # line is furthest from the cond's last line.
    cond_line = last_op.location.line
    cands = [
        s for s in last_bb.successors
        if s.assignments and s.assignments[0].location.line > cond_line
    ]
    if len(cands) < 2:
        # Single successor or back-jump — can't disambiguate. Bail.
        return None
    cands.sort(key=lambda s: s.assignments[0].location.line)
    # Smallest line above cond is the fall-through; furthest is the
    # branch target (compiled TEAL emits the labelled-jump target
    # later in source order).
    return cands[-1]


def _arm_starts_at(region: Region, target_bb: Optional[BasicBlock]) -> bool:
    """True if ``region``'s entry BB is ``target_bb``."""
    if target_bb is None:
        return False
    for bb in region.basic_blocks():
        return bb is target_bb
    return False


def _lift_if(region: IfR) -> ir.Stmt:
    prelude, cond, negated = _extract_cond(region.cond)
    then_stmt = _lift_region(region.then_branch)
    # Check if the structural ``then`` is actually the bnz-target arm.
    target = _branch_target_bb(region.cond)
    if target is not None and not _arm_starts_at(region.then_branch, target):
        # The structural ``then`` is the fall-through, not the branch
        # target — flip the cond.
        negated = not negated
    if_stmt = ir.If(cond=cond, then=then_stmt, negated=negated)
    return ir.Block(_flatten([prelude, if_stmt]))


def _lift_ifelse(region: IfElseR) -> ir.Stmt:
    prelude, cond, negated = _extract_cond(region.cond)
    then_stmt = _lift_region(region.then_branch)
    else_stmt = _lift_region(region.else_branch)
    # Make sure the printed ``then`` arm is the branch-taken arm.
    target = _branch_target_bb(region.cond)
    if target is not None and not _arm_starts_at(region.then_branch, target):
        then_stmt, else_stmt = else_stmt, then_stmt
    ifelse = ir.IfElse(
        cond=cond, then_=then_stmt, else_=else_stmt, negated=negated
    )
    return ir.Block(_flatten([prelude, ifelse]))


def _lift_switch(region: SwitchR) -> ir.Stmt:
    # Cond region's last op is ``switch`` / ``match`` — extract the
    # selector value and the labelled targets.
    last_bb = _last_bb(region.cond)
    labels: list[str] = []
    if last_bb and last_bb.assignments and last_bb.assignments[-1].op in _BRANCH_OPS:
        sel_op = last_bb.assignments[-1]
        cond_expr = _operand_expr(sel_op.inputs[0]) if sel_op.inputs else ir.Lit(0)
        # The op's immediates carry the label names: "L100 L200 L300"
        # (or comma-separated in some emitters).
        imm = (sel_op.immediates or "").replace(",", " ").split()
        labels = imm
    else:
        cond_expr = ir.Lit(0)
    arms = [_lift_region(c) for c in region.cases]
    sw = ir.Switch(cond=cond_expr, arms=arms, labels=labels)
    prelude = _lift_region(region.cond)
    return ir.Block(_flatten([prelude, sw]))


def _lift_guard(region: GuardR) -> ir.Stmt:
    prelude, cond, negated = _extract_cond(region.cond)
    exit_stmt = _lift_region(region.exit_arm)
    g = ir.Guard(cond=cond, exit_arm=exit_stmt, negated=negated)
    return ir.Block(_flatten([prelude, g]))


def _lift_loop(region: LoopR) -> ir.Stmt:
    """A LoopR's body (region.body) is itself a Region — sequence or
    block. The back-edge is implicit in the SSA's CFG; the body's
    last BB ends in ``bnz top`` (continue) or ``b top``
    (unconditional). For ``bnz``, we emit
    ``Loop(body=Block([body_stmts..., If(not cond, Break)]))`` —
    a do-while.

    ``mat_phi_k = ...`` Assignments inside the body just look like
    re-assignments to a mutable loop variable. No explicit
    loop-carried state syntax needed."""
    body_region = region.body
    body_stmt = _lift_region(body_region)
    # Find the back-edge's source BB inside the loop nodes — that's
    # where the back-edge branch lives.
    back_edge_srcs = {src for src, _ in region.loop.back_edges}
    cond_expr: Optional[ir.Expr] = None
    negated_back = False
    for back_src in back_edge_srcs:
        if not back_src.assignments:
            continue
        last = back_src.assignments[-1]
        if last.op in ("bnz", "bz") and last.inputs:
            cond_expr = _operand_expr(last.inputs[0])
            # bnz target = continue if nonzero → exit if zero → break_cond = not cond
            # bz target = continue if zero → exit if nonzero → break_cond = cond
            negated_back = (last.op == "bnz")
            break
    if cond_expr is None:
        # Unconditional back-edge or detection failed. Emit Loop with
        # a placeholder break that never fires (caller can post-process).
        return ir.Loop(body=body_stmt)
    # Append "if break-condition: Break" to the body.
    break_stmt = ir.If(
        cond=cond_expr,
        then=ir.Break(),
        negated=negated_back,
    )
    if isinstance(body_stmt, ir.Block):
        body_stmt.body.append(break_stmt)
        return ir.Loop(body=body_stmt)
    return ir.Loop(body=ir.Block([body_stmt, break_stmt]))


# ---------------------------------------------------------------------------
# Improper-as-labelled-gotos rendering
# ---------------------------------------------------------------------------


def _lift_improper(region: ImproperR) -> ir.Stmt:
    """Render an irreducible region as a sequence of labelled child
    regions plus explicit gotos. The interior of an Improper is
    acyclic by construction (loops were collapsed in Phase 1 of
    :func:`build_control_tree`), so we topologically order the nodes
    and emit ``Label`` / ``Goto`` / ``IfGoto`` for the in-region edges
    that don't naturally fall through."""
    import networkx as nx

    g = nx.DiGraph()
    for n in region.nodes:
        g.add_node(n)
    for u, v in region.edges:
        g.add_edge(u, v)
    try:
        topo = list(nx.topological_sort(g))
    except nx.NetworkXUnfeasible:
        # Cyclic — bail to flat body (no gotos).
        return ir.Unstructured(
            label=f"improper-cyclic ({len(region.nodes)} nodes)",
            body=_flatten([_lift_region(c) for c in region.nodes]),
        )

    # Map each region to a label.
    label_for: dict = {}
    for r in topo:
        first_bb = next(iter(r.basic_blocks()), None)
        if first_bb and first_bb.assignments:
            loc = first_bb.assignments[0].location
            label_for[id(r)] = f"L{loc.line}"
        else:
            label_for[id(r)] = f"node_{id(r) & 0xFFFF}"

    body: list[ir.Stmt] = []
    for idx, r in enumerate(topo):
        body.append(ir.Label(name=label_for[id(r)]))
        # Lift the region. For BlockR, lift with the terminal branch
        # included so we can convert it to a Goto/IfGoto.
        if isinstance(r, BlockR):
            lifted = _lift_block_with_terminal(r.bb, label_for, g)
        else:
            lifted = _lift_region(r)
        body.append(lifted)
        # Fall-through: the next region in topo order. If the lifted
        # block already ends in a Goto/Return/Halt/Break, no extra
        # statement needed. Else, if there are out-edges, emit goto
        # to the topo-next node (or whichever is the "natural" next).
        next_in_topo = topo[idx + 1] if idx + 1 < len(topo) else None
        succs = [s for s in g.successors(r)]
        if (
            succs
            and next_in_topo in succs
            and not _ends_with_transfer(lifted)
        ):
            # Fall-through goto only if there are multiple successors
            # and the natural fall-through is ambiguous. For a single
            # successor that is the topo-next, fall-through is implicit.
            if len(succs) > 1:
                body.append(ir.Goto(target=label_for[id(next_in_topo)]))

    return ir.Unstructured(
        label=f"improper ({len(region.nodes)} nodes, {len(region.edges)} edges)",
        body=body,
    )


def _lift_block_with_terminal(
    bb: BasicBlock, label_for: dict, g
) -> ir.Stmt:
    """Like :func:`_lift_block` but emits Goto / IfGoto for the
    terminal branch op (instead of dropping it) — for use inside
    :func:`_lift_improper` where parent regions don't absorb the
    branch."""
    stmts: list[ir.Stmt] = []
    for i, a in enumerate(bb.assignments):
        is_last = i == len(bb.assignments) - 1
        if not is_last:
            stmts.append(_dispatch_op(a, bb))
            continue
        # Terminal: convert branches to gotos.
        if a.op == "b":
            # Unconditional branch — target is the BB's sole successor.
            succ = bb.successors[0] if bb.successors else None
            target_label = _label_for_succ(succ, label_for)
            stmts.append(ir.Goto(target=target_label))
        elif a.op in ("bnz", "bz"):
            cond = _operand_expr(a.inputs[0]) if a.inputs else ir.Lit(0)
            negated = a.op == "bz"
            target_bb = _branch_target_succ(bb, a)
            target_label = _label_for_succ(target_bb, label_for)
            stmts.append(ir.IfGoto(cond=cond, target=target_label, negated=negated))
        elif a.op in _BRANCH_OPS:
            # switch/match: fall back to a verbose Goto-list.
            for succ in bb.successors:
                target_label = _label_for_succ(succ, label_for)
                stmts.append(ir.Goto(target=target_label))
        elif a.op in _TERMINATOR_TO_IR:
            stmts.append(_lift_terminator(a))
        elif a.op == "assert":
            stmts.append(ir.Assert(value=_operand_expr(a.inputs[0]) if a.inputs else ir.Lit(0)))
        elif a.op == "callsub":
            stmts.append(_lift_callsub(a, bb))
        else:
            stmts.append(_lift_assignment(a))
    if len(stmts) == 1:
        return stmts[0]
    return ir.Block(stmts)


def _dispatch_op(a: Assignment, bb: BasicBlock) -> ir.Stmt:
    """Dispatch a non-terminal op to its lift function."""
    if a.op == "assert":
        return ir.Assert(value=_operand_expr(a.inputs[0]) if a.inputs else ir.Lit(0))
    if a.op == "callsub":
        return _lift_callsub(a, bb)
    if a.op in _TERMINATOR_TO_IR:
        return _lift_terminator(a)
    return _lift_assignment(a)


def _branch_target_succ(bb: BasicBlock, branch_op: Assignment) -> Optional[BasicBlock]:
    """The branch-taken successor of ``bb`` (for bnz/bz)."""
    line = branch_op.location.line
    cands = [
        s for s in bb.successors
        if s.assignments and s.assignments[0].location.line > line
    ]
    if len(cands) < 2:
        # Fall-back: take the sole successor that's far from current.
        return bb.successors[-1] if bb.successors else None
    cands.sort(key=lambda s: s.assignments[0].location.line)
    return cands[-1]


def _label_for_succ(bb, label_for: dict) -> str:
    if bb is None:
        return "<exit>"
    for k, v in label_for.items():
        # We keyed by id(region); match by checking if region's first
        # BB equals this BB.
        # Look up the region whose id matches the key.
        pass
    # Simple fallback: label by line.
    if bb.assignments:
        return f"L{bb.assignments[0].location.line}"
    return "<unknown>"


def _ends_with_transfer(stmt: ir.Stmt) -> bool:
    if isinstance(stmt, (ir.Goto, ir.Return, ir.Halt, ir.Break)):
        return True
    if isinstance(stmt, ir.Block) and stmt.body:
        return _ends_with_transfer(stmt.body[-1])
    return False


# ---------------------------------------------------------------------------
# Operand / name conversion
# ---------------------------------------------------------------------------


def _operand_expr(o) -> ir.Expr:
    if isinstance(o, Const):
        return _const_expr(o)
    if isinstance(o, MatPhiVar):
        # Single-assignment alias: substitute the resolved source so
        # ``*m37`` references inline to the underlying SSAVar / Const.
        if o in _alias_map:
            return _operand_expr(_alias_map[o])
        return ir.Ref(name=_var_name(o), is_mut=True)
    if isinstance(o, SSAVar):
        return ir.Ref(name=_var_name(o), is_mut=False)
    if isinstance(o, Phi):
        # After materialize_phis, raw Phi shouldn't appear — but be defensive.
        return ir.Ref(name=f"phi@L{o.line}_{o.stack_index}", is_mut=True)
    return ir.Lit(value=str(o))


def _const_expr(c: Const) -> ir.Expr:
    val = getattr(c, "value", None)
    if val is None:
        return ir.Lit(value=repr(c))
    if isinstance(val, int):
        return ir.Lit(value=val, kind="int")
    if isinstance(val, bytes):
        return ir.Lit(value=val, kind="bytes")
    return ir.Lit(value=val, kind="other")


def _var_name(o) -> str:
    if isinstance(o, MatPhiVar):
        return f"m{o.index}"
    if isinstance(o, SSAVar):
        return f"v{o.line}_{o.index}"
    return f"<{type(o).__name__}>"


def _sub_name(entry_bb: BasicBlock) -> str:
    if not entry_bb.assignments:
        return "sub_unknown"
    first = entry_bb.assignments[0]
    f = first.location.file.split("/")[-1].replace(".", "_")
    return f"sub_{f}_L{first.location.line}"


def _sub_params(entry_bb: BasicBlock) -> list[str]:
    """Read the ``proto N M`` op (if present at the entry) to name
    the subroutine's parameters. Defaults to an empty list otherwise."""
    if not entry_bb.assignments:
        return []
    first = entry_bb.assignments[0]
    if first.op != "proto":
        return []
    # ``proto N M`` — N args, M results. Caller names are unknown
    # statically; use positional names.
    try:
        parts = (first.immediates or "").split()
        n = int(parts[0]) if parts else 0
    except (ValueError, IndexError):
        n = 0
    return [f"p{i}" for i in range(n)]


# ---------------------------------------------------------------------------
# Block flattening helper
# ---------------------------------------------------------------------------


def _flatten(stmts: list[ir.Stmt]) -> list[ir.Stmt]:
    """Flatten one level of nested ``Block`` nodes and drop empty
    ones — keeps the printed IR compact without changing semantics."""
    out: list[ir.Stmt] = []
    for s in stmts:
        if isinstance(s, ir.Block):
            if not s.body:
                continue  # dropped-assignment placeholder
            out.extend(c for c in s.body if not _is_empty_block(c))
        else:
            out.append(s)
    return out


def _is_empty_block(s: ir.Stmt) -> bool:
    return isinstance(s, ir.Block) and not s.body
