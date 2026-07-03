"""Inner-transaction field grouping for SSA programs.

For every ``itxn_field`` opcode, identify the immediately-enclosing
inner-transaction ``(start, end)`` pair via CFG reachability and emit
one row per consumed-value definition; the result is consumed by
:class:`tealql.tealtools.inner_txn_report.InnerTxnReport`.

A construction-time substrate helper: it lives in the ``ssa`` package
but is split out of ``ssa.py`` (which calls it eagerly while building a
program) so the builder stays focused on SSA construction. It is *not*
an optional ``passes/`` analysis — those layer on a finished program;
this one runs as part of producing it (cf. the sibling
:mod:`const_fold` / :mod:`scratch_influence` helpers).
"""
from __future__ import annotations

from .models import Phi, SSAVar
from .program import SSAProgram


def compute_inner_txn_fields(prog: SSAProgram) -> list:
    """For every ``itxn_field`` opcode, identify the immediately-
    enclosing inner-transaction ``(start, end)`` pair via CFG reach
    and emit one row per consumed-value definition.

    A ``start`` is ``itxn_begin`` or ``itxn_next``; an ``end`` is
    ``itxn_submit`` or ``itxn_next``. "Immediately enclosing" means:

      - ``start.reaches(field)`` (CFG-forward) and no other start
        sits between ``start`` and ``field``.
      - ``field.reaches(end)`` and no other end sits between
        ``field`` and ``end``.

    Returns a list of dicts matching the shape consumed by
    :class:`tealql.tealtools.inner_txn_report.InnerTxnReport`.
    """
    start_ops: list = []
    end_ops: list = []
    field_ops: list = []
    for a in prog.assignments:
        if a.op == "itxn_begin":
            start_ops.append((a, "itxn_begin"))
        elif a.op == "itxn_next":
            start_ops.append((a, "itxn_next"))
            end_ops.append((a, "itxn_next"))
        elif a.op == "itxn_submit":
            end_ops.append((a, "itxn_submit"))
        elif a.op == "itxn_field":
            field_ops.append((a, a.immediates.strip()))
    if not field_ops:
        return []

    # Per-assignment ``(BB, op_index)`` map — used by ``_op_reaches``
    # to disambiguate same-BB order from across-BB CFG reach.
    op_idx: dict = {}
    for b in prog.blocks.values():
        for i, a in enumerate(b.assignments):
            op_idx[id(a)] = (b, i)

    # BB-level forward reachability (transitive successors, inclusive
    # of the source BB).
    bb_forward: dict = {}
    for b in prog.blocks.values():
        seen: set = {b}
        stack: list = [b]
        while stack:
            cur = stack.pop()
            for s in cur.successors:
                if s not in seen:
                    seen.add(s)
                    stack.append(s)
        bb_forward[b] = seen

    def _op_reaches(src, dst) -> bool:
        src_info = op_idx.get(id(src))
        dst_info = op_idx.get(id(dst))
        if src_info is None or dst_info is None:
            return False
        src_bb, src_i = src_info
        dst_bb, dst_i = dst_info
        if src_bb is dst_bb:
            return src_i <= dst_i
        return dst_bb in bb_forward[src_bb]

    def _resolve_def_key(op_input):
        """Map an :class:`SSAVar` / :class:`Phi` to the row's
        ``(kind, file, line, idx)`` tuple. Returns ``None`` for
        anything else (e.g. ``Const``, unresolved operand)."""
        if isinstance(op_input, SSAVar):
            return ("SSAVar", op_input.file, op_input.line, op_input.index)
        if isinstance(op_input, Phi):
            return (op_input.kind, op_input.file, op_input.line,
                    op_input.stack_index)
        return None

    entries: list = []
    for field_op, field_name in field_ops:
        candidate_starts = [
            s for s, _ in start_ops if _op_reaches(s, field_op)
        ]
        immediate_starts = [
            s for s in candidate_starts
            if not any(
                other is not s
                and _op_reaches(s, other)
                and _op_reaches(other, field_op)
                for other in candidate_starts
            )
        ]
        candidate_ends = [
            e for e, _ in end_ops if _op_reaches(field_op, e)
        ]
        immediate_ends = [
            e for e in candidate_ends
            if not any(
                other is not e
                and _op_reaches(field_op, other)
                and _op_reaches(other, e)
                for other in candidate_ends
            )
        ]

        if not field_op.inputs:
            continue
        # ``itxn_field`` consumes exactly one operand. The row's
        # ``def`` IS that operand (an SSAVar or a Phi) — NOT the phi's
        # args. ``inner_txn_report._resolve_operand`` resolves the phi
        # itself and expands it to ``{100 | 200}`` etc. Fanning out per
        # phi-arg here would emit one row per arg and the report would
        # render ``(set@L30, L30, …)``.
        key = _resolve_def_key(field_op.inputs[0])
        if key is None:
            continue
        def_kind, def_file, def_line, def_idx = key

        for start in immediate_starts:
            if start is field_op:
                continue
            start_kind = (
                "itxn_begin" if start.op == "itxn_begin" else "itxn_next"
            )
            for end in immediate_ends:
                if end is start or end is field_op:
                    continue
                end_kind = (
                    "itxn_submit" if end.op == "itxn_submit" else "itxn_next"
                )
                entries.append({
                    "field_file": field_op.location.file,
                    "field_line": field_op.location.line,
                    "field_name": field_name,
                    "start_line": start.location.line,
                    "start_kind": start_kind,
                    "end_line": end.location.line,
                    "end_kind": end_kind,
                    "def_kind": def_kind,
                    "def_file": def_file,
                    "def_line": def_line,
                    "def_idx": def_idx,
                })
    return entries
