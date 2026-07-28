"""Inner-transaction field grouping — which inner-transaction ``(start, end)``
pair each ``itxn_field`` belongs to, for
:class:`tealql.tealtools.inner_txn_report.InnerTxnReport`.
"""
from __future__ import annotations

from .models import Phi, SSAVar
from .program import SSAProgram


def compute_inner_txn_fields(prog: SSAProgram) -> list:
    """One row per ``itxn_field`` × immediately-enclosing ``(start, end)`` pair,
    where a start is ``itxn_begin``/``itxn_next``, an end is
    ``itxn_submit``/``itxn_next``, and "immediately" means CFG-forward reach with
    no other start between start and field (resp. no other end after it).
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

    # Per-assignment ``(BB, op_index)`` — lets ``_op_reaches`` tell same-BB order
    # from across-BB CFG reach.
    op_idx: dict = {}
    for b in prog.blocks.values():
        for i, a in enumerate(b.assignments):
            op_idx[id(a)] = (b, i)

    # BB-level forward reachability (transitive successors, source BB included).
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
            # Forward within the block, OR backward around a DIRECT self-loop: in
            # a single-block loop body an `itxn_field` written textually above its
            # `itxn_begin` still reaches it next lap. Keyed on a real self-edge,
            # NOT `bb_forward` membership — any block inside a larger cycle
            # reaches itself, which would make every op reach every other and
            # collapse the boundary pairing entirely.
            return src_i <= dst_i or src_bb in getattr(src_bb, "successors", ())
        return dst_bb in bb_forward[src_bb]

    def _resolve_def_key(op_input):
        """The row's ``(kind, file, line, idx)`` for an :class:`SSAVar` /
        :class:`Phi`, or ``None`` for anything else (``Const``, unresolved)."""
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
        # ``itxn_field`` consumes exactly one operand, and the row's ``def`` IS
        # that operand — NOT a phi's args. ``inner_txn_report._resolve_operand``
        # expands the phi itself to ``{100 | 200}``; fanning out per arg here
        # would emit one row each and render ``(set@L30, L30, …)``.
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
