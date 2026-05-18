"""Minimal structured dump for experimental_2.

Walks the existing control tree and renders it as text. The *only*
structural lift is if-else: :class:`IfR` and :class:`IfElseR` render
as ``if (cond) { ... } else { ... }`` (C-style). Every other region
type — sequences, loops, guards, switches, subroutines, improper —
just walks its children plainly at the same indent.

The single rendering cleanup is dropping ``.shuffled`` assignments
(copy-prop residue that consumers already see as direct values).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..control_tree import (
    BlockR,
    GuardR,
    IfElseR,
    IfR,
    LoopR,
    ProgramR,
    Region,
    SequenceR,
    SwitchR,
    build_control_tree,
)
from ..ssa import Assignment, BasicBlock, SSAProgram

from .passes import run_all_passes

_INDENT = "  "


def _build_label_index(prog: SSAProgram) -> dict[tuple[str, int], str]:
    return {(f, line): code.rstrip(":") for f, line, code in prog.labels}


def _bb_label(bb: BasicBlock, labels: dict[tuple[str, int], str]) -> Optional[str]:
    return labels.get((bb.file, bb.first_line))


def _find_branch_terminator(bb: BasicBlock) -> Optional[Assignment]:
    for a in bb.assignments:
        if a.op in ("bnz", "bz"):
            return a
    return None


def _then_runs_when_cond_true(
    term: Assignment,
    cond_bb: BasicBlock,
    then_branch: Region,
    labels: dict[tuple[str, int], str],
) -> bool:
    """Decide whether ``if (term.inputs[0]) { then_branch }`` is the
    correct polarity, or whether we need ``if (!(term.inputs[0])) { ... }``.

    ``bnz`` fires when its input is non-zero; ``bz`` when zero. The
    branch-target BB lives on the *fired* side. If the then_branch
    contains the branch target, the firing side matches the then;
    otherwise the fall-through side matches it. Combined with bnz/bz
    polarity, this tells us whether the SSA value being tested is the
    *exact* truth value of "we should enter the then" — or its
    negation.

    This matters because control_tree's :func:`_try_guard` picks
    *whichever* terminal successor it finds first as the ``exit_arm``,
    not necessarily the bnz-taken one. So a ``GuardR`` whose
    ``exit_arm`` is the fall-through side needs the negated condition.
    """
    target_label = term.immediates.strip()
    target_bb: Optional[BasicBlock] = None
    for s in cond_bb.successors:
        if labels.get((s.file, s.first_line)) == target_label:
            target_bb = s
            break
    if target_bb is None:
        return True  # can't determine; default to positive
    then_bbs = set(then_branch.basic_blocks())
    then_holds_branch_target = target_bb in then_bbs
    branch_fires_when_cond_true = (term.op == "bnz")
    return branch_fires_when_cond_true == then_holds_branch_target


def _render_block(
    bb: BasicBlock,
    labels: dict[tuple[str, int], str],
    indent: int,
    *,
    skip: Optional[Assignment] = None,
) -> list[str]:
    # Labels and assignments render at the same indent — only braces
    # ``{ }`` introduce additional depth. Keeps the C-style layout
    # promised by the if/else lift: cond setup, ``if (...) {``, and
    # ``} else {`` all visually peer.
    pad = _INDENT * indent
    out: list[str] = []
    lbl = _bb_label(bb, labels)
    if lbl:
        out.append(f"{pad}{lbl}:")
    for a in bb.assignments:
        if a is skip or a.shuffled or a.op == "proto":
            continue
        out.append(f"{pad}L{a.location.line:>4}: {a.functional()}")
    return out


def _render_if(
    cond: Region,
    then_branch: Region,
    else_branch: Optional[Region],
    labels: dict[tuple[str, int], str],
    indent: int,
) -> list[str]:
    # Try to extract: cond_bb + a branch terminator (bnz / bz). If we
    # can't (e.g., cond is itself a structured region like a LoopR),
    # render cond and the branches flat at the same indent — no
    # ``if (?) { ... }`` placeholder.
    cond_bb: Optional[BasicBlock] = None
    setup_parts: list[Region] = []
    if isinstance(cond, BlockR):
        cond_bb = cond.bb
    elif isinstance(cond, SequenceR) and cond.parts:
        last = cond.parts[-1]
        if isinstance(last, BlockR):
            cond_bb = last.bb
            setup_parts = list(cond.parts[:-1])

    term: Optional[Assignment] = None
    if cond_bb is not None:
        term = _find_branch_terminator(cond_bb)

    out: list[str] = []
    if cond_bb is None or term is None or not term.inputs:
        out.extend(_render_region(cond, labels, indent))
        out.extend(_render_region(then_branch, labels, indent))
        if else_branch is not None:
            out.extend(_render_region(else_branch, labels, indent))
        return out

    pad = _INDENT * indent
    for setup in setup_parts:
        out.extend(_render_region(setup, labels, indent))
    out.extend(_render_block(cond_bb, labels, indent, skip=term))

    cond_str = repr(term.inputs[0])
    if not _then_runs_when_cond_true(term, cond_bb, then_branch, labels):
        cond_str = f"!({cond_str})"

    out.append(f"{pad}if ({cond_str}) {{")
    out.extend(_render_region(then_branch, labels, indent + 1))
    if else_branch is not None:
        out.append(f"{pad}}} else {{")
        out.extend(_render_region(else_branch, labels, indent + 1))
    out.append(f"{pad}}}")
    return out


def _render_loop(
    r: LoopR,
    labels: dict[tuple[str, int], str],
    indent: int,
) -> list[str]:
    """Render a ``LoopR`` as ``while (cond) { body }`` when the head
    BB has a clean conditional exit (``bnz``/``bz`` with exactly one
    successor inside the loop's SCC); otherwise fall back to a bare
    ``loop { body }``.

    Polarity uses the same logic as ``if``: check whether the
    branch-taken target stays in the loop, then combine with ``bnz``/
    ``bz`` semantics to decide whether the SSA cond value expresses
    "continue while true" (``while (cond)``) or its negation
    (``while (!(cond))``).
    """
    pad = _INDENT * indent

    header_block: Optional[BlockR] = None
    if len(r.loop.entries) == 1:
        header_bb = next(iter(r.loop.entries))
        if isinstance(r.body, BlockR) and r.body.bb is header_bb:
            header_block = r.body
        elif isinstance(r.body, SequenceR) and r.body.parts:
            first = r.body.parts[0]
            if isinstance(first, BlockR) and first.bb is header_bb:
                header_block = first

    term: Optional[Assignment] = None
    if header_block is not None:
        term = _find_branch_terminator(header_block.bb)

    if header_block is None or term is None or not term.inputs:
        out: list[str] = [f"{pad}loop {{"]
        out.extend(_render_region(r.body, labels, indent + 1))
        out.append(f"{pad}}}")
        return out

    target_label = term.immediates.strip()
    target_bb: Optional[BasicBlock] = None
    for s in header_block.bb.successors:
        if labels.get((s.file, s.first_line)) == target_label:
            target_bb = s
            break
    target_in_loop = target_bb in r.loop.nodes if target_bb is not None else False
    branch_fires_when_cond_true = (term.op == "bnz")
    continue_when_cond_true = (branch_fires_when_cond_true == target_in_loop)
    cond_str = repr(term.inputs[0])
    if not continue_when_cond_true:
        cond_str = f"!({cond_str})"

    out = _render_block(header_block.bb, labels, indent, skip=term)
    out.append(f"{pad}while ({cond_str}) {{")
    if isinstance(r.body, SequenceR):
        for part in r.body.parts:
            if part is header_block:
                continue
            out.extend(_render_region(part, labels, indent + 1))
    out.append(f"{pad}}}")
    return out


def _render_region(
    r: Region,
    labels: dict[tuple[str, int], str],
    indent: int,
) -> list[str]:
    if isinstance(r, BlockR):
        return _render_block(r.bb, labels, indent)
    if isinstance(r, IfElseR):
        return _render_if(r.cond, r.then_branch, r.else_branch, labels, indent)
    if isinstance(r, IfR):
        return _render_if(r.cond, r.then_branch, None, labels, indent)
    if isinstance(r, GuardR):
        # Guards reuse the if-lift: `if (cond) { exit_arm }`. The exit
        # arm terminates internally (retsub/return/err), so the missing
        # ``else`` is structurally correct — the continuation is just
        # whatever comes next in the enclosing sequence.
        return _render_if(r.cond, r.exit_arm, None, labels, indent)
    if isinstance(r, LoopR):
        return _render_loop(r, labels, indent)
    if isinstance(r, SwitchR):
        return _render_switch(r, labels, indent)
    if isinstance(r, ProgramR):
        out: list[str] = []
        for p in r.programs:
            out.extend(_render_region(p, labels, indent))
        for entry_bb, sub_body in r.subroutines.items():
            out.append("")
            out.extend(_render_subroutine(entry_bb, sub_body, labels, indent))
        return out
    # Everything else (SequenceR, GuardR, LoopR, SwitchR, ImproperR,
    # SubroutineR): walk children flat at the same indent.
    out_flat: list[str] = []
    for c in r.children():
        out_flat.extend(_render_region(c, labels, indent))
    return out_flat


def _render_switch(
    r: SwitchR,
    labels: dict[tuple[str, int], str],
    indent: int,
) -> list[str]:
    """Render ``SwitchR`` as ``switch (value) { case 0: { ... } ... }``.

    TEAL ``switch L0 L1 L2`` branches to ``L_i`` when the popped value
    equals ``i``, and falls through when out of range. control_tree
    reflects this with ``len(cases) == len(labels)`` for an exhaustive
    cover, or ``len(cases) == len(labels) + 1`` when the fall-through
    has been folded in as the trailing case (which we label
    ``default:``). For ``match L0 L1 L2``, the labels are bytecode
    constants and the same shape applies.

    Falls back to walking ``cond`` and ``cases`` flat if the cond BB
    can't be extracted or has no ``switch``/``match`` terminator.
    """
    pad = _INDENT * indent

    cond_bb: Optional[BasicBlock] = None
    setup_parts: list[Region] = []
    if isinstance(r.cond, BlockR):
        cond_bb = r.cond.bb
    elif isinstance(r.cond, SequenceR) and r.cond.parts:
        last = r.cond.parts[-1]
        if isinstance(last, BlockR):
            cond_bb = last.bb
            setup_parts = list(r.cond.parts[:-1])

    term: Optional[Assignment] = None
    if cond_bb is not None:
        for a in cond_bb.assignments:
            if a.op in ("switch", "match"):
                term = a
                break

    out: list[str] = []
    if cond_bb is None or term is None or not term.inputs:
        out.extend(_render_region(r.cond, labels, indent))
        for case in r.cases:
            out.extend(_render_region(case, labels, indent))
        return out

    for setup in setup_parts:
        out.extend(_render_region(setup, labels, indent))
    out.extend(_render_block(cond_bb, labels, indent, skip=term))

    cond_str = repr(term.inputs[0])
    n_labels = len(term.immediates.split()) if term.immediates else 0
    case_pad = pad + _INDENT
    out.append(f"{pad}switch ({cond_str}) {{")
    for i, case in enumerate(r.cases):
        case_label = "default" if i == n_labels else f"case {i}"
        out.append(f"{case_pad}{case_label}: {{")
        out.extend(_render_region(case, labels, indent + 2))
        out.append(f"{case_pad}}}")
    out.append(f"{pad}}}")
    return out


def _render_subroutine(
    entry_bb: BasicBlock,
    body: Region,
    labels: dict[tuple[str, int], str],
    indent: int,
) -> list[str]:
    """Render a subroutine as ``sub NAME(args=X, returns=Y) { body }``.

    ``build_control_tree`` doesn't wrap sub bodies in :class:`SubroutineR`
    nodes — it stores each ``entry_bb → body Region`` pair in
    :attr:`ProgramR.subroutines` directly — so the "lift" is really
    just emitting the C-style wrapper around the entry's body. The
    arity comes from the ``proto X Y`` opcode in the entry BB; the
    ``proto`` line itself is filtered out of the body (handled in
    :func:`_render_block`) since it's redundant with the header.
    """
    pad = _INDENT * indent
    name = _bb_label(entry_bb, labels) or f"sub_at_L{entry_bb.first_line}"
    proto = next((a for a in entry_bb.assignments if a.op == "proto"), None)
    sig = "args=?, returns=?"
    if proto is not None:
        parts = proto.immediates.split()
        if len(parts) == 2:
            sig = f"args={parts[0]}, returns={parts[1]}"
    out = [f"{pad}sub {name}({sig}) {{"]
    out.extend(_render_region(body, labels, indent + 1))
    out.append(f"{pad}}}")
    return out


def structured_dump(prog: SSAProgram, *, file: Optional[str] = None) -> str:
    run_all_passes(prog)
    root = build_control_tree(prog)
    labels = _build_label_index(prog)
    text = "\n".join(_render_region(root, labels, 0))
    if file is not None:
        Path(file).write_text(text)
    return text
