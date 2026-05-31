"""Block-argument (functional-SSA) lowering view of an :class:`SSAProgram`.

The canonical out-of-SSA form for a *functional executable* IR — the shape
MLIR / Cranelift / Swift SIL use: each block that has phis is a function whose
parameters are those phis, and every predecessor's terminator passes, on its
edge, the value it holds in each of those slots.

Why this and not :mod:`tealtools.passes.materialize`: materialisation flattens
a phi to its transitive leaf value-*set* and drops one ``mat_phi = leaf`` copy
at each leaf's def site. That discards *which value arrives on which edge*, so
when a phi's leaves are co-defined on one path (e.g. a ``swap`` after copy-
propagation) every copy fires and the last writer wins — the control-flow
selection is lost. Block-args keep the per-edge value explicit, so the
lost-copy / swap problems cannot arise; it is a faithful (value-preserving)
out-of-SSA translation.

The per-edge value of a join's slot ``k`` is the predecessor's
``exit_stack[-k]`` — phi ``stack_index`` is 1-based top-first while
:attr:`BasicBlock.exit_stack` is bottom-first, so slot ``k`` is index ``-k``.
``exit_stack`` is surfaced verbatim from construction, so this view reflects
the real data movement (a ``swap``'s fresh output vars, not their copy-
propagated sources) regardless of which value-flow passes have run.

Run it on the **pre-materialisation** IR — phis must still exist. It is an
*alternative* to :func:`tealtools.passes.materialize_phis` (which is the last
``run_all_passes`` step and clears the phis), not something to run after it;
on a fully-passed program it finds no joins. Value-flow passes (constants,
ranges, shuffles, …) may run first — ``exit_stack`` is fixed at construction,
so the view is stable across them.

This is a **view** — it does not mutate the program. Lowering block-args
*further* to imperative edge-copies (split critical edges, sequentialise the
parallel copy on each edge, break swap cycles with a temp, coalesce on
interference) is a separate backend step and is intentionally not done here.

    >>> from tealtools.ssa import SSAProgram
    >>> from tealtools.block_args import to_block_args
    >>> form = to_block_args(SSAProgram(db))
    >>> print(form.render())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .ssa import BasicBlock, Const, Phi, SSAProgram, SSAVar


def _fmt(o) -> str:
    """Compact operand label for the render. ``None`` is a dead slot."""
    if o is None:
        return "·"  # ·
    if isinstance(o, SSAVar):
        return o.identifier
    if isinstance(o, Phi):
        return o._short()
    if isinstance(o, Const):
        return f"{o.kind} {o.value}"
    return repr(o)


def _slot_value(pred: BasicBlock, slot: int):
    """The operand predecessor ``pred`` supplies for a join slot.

    ``slot`` is 1-based top-first (phi ``stack_index``); ``exit_stack`` is
    bottom-first, so the slot is index ``-slot``. Returns ``None`` if the
    predecessor's exit stack is too shallow (a malformed edge) — never
    raises, so a bad CFG degrades to an explicit ``·`` rather than a crash.
    """
    es = pred.exit_stack
    if 0 < slot <= len(es):
        return es[-slot]
    return None


@dataclass
class EdgeArgs:
    """The argument list one CFG edge supplies to its successor's params.

    ``args[i]`` is the value for ``params[succ][i]`` — same order as the
    successor's parameter list (sorted by phi ``stack_index``).
    """

    pred: BasicBlock
    succ: BasicBlock
    args: list  # one operand (SSAVar | Phi | Const | None) per succ param


@dataclass
class BlockArgForm:
    """Block-argument view of a program.

    ``params[bb]`` is ``bb``'s parameter list (its phis, sorted by
    ``stack_index``) for every ``bb`` that has phis. ``edges`` holds one
    :class:`EdgeArgs` per (predecessor → parameterised-block) CFG edge.

    Invariant: every phi is a block parameter, and every edge into a
    parameterised block carries exactly one argument per parameter. Single-
    predecessor "joins" are kept (their one edge supplies the args) — that is
    a faithful, uniform form; eliminating those trivial parameters is a later
    optimisation, not a correctness concern.
    """

    prog: SSAProgram
    params: dict  # BasicBlock -> list[Phi]
    edges: list = field(default_factory=list)  # list[EdgeArgs]

    def edge(self, pred: BasicBlock, succ: BasicBlock) -> Optional[EdgeArgs]:
        """The :class:`EdgeArgs` for ``pred -> succ``, or ``None`` if ``succ``
        has no parameters (so the edge carries no arguments)."""
        for e in self.edges:
            if e.pred is pred and e.succ is succ:
                return e
        return None

    def render(self) -> str:
        """A readable functional dump: each block as ``L<n>(params):`` with
        its assignments, then one ``-> L<succ>(args)`` line per CFG edge."""
        out: list[str] = []
        for bb in sorted(self.prog.blocks.values(),
                         key=lambda b: (b.file, b.first_line)):
            ps = self.params.get(bb, [])
            head = f"block L{bb.first_line}"
            if ps:
                head += "(" + ", ".join(_fmt(p) for p in ps) + ")"
            out.append(head + ":")
            for a in bb.assignments:
                out.append(f"    {a.functional()}")
            for succ in bb.successors:
                e = self.edge(bb, succ)
                if e is not None and e.args:
                    out.append(
                        f"    → L{succ.first_line}("
                        + ", ".join(_fmt(x) for x in e.args) + ")"
                    )
                else:
                    out.append(f"    → L{succ.first_line}")
            out.append("")
        return "\n".join(out)


def to_block_args(prog: SSAProgram) -> BlockArgForm:
    """Build the block-argument view of ``prog`` (see the module docstring).

    Reads only the CFG (``BasicBlock.predecessors`` / ``phis`` /
    ``exit_stack``), so it is independent of which value-flow passes have run
    and never mutates the program.
    """
    params: dict = {
        bb: sorted(bb.phis, key=lambda p: p.stack_index)
        for bb in prog.blocks.values()
        if bb.phis
    }
    edges: list = []
    for succ, ps in params.items():
        for pred in succ.predecessors:
            edges.append(EdgeArgs(
                pred=pred,
                succ=succ,
                args=[_slot_value(pred, p.stack_index) for p in ps],
            ))
    return BlockArgForm(prog=prog, params=params, edges=edges)
