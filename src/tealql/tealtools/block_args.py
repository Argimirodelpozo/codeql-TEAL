"""Block-argument (functional-SSA) lowering view of an :class:`SSAProgram`.

Each block with phis is a function whose parameters are those phis, and every
predecessor passes, on its edge, the value it holds in each slot. Unlike
:mod:`tealql.tealtools.passes.materialize` — which flattens a phi to its leaf
value-*set* and drops a copy at each leaf's def site, discarding *which value
arrives on which edge* — the per-edge value stays explicit, so the lost-copy /
swap problems cannot arise.

HAZARD: the per-edge value of a join's slot ``k`` is the predecessor's
``exit_stack[-k]`` — phi ``stack_index`` is 1-based TOP-FIRST while
:attr:`BasicBlock.exit_stack` is bottom-first.

A read-only view: run it while phis still exist. Value-flow passes may run
first (``exit_stack`` is fixed at construction, so it still reflects the real
data movement). Lowering further to imperative edge-copies is a separate
backend step, deliberately not done here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .ssa import BasicBlock, Const, Phi, SSAProgram, SSAVar


def _fmt(o) -> str:
    """Compact operand label for the render; ``None`` is a dead slot."""
    if o is None:
        return "·"  # ·
    if isinstance(o, SSAVar):
        return o.identifier
    if isinstance(o, Phi):
        return o._short()
    if isinstance(o, Const):
        return o.value
    return repr(o)


def _slot_value(pred: BasicBlock, slot: int):
    """The operand predecessor ``pred`` supplies for a join slot.

    HAZARD: ``slot`` is 1-based TOP-FIRST (phi ``stack_index``); ``exit_stack``
    is bottom-first, so the slot is index ``-slot``. A too-shallow exit stack
    (malformed edge) yields ``None`` rather than raising."""
    es = pred.exit_stack
    if 0 < slot <= len(es):
        return es[-slot]
    return None


@dataclass
class EdgeArgs:
    """The argument list one CFG edge supplies to its successor's params —
    ``args[i]`` is the value for ``params[succ][i]``."""

    pred: BasicBlock
    succ: BasicBlock
    args: list  # one operand (SSAVar | Phi | Const | None) per succ param


@dataclass
class BlockArgForm:
    """Block-argument view: ``params[bb]`` is ``bb``'s phis sorted by
    ``stack_index``, ``edges`` one :class:`EdgeArgs` per (predecessor →
    parameterised-block) CFG edge."""

    prog: SSAProgram
    params: dict  # BasicBlock -> list[Phi]
    edges: list = field(default_factory=list)  # list[EdgeArgs]

    def edge(self, pred: BasicBlock, succ: BasicBlock) -> Optional[EdgeArgs]:
        """The :class:`EdgeArgs` for ``pred -> succ``, or ``None`` if ``succ`` has
        no parameters."""
        for e in self.edges:
            if e.pred is pred and e.succ is succ:
                return e
        return None

    def _src(self, op) -> str:
        """Display label for an operand — trivial (single-predecessor) phis are
        inlined to their source transitively, a known constant preferred over the
        var name; a real multi-predecessor phi passes through by name."""
        seen: set = set()
        while isinstance(op, Phi):
            bb = op.basic_block
            if bb is None or len(bb.predecessors) != 1 or id(op) in seen:
                break
            seen.add(id(op))
            es = bb.predecessors[0].exit_stack
            k = op.stack_index
            nxt = es[-k] if 0 < k <= len(es) else None
            if nxt is None:
                break
            op = nxt
        cv = getattr(op, "const_value", None)
        return _fmt(cv) if cv is not None else _fmt(op)

    def render(self) -> str:
        """Readable *phi-at-join* dump: per block, its phis as ``<phi> =
        phi(L<pred>: <value>, …)``, its assignments, then one ``-> L<succ>(carried
        values)`` line per successor."""
        out: list[str] = []
        for bb in sorted(self.prog.blocks.values(),
                         key=lambda b: (b.file, b.first_line)):
            head = f"block L{bb.first_line}"
            if bb.predecessors:
                head += ("  (preds: "
                         + ", ".join(f"L{p.first_line}" for p in bb.predecessors)
                         + ")")
            out.append(head + ":")
            # Only real joins define phis; trivial single-pred phis are inlined
            # by _src at their uses.
            if len(bb.predecessors) > 1:
                for i, phi in enumerate(self.params.get(bb, [])):
                    srcs = []
                    for pred in bb.predecessors:
                        e = self.edge(pred, bb)
                        val = e.args[i] if (e is not None and i < len(e.args)) else None
                        srcs.append(f"L{pred.first_line}: {self._src(val)}")
                    out.append(f"    {_fmt(phi)} = phi(" + ", ".join(srcs) + ")")
            for a in bb.assignments:
                # _src inlines constants at use sites, so the pool decls and
                # const-push lines are redundant here.
                if a.op in ("intcblock", "bytecblock"):
                    continue
                if (len(a.outputs) == 1 and not a.inputs
                        and getattr(a.outputs[0], "const_value", None) is not None):
                    continue
                outs = ", ".join(_fmt(o) for o in a.outputs)
                ins = ", ".join(self._src(x) for x in a.inputs)
                imm = f" {a.immediates}" if a.immediates else ""
                lhs = f"{outs} = " if a.outputs else ""
                out.append(f"    {lhs}{a.op}{imm} ({ins})")
            for succ in bb.successors:
                e = self.edge(bb, succ)
                if e is not None and e.args:
                    out.append(f"    -> L{succ.first_line}("
                               + ", ".join(self._src(x) for x in e.args) + ")")
                else:
                    out.append(f"    -> L{succ.first_line}")
            out.append("")
        return "\n".join(out)


def to_block_args(prog: SSAProgram) -> BlockArgForm:
    """Build the block-argument view of ``prog`` — reads only the CFG
    (``predecessors`` / ``phis`` / ``exit_stack``) and never mutates."""
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
