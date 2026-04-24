"""Typed SSA-assignment representation of a TEAL program.

Built on top of :mod:`teal_graphs` (which runs the CodeQL queries). Where
``teal_graphs`` exposes a low-level ``MultiDiGraph`` keyed by AST nodes,
this module presents the same information as a first-class *program*
object: a sequence of :class:`Assignment`\\ s grouped into
:class:`BasicBlock`\\ s, referring to :class:`SSAVar`\\ s, :class:`Phi`\\ s,
and :class:`Const` literals.

    from teal_ssa import SSAProgram
    p = SSAProgram("test-dbs/xgov-db")
    print(p.functional(file="approval.teal", line_range=(225, 260)))

Model
-----

- :class:`SSAVar` — a stack variable produced by one opcode.
  Identity: ``(file, line, output_index)``. Back-reference
  ``defined_by`` points at the :class:`Assignment` that produced it;
  ``uses`` lists assignments consuming it.

- :class:`Phi` — an SSA phi (direct or indirect). Identity:
  ``(file, line, kind, stack_index)``. ``args`` is an ordered list of
  :class:`SSAVar` (for ``DirectPhi``) or a single :class:`Phi` (for
  ``IndirectPhi``, pointing at its root ``DirectPhi``). Back-reference
  ``basic_block`` points at the :class:`BasicBlock` it lives in.

- :class:`Const` — a resolved compile-time literal
  (``intcblock``/``bytecblock`` entry, ``pushint``, ``pushbytes``,
  or the ``int`` pseudo-opcode).

- :class:`Assignment` — ``outputs = op immediates (inputs)``.
  ``outputs`` are SSAVars; ``inputs`` are :class:`SSAVar` / :class:`Phi`
  operands. ``const`` is populated for const-pushing opcodes so consumers
  can render ``V#1@L5 = 10`` instead of ``V#1@L5 = intc_2 ()``. Back-
  reference ``basic_block``.

- :class:`BasicBlock` — maximal single-entry/single-exit straight-line
  region. Identity: ``(file, first_line, last_line)``. Carries its
  ordered ``assignments`` + entry ``phis``, plus ``predecessors`` and
  ``successors`` (both lists of ``BasicBlock``).

Phi materialization is lazy: only phis referenced (directly or
transitively via ``IndirectPhi`` parents) by some assignment are
materialized. This keeps the object count tractable on programs where
the underlying QL model emits many unreferenced phi identities.

The module does not re-run CodeQL queries itself — it calls
:func:`teal_graphs.load_graph` and reads the populated node attributes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

import networkx as nx


@dataclass(frozen=True)
class Location:
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


class SSAVar:
    """A stack variable produced by one opcode.

    Identity is ``(file, line, index)`` — matching CodeQL's ``SSAVar``
    newtype ``MkSSAVar(idx, node)``. The textual form
    ``V#{index}@L{line}`` matches ``SSAVar.getIdentifier()`` in QL.
    """

    __slots__ = ("file", "line", "index", "defined_by", "uses")

    def __init__(self, file: str, line: int, index: int):
        self.file = file
        self.line = line
        self.index = index
        self.defined_by: Optional["Assignment"] = None
        self.uses: list["Assignment"] = []

    @property
    def identifier(self) -> str:
        return f"V#{self.index}@L{self.line}"

    def _key(self) -> tuple:
        return (self.file, self.line, self.index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, SSAVar) and self._key() == other._key()

    def __repr__(self) -> str:
        return self.identifier


class Phi:
    """An SSA phi. ``kind`` is ``"DirectPhi"`` or ``"IndirectPhi"``.

    For ``DirectPhi``, ``args`` is the list of originating-input
    :class:`SSAVar`\\ s, one per contributing predecessor BB.
    For ``IndirectPhi``, ``args`` is a single-element list containing
    the root :class:`Phi` the indirect phi propagates from.
    """

    __slots__ = (
        "file", "line", "stack_index", "kind",
        "args", "uses", "basic_block",
    )

    def __init__(self, file: str, line: int, stack_index: int, kind: str):
        self.file = file
        self.line = line
        self.stack_index = stack_index
        self.kind = kind
        self.args: list[Union[SSAVar, "Phi"]] = []
        self.uses: list["Assignment"] = []
        self.basic_block: Optional["BasicBlock"] = None

    def _key(self) -> tuple:
        return (self.file, self.line, self.kind, self.stack_index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, Phi) and self._key() == other._key()

    def __repr__(self) -> str:
        if not self.args:
            tag = "φ" if self.kind == "DirectPhi" else "φᵢ"
            return f"{tag}_{self.stack_index}@L{self.line}"
        return "phi(" + ", ".join(repr(a) for a in self.args) + ")"


@dataclass(frozen=True)
class Const:
    """A resolved compile-time literal. ``kind`` ∈ ``{"int", "bytes"}``."""
    kind: str
    value: str

    def __repr__(self) -> str:
        return self.value


Operand = Union[SSAVar, Phi, Const]


@dataclass
class Assignment:
    """``outputs = op immediates (inputs)`` — one TEAL opcode's SSA form."""

    outputs: list[SSAVar]
    op: str
    immediates: str
    inputs: list[Operand]
    location: Location
    ast_code: str
    const: Optional[Const] = None
    basic_block: Optional["BasicBlock"] = None

    def functional(self, *, resolve_consts: bool = True) -> str:
        out_str = ", ".join(v.identifier for v in self.outputs)
        if resolve_consts and self.const is not None:
            return f"{out_str} = {self.const.value}" if self.outputs else self.const.value
        in_str = "(" + ", ".join(repr(i) for i in self.inputs) + ")"
        rhs = f"{self.op} {self.immediates} {in_str}" if self.immediates else f"{self.op} {in_str}"
        return f"{out_str} = {rhs}" if self.outputs else rhs

    def __repr__(self) -> str:
        return self.functional()


class BasicBlock:
    """A maximal straight-line region of assignments.

    Identity is ``(file, first_line, last_line)``. ``assignments`` is the
    ordered list of the BB's :class:`Assignment`\\ s (by source line).
    ``phis`` is the list of :class:`Phi`\\ s attached at the BB's entry.
    ``predecessors`` / ``successors`` are the other BBs this BB is
    directly connected to via inter-BB CFG edges.
    """

    __slots__ = (
        "file", "first_line", "last_line",
        "assignments", "phis",
        "predecessors", "successors",
    )

    def __init__(self, file: str, first_line: int, last_line: int):
        self.file = file
        self.first_line = first_line
        self.last_line = last_line
        self.assignments: list[Assignment] = []
        self.phis: list[Phi] = []
        self.predecessors: list["BasicBlock"] = []
        self.successors: list["BasicBlock"] = []

    def _key(self) -> tuple:
        return (self.file, self.first_line, self.last_line)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return isinstance(other, BasicBlock) and self._key() == other._key()

    def __repr__(self) -> str:
        return f"BB({self.file}:{self.first_line}-{self.last_line})"

    def contains(self, line: int) -> bool:
        return self.first_line <= line <= self.last_line


# -------------------------------------------------------------------------


_CONST_BLOCK_REF_NAMES = frozenset({
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
})


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    def __init__(self, db_path: str | Path, *, refresh: bool = False, verbose: bool = False):
        import teal_graphs as tg
        from teal_ast import Opcode

        g = tg.load_graph(db_path, refresh=refresh, verbose=verbose)
        self._graph = g
        self.db_path = Path(db_path).resolve()

        self.vars: dict[tuple, SSAVar] = {}
        self.phis: dict[tuple, Phi] = {}
        self.assignments: list[Assignment] = []
        self.blocks: dict[tuple, BasicBlock] = {}

        # Index graph-side phis by key for fast lookup during lazy materialization.
        g_phi_by_key: dict[tuple, tg.PhiNode] = {}
        for n in g.nodes:
            if isinstance(n, tg.PhiNode):
                g_phi_by_key[
                    (n.location.file, n.location.start_line, n.kind, n.stack_index)
                ] = n

        def _to_var(gv: "tg.SSAVar") -> SSAVar:
            key = (gv.file, gv.line, gv.output_index)
            v = self.vars.get(key)
            if v is None:
                v = SSAVar(*key)
                self.vars[key] = v
            return v

        def _to_phi(gp: "tg.PhiNode") -> Phi:
            key = (gp.location.file, gp.location.start_line, gp.kind, gp.stack_index)
            p = self.phis.get(key)
            if p is None:
                p = Phi(gp.location.file, gp.location.start_line, gp.stack_index, gp.kind)
                self.phis[key] = p
            return p

        def _to_operand(x) -> Operand:
            if isinstance(x, tg.SSAVar):
                return _to_var(x)
            if isinstance(x, tg.PhiNode):
                return _to_phi(x)
            raise TypeError(f"unexpected stack-input type: {type(x).__name__}")

        def _bb_from_tuple(bb_id: tuple) -> BasicBlock:
            bb = self.blocks.get(bb_id)
            if bb is None:
                bb = BasicBlock(*bb_id)
                self.blocks[bb_id] = bb
            return bb

        # Pass 1: build Assignments (creating SSAVars + phis lazily via _to_operand).
        for n in g.nodes:
            if not isinstance(n, Opcode):
                continue
            outs_g = g.nodes[n].get("stack_outputs") or []
            ins_g = g.nodes[n].get("stack_inputs") or []
            code = n.code or n.ql_class
            op_name, _, imms = code.partition(" ")
            cv = g.nodes[n].get("const_value")
            const: Optional[Const] = None
            if cv is not None and type(n).__name__ in _CONST_BLOCK_REF_NAMES:
                kind, value = cv
                const = Const(kind, value)
            bb_id = g.nodes[n].get("bb")
            bb = _bb_from_tuple(bb_id) if bb_id is not None else None

            outs = [_to_var(v) for v in outs_g]
            ins = [_to_operand(x) for x in ins_g]
            a = Assignment(
                outputs=outs,
                op=op_name,
                immediates=imms,
                inputs=ins,
                location=Location(n.location.file, n.location.start_line),
                ast_code=code,
                const=const,
                basic_block=bb,
            )
            self.assignments.append(a)
            for v in outs:
                v.defined_by = a
            for inp in ins:
                inp.uses.append(a)
            if bb is not None:
                bb.assignments.append(a)

        # Pass 2: close over transitively-referenced phis. Each phi we've
        # already materialized references 0+ more phis via its ``args``;
        # resolve args lazily so we only touch phis that actually matter.
        pending = list(self.phis.values())
        while pending:
            p = pending.pop()
            if p.args:
                continue
            gp = g_phi_by_key.get((p.file, p.line, p.kind, p.stack_index))
            if gp is None:
                continue
            for a in gp.args:
                arg = _to_operand(a)
                p.args.append(arg)
                if isinstance(arg, Phi) and not arg.args:
                    pending.append(arg)

        # Pass 3: attach phis to their host BBs (phi.line == bb.first_line).
        bb_by_first_line: dict[tuple[str, int], BasicBlock] = {
            (bb.file, bb.first_line): bb for bb in self.blocks.values()
        }
        for p in self.phis.values():
            bb = bb_by_first_line.get((p.file, p.line))
            if bb is not None:
                p.basic_block = bb
                bb.phis.append(p)

        # Pass 4: wire BB predecessor/successor from inter-BB CFG edges.
        # Walk the op-level CFG in `g`, skip PhiIn/PhiOut (not actual control
        # flow), and project each inter-BB edge onto BasicBlock pairs.
        seen_edges: set[tuple[BasicBlock, BasicBlock]] = set()
        for u, v, data in g.edges(data=True):
            if data.get("kind") != "cfg":
                continue
            succ = data.get("successor")
            if succ in ("PhiIn", "PhiOut"):
                continue
            u_bb_id = g.nodes[u].get("bb")
            v_bb_id = g.nodes[v].get("bb")
            if u_bb_id is None or v_bb_id is None or u_bb_id == v_bb_id:
                continue
            u_bb = self.blocks.get(u_bb_id)
            v_bb = self.blocks.get(v_bb_id)
            if u_bb is None or v_bb is None:
                continue
            if (u_bb, v_bb) in seen_edges:
                continue
            seen_edges.add((u_bb, v_bb))
            u_bb.successors.append(v_bb)
            v_bb.predecessors.append(u_bb)

        # Final ordering.
        self.assignments.sort(key=lambda a: (a.location.file, a.location.line))
        for bb in self.blocks.values():
            bb.assignments.sort(key=lambda a: a.location.line)
            bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    # -- iteration / lookup -------------------------------------------------

    def __iter__(self) -> Iterable[Assignment]:
        return iter(self.assignments)

    def __len__(self) -> int:
        return len(self.assignments)

    def var(self, file: str, line: int, index: int) -> Optional[SSAVar]:
        return self.vars.get((file, line, index))

    def phi(self, file: str, line: int, kind: str, stack_index: int) -> Optional[Phi]:
        return self.phis.get((file, line, kind, stack_index))

    def block(self, file: str, first_line: int, last_line: int) -> Optional[BasicBlock]:
        return self.blocks.get((file, first_line, last_line))

    def block_containing(self, file: str, line: int) -> Optional[BasicBlock]:
        for bb in self.blocks.values():
            if bb.file == file and bb.contains(line):
                return bb
        return None

    def assignments_in(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
    ) -> list[Assignment]:
        out = []
        for a in self.assignments:
            if file is not None and a.location.file != file:
                continue
            if line_range is not None and not (line_range[0] <= a.location.line <= line_range[1]):
                continue
            out.append(a)
        return out

    # -- rendering ----------------------------------------------------------

    def functional(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
        resolve_consts: bool = True,
    ) -> str:
        lines = []
        for a in self.assignments_in(file=file, line_range=line_range):
            lines.append(f"L{a.location.line:>4}: {a.functional(resolve_consts=resolve_consts)}")
        return "\n".join(lines)

    def print_functional(self, **kwargs) -> None:
        print(self.functional(**kwargs))

    def functional_by_block(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
    ) -> str:
        """Same as :meth:`functional` but groups assignments by BB with a
        header line and predecessor/successor summary per block."""
        blocks = sorted(
            (bb for bb in self.blocks.values() if file is None or bb.file == file),
            key=lambda bb: (bb.file, bb.first_line),
        )
        out = []
        for bb in blocks:
            preds = ", ".join(f"L{p.first_line}" for p in bb.predecessors) or "-"
            succs = ", ".join(f"L{s.first_line}" for s in bb.successors) or "-"
            out.append(f"# {bb}  preds=[{preds}] succs=[{succs}]")
            for p in bb.phis:
                out.append(f"  {p.kind[0]}_{p.stack_index} = {p!r}")
            for a in bb.assignments:
                out.append(f"  L{a.location.line:>4}: {a.functional(resolve_consts=resolve_consts)}")
            out.append("")
        return "\n".join(out)

    # -- graph view ---------------------------------------------------------

    def data_graph(self) -> nx.MultiDiGraph:
        """Data-dependency graph over SSA objects.

        Nodes: :class:`Assignment`, :class:`SSAVar`, :class:`Phi`.
        Edges:

        - ``Assignment → SSAVar`` (``kind="def"``)
        - ``SSAVar → Assignment`` (``kind="use"``)
        - ``Phi → Assignment`` (``kind="use"``)
        - ``SSAVar → Phi`` (``kind="phi_in"``)
        - ``Phi → Phi`` (``kind="phi_in"``)
        """
        h = nx.MultiDiGraph()
        for a in self.assignments:
            h.add_node(a)
            for v in a.outputs:
                h.add_node(v)
                h.add_edge(a, v, kind="def")
            for inp in a.inputs:
                if isinstance(inp, Const):
                    continue
                h.add_node(inp)
                h.add_edge(inp, a, kind="use")
        for p in self.phis.values():
            h.add_node(p)
            for arg in p.args:
                if isinstance(arg, Const):
                    continue
                h.add_node(arg)
                h.add_edge(arg, p, kind="phi_in")
        return h

    def cfg(self) -> nx.MultiDiGraph:
        """Basic-block CFG: nodes are :class:`BasicBlock`, edges are
        ``pred → succ``. No labels beyond the structural relation;
        consult ``bb.assignments[-1]`` for branch discrimination."""
        h = nx.MultiDiGraph()
        for bb in self.blocks.values():
            h.add_node(bb)
        for bb in self.blocks.values():
            for succ in bb.successors:
                h.add_edge(bb, succ)
        return h
