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

    __slots__ = ("file", "line", "index", "defined_by", "uses", "const_value")

    def __init__(self, file: str, line: int, index: int):
        self.file = file
        self.line = line
        self.index = index
        self.defined_by: Optional["Assignment"] = None
        self.uses: list["Assignment"] = []
        # Resolved by SSAProgram.propagate_constants(): when set, this
        # SSAVar's value is statically known and renders as the literal
        # in functional form. None means "unknown / not constant".
        self.const_value: Optional["Const"] = None

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
        "args", "uses", "basic_block", "const_value",
    )

    def __init__(self, file: str, line: int, stack_index: int, kind: str):
        self.file = file
        self.line = line
        self.stack_index = stack_index
        self.kind = kind
        self.args: list[Union[SSAVar, "Phi"]] = []
        self.uses: list["Assignment"] = []
        self.basic_block: Optional["BasicBlock"] = None
        # Resolved by SSAProgram.propagate_constants(): set when every
        # arg of this phi resolves to the same constant literal.
        self.const_value: Optional["Const"] = None

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


class MatPhiVar:
    """A materialised-phi variable produced by :meth:`SSAProgram.materialize_phis`.

    Identity: ``index`` (monotonic, globally unique per program). Unlike
    :class:`SSAVar`, a ``MatPhiVar`` has *multiple* definitions — one per
    DirectPhi argument — which is a legitimate post-SSA-lowering state
    where each copy assignment targets the same variable. Strict SSA is
    intentionally broken; see the "out-of-SSA" literature.
    """

    __slots__ = ("index",)

    def __init__(self, index: int):
        self.index = index

    @property
    def identifier(self) -> str:
        return f"mat_phi_{self.index}"

    def __hash__(self) -> int:
        return hash(("MatPhi", self.index))

    def __eq__(self, other) -> bool:
        return isinstance(other, MatPhiVar) and self.index == other.index

    def __repr__(self) -> str:
        return self.identifier


@dataclass(frozen=True)
class Const:
    """A resolved compile-time literal. ``kind`` ∈ ``{"int", "bytes"}``."""
    kind: str
    value: str

    def __repr__(self) -> str:
        return self.value


Operand = Union[SSAVar, Phi, Const, MatPhiVar]


@dataclass
class Assignment:
    """``outputs = op immediates (inputs)`` — one TEAL opcode's SSA form.

    After :meth:`SSAProgram.materialize_phis`, outputs may include
    :class:`MatPhiVar` instances (for synthetic ``mat_phi_k = arg``
    copies inserted at the original phi-argument def sites), and inputs
    may reference :class:`MatPhiVar` where phis used to be.
    """

    outputs: list[Union[SSAVar, MatPhiVar]]
    op: str
    immediates: str
    inputs: list[Operand]
    location: Location
    ast_code: str
    const: Optional[Const] = None
    basic_block: Optional["BasicBlock"] = None

    def functional(
        self,
        *,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
    ) -> str:
        """Render this assignment in functional form.

        ``resolve_consts``: replace constblock-referencing opcodes
            (``intc_*``/``bytec_*``) with the resolved literal as the RHS.
        ``propagate_consts``: when an input's :class:`SSAVar` or :class:`Phi`
            has been resolved by :meth:`SSAProgram.propagate_constants`,
            render it as its literal instead of the variable identifier.
        """
        out_str = ", ".join(v.identifier for v in self.outputs)
        if resolve_consts and self.const is not None:
            return f"{out_str} = {self.const.value}" if self.outputs else self.const.value

        def _input_label(operand) -> str:
            if propagate_consts:
                cv = getattr(operand, "const_value", None)
                if cv is not None:
                    return cv.value
            return repr(operand)

        # Copy assignment (materialized phi): render `mat_phi_k = arg` without
        # the opcode/tuple syntax.
        if self.op == "=" and len(self.inputs) == 1 and self.outputs:
            return f"{out_str} = {_input_label(self.inputs[0])}"
        in_str = "(" + ", ".join(_input_label(i) for i in self.inputs) + ")"
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
    # constblock references
    "Intc0Opcode", "Intc1Opcode", "Intc2Opcode", "Intc3Opcode", "IntcOpcode",
    "Bytec0Opcode", "Bytec1Opcode", "Bytec2Opcode", "Bytec3Opcode", "BytecOpcode",
    # inline-literal pushers (carry their literal in immediates; constValues.ql
    # already emits values for them via the IntegerConstant/BytesConstant
    # superclasses, so propagation reads through naturally).
    "IntOpcode", "PushintOpcode", "PushbytesOpcode",
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
        self.mat_phis: list[MatPhiVar] = []
        self._materialized: bool = False
        self._consts_propagated: bool = False
        self._dead_eliminated: bool = False
        self._scratch_propagated: bool = False

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
            # Pre-attach per-output constant literals from constValues.ql
            # (literal-only, sound) AND from mustValues.ql (dataflow-
            # extended, also sound — covers arithmetic, scratch, callsub
            # bridges via the ConstantPropagation library, but with a
            # must-overwrite check that excludes may-be-K results).
            # constValues is the literal source; mustValues only fills
            # in slots not already populated.
            const_outputs = g.nodes[n].get("const_outputs") or {}
            must_outputs = g.nodes[n].get("must_outputs") or {}
            for v in outs:
                co = const_outputs.get(v.index)
                if co is not None:
                    v.const_value = Const(*co)
                    continue
                mo = must_outputs.get(v.index)
                if mo is not None:
                    v.const_value = Const(*mo)
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

    # -- passes -------------------------------------------------------------

    def propagate_constants(self) -> None:
        """Resolve each :class:`SSAVar` and :class:`Phi` to its compile-time
        literal value where statically known.

        Two passes:

        1. Every SSAVar whose defining :class:`Assignment` has ``const`` set
           (an ``intc_*``/``bytec_*``/``intc``/``bytec`` opcode resolved
           via the constblock) is tagged with that ``Const``. ``pushint``,
           ``pushbytes``, and the ``int`` pseudo-opcode all carry their
           literal in immediates and are similarly resolvable, but only
           constblock references currently set ``Assignment.const``; the
           others are left for later (extend ``_CONST_BLOCK_REF_NAMES`` in
           ``__init__`` to widen).

        2. A :class:`Phi` whose every arg (recursively) resolves to the
           *same* literal becomes constant. Iterates to a fixed point so
           phi → phi → … chains converge.

        After this pass, :meth:`Assignment.functional` substitutes any
        SSAVar/Phi input with its literal when ``propagate_consts=True``
        (default). Idempotent.
        """
        if self._consts_propagated:
            return

        # Pass 1: SSAVars from their defining Assignment's resolved constant.
        for v in self.vars.values():
            if v.defined_by is not None and v.defined_by.const is not None:
                v.const_value = v.defined_by.const

        # Pass 2: Phis where every arg resolves to the same literal.
        # Fixed-point iteration: a phi may reference another phi that only
        # becomes constant after a later iteration.
        changed = True
        while changed:
            changed = False
            for phi in self.phis.values():
                if phi.const_value is not None:
                    continue
                arg_consts: list[Const] = []
                ok = True
                for arg in phi.args:
                    if isinstance(arg, SSAVar):
                        cv = arg.const_value
                    elif isinstance(arg, Phi):
                        cv = arg.const_value
                    else:
                        cv = None
                    if cv is None:
                        ok = False
                        break
                    arg_consts.append(cv)
                if ok and arg_consts and all(c == arg_consts[0] for c in arg_consts):
                    phi.const_value = arg_consts[0]
                    changed = True

        self._consts_propagated = True

    def propagate_scratch_constants(self) -> None:
        """Resolve each ``load N`` opcode's output to a literal when every
        ``store N`` that may influence the load wrote the same compile-
        time literal value.

        A separate pass from :meth:`propagate_constants` so the scratch
        analysis can be reasoned about (and toggled) independently of
        stack-based propagation. The QL ``scratchInfluence.ql`` query
        provides the may-influence relation and the SSAVar key of each
        store's consumed value; this pass aggregates them in Python.
        Must-semantics: any load whose stores include even one non-
        constant value is left non-resolved.
        """
        if self._scratch_propagated:
            return
        # Stack-side propagation needs to have run first so each store's
        # consumed SSAVar already has its const_value (if any) set.
        if not self._consts_propagated:
            self.propagate_constants()

        # Iterate to fixed point: a load resolved to K can in turn flow
        # back into another store, whose load can then resolve, and so on.
        changed = True
        while changed:
            changed = False
            for n in self._graph.nodes:
                stores = self._graph.nodes[n].get("scratch_stores")
                if not stores:
                    continue
                # The load op `n` has a single output SSAVar at outIdx=1.
                load_var = self.var(n.location.file, n.location.start_line, 1)
                if load_var is None or load_var.const_value is not None:
                    continue
                # Look up each store's consumed-value SSAVar by its key.
                resolved: list[Const] = []
                ok = True
                for sv_file, sv_line, sv_idx in stores:
                    src = self.var(sv_file, sv_line, sv_idx)
                    if src is None or src.const_value is None:
                        ok = False
                        break
                    resolved.append(src.const_value)
                if ok and resolved and all(c == resolved[0] for c in resolved):
                    load_var.const_value = resolved[0]
                    changed = True

        self._scratch_propagated = True

    def eliminate_dead_constants(self) -> None:
        """Inline constant literals into every consumer's input list, then
        drop the now-orphan SSAVars / Phis and any Assignment whose
        outputs are *all* dead.

        Conservative: only touches SSAVars/Phis with ``const_value`` set
        (i.e. things whose literal was resolved by
        :meth:`propagate_constants`). Non-constant producers — ``txn``
        reads, ``load N``, function-call results — are kept even if they
        end up unreferenced after the inlining, because their AST node
        carries side-effect / source-meaning information we want to
        preserve in the trace.

        Effect on the functional dump: trivial constant pushes
        (``L 5: V#1@L5 = 0``) disappear, and consumers that previously
        showed ``(V#1@L5, …)`` already render as ``(0, …)``.

        Idempotent. Implicitly runs :meth:`propagate_constants` first if
        that hasn't been done.
        """
        if self._dead_eliminated:
            return
        if not self._consts_propagated:
            self.propagate_constants()

        def _resolve(o):
            if isinstance(o, (SSAVar, Phi)) and o.const_value is not None:
                return o.const_value
            return o

        # Pass 1: replace every const-resolvable reference with its literal.
        for a in self.assignments:
            a.inputs = [_resolve(i) for i in a.inputs]
        for ph in self.phis.values():
            ph.args = [_resolve(arg) for arg in ph.args]

        # Pass 2: recompute structural reference sets.
        ref_vars: set[SSAVar] = set()
        ref_phis: set[Phi] = set()
        for a in self.assignments:
            for i in a.inputs:
                if isinstance(i, SSAVar):
                    ref_vars.add(i)
                elif isinstance(i, Phi):
                    ref_phis.add(i)
        for ph in self.phis.values():
            for arg in ph.args:
                if isinstance(arg, SSAVar):
                    ref_vars.add(arg)
                elif isinstance(arg, Phi):
                    ref_phis.add(arg)

        # Pass 3: identify dead constant SSAVars / Phis (have const_value
        # AND no remaining structural references).
        dead_vars = {
            v for v in self.vars.values()
            if v.const_value is not None and v not in ref_vars
        }
        dead_phis = {
            ph for ph in self.phis.values()
            if ph.const_value is not None and ph not in ref_phis
        }

        # Pass 4: assignments whose every output is dead are dropped. Use
        # `id()` for set membership because :class:`Assignment` is an
        # unfrozen dataclass and not hashable.
        dead_assignment_ids: set[int] = {
            id(a) for a in self.assignments
            if a.outputs and all(o in dead_vars for o in a.outputs)
        }
        # Also clear `defined_by` on the dropped SSAVars (defensive — they're
        # being removed from `self.vars` so back-refs into them shouldn't
        # accidentally bring them back).
        for v in dead_vars:
            v.defined_by = None

        # Pass 5: commit removals.
        self.vars = {k: v for k, v in self.vars.items() if v not in dead_vars}
        self.phis = {k: ph for k, ph in self.phis.items() if ph not in dead_phis}
        self.assignments = [a for a in self.assignments if id(a) not in dead_assignment_ids]
        for bb in self.blocks.values():
            bb.assignments = [a for a in bb.assignments if id(a) not in dead_assignment_ids]
            bb.phis = [ph for ph in bb.phis if ph not in dead_phis]

        self._dead_eliminated = True

    def materialize_phis(self) -> None:
        """Out-of-SSA lowering: replace each live :class:`Phi` with a
        synthetic :class:`MatPhiVar`, inserting copy assignments
        ``mat_phi_k = leaf_ssavar`` at each reachable leaf's def site.

        **DirectPhi ``p`` with args ``(v1, …, vN)``** — all SSAVars:
            1. Allocate a fresh ``mat_phi_k``.
            2. Insert one copy per ``v_i`` at ``v_i``'s def site.
            3. Consumers reading ``p`` now read ``mat_phi_k``.

        **IndirectPhi ``ip``** — ``args`` is a list of :class:`Phi`
        (DirectPhi roots from the QL ``getGenerator()`` walk):

            - Single root ``[root]``: ``ip`` re-uses ``root``'s
              ``mat_phi_k``. No extra allocation or copies.
            - Multiple roots ``[r1, r2, …]``: ``ip`` represents a meet
              across *all* rs. Allocate a fresh ``mat_phi_k`` for
              ``ip`` and insert copies at every originating SSAVar leaf
              transitively reachable from any ``r_i`` (so every
              incoming edge in the meet gets represented, none dropped).

        Idempotent — calling twice is a no-op.
        """
        if self._materialized:
            return

        def _leaf_ssavars(phi: Phi) -> list[SSAVar]:
            """Transitive SSAVar leaves reachable from ``phi.args``.
            Terminates on cycles via the ``seen`` set (the args DAG may
            rarely cycle under the raw SSA model; guard anyway)."""
            seen: set[Phi] = set()
            leaves: list[SSAVar] = []
            stack = [phi]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                for arg in cur.args:
                    if isinstance(arg, SSAVar):
                        leaves.append(arg)
                    elif isinstance(arg, Phi):
                        stack.append(arg)
            return leaves

        # Deterministic ordering so mat_phi indices are stable across runs.
        sorted_phis = sorted(
            self.phis.values(),
            key=lambda p: (p.file, p.line, p.kind, p.stack_index),
        )

        phi_to_mat: dict[Phi, MatPhiVar] = {}
        next_idx = 0

        # Pass A: allocate mat vars.
        #   DirectPhi: always fresh.
        #   IndirectPhi with 1 arg: alias its root's mat var (allocated
        #     earlier in the sort order if possible; otherwise deferred).
        #   IndirectPhi with >=2 args: fresh mat var — it's a true meet.
        # We do a second pass for the 1-arg indirects so their root's mat
        # is guaranteed to exist.
        for phi in sorted_phis:
            if phi.kind == "DirectPhi":
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)
            elif phi.kind == "IndirectPhi" and len(phi.args) >= 2:
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)

        # IndirectPhi with exactly 1 arg: alias if possible, else fresh.
        for phi in sorted_phis:
            if phi.kind != "IndirectPhi" or len(phi.args) != 1:
                continue
            parent = phi.args[0]
            if isinstance(parent, Phi) and parent in phi_to_mat:
                phi_to_mat[phi] = phi_to_mat[parent]
            else:
                # Defensive — shouldn't happen if the closure pass populated args.
                next_idx += 1
                mv = MatPhiVar(next_idx)
                phi_to_mat[phi] = mv
                self.mat_phis.append(mv)

        # Pass B: insert copy assignments. For each phi with its own mat
        # var (DirectPhi or multi-arg IndirectPhi), emit `mat = leaf` at
        # every reachable SSAVar leaf's def site.
        seen_owned: set[MatPhiVar] = set()
        new_copies: list[Assignment] = []
        for phi in sorted_phis:
            mv = phi_to_mat.get(phi)
            if mv is None or mv in seen_owned:
                continue
            # Only emit copies for the phi that OWNS this mat var (first
            # occurrence in sorted order). Aliased indirects skip.
            if phi.kind == "IndirectPhi" and len(phi.args) == 1:
                # Single-arg indirect: already aliased to its parent's mat,
                # so the parent emits the copies.
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
        for a in self.assignments:
            new_inputs: list[Operand] = []
            for inp in a.inputs:
                if isinstance(inp, Phi) and inp in phi_to_mat:
                    new_inputs.append(phi_to_mat[inp])
                else:
                    new_inputs.append(inp)
            a.inputs = new_inputs

        self.assignments.extend(new_copies)
        self.assignments.sort(key=lambda a: (a.location.file, a.location.line))
        for bb in self.blocks.values():
            bb.assignments.sort(key=lambda a: a.location.line)

        self._materialized = True

    # -- rendering ----------------------------------------------------------

    def functional(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
    ) -> str:
        lines = []
        for a in self.assignments_in(file=file, line_range=line_range):
            lines.append(
                f"L{a.location.line:>4}: "
                f"{a.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts)}"
            )
        return "\n".join(lines)

    def print_functional(self, **kwargs) -> None:
        print(self.functional(**kwargs))

    def functional_by_block(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
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
                out.append(
                    f"  L{a.location.line:>4}: "
                    f"{a.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts)}"
                )
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

    # -- graphviz rendering ------------------------------------------------

    def to_dot(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        rankdir: str = "TB",
        max_lines_per_bb: int = 80,
    ) -> str:
        """Emit Graphviz DOT source: one rounded box per BB, labeled with
        entry phis + functional assignments; edges are pred→succ. Pass
        ``file`` to restrict to one source file."""

        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        def _bb_id(bb: BasicBlock) -> str:
            return f'"BB_{bb.file}_{bb.first_line}_{bb.last_line}"'

        def _bb_label(bb: BasicBlock) -> str:
            header = f"BB L{bb.first_line}-L{bb.last_line}"
            lines_out = [header]
            for phi in bb.phis:
                lines_out.append(f"  φ_{phi.stack_index}[{phi.kind[0]}] = {repr(phi)}")
            for a in bb.assignments:
                lines_out.append(f"  L{a.location.line:>4}: {a.functional(resolve_consts=resolve_consts)}")
            if len(lines_out) > max_lines_per_bb:
                elided = len(lines_out) - (max_lines_per_bb - 1)
                lines_out = lines_out[: max_lines_per_bb - 1] + [f"  ... (+{elided} more)"]
            return "\\l".join(lines_out) + "\\l"

        blocks = [
            bb for bb in self.blocks.values()
            if file is None or bb.file == file
        ]
        blocks.sort(key=lambda bb: (bb.file, bb.first_line))

        out = [
            "digraph TEAL_SSA {",
            f"  rankdir={rankdir};",
            "  overlap=false;",
            "  splines=true;",
            '  node [shape=box, fontname="Monospace", fontsize=9];',
            '  edge [fontname="Monospace", fontsize=9];',
        ]
        node_set = set(blocks)
        for bb in blocks:
            attrs = (
                f'label="{_esc(_bb_label(bb))}", '
                'style="rounded,filled", fillcolor="#f4f4f8"'
            )
            out.append(f"  {_bb_id(bb)} [{attrs}];")
        seen = set()
        for bb in blocks:
            for succ in bb.successors:
                if succ not in node_set:
                    continue
                pair = (bb, succ)
                if pair in seen:
                    continue
                seen.add(pair)
                out.append(f"  {_bb_id(bb)} -> {_bb_id(succ)};")
        out.append("}")
        return "\n".join(out)

    def draw(
        self,
        *,
        file: Optional[str] = None,
        resolve_consts: bool = True,
        format: str = "svg",
        engine: str = "dot",
        rankdir: str = "TB",
        max_lines_per_bb: int = 80,
    ):
        """Render :meth:`to_dot` via Graphviz; returns a Jupyter-renderable
        SVG (same ``_SvgResult`` type :mod:`teal_graphs` uses)."""
        from teal_graphs import _render_dot  # reuse the same subprocess helper
        return _render_dot(
            self.to_dot(
                file=file,
                resolve_consts=resolve_consts,
                rankdir=rankdir,
                max_lines_per_bb=max_lines_per_bb,
            ),
            format=format,
            engine=engine,
        )
