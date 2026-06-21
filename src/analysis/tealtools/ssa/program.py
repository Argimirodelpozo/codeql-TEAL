"""The :class:`SSAProgram` class — the canonical program type every
analysis consumes.

``SSAProgram(db)`` runs a graph-loading pre-pass via
:mod:`tealtools.graph`
(CFG / AST / arity / constant annotations, populating the data
classes from :mod:`tealtools.ssa.models`), then routes SSA
construction through :class:`PySSA` (:mod:`tealtools.ssa.ssa`) which
overwrites the phi layer in place. The constant-folding / range /
liveness / materialize passes live here as methods consumed by the
detectors and reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

import networkx as nx

from .models import (
    Assignment,
    BasicBlock,
    Const,
    Location,
    MatPhiVar,
    Phi,
    SSAVar,
    _CONST_BLOCK_REF_NAMES,
)
from ..opcode_sigs import op_arity
from ..dot import render


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    def __init__(self, source: str | Path, *, verbose: bool = False):
        """Convenience constructor: parse a ``.teal`` file/dir into a graph, then
        reconstruct SSA. The two stages are separable -- prefer :meth:`from_source`
        when you want the parse stage explicit, or :meth:`from_graph` to build SSA
        from an already-loaded graph (no parsing). ``SSAProgram(source)`` stays as
        the one-liner."""
        from .. import graph as tg
        self._build_from_graph(tg.load_graph(source, verbose=verbose))

    @classmethod
    def from_source(cls, source: str | Path, *, verbose: bool = False) -> "SSAProgram":
        """Build SSA from TEAL source as an EXPLICIT two-stage pipeline:
        ``graphs.load_graph(source)`` (parse / extract → graph) then
        :meth:`from_graph` (SSA reconstruction). Same result as ``cls(source)`` --
        named so the parse stage is visible at the call site."""
        from .. import graph as tg
        return cls.from_graph(tg.load_graph(source, verbose=verbose))

    @classmethod
    def from_graph(cls, graph) -> "SSAProgram":
        """Reconstruct SSA from an ALREADY-LOADED graph (the output of
        :func:`graphs.load_graph`). This is the SSA stage with parsing DECOUPLED --
        ``__init__`` is just this plus a ``load_graph`` call. Lets a caller load /
        cache / transform the graph once and build SSA without re-parsing."""
        self = cls.__new__(cls)
        self._build_from_graph(graph)
        return self

    @classmethod
    def from_text(cls, teal: str, *, name: str = "contract.teal",
                  verbose: bool = False) -> "SSAProgram":
        """Build SSA from in-memory TEAL source TEXT -- no filesystem. ``name`` is
        the logical file name the SSA / findings report. For several files pass a
        ``{name: text}`` mapping straight to :func:`graphs.load_graph`. (The lift's
        source-text recovery -- template names, dropped consts -- still needs a real
        path; all SSA + detector analysis works in-memory.)"""
        from .. import graph as tg
        return cls.from_graph(tg.load_graph({name: teal}, verbose=verbose))

    def _build_from_graph(self, g) -> None:
        """Reconstruct the SSA program from a loaded graph ``g`` (no parsing)."""
        from ..ast import Opcode, Label

        self._graph = g
        src = g.graph.get("source", "")
        self.source_path = Path(src).resolve() if src else Path("")

        self.vars: dict[tuple, SSAVar] = {}
        self.phis: dict[tuple, Phi] = {}
        self.assignments: list[Assignment] = []
        self.blocks: dict[tuple, BasicBlock] = {}
        self.mat_phis: list[MatPhiVar] = []
        # Sorted (file, line, label_text) — purely for rendering. Labels
        # have no SSA effect, but interleaving them with assignments in
        # ``functional()`` keeps the dump anchored to the source layout.
        self.labels: list[tuple[str, int, str]] = []
        self._materialized: bool = False
        self._consts_propagated: bool = False
        self._dead_eliminated: bool = False
        self._scratch_propagated: bool = False
        self._ranges_propagated: bool = False
        self._shuffles_propagated: bool = False
        self._inputs_propagated: bool = False
        self._stable_propagated: bool = False
        self._phis_deduped: bool = False

        def _bb_from_tuple(bb_id: tuple) -> BasicBlock:
            bb = self.blocks.get(bb_id)
            if bb is None:
                bb = BasicBlock(*bb_id)
                self.blocks[bb_id] = bb
            return bb

        # Pass 1: build Assignments + their output SSAVars (arities from the
        # opcode signature table; PySSA reconstructs operand wiring + phis).
        for n in g.nodes:
            if not isinstance(n, Opcode):
                continue
            code = n.code or n.node_class
            op_name, _, imms = code.partition(" ")
            cv = g.nodes[n].get("const_value")
            const: Optional[Const] = None
            if cv is not None and type(n).__name__ in _CONST_BLOCK_REF_NAMES:
                kind, value = cv
                const = Const(kind, value)
            bb_id = g.nodes[n].get("bb")
            bb = _bb_from_tuple(bb_id) if bb_id is not None else None

            # Output SSAVars from the opcode signature table. Inputs are
            # left empty here — PySSA
            # reconstructs the operand wiring in _apply_pyssa_to. The output
            # vars exist so the const_value/const_outputs seeding below
            # (carried into the PySSA-built vars by key) has somewhere to land.
            _, n_out = op_arity(op_name, imms.strip())
            outs = []
            for k in range(1, n_out + 1):
                key = (n.location.file, n.location.start_line, k)
                v = self.vars.get(key)
                if v is None:
                    v = SSAVar(*key)
                    self.vars[key] = v
                outs.append(v)
            ins = []
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
            # Pre-attach per-output constant literals from the resolved-
            # constant pass: g.nodes[n]["const_outputs"] = {out_idx: (kind, value)}.
            const_outputs = g.nodes[n].get("const_outputs") or {}
            for v in outs:
                co = const_outputs.get(v.index)
                if co is not None:
                    v.const_value = Const(*co)
            if bb is not None:
                bb.assignments.append(a)

        # Pass 2: wire BB predecessor/successor from CFG edges that
        # cross BB *boundaries*. An edge ``u → v`` represents entering
        # ``v``'s BB iff ``v`` is its BB's first node — that's the only
        # way to land on the BB. Filtering on "v is first node of v's
        # BB" rather than on "u_bb != v_bb" correctly captures
        # self-loops (single-BB loops where the BB's tail branch
        # targets the BB's own head — e.g. ``bnz l_loop`` at L25
        # branching back to the ``l_loop:`` label at L16, both inside
        # the same BB). The previous "u_bb != v_bb" filter dropped
        # such self-loops, so ``bb.predecessors`` for a one-BB loop
        # missed the back-edge entirely.
        seen_edges: set[tuple[BasicBlock, BasicBlock]] = set()
        for u, v, data in g.edges(data=True):
            if data.get("kind") != "cfg":
                continue
            succ = data.get("successor")
            if succ in ("PhiIn", "PhiOut"):
                continue
            u_bb_id = g.nodes[u].get("bb")
            v_bb_id = g.nodes[v].get("bb")
            if u_bb_id is None or v_bb_id is None:
                continue
            # Intra-BB CFG edges must represent a back-edge from a
            # branch at the BB's tail to its head — i.e. ``u.line >
            # v.line``. Equal-line intra-BB edges arise from template
            # markers (``pushint TMPL_FOO`` → ``Label@TMPL_FOO``) modelled
            # as same-line CFG edges that aren't real control flow;
            # including them creates spurious BB-self-loops that
            # ``find_loops`` then misclassifies as actual loops.
            if (
                u_bb_id == v_bb_id
                and u.location.start_line <= v.location.start_line
            ):
                continue
            # Only edges into the BB's first node represent BB entry.
            # Intra-BB sequential edges (op → next op within one BB)
            # target later nodes and don't add BB-level info.
            if v.location.start_line != v_bb_id[1]:
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

        # Pass 3: collect Label nodes for rendering. They aren't part of
        # the SSA — they don't define or consume values — but printing
        # them in :meth:`functional` lets the dump line up with the
        # source listing (branch targets stay visible).
        for n in g.nodes:
            if isinstance(n, Label):
                self.labels.append(
                    (n.location.file, n.location.start_line, n.code or "")
                )
        self.labels.sort()

        # Final ordering.
        self.assignments.sort(key=lambda a: (a.location.file, a.location.line))
        for bb in self.blocks.values():
            bb.assignments.sort(key=lambda a: a.location.line)
            bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

        # The pre-pass above only populates ``self._graph`` / ``self.vars`` (for
        # const/range/type seeding) / ``self.blocks`` / ``self.assignments`` (for
        # arity). PySSA then computes phi placement + chain collapse from the
        # graph's nodes + CFG edges + basic blocks, and overwrites in place.
        from .ssa import PySSA, _apply_pyssa_to
        _apply_pyssa_to(self, PySSA._construct(self))

    # -- iteration / lookup -------------------------------------------------

    def __iter__(self) -> Iterable[Assignment]:
        return iter(self.assignments)

    def __len__(self) -> int:
        return len(self.assignments)

    def var(self, file: str, line: int, index: int) -> Optional[SSAVar]:
        return self.vars.get((file, line, index))

    def phi(self, file: str, line: int, kind: str, stack_index: int) -> Optional[Phi]:
        # PySSA-built progs unify the Direct/Indirect distinction
        # under ``DirectPhi``. Fall back to the other kind so callers
        # that get a ``kind`` from field-row data (e.g.
        # ``inner_txn_report._resolve_operand``) still resolve.
        p = self.phis.get((file, line, kind, stack_index))
        if p is not None:
            return p
        other = "IndirectPhi" if kind == "DirectPhi" else "DirectPhi"
        return self.phis.get((file, line, other, stack_index))

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

    # -- chain-structure queries (backend-agnostic) ------------------------
    #
    # Most analyses only need the *leaf-set* of a phi — what SSAVars can
    # flow in — and read it directly from ``phi.args``. A few analyses
    # need *chain structure*: which intermediate phis sit between a phi
    # and its leaves (loop detection, chain-root coalescing, etc.).
    #
    # Graph-loaded programs carry chain structure in ``IndirectPhi.args``
    # (single-element list pointing at the chain root). PySSA-built
    # programs (via :meth:`tealtools.ssa.PySSA.build`) collapse args to
    # SSAVar leaves for fast iteration but keep an auxiliary
    # back-reference to the original PyPhi graph in ``self._pyssa`` /
    # ``self._phi_to_pyphi``. These helpers abstract over both, so
    # consumers can write backend-agnostic structural code without
    # paying the iteration cost when they don't need it.

    def chain_predecessors(self, phi: "Phi") -> list["Phi"]:
        """Phis whose values flow into ``phi`` via propagation. Empty
        for chain roots (whose args are all :class:`SSAVar`)."""
        # IndirectPhi-backed: read IndirectPhi.args directly.
        if isinstance(phi, Phi) and phi.kind == "IndirectPhi":
            return [a for a in phi.args if isinstance(a, Phi)]
        # PySSA-wrapped: walk via the PyPhi graph if present.
        ptp = getattr(self, "_phi_to_pyphi", None)
        ptw = getattr(self, "_pyphi_to_phi", None)
        if ptp is None or ptw is None:
            return []
        # Local import to avoid hard dep on the PySSA builder here.
        try:
            from .ssa import PyPhi  # type: ignore
        except Exception:
            return []
        pyphi = ptp.get(phi)
        if pyphi is None:
            return []
        out: list[Phi] = []
        for arg in pyphi.args:
            if isinstance(arg, PyPhi):
                w = ptw.get(arg)
                if w is not None:
                    out.append(w)
        return out

    def chain_root(self, phi: "Phi") -> "Phi":
        """Walk the chain back to the phi whose args are all SSAVars
        (the ``DirectPhi``-equivalent at the start of the chain). For a
        chain root, returns ``phi`` itself. Cycle-safe via ``seen`` set."""
        seen: set = set()
        cur = phi
        while True:
            if id(cur) in seen:
                return cur
            seen.add(id(cur))
            preds = self.chain_predecessors(cur)
            if not preds:
                return cur
            cur = preds[0]

    def chain_reaches(self, src: "Phi", dst: "Phi") -> bool:
        """True if ``src`` propagates to ``dst`` along the chain."""
        if src is dst:
            return True
        seen: set = {id(dst)}
        stack = [dst]
        while stack:
            cur = stack.pop()
            for p in self.chain_predecessors(cur):
                if p is src:
                    return True
                if id(p) not in seen:
                    seen.add(id(p))
                    stack.append(p)
        return False

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

        from ..passes.const_prop import propagate_constants as _impl
        _impl(self)
        self._consts_propagated = True

    def propagate_inputs(self) -> None:
        """Unify execution-stable input reads (``txn`` / ``txna`` /
        ``gtxn``-family / ``global`` / ``arg``) so multiple syntactic
        reads of the same input collapse to one canonical SSAVar.

        Idempotent. Mutates the SSA: duplicate readers' outputs get
        rewired in every consumer (assignment inputs and phi args) to
        point at the first reader's output. Lazily imported because
        the unification logic lives in :mod:`tealtools.input_prop`
        — the substrate just provides the entry point.

        ``itxn``-family reads are deliberately *not* included; itxn
        fields observe the most-recently-submitted inner transaction
        and can legitimately differ between submits."""
        if getattr(self, "_inputs_propagated", False):
            return
        from ..passes.input_prop import propagate_inputs as _impl
        _impl(self)
        self._inputs_propagated = True

    def propagate_stable_expressions(self) -> None:
        """Transitive extension of :meth:`propagate_inputs`: a pure op
        whose inputs are all execution-stable is itself stable, so
        syntactically-equal stable expressions (e.g. two ``sha256(txn
        Sender)``) unify to one canonical SSAVar via CSE. Logic lives in
        :mod:`tealtools.passes.stable_prop`; idempotent. Best run after
        ``propagate_inputs`` (leaves unified) and
        ``propagate_stack_shuffles`` (operands reach compute ops
        directly)."""
        if getattr(self, "_stable_propagated", False):
            return
        from ..passes.stable_prop import propagate_stable_expressions as _impl
        _impl(self)
        self._stable_propagated = True

    def dedup_phis(self) -> int:
        """Collapse value-equal phi nodes — those with identical
        (value-normalised) args, merge-point-agnostic — to one
        canonical, to a fixpoint. PySSA's constant-stack unroll
        over-generates phis
        (xgov: ~21k phis, ~667 distinct); running this just before
        :meth:`materialize_phis` keeps its ``mat_phi`` output bounded,
        and it makes every phi-iterating analysis cheaper. Logic lives
        in :mod:`tealtools.passes.phi_dedup`; idempotent. Returns the
        number of phi objects removed."""
        if getattr(self, "_phis_deduped", False):
            return 0
        from ..passes.phi_dedup import dedup_phis as _impl
        n = _impl(self)
        self._phis_deduped = True
        return n

    def propagate_scratch_values(self) -> int:
        """Generalises :meth:`propagate_scratch_constants` from compile-
        time literals to arbitrary SSA values.

        For each ``load N`` opcode whose may-influencing stores
        (provided by the ``scratch_stores`` annotation) all
        write the *same* :class:`SSAVar` ``V``, rewire every consumer
        of the load's output to reference ``V`` directly. The load's
        ``Assignment`` stays in the IR with empty ``uses`` until a
        subsequent :meth:`cleanup_unused_ssavars` removes it.

        Returns the number of loads forwarded. Mutates the SSA in place.
        Idempotent — a second call finds nothing further to forward.

        Best run after :meth:`propagate_inputs` (so equivalent input
        reads are already unified and forwarding through scratch can
        see them as a single SSAVar) and :meth:`propagate_scratch_constants`
        (so const stores resolve via const_value first). Not part of
        :func:`run_all_passes` because — like ``propagate_inputs`` —
        the SSAVar-identity change can surprise analyses that expect a
        1:1 mapping between load assignments and their downstream uses.
        """
        from ..passes.scratch_prop import propagate_scratch_values as _impl
        return _impl(self)

    def cleanup_unused_ssavars(self) -> int:
        """Drop side-effect-free :class:`Assignment` s whose every
        output has empty ``uses``. Typically called after
        :meth:`propagate_inputs` to physically remove the duplicate
        input reads it unified semantically. Returns the count of
        assignments removed.

        Idempotent on a fixed IR — repeated calls find nothing more
        to drop. Lazily imports the implementation from
        :mod:`tealtools.cleanup` so the substrate stays free of the
        per-op pure-set decisions."""
        from ..passes.cleanup import cleanup_unused_ssavars as _impl
        return _impl(self)

    def propagate_scratch_constants(self) -> None:
        """Resolve each ``load N`` opcode's output to a literal when every
        ``store N`` that may influence the load wrote the same compile-
        time literal value.

        A separate pass from :meth:`propagate_constants` so the scratch
        analysis can be reasoned about (and toggled) independently of
        stack-based propagation. The scratch-influence analysis
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

        from ..passes.scratch_prop import propagate_scratch_constants as _impl
        _impl(self)
        self._scratch_propagated = True

    def propagate_ranges(self) -> None:
        """Tag SSAVars / Phis with a static integer range and type.

        Independent, idempotent. Seeds come from the tables:
        :data:`_OP_RANGE_SEEDS` (op alone determines a single output's
        bound, e.g. bool-shaped comparisons, ``getbyte``, ``sqrt``,
        ``len``), :data:`_OP_OUTPUT_SEEDS` (positional bounds on a
        multi-output op — the 0/1 exists-flag the ``*_get`` / ``*_ex``
        family pushes, ``box_len``'s length, ``addw``'s carry),
        :data:`_PARAMS_VALUE_RANGES` (the bounded value output of
        ``*_params_get`` by field immediate), :data:`_TXN_FIELD_RANGES`
        (any ``txn`` / ``gtxn*`` / ``itxn*`` / ``gitxn*`` form with an
        enum- or count-valued field name), and
        :data:`_GLOBAL_FIELD_RANGES` (``global FIELD``). A second pass
        unions arg ranges through phis to fixed point.
        """
        if self._ranges_propagated:
            return

        from ..passes.range_seed import propagate_ranges as _impl
        _impl(self)
        self._ranges_propagated = True

    def propagate_range_arithmetic(self) -> int:
        """Forward ``IntRange`` annotations through ``+`` / ``-`` /
        ``*`` / ``/`` / ``%`` (and re-union phis with the widened
        ranges) — capabilities that :meth:`propagate_ranges` doesn't
        provide. Opt-in.

        Returns the number of SSAVars / Phis newly ranged or whose
        range was widened during a phi re-union. Lazy-trips
        :meth:`propagate_ranges` first so the stdlib seeds (boolean
        ops, txn enum fields) are in place before arithmetic
        composes them. Lazily imported from
        :mod:`tealtools.range_arith` so the substrate stays free of
        the AVM arithmetic semantics."""
        from ..passes.range_arith import propagate_range_arithmetic as _impl
        return _impl(self)

    def propagate_assert_ranges(self) -> int:
        """Tighten ``IntRange`` annotations from the contract's ``assert``
        guards, flow-sensitively (a guard only constrains the paths it
        dominates). Part of :func:`tealtools.passes.run_all_passes`
        (Phase B, after :meth:`propagate_range_arithmetic`).

        Returns the number of ranges newly tightened. Lazy-trips
        :meth:`propagate_range_arithmetic` (hence :meth:`propagate_ranges`)
        first so const / arithmetic bounds exist to refine. Lazily imported
        from :mod:`tealtools.passes.range_assert` so the substrate stays free
        of the dominance / refinement logic."""
        from ..passes.range_assert import propagate_assert_ranges as _impl
        return _impl(self)

    def propagate_bytemath_ranges(self) -> int:
        """Flow bigint ranges through bytemath ops (``b+``, ``b-``,
        ``b*``, ``b/``, ``b%``) using Python's arbitrary-precision
        ints, with ``itob`` / ``btoi`` bridging the uint64 ↔ bytes
        value spaces. Populates :attr:`TealType.int_value_range`.

        Returns the cumulative number of range installations /
        tightenings. Opt-in. Lazily trips
        :meth:`propagate_constants` and :meth:`propagate_ranges`
        first. Lazily imported from :mod:`tealtools.bytemath` so the
        substrate stays free of bytemath semantics."""
        from ..passes.bytemath import propagate_bytemath_ranges as _impl
        return _impl(self)

    def propagate_byte_lengths(self) -> int:
        """Tag bytes-producing SSAVars / Phis with their statically
        derivable :attr:`TealType.byte_length`. Opt-in (not part of
        :func:`tealtools.passes.run_all_passes`) so
        analyses that don't care about lengths aren't paying for it.

        Covers ``itob`` (always 8), ``bzero N`` with const ``N``,
        ``extract A B`` / ``substring A B`` (immediate forms),
        ``concat`` (sum of input lengths), and lifts the length
        directly from any ``Const("bytes", "0x..")`` literal already
        on an output. Phis adopt a length only when every arg agrees.

        Returns the number of SSAVars / Phis newly tagged. Idempotent:
        a second call walks the fixed point again and finds nothing
        further to add. Lazily imported from
        :mod:`tealtools.byte_length_prop` so the TEAL byte-op
        semantics stay out of the substrate."""
        from ..passes.byte_length_prop import propagate_byte_lengths as _impl
        return _impl(self)

    def propagate_stack_shuffles(self) -> None:
        """Copy-propagate the outputs of pure stack-shuffle opcodes
        (:data:`_STACK_SHUFFLE_OPS`) into their consumers and mark the
        shuffle assignments themselves with :attr:`Assignment.shuffled`
        so :meth:`Assignment.functional` renders them as ``// …``
        comments — the structural rewrite happens, but the original
        stack movement stays visible in the dump for inspection.

        For each shuffle ``a``, :func:`_shuffle_mapping` gives the
        per-output input index. Each output SSAVar ``a.outputs[i]`` is
        therefore guaranteed equal at runtime to ``a.inputs[m[i]]``, so
        every consumer (other ``Assignment.inputs`` slots and
        ``Phi.args``) is rewritten to read the input directly. Chains
        of shuffles are flattened in one pass via :func:`_resolve` so a
        single rewrite of consumers suffices.

        Should run before :meth:`materialize_phis` — phi args are
        list[SSAVar | Phi] until materialisation; rewriting them after
        materialisation could inject :class:`MatPhiVar` and break that
        invariant. Idempotent.
        """
        if self._shuffles_propagated:
            return

        from ..passes.stack_shuffle import propagate_stack_shuffles as _impl
        _impl(self)
        self._shuffles_propagated = True

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

        from ..passes.dead_const import eliminate_dead_constants as _impl
        _impl(self)
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
        (DirectPhi roots from the generator walk):

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

        from ..passes.materialize import materialize_phis as _impl
        _impl(self)
        self._materialized = True

    # -- rendering ----------------------------------------------------------

    def functional(self, **kwargs) -> str:
        from .render import functional as _impl
        return _impl(self, **kwargs)

    def print_functional(self, **kwargs) -> None:
        print(self.functional(**kwargs))

    def functional_by_block(self, **kwargs) -> str:
        from .render import functional_by_block as _impl
        return _impl(self, **kwargs)

    # -- graph view ---------------------------------------------------------

    def data_graph(self) -> nx.MultiDiGraph:
        from .render import data_graph as _impl
        return _impl(self)

    def cfg(self) -> nx.MultiDiGraph:
        from .render import cfg as _impl
        return _impl(self)

    # -- frame view (opt-in precision over PySSA's fat-frame substrate) ------

    def frame_resolution(self) -> dict:
        """Precise frame-slot model ``{Subroutine: passes.frame_resolution.SubFrames}``
        — each ``frame_dig``/``frame_bury`` resolved to its logical param / versioned
        local. Opt-in precision; the conservative fat-frame substrate the may-analyses
        rely on is untouched. Lazy + cached."""
        cache = getattr(self, "_frame_resolution_cache", None)
        if cache is None:
            from ..passes.frame_resolution import resolve
            cache = self._frame_resolution_cache = resolve(self)
        return cache

    # -- graphviz rendering ------------------------------------------------

    def to_dot(self, **kwargs) -> str:
        from .render import to_dot as _impl
        return _impl(self, **kwargs)

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
        SVG (same ``SvgResult`` type :mod:`tealtools.dot` uses)."""
        return render(
            self.to_dot(
                file=file,
                resolve_consts=resolve_consts,
                rankdir=rankdir,
                max_lines_per_bb=max_lines_per_bb,
            ),
            format=format,
            engine=engine,
        )
