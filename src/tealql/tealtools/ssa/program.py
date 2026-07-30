""":class:`SSAProgram` — the canonical program type every analysis consumes.

``SSAProgram(source)`` loads a graph (:mod:`..graph`: CFG, AST, arities, const
annotations) then reconstructs SSA through :class:`PySSA` (:mod:`.ssa`), which
overwrites the phi layer in place. The pass bridge methods the detectors and
reports call live here.
"""
from __future__ import annotations

import bisect as _bisect
from pathlib import Path
from typing import Iterable, Optional

import networkx as nx

from .models import (
    Assignment,
    BasicBlock,
    Const,
    Location,
    Phi,
    SSAVar,
)
from ..avm import _CONST_BLOCK_REF_NAMES, op_arity
from .._utils.dot import render


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    # Four ways in, same two stages: load_graph(source) then SSA reconstruction.
    # `from_graph` exists so a caller can load/cache/transform the graph once and
    # rebuild SSA without re-parsing.

    def __init__(self, source: str | Path):
        """Parse a ``.teal`` file/dir and reconstruct SSA."""
        from .. import graph as tg
        self._build_from_graph(tg.load_graph(source))

    @classmethod
    def from_source(cls, source: str | Path) -> "SSAProgram":
        """As ``cls(source)``, named so the parse stage is visible at the call site."""
        from .. import graph as tg
        return cls.from_graph(tg.load_graph(source))

    @classmethod
    def from_graph(cls, graph) -> "SSAProgram":
        """Reconstruct SSA from an already-loaded graph — no parsing."""
        self = cls.__new__(cls)
        self._build_from_graph(graph)
        return self

    @classmethod
    def from_text(cls, teal: str, *, name: str = "contract.teal") -> "SSAProgram":
        """Build SSA from in-memory source; ``name`` is the file name findings report.

        The lift's source-text recovery (template names, dropped consts) still
        needs a real path; SSA and detector analysis work fully in-memory."""
        from .. import graph as tg
        return cls.from_graph(tg.load_graph({name: teal}))

    @property
    def parse_diagnostics(self) -> tuple:
        """Spans of TEAL source the grammar could not parse — recorded by
        :class:`..errors.ParseDiagnostic` spans dropped from analysis.

        HAZARD: non-empty means the program is PARTIAL — every downstream result
        may be incomplete. Never report a partially-parsed contract as clean."""
        return self._graph.graph.get("parse_diagnostics", ())

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
        # Sorted (file, line, label_text) — purely for rendering. Labels
        # have no SSA effect, but interleaving them with assignments in
        # ``functional()`` keeps the dump anchored to the source layout.
        self.labels: list[tuple[str, int, str]] = []
        self._consts_propagated: bool = False
        self._scratch_propagated: bool = False
        self._ranges_propagated: bool = False
        self._shuffles_propagated: bool = False
        self._inputs_propagated: bool = False

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
            # a loop finder would then misclassify as actual loops.
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
        """The BB whose source range contains ``(file, line)``.

        Bisects a per-file index of (first_line, last_line, bb), built once and
        cached. This is called per-instruction by several detectors, so the
        former linear scan over every block made those callers quadratic in
        program size."""
        cached = getattr(self, "_bb_line_index", None)
        # Cheap staleness check: the blocks dict is not rebuilt after
        # construction, but re-index if it ever is.
        if cached is None or cached[0] != len(self.blocks):
            idx: dict = {}
            for bb in self.blocks.values():
                idx.setdefault(bb.file, []).append(bb)
            # Store the sorted first_lines ALONGSIDE the blocks so the bisect
            # key list isn't rebuilt (an O(n) scan) on every lookup.
            packed = {
                f: (sorted(bs, key=lambda b: b.first_line),
                    sorted(b.first_line for b in bs))
                for f, bs in idx.items()
            }
            cached = (len(self.blocks), packed)
            self._bb_line_index = cached       # type: ignore[attr-defined]
        entry = cached[1].get(file)
        if entry is None:
            return None
        blocks, firsts = entry
        # Rightmost block whose first_line <= line; BB ranges are disjoint and
        # ordered, so only that one can contain the line.
        i = _bisect.bisect_right(firsts, line) - 1
        if i < 0:
            return None
        bb = blocks[i]
        return bb if bb.contains(line) else None

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
    # programs (via :meth:`tealql.tealtools.ssa.PySSA.build`) collapse args to
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

        # Const_value seeding + the ``identity_steps`` relation the impl reads
        # are now computed lazily (formerly eager at construction). Trigger
        # them here so every ``const_value`` reader — which runs this first —
        # sees the identical post-build state.
        self._ensure_identity_steps()
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
        the unification logic lives in :mod:`tealql.tealtools.input_prop`
        — the substrate just provides the entry point.

        ``itxn``-family reads are deliberately *not* included; itxn
        fields observe the most-recently-submitted inner transaction
        and can legitimately differ between submits."""
        if getattr(self, "_inputs_propagated", False):
            return
        from ..passes.input_prop import propagate_inputs as _impl
        _impl(self)
        self._inputs_propagated = True

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
        Iterates to a fixed point (a chained ``store/load/store/load``
        round-trip resolves one level per sweep), so a second call finds
        nothing further to forward.

        Best run after :meth:`propagate_inputs` (so equivalent input
        reads are already unified and forwarding through scratch can
        see them as a single SSAVar) and :meth:`propagate_scratch_constants`
        (so const stores resolve via const_value first). Runs as Phase A
        step 4 of :func:`tealql.tealtools.passes.run_all_passes`. Callers
        outside that pipeline should note that the SSAVar-identity change
        can surprise an analysis expecting a 1:1 mapping between load
        assignments and their downstream uses.
        """
        self._ensure_scratch_influence()
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
        :mod:`tealql.tealtools.cleanup` so the substrate stays free of the
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

        self._ensure_scratch_influence()
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
        :mod:`tealql.tealtools.range_arith` so the substrate stays free of
        the AVM arithmetic semantics."""
        from ..passes.range_arith import propagate_range_arithmetic as _impl
        return _impl(self)

    def propagate_assert_ranges(self) -> int:
        """Tighten ``IntRange`` annotations from the contract's ``assert``
        guards, flow-sensitively (a guard only constrains the paths it
        dominates). Part of :func:`tealql.tealtools.passes.run_all_passes`
        (Phase B, after :meth:`propagate_range_arithmetic`).

        Returns the number of ranges newly tightened. Lazy-trips
        :meth:`propagate_range_arithmetic` (hence :meth:`propagate_ranges`)
        first so const / arithmetic bounds exist to refine. Lazily imported
        from :mod:`tealql.tealtools.passes.range_assert` so the substrate stays free
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
        first. Lazily imported from :mod:`tealql.tealtools.bytemath` so the
        substrate stays free of bytemath semantics."""
        from ..passes.bytemath import propagate_bytemath_ranges as _impl
        return _impl(self)

    def propagate_byte_lengths(self) -> int:
        """Tag bytes-producing SSAVars / Phis with their statically
        derivable :attr:`TealType.byte_length`. Opt-in (not part of
        :func:`tealql.tealtools.passes.run_all_passes`) so
        analyses that don't care about lengths aren't paying for it.

        Covers ``itob`` (always 8), ``bzero N`` with const ``N``,
        ``extract A B`` / ``substring A B`` (immediate forms),
        ``concat`` (sum of input lengths), and lifts the length
        directly from any ``Const("bytes", "0x..")`` literal already
        on an output. Phis adopt a length only when every arg agrees.

        Returns the number of SSAVars / Phis newly tagged. Idempotent:
        a second call walks the fixed point again and finds nothing
        further to add. Lazily imported from
        :mod:`tealql.tealtools.byte_length_prop` so the TEAL byte-op
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

        Idempotent.
        """
        if self._shuffles_propagated:
            return

        from ..passes.stack_shuffle import propagate_stack_shuffles as _impl
        _impl(self)
        self._shuffles_propagated = True

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

    # -- lazy consumer-specific analyses (pay-for-what-you-use) ------------
    #
    # These three analyses used to run EAGERLY at the end of SSA
    # construction (``ssa._apply_pyssa_to``), even for callers that never
    # read their output (~58% of build time on a mid-size contract). They
    # are now computed-and-cached on first demand, mirroring
    # :meth:`frame_resolution`. Each ``_ensure_*`` is idempotent and moves
    # the eager block verbatim, so the deferral is observationally neutral:
    # every ``scratch_stores`` / ``inner_txn_fields`` reader now calls the
    # matching ``_ensure_*`` at its entry, and ``identity_steps`` +
    # ``const_value`` seeding are triggered by :meth:`propagate_constants`
    # (which every ``const_value`` reader runs first — see ``operands.py``).

    def _ensure_inner_txn_fields(self) -> None:
        """Group each ``itxn_field`` op under its immediately-enclosing
        ``(start, end)`` pair via CFG reach; stash on
        ``self._graph.graph["inner_txn_fields"]`` (the shape
        :class:`tealql.tealtools.inner_txn_report.InnerTxnReport` expects).
        Lazy + cached; formerly eager in ``_apply_pyssa_to``."""
        if getattr(self, "_inner_txn_fields_done", False):
            return
        from .ssa import _compute_inner_txn_fields
        if self._graph is not None and hasattr(self._graph, "graph"):
            self._graph.graph["inner_txn_fields"] = _compute_inner_txn_fields(self)
        self._inner_txn_fields_done = True

    def _ensure_scratch_influence(self) -> None:
        """Scratch-slot reaching-definitions: for every ``load N`` op, the
        set of ``store N`` value-SSAVars that may reach it via the CFG (with
        kill analysis). Populates the per-node annotation
        ``self._graph.nodes[load_node]["scratch_stores"]`` every consumer
        reads, and caches the raw dict on ``self._scratch_influence`` for
        :meth:`_ensure_identity_steps`. Lazy + cached; formerly eager in
        ``_apply_pyssa_to``."""
        if getattr(self, "_scratch_influence_done", False):
            return
        from .ssa import _compute_scratch_influence
        _scratch_stores = _compute_scratch_influence(self)
        self._scratch_influence = _scratch_stores
        if self._graph is not None:
            _nodes_by_loc: dict = {}
            for _n in self._graph.nodes:
                _loc = getattr(_n, "location", None)
                if _loc is not None:
                    _nodes_by_loc.setdefault(
                        (_loc.file, _loc.start_line), []
                    ).append(_n)
            for _load_key, _val_keys in _scratch_stores.items():
                for _node in _nodes_by_loc.get(_load_key, []):
                    self._graph.nodes[_node]["scratch_stores"] = list(_val_keys)
        self._scratch_influence_done = True

    def _ensure_identity_steps(self) -> None:
        """Seed ``const_value`` through value-identity edges (shuffle pass-
        through + scratch reads, to a fixed point) and build the identity-
        flow step relation on ``self._graph.graph["identity_steps"]``
        (consumed by :meth:`propagate_constants`). Depends on scratch
        influence, so ensures it first. Lazy + cached; formerly eager in
        ``_apply_pyssa_to``."""
        if getattr(self, "_identity_steps_done", False):
            return
        self._ensure_scratch_influence()
        from .ssa import _seed_consts_and_identity_steps
        _seed_consts_and_identity_steps(self, self._scratch_influence)
        self._identity_steps_done = True

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
        SVG (same ``SvgResult`` type :mod:`tealql.tealtools._utils.dot` uses)."""
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
