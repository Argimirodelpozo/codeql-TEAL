"""The :class:`SSAProgram` class — the canonical program type every
analysis consumes.

``SSAProgram(db)`` runs a QL pre-pass via :mod:`tealtools.graphs`
(CFG / AST / arity / constant annotations, populating the data
classes from :mod:`tealtools.ssa.models`), then routes SSA
construction through :class:`PySSA` (:mod:`tealtools.ssa.ssa`) which
overwrites the phi layer in place. The constant-folding / range /
liveness / materialize passes live here as methods consumed by the
detectors and reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Union

import networkx as nx

from .models import (
    Assignment,
    BasicBlock,
    Const,
    IntRange,
    Location,
    MatPhiVar,
    Operand,
    Phi,
    SSAVar,
    TealType,
    _CONST_BLOCK_REF_NAMES,
    _GLOBAL_FIELD_RANGES,
    _OP_RANGE_SEEDS,
    _STACK_SHUFFLE_OPS,
    _TERMINATOR_OPS,
    _TXN_FIELD_RANGES,
    _shuffle_mapping,
)
from ..opcode_sigs import op_arity
from ..dot import escape, render


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    def __init__(self, db_path: str | Path, *, refresh: bool = False, verbose: bool = False):
        from .. import graphs as tg
        from ..ast import Opcode, Label

        g = tg.load_graph(db_path, refresh=refresh, verbose=verbose)
        self._graph = g
        self.db_path = Path(db_path).resolve()

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
            code = n.code or n.ql_class
            op_name, _, imms = code.partition(" ")
            cv = g.nodes[n].get("const_value")
            const: Optional[Const] = None
            if cv is not None and type(n).__name__ in _CONST_BLOCK_REF_NAMES:
                kind, value = cv
                const = Const(kind, value)
            bb_id = g.nodes[n].get("bb")
            bb = _bb_from_tuple(bb_id) if bb_id is not None else None

            # Output SSAVars from the opcode signature table (replaces QL's
            # ssaOutputs query). Inputs are left empty here — PySSA
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
            # Pre-attach per-output constant literals from the constValues
            # Python port: g.nodes[n]["const_outputs"] = {out_idx: (kind, value)}.
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
            # v.line``. Equal-line intra-BB edges arise from the
            # CodeQL extractor modeling template markers
            # (``pushint TMPL_FOO`` → ``Label@TMPL_FOO``) as
            # same-line CFG edges that aren't real control flow;
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

        # Replace the QL-loaded SSA layer (phis + assignment inputs +
        # block back-refs) with a PySSA-built one. The QL pre-pass
        # above only needs to populate ``self._graph`` /
        # ``self.vars`` (for const/range/type seeding) /
        # ``self.blocks`` / ``self.assignments`` (for arity); PySSA
        # then computes phi placement + chain collapse and overwrites
        # in place. This is what unblocks dropping the slow
        # ``phiArgs.ql`` / ``phiNodes.ql`` / ``phiEdges.ql`` queries
        # from the load path (see ``graphs.QUERY_NAMES``).
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
        # that get a ``kind`` from QL-row data (e.g.
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
    # QL-loaded programs carry chain structure in ``IndirectPhi.args``
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
        # QL-backed: read IndirectPhi.args directly.
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

        # Pass 1: SSAVars from their defining Assignment's resolved constant.
        for v in self.vars.values():
            if v.defined_by is not None and v.defined_by.const is not None:
                v.const_value = v.defined_by.const

        # Pass 2: fixed point over (a) phi-arg unification and (b) the
        # value-identity step relation from `valueIdentitySteps.ql`.
        #
        # (a) phi unification: a phi resolves when every arg resolves to
        #     the same literal. Covers phi-of-phi chains via iteration.
        # (b) identity steps: the QL lib emits one row per src/sink pair
        #     where `valueIdentityFlowStep` proves the runtime values are
        #     equal (stack passthrough, single-source phi, callsub /
        #     scratch bridge). If src has a `const_value`, sink shares it.
        #     This is what plugs the gap multi-arg phi unification can't
        #     close at the lib stratum: a phi K resolved by `tryAsIntPhi`
        #     in the query layer flows here into downstream consumer
        #     SSAVars and further phis.
        steps = self._graph.graph.get("identity_steps", []) or []

        def _resolve_endpoint(key):
            if key[0] == "var":
                _, f, l, i = key
                return self.vars.get((f, l, i))
            _, f, l, kind, idx = key
            return self.phis.get((f, l, kind, idx))

        # Pre-resolve endpoints once; skip steps where either side is
        # missing (e.g. a phi pruned by the SSA layer).
        resolved_steps: list[tuple] = []
        for src_key, snk_key in steps:
            src = _resolve_endpoint(src_key)
            snk = _resolve_endpoint(snk_key)
            if src is not None and snk is not None and src is not snk:
                resolved_steps.append((src, snk))

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
            for src, snk in resolved_steps:
                if src.const_value is not None and snk.const_value is None:
                    snk.const_value = src.const_value
                    changed = True
            # Op-level constant folding: any single-output Assignment
            # whose every input is now const-resolved gets its output
            # computed (concat / extract / itob / btoi / arithmetic /
            # comparisons / logical / ...). Lazily imported so the
            # substrate carries no TEAL-semantics knowledge by itself.
            # Runs inside the fixpoint so a fold-then-propagate-then-
            # fold chain converges naturally.
            from ..passes.const_fold import try_fold_assignment
            for a in self.assignments:
                if len(a.outputs) != 1:
                    continue
                out = a.outputs[0]
                if not isinstance(out, SSAVar) or out.const_value is not None:
                    continue
                folded = try_fold_assignment(a)
                if folded is not None:
                    out.const_value = folded
                    changed = True

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

    def propagate_scratch_values(self) -> int:
        """Generalises :meth:`propagate_scratch_constants` from compile-
        time literals to arbitrary SSA values.

        For each ``load N`` opcode whose may-influencing stores
        (provided by the CodeQL ``scratch_stores`` annotation) all
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

        from ..passes.scratch_prop import propagate_scratch_constants as _impl
        _impl(self)
        self._scratch_propagated = True

    def propagate_ranges(self) -> None:
        """Tag SSAVars / Phis with a static integer range and type.

        Independent, idempotent. Seeds come from three tables:
        :data:`_OP_RANGE_SEEDS` (op alone determines the bound, e.g.
        bool-shaped comparisons, ``getbyte``, ``len``),
        :data:`_TXN_FIELD_RANGES` (``txn``/``gtxn``/``gtxns``/``itxn``
        with an enum-valued field name as immediate), and
        :data:`_GLOBAL_FIELD_RANGES` (``global FIELD``). A second pass
        unions arg ranges through phis to fixed point.
        """
        if self._ranges_propagated:
            return

        UINT64 = TealType("uint64")

        def _seed(o, lo: int, hi: int) -> None:
            if isinstance(o, SSAVar) and o.range is None:
                o.range = IntRange(lo, hi)
                o.type = UINT64

        # Pass 1: seed from per-op rules. Single-output guard reflects
        # that every range-yielding op here produces exactly one stack
        # output; anything else would be a malformed Assignment.
        for a in self.assignments:
            if len(a.outputs) != 1:
                continue
            o = a.outputs[0]

            # 1a. Op alone gives the range (covers comparisons,
            # logical ops, getbit/getbyte, extract_uint{16,32},
            # len/bitlen).
            seed = _OP_RANGE_SEEDS.get(a.op)
            if seed is not None:
                _, lo, hi = seed
                _seed(o, lo, hi)
                continue

            if not a.immediates:
                continue
            toks = a.immediates.split()

            # 1b. txn-family field reads where the field carries the
            # range. ``txn``/``gtxns``/``itxn`` put the field in the
            # first immediate; ``gtxn`` / ``gtxna`` / ``gtxnsa`` etc.
            # put a group index first and the field second.
            field: Optional[str] = None
            if a.op in ("txn", "gtxns", "itxn") and toks:
                field = toks[0]
            elif a.op in ("gtxn", "gtxna", "gtxnas") and len(toks) >= 2:
                field = toks[1]
            if field is not None:
                rng = _TXN_FIELD_RANGES.get(field)
                if rng is not None:
                    _seed(o, *rng)
                    continue

            # 1c. global FIELD (only enum-valued fields seed).
            if a.op == "global" and toks:
                rng = _GLOBAL_FIELD_RANGES.get(toks[0])
                if rng is not None:
                    _seed(o, *rng)
                    continue

        # Pass 2: union ranges through phis to fixed point. A phi gets a
        # range only if every arg has one; the result is the smallest
        # box covering all of them. Type unifies to uint64 only when
        # every arg agrees.
        changed = True
        while changed:
            changed = False
            for ph in self.phis.values():
                if ph.range is not None or not ph.args:
                    continue
                arg_ranges: list[IntRange] = []
                ok = True
                for arg in ph.args:
                    r = getattr(arg, "range", None)
                    if r is None:
                        ok = False
                        break
                    arg_ranges.append(r)
                if not ok:
                    continue
                lo = min(r.lo for r in arg_ranges)
                hi = max(r.hi for r in arg_ranges)
                ph.range = IntRange(lo, hi)
                arg_types = [getattr(arg, "type", None) for arg in ph.args]
                if all(t is not None and t.kind == "uint64" for t in arg_types):
                    ph.type = UINT64
                changed = True

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

        # Step 1: collect the shuffle assignments and the per-output
        # redirect from each output SSAVar to its source operand.
        redirect: dict[SSAVar, Operand] = {}
        shuffle_assigns: list[Assignment] = []
        for a in self.assignments:
            if a.op not in _STACK_SHUFFLE_OPS:
                continue
            mapping = _shuffle_mapping(a)
            if mapping is None:
                continue
            shuffle_assigns.append(a)
            for out_idx, in_idx in enumerate(mapping):
                out = a.outputs[out_idx]
                if isinstance(out, SSAVar):
                    redirect[out] = a.inputs[in_idx]

        if not redirect:
            self._shuffles_propagated = True
            return

        # Step 2: flatten shuffle-of-shuffle chains so each output
        # resolves to its deepest non-shuffle source in one hop.
        def _resolve(o: Operand) -> Operand:
            seen: set[SSAVar] = set()
            while isinstance(o, SSAVar) and o in redirect:
                if o in seen:
                    break  # defensive: cycles shouldn't exist on valid TEAL
                seen.add(o)
                o = redirect[o]
            return o

        final: dict[SSAVar, Operand] = {v: _resolve(v) for v in redirect}

        # Step 3: rewrite every consumer. Both Assignment.inputs and
        # Phi.args may reference shuffle outputs.
        for a in self.assignments:
            a.inputs = [final.get(i, i) if isinstance(i, SSAVar) else i
                        for i in a.inputs]
        for ph in self.phis.values():
            ph.args = [final.get(arg, arg) if isinstance(arg, SSAVar) else arg
                       for arg in ph.args]

        # Step 4: mark the shuffle assignments. They stay in
        # ``self.assignments`` / ``bb.assignments`` and their output
        # SSAVars stay in ``self.vars`` so the commented dump line can
        # still resolve identifiers; the ``shuffled`` flag drives the
        # ``// …`` prefix in :meth:`Assignment.functional`.
        for a in shuffle_assigns:
            a.shuffled = True

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

        # Pass 2b: pin the topmost-stack SSAVar at every ``return`` op.
        # The CodeQL extractor models ``return`` with 0 stack_inputs, so
        # the program's exit value (always 1 popped value at runtime —
        # ``pushint 1; return`` is the canonical success pattern) has no
        # SSA consumer. Without this pin, propagate_constants resolves
        # the exit value's SSAVar to a literal, ref_vars no longer
        # includes it, and Pass 3 drops it — and Pass 4 then deletes
        # the producing op (the ``pushint`` / ``intc_*``) from the dump
        # entirely, even though that op *is* the program return value.
        # Heuristic: in any BB whose last assignment is ``return``, the
        # last op with non-empty ``outputs`` before the return produced
        # the value being returned; keep its outputs alive.
        returned_vars: set[SSAVar] = set()
        for bb in self.blocks.values():
            ret_idx = None
            for i, a in enumerate(bb.assignments):
                if a.op == "return":
                    ret_idx = i
                    break
            if ret_idx is None:
                continue
            for a in reversed(bb.assignments[:ret_idx]):
                if a.outputs:
                    for v in a.outputs:
                        if isinstance(v, SSAVar):
                            returned_vars.add(v)
                    break

        # Pass 3: identify dead constant SSAVars / Phis (have const_value
        # AND no remaining structural references).
        dead_vars = {
            v for v in self.vars.values()
            if v.const_value is not None
            and v not in ref_vars
            and v not in returned_vars
        }
        dead_phis = {
            ph for ph in self.phis.values()
            if ph.const_value is not None and ph not in ref_phis
        }

        # Pass 4: assignments whose every output is dead are dropped. Use
        # `id()` for set membership because :class:`Assignment` is an
        # unfrozen dataclass and not hashable. Control-flow terminators
        # (``retsub``, ``callsub``, ``b``, branches, ``return``, ``err``,
        # ``switch``, ``match``) are *never* dead — they have flow-graph
        # side effects independent of whether their SSA outputs have
        # consumers. Excluding them here is the substrate's correctness
        # guarantee that every consumer (control-tree builder, dataflow,
        # path analyses) can rely on retsubs etc. remaining in the IR.
        dead_assignment_ids: set[int] = {
            id(a) for a in self.assignments
            if a.outputs
            and all(o in dead_vars for o in a.outputs)
            and a.op not in _TERMINATOR_OPS
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

        # Compute transitive SSAVar leaves per phi via SCC condensation of
        # the phi-arg graph. All phis in the same SCC reach the same set
        # of SSAVar leaves by definition — computing leaves per-phi via
        # naive DFS does O(phi_count) redundant work on cycle-heavy
        # graphs (e.g. PySSA's unified PyPhi at constant-stack CFG loops
        # produces a giant SCC of ~17k phis on wormhole, making the
        # naive walk O(N²) and timing out at >20min for ~150k phis).
        # SCC-based memoization makes this O(N + E).
        import networkx as nx
        _args_graph = nx.DiGraph()
        _args_graph.add_nodes_from(self.phis.values())
        for _phi in self.phis.values():
            for _arg in _phi.args:
                if isinstance(_arg, Phi):
                    _args_graph.add_edge(_phi, _arg)
        _sccs = list(nx.strongly_connected_components(_args_graph))
        _scc_of: dict[Phi, int] = {}
        for _i, _scc in enumerate(_sccs):
            for _phi in _scc:
                _scc_of[_phi] = _i
        # Condensation DAG of SCCs; compute leaves bottom-up.
        _scc_succs: list[set[int]] = [set() for _ in _sccs]
        for _u, _v in _args_graph.edges:
            _su, _sv = _scc_of[_u], _scc_of[_v]
            if _su != _sv:
                _scc_succs[_su].add(_sv)
        # Seed each SCC with its members' direct SSAVar args.
        _scc_direct: list[list[SSAVar]] = [[] for _ in _sccs]
        for _phi in self.phis.values():
            _s = _scc_of[_phi]
            for _arg in _phi.args:
                if isinstance(_arg, SSAVar):
                    _scc_direct[_s].append(_arg)
        # Bottom-up: leaves(s) = direct(s) ∪ ⋃ leaves(succ) for each succ.
        # Build condensation as a DAG and walk in reverse topo order.
        _cond_dag = nx.DiGraph()
        _cond_dag.add_nodes_from(range(len(_sccs)))
        for _u, _succs_set in enumerate(_scc_succs):
            for _v in _succs_set:
                _cond_dag.add_edge(_u, _v)
        _scc_leaves: list[list[SSAVar]] = [[] for _ in _sccs]
        # ``nx.topological_sort`` orders ancestors first; reverse for
        # bottom-up.
        for _s in reversed(list(nx.topological_sort(_cond_dag))):
            _seen: set[int] = set()
            _out: list[SSAVar] = []
            for _v in _scc_direct[_s]:
                _key = id(_v)
                if _key not in _seen:
                    _seen.add(_key)
                    _out.append(_v)
            for _succ in _scc_succs[_s]:
                for _v in _scc_leaves[_succ]:
                    _key = id(_v)
                    if _key not in _seen:
                        _seen.add(_key)
                        _out.append(_v)
            _scc_leaves[_s] = _out

        def _leaf_ssavars(phi: Phi) -> list[SSAVar]:
            """Transitive SSAVar leaves reachable from ``phi.args``.
            O(1) lookup via precomputed SCC condensation; safe for
            cycles in the args graph."""
            return _scc_leaves[_scc_of[phi]]

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

        # Pass D: prune the original phis. Pass C just rewrote every
        # Assignment.inputs reference from Phi to MatPhiVar, so no
        # Assignment still consumes a Phi; their only remaining incoming
        # references are within other Phi.args (the phi-of-phi DAG),
        # which becomes structurally unreachable from the program once
        # we clear self.phis and bb.phis. Python GC reclaims it.
        self.phis = {}
        for bb in self.blocks.values():
            bb.phis = []

        self._materialized = True

    # -- rendering ----------------------------------------------------------

    def functional(
        self,
        *,
        file: Optional[str] = None,
        line_range: Optional[tuple[int, int]] = None,
        resolve_consts: bool = True,
        propagate_consts: bool = True,
        show_ranges: bool = False,
    ) -> str:
        # Merge labels and assignments by (file, line). Labels carry no
        # SSA effect, so the ``kind`` tiebreaker (0 for label, 1 for
        # assignment) just makes labels sort above assignments at the
        # same line — matching how they appear in the source.
        items: list[tuple] = []
        for lbl_file, lbl_line, lbl_code in self.labels:
            if file is not None and lbl_file != file:
                continue
            if line_range is not None and not (line_range[0] <= lbl_line <= line_range[1]):
                continue
            items.append((lbl_file, lbl_line, 0, lbl_code))
        for a in self.assignments_in(file=file, line_range=line_range):
            items.append((a.location.file, a.location.line, 1, a))
        items.sort(key=lambda x: (x[0], x[1], x[2]))

        lines = []
        for _, line, kind, obj in items:
            if kind == 0:  # Label
                lines.append(f"L{line:>4}: {obj}")
            else:
                lines.append(
                    f"L{line:>4}: "
                    f"{obj.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
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
        show_ranges: bool = False,
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
                    f"{a.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
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
                f'label="{escape(_bb_label(bb))}", '
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
