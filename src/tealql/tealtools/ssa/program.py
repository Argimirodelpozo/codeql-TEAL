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
from ..language.avm import _CONST_BLOCK_REF_NAMES, is_known_op, op_arity
from .._utils.dot import render


class SSAProgram:
    """Typed SSA-form representation of a TEAL program."""

    # Four ways in, same two stages: load_graph(source) then SSA reconstruction.
    # `from_graph` exists so a caller can load/cache/transform the graph once and
    # rebuild SSA without re-parsing.

    def __init__(self, source: str | Path, *, strict: bool = True):
        """Parse a ``.teal`` file/dir and reconstruct SSA.

        ``strict`` (the default) REFUSES a program the representation cannot
        be truthful about — unparsed spans (:class:`..errors.TealParseError`)
        or opcodes this build cannot model
        (:class:`..errors.UnknownOpcodeError`) — instead of silently building
        a wrong stack model. ``strict=False`` restores the permissive
        behaviour for surfaces that surface partiality themselves (the CLI
        and ``security.scan`` warn and annotate)."""
        from ..frontend import graph as tg
        self._build_from_graph(tg.load_graph(source), strict=strict)

    @classmethod
    def from_source(cls, source: str | Path, *, strict: bool = True) -> "SSAProgram":
        """As ``cls(source)``, named so the parse stage is visible at the call site."""
        from ..frontend import graph as tg
        return cls.from_graph(tg.load_graph(source), strict=strict)

    @classmethod
    def from_graph(cls, graph, *, strict: bool = True) -> "SSAProgram":
        """Reconstruct SSA from an already-loaded graph — no parsing."""
        self = cls.__new__(cls)
        self._build_from_graph(graph, strict=strict)
        return self

    @classmethod
    def from_text(cls, teal: str, *, name: str = "contract.teal",
                  strict: bool = True) -> "SSAProgram":
        """Build SSA from in-memory source; ``name`` is the file name findings report.

        The lift's source-text recovery (template names, dropped consts) still
        needs a real path; SSA and detector analysis work fully in-memory."""
        from ..frontend import graph as tg
        return cls.from_graph(tg.load_graph({name: teal}), strict=strict)

    @property
    def parse_diagnostics(self) -> tuple:
        """Spans of TEAL source the grammar could not parse — recorded by
        :class:`..errors.ParseDiagnostic` spans dropped from analysis.

        HAZARD: non-empty means the program is PARTIAL — every downstream result
        may be incomplete. Never report a partially-parsed contract as clean."""
        return self._graph.graph.get("parse_diagnostics", ())

    @property
    def source_files(self) -> tuple[str, ...]:
        """Source-file identities represented by this program, in stable order.

        A directory-backed :class:`SSAProgram` is a DISJOINT collection of AVM
        programs, not one executable.  Most SSA analyses can stay file-scoped;
        representations with a single entry (notably the lifted IR) must project
        one member first via :meth:`for_file`.
        """
        return tuple(sorted({a.location.file for a in self.assignments}))

    def for_file(self, file: str, *, strict: bool = True) -> "SSAProgram":
        """Reconstruct an independent SSA view containing exactly ``file``.

        The projection starts from the already parsed graph, so it neither
        reparses nor accidentally carries another contract's CFG edges, phis,
        diagnostics, or const-block state into this one.  ``file`` is the exact
        location identity exposed by :attr:`source_files` (nested directory
        inputs therefore use their relative path, not merely a basename).
        """
        files = self.source_files
        if file not in files:
            shown = ", ".join(files[:8]) + (" …" if len(files) > 8 else "")
            raise ValueError(f"source file {file!r} is not in this program ({shown})")
        if len(files) == 1 and (not strict or self._strict):
            return self

        if len(files) == 1:
            # A permissively-built program cannot satisfy a later strict
            # request by returning itself: its parser may already have dropped
            # instructions. Re-enter the boundary so diagnostics/unknown ops
            # raise exactly as a fresh strict construction would.
            return type(self).from_graph(self._graph, strict=True)

        nodes = [
            n for n in self._graph.nodes
            if getattr(getattr(n, "location", None), "file", None) == file
        ]
        g = self._graph.subgraph(nodes).copy()
        g.graph["parse_diagnostics"] = tuple(
            d for d in self.parse_diagnostics if getattr(d, "file", None) == file
        )
        g.graph["sources"] = self.sources.select({file})
        # Derived relations are program-wide caches.  Recompute them lazily on
        # the projected graph rather than retaining endpoints from other files.
        g.graph.pop("identity_steps", None)
        g.graph.pop("inner_txn_fields", None)

        return type(self).from_graph(g, strict=strict)

    def _build_from_graph(self, g, *, strict: bool = True) -> None:
        """Reconstruct the SSA program from a loaded graph ``g`` (no parsing).

        Strict mode enforces the representation's never-lie contract at its
        boundary: the parser DROPS spans it cannot parse (the model then
        behaves as if those ops never ran), and an opcode absent from this
        build's langspec is modelled with a ``(0, 0)`` stack effect (every
        value after it lands in the wrong slot). Both produce a plausible,
        silently wrong program — refusal with a named cause is the only
        truthful answer."""
        from ..ast import Opcode, Label

        if strict:
            _diags = g.graph.get("parse_diagnostics", ())
            if _diags:
                from ..core.errors import TealParseError
                raise TealParseError(_diags)

        self._graph = g
        self._strict = bool(strict)
        self._revision = 0
        from ..frontend.sources import ProgramSources
        sources = g.graph.get("sources")
        if not isinstance(sources, ProgramSources):
            # Compatibility for third-party graph producers. New graphs always
            # carry the snapshot; a legacy physical path is captured once here.
            src = g.graph.get("source", "")
            try:
                sources = (ProgramSources.load(src)
                           if src and src != "<memory>" else ProgramSources.empty())
            except Exception:
                sources = ProgramSources.empty()
            g.graph["sources"] = sources
        self.sources = sources
        self.source_path = sources.origin

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
        self._byte_lengths_propagated: bool = False
        self._bytemath_ranges_propagated: bool = False

        def _bb_from_tuple(bb_id: tuple) -> BasicBlock:
            bb = self.blocks.get(bb_id)
            if bb is None:
                bb = BasicBlock(*bb_id)
                self.blocks[bb_id] = bb
            return bb

        # Pass 1: build Assignments + their output SSAVars (arities from the
        # opcode signature table; PySSA reconstructs operand wiring + phis).
        _unknown_ops: set = set()
        for n in g.nodes:
            if not isinstance(n, Opcode):
                continue
            code = n.code or n.node_class
            op_name, _, imms = code.partition(" ")
            if not is_known_op(op_name):
                _unknown_ops.add(op_name)
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

        #: Opcodes THIS program uses that this build cannot model (each got a
        #: (0, 0) stack effect) — per-program, unlike the process-wide union
        #: ``avm.unknown_opcodes()``; the CLI's parse-health warning reads this.
        self.unknown_ops: frozenset = frozenset(_unknown_ops)
        if strict and _unknown_ops:
            from ..core.errors import UnknownOpcodeError
            raise UnknownOpcodeError(_unknown_ops)

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
        #: bb IDs with a control-flow edge that leaves the program without
        #: landing on any block (a branch to a label at EOF: the AVM runs off
        #: the end and terminates). There is no target BB, so this cannot be a
        #: ``successors`` entry — :attr:`cfg.CFG.exits` reads it here instead.
        self.off_end_exits: set[tuple] = set()
        #: ``(pred bb id, succ bb id) -> {successor labels}`` — the branch
        #: POLARITY :mod:`..cfg.build` already computed, carried down to the BB
        #: level. ``true`` means the branch condition was non-zero on that edge,
        #: ``false`` that it was zero, ``normal`` that it carries no condition.
        #:
        #: A pair maps to MORE THAN ONE label when a branch's arms collapse onto
        #: one block (``bnz next`` where ``next:`` is the following line): the
        #: branch does not partition flow there, so no predicate holds.
        #: :mod:`..path_predicates` reads this instead of re-deriving polarity
        #: from a second label map, which is how the two could disagree.
        self.edge_polarity: dict[tuple, frozenset] = {}
        _polarity: dict[tuple, set] = {}
        seen_edges: set[tuple[BasicBlock, BasicBlock]] = set()
        for u, v, data in g.edges(data=True):
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
            # A LABEL-ONLY block has a bb id but no BasicBlock — nothing defines or
            # consumes a value there, so none is built. Dropping its edges severs the
            # control flow THROUGH it: `bz L_end` and the fallthrough above it both
            # land on the label, and the block after it is left unreachable. Forward
            # to the first real block instead, which is where control actually goes.
            if v_bb is None:
                v_bb = self._forward_through_empty(g, v)
                if v_bb is None:
                    # No real block behind the label chain: control LEAVES the
                    # program here. `bz L_end` where `L_end:` is the last line
                    # runs off the end, which TERMINATES on the AVM (the stack
                    # top is the result) — a genuine exit with no BB to name.
                    # Record it, or the path vanishes and post-dominance rules
                    # the fall-through unavoidable. A pathological empty-label
                    # cycle also lands here; counting it as an exit only ever
                    # LOSES a proof, never invents one.
                    #
                    # HAZARD: keyed by bb ID, not stored on the BasicBlock —
                    # PySSA REBUILDS every block object afterwards, so a flag
                    # set on one here would be silently discarded.
                    self.off_end_exits.add(u_bb_id)
            if u_bb is None or v_bb is None:
                continue
            # BEFORE the dedup: a collapsed branch contributes two labels for
            # ONE (pred, succ) pair, and skipping here would keep only the first.
            kind = data.get("successor")
            if kind is not None:
                _polarity.setdefault((u_bb_id, v_bb._key()), set()).add(kind)
            if (u_bb, v_bb) in seen_edges:
                continue
            seen_edges.add((u_bb, v_bb))
            u_bb.successors.append(v_bb)
            v_bb.predecessors.append(u_bb)

        self.edge_polarity = {k: frozenset(v) for k, v in _polarity.items()}

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
            bb.phis.sort(key=lambda p: p.stack_index)

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

    @property
    def revision(self) -> int:
        """Monotonic version of this mutable SSA view.

        Derived caches key on this value. Public mutation still happens through
        the long-standing pass methods; each one commits a revision only after
        restoring def/use and invalidating dependent indexes.
        """
        return self._revision

    @property
    def stack_assignments(self) -> tuple[Assignment, ...]:
        """Canonical AVM opcode stream, unaffected by functional DCE.

        ``assignments`` remains the backward-compatible optimized/live value
        view. Stack-semantic consumers such as the lifter use this stream so a
        copy-propagated push cannot disappear underneath their simulation.
        """
        return getattr(self, "_stack_assignments", tuple(self.assignments))

    def stack_var(self, file: str, line: int, index: int) -> Optional[SSAVar]:
        """A value from the canonical opcode stream, including DCE'd values."""
        return getattr(self, "_stack_vars", self.vars).get((file, line, index))

    def health(self, *, deep: bool = False):
        """Completeness of this representation and, optionally, lazy facts."""
        from ..core.health import health_for
        return health_for(self, deep=deep)

    def result(self, value, *, deep: bool = False):
        """Wrap an analysis value with standardized completeness metadata."""
        from ..core.health import AnalysisResult
        return AnalysisResult(value, self.health(deep=deep))

    def _rebuild_uses(self) -> None:
        """Rebuild functional def/use after an operand rewrite."""
        values = {id(v): v for v in getattr(self, "_stack_vars", self.vars).values()}
        values.update((id(p), p) for p in self.phis.values())
        for value in values.values():
            value.uses = []
        for assignment in self.assignments:
            if assignment.shuffled:
                continue
            for operand in assignment.inputs:
                if hasattr(operand, "uses"):
                    operand.uses.append(assignment)

    def _invalidate_value_relations(self) -> None:
        """Drop products whose keys are SSA operands rewritten by a pass."""
        self._invalidate_phi_users()
        self._frame_resolution_cache = None
        self._frame_gap_sources_cache = None
        self._scratch_influence_done = False
        self._identity_steps_done = False
        self._scratch_influence = None
        self._scratch_facts = None
        graph = getattr(self, "_graph", None)
        if graph is not None:
            graph.graph.pop("identity_steps", None)
            for node in graph.nodes:
                graph.nodes[node].pop("scratch_stores", None)
                graph.nodes[node].pop("scratch_taint_sources", None)

    def _assert_analysis_mutable(self) -> None:
        if getattr(self, "_analysis_read_only", False):
            raise RuntimeError("cached derived analysis programs are read-only")

    def _commit_mutation(self, *, value_rewrite: bool = False) -> None:
        """Atomically publish one supported mutation to derived consumers."""
        self._assert_analysis_mutable()
        if value_rewrite:
            self._rebuild_uses()
            self._invalidate_value_relations()
        self._revision += 1

    def assignment_for_pyop(self, py_op):
        """Return the public :class:`Assignment` rebuilt from ``py_op``.

        This is the identity-safe bridge for internal consumers that combine
        canonical Python-SSA products with public SSA annotations.  Source
        locations are reporting coordinates, not cross-representation keys.
        ``None`` means the op belongs to a different program/build.
        """
        return getattr(self, "_pyop_id_to_assignment", {}).get(id(py_op))

    def pyop_for_assignment(self, assignment):
        """Return the canonical private op behind a public ``assignment``.

        The returned object is intentionally opaque to most callers; it is
        useful to consumers of semantic products retained on ``_pyssa``.
        """
        return getattr(self, "_assignment_to_pyop", {}).get(assignment)

    def var_for_pyvar(self, py_var):
        """Return the exact public :class:`SSAVar` rebuilt from ``py_var``."""
        return getattr(self, "_pyvar_id_to_var", {}).get(id(py_var))

    def pyvar_for_var(self, var):
        """Return the canonical private value behind a public ``SSAVar``."""
        return getattr(self, "_var_id_to_pyvar", {}).get(id(var))

    def phi_for_pyphi(self, py_phi):
        """Return the exact public :class:`Phi` rebuilt from ``py_phi``."""
        return getattr(self, "_pyphi_id_to_phi", {}).get(id(py_phi))

    def pyphi_for_phi(self, phi):
        """Return the canonical private phi behind a public ``Phi``."""
        return getattr(self, "_phi_id_to_pyphi", {}).get(id(phi))

    def block_for_pyblock(self, py_block):
        """Return the exact public block rebuilt from ``py_block``."""
        return getattr(self, "_pyblock_to_block", {}).get(py_block)

    def pyblock_for_block(self, block):
        """Return the canonical private block behind a public block."""
        return getattr(self, "_block_id_to_pyblock", {}).get(id(block))

    def var(self, file: str, line: int, index: int) -> Optional[SSAVar]:
        return self.vars.get((file, line, index))

    def phi(self, file: str, line: int, stack_index: int) -> Optional[Phi]:
        return self.phis.get((file, line, stack_index))

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
    # ``Phi.args`` is collapsed to SSAVar leaves for fast iteration, so the
    # structure lives on the auxiliary back-reference to the PyPhi graph.
    # These helpers cross through the exact-object bridge, so
    # consumers get structural queries without paying the iteration cost when
    # they don't need them. (The CodeQL extractor used to carry the same
    # structure in an ``IndirectPhi``'s args; nothing produces one any more.)

    def chain_predecessors(self, phi: "Phi") -> list["Phi"]:
        """Phis whose values flow into ``phi`` via propagation. Empty
        for chain roots (whose args are all :class:`SSAVar`)."""
        # Walk via the PyPhi graph if present.
        # Local import to avoid hard dep on the PySSA builder here.
        try:
            from .ssa import PyPhi  # type: ignore
        except Exception:
            return []
        pyphi = self.pyphi_for_phi(phi)
        if pyphi is None:
            return []
        out: list[Phi] = []
        for arg in pyphi.args:
            if isinstance(arg, PyPhi):
                w = self.phi_for_pyphi(arg)
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

    # -- query-scoped analysis ----------------------------------------------

    def analysis_context(self):
        """Return the revision-aware immutable fact cache for this program."""
        from ..analysis import AnalysisContext
        context = getattr(self, "_analysis_context_cache", None)
        if context is None:
            context = AnalysisContext(self)
            self._analysis_context_cache = context
        return context

    def facts(self, *domains):
        """Immutable value facts; never rewrites this SSA program."""
        return self.analysis_context().facts(*domains)

    def _deprecated_derived_view(self, method: str, profile):
        """Compatibility bridge for the former in-place analysis methods.

        The returned program is the cached, read-only normal form.  Deliberately
        do not mutate ``self``: old callers that ignored these methods' return
        values retain a truthful canonical program, while callers that need the
        historical annotations can migrate by consuming the returned view.
        """
        import warnings

        from ..analysis import derived_program

        warnings.warn(
            f"SSAProgram.{method}() no longer mutates the canonical program; "
            "consume the returned derived view or use analysis facts instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return derived_program(self, profile)

    def propagate_inputs(self):
        """Deprecated: return the immutable value-normalized SSA view."""
        from ..analysis import DerivedProfile
        return self._deprecated_derived_view("propagate_inputs", DerivedProfile.VALUE)

    def propagate_stack_shuffles(self):
        """Deprecated: return the immutable value-normalized SSA view."""
        from ..analysis import DerivedProfile
        return self._deprecated_derived_view(
            "propagate_stack_shuffles", DerivedProfile.VALUE
        )

    def propagate_assert_ranges(self):
        """Deprecated: return the immutable guard-refined SSA view."""
        from ..analysis import DerivedProfile
        return self._deprecated_derived_view(
            "propagate_assert_ranges", DerivedProfile.GUARDED
        )

    def propagate_scratch_values(self):
        """Deprecated: return the immutable value-normalized SSA view."""
        from ..analysis import DerivedProfile
        return self._deprecated_derived_view(
            "propagate_scratch_values", DerivedProfile.VALUE
        )

    def cleanup_unused_ssavars(self):
        """Deprecated: return the immutable presentation SSA view."""
        from ..analysis import DerivedProfile
        return self._deprecated_derived_view(
            "cleanup_unused_ssavars", DerivedProfile.PRESENTATION
        )

    # -- legacy annotation entry points ------------------------------------
    #
    # These remain temporarily for internal algorithms operating on a PRIVATE
    # derived program.  Shared-program consumers must use ``facts()`` or
    # ``analysis.derived_program`` so query order cannot change later results.

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
        self._assert_analysis_mutable()

        # Const_value seeding + the ``identity_steps`` relation the impl reads
        # are now computed lazily (formerly eager at construction). Trigger
        # them here so every ``const_value`` reader — which runs this first —
        # sees the identical post-build state.
        self._ensure_identity_steps()
        from ..analysis._constants import propagate_constants as _impl
        _impl(self)
        self._consts_propagated = True
        self._commit_mutation()

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
        self._assert_analysis_mutable()
        # Stack-side propagation needs to have run first so each store's
        # consumed SSAVar already has its const_value (if any) set.
        if not self._consts_propagated:
            self.propagate_constants()

        self._ensure_scratch_influence()
        from ..analysis._scratch import propagate_scratch_constants as _impl
        _impl(self)
        self._scratch_propagated = True
        self._commit_mutation()

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
        self._assert_analysis_mutable()

        from ..analysis._range_seed import propagate_ranges as _impl
        _impl(self)
        self._ranges_propagated = True
        self._commit_mutation()

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
        if (getattr(self, "_analysis_read_only", False)
                and getattr(self, "_range_arith_propagated", False)):
            return 0
        self._assert_analysis_mutable()
        from ..analysis._range_arithmetic import propagate_range_arithmetic as _impl
        changed = _impl(self)
        if changed:
            self._commit_mutation()
        return changed

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
        if (getattr(self, "_analysis_read_only", False)
                and self._bytemath_ranges_propagated):
            return 0
        self._assert_analysis_mutable()
        from ..analysis._bigints import propagate_bytemath_ranges as _impl
        changed = _impl(self)
        self._bytemath_ranges_propagated = True
        if changed:
            self._commit_mutation()
        return changed

    def propagate_byte_lengths(self) -> int:
        """Tag bytes-producing SSAVars / Phis with their statically
        derivable :attr:`TealType.byte_length`. Opt-in so analyses that don't
        care about lengths do not pay for it.

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
        if (getattr(self, "_analysis_read_only", False)
                and self._byte_lengths_propagated):
            return 0
        self._assert_analysis_mutable()
        from ..analysis._byte_lengths import propagate_byte_lengths as _impl
        changed = _impl(self)
        self._byte_lengths_propagated = True
        if changed:
            self._commit_mutation()
        return changed

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

    def _forward_through_empty(self, g, node, _limit: int = 64):
        """The first real :class:`BasicBlock` reachable from ``node`` through label-only blocks.

        A label with no instructions between it and the next label gets a bb id but no BasicBlock,
        because a BasicBlock is built from assignments and it has none. Every CFG edge that targets
        it was therefore discarded, taking two edges with it each time: the branch that named the
        label, and the fallthrough from the block above. The block after the label then had no
        predecessors at all, and the lift — with nowhere to branch — terminated the preceding block
        by exiting the program, handing puya whatever value the stack simulation happened to be
        holding. A `Can only exit with uint64 backed value` three layers downstream.

        TEALScript emits exactly this shape whenever an `if` ends where a loop continues::

            *if4_end:                  <- no instructions
            *for_0_continue:

        18 times in Reti's StakingPool, 16 in its ValidatorRegistry; puya-ts never does it, which is
        why it went unseen. Empty labels can chain, so this follows them transitively; `_limit`
        bounds a pathological chain and a `seen` set makes a cycle of empty labels terminate rather
        than hang.
        """
        seen = {node}
        frontier = [node]
        while frontier and _limit > 0:
            _limit -= 1
            nxt = []
            for n in frontier:
                for succ in g.successors(n):
                    if succ in seen:
                        continue
                    seen.add(succ)
                    bb_id = g.nodes[succ].get("bb")
                    bb = self.blocks.get(bb_id) if bb_id is not None else None
                    if bb is not None:
                        return bb
                    nxt.append(succ)
            frontier = nxt
        return None

    def cfg(self) -> nx.MultiDiGraph:
        from .render import cfg as _impl
        return _impl(self)

    # -- frame view (compatibility classification over canonical frame SSA) --

    def frame_resolution(self) -> dict:
        """Compatibility ``{Subroutine: FrameLayout}`` classification.

        Canonical SSA inputs carry live frame provenance. This lazy view remains
        for callers that classify reads as parameters, locals, or pushed slots.
        """
        cache = getattr(self, "_frame_resolution_cache", None)
        if cache is None:
            from .frame_slots import resolve_program
            cache = self._frame_resolution_cache = resolve_program(self)
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
        :class:`tealql.tealtools.reporting.inner_transactions.InnerTxnReport` expects).
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
        from .scratch_influence import compute_scratch_facts
        _scratch_facts = compute_scratch_facts(self)
        _scratch_stores = {
            location: list(fact.legacy_value_keys())
            for location, fact in _scratch_facts.items()
        }
        self._scratch_facts = _scratch_facts
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
                    self._graph.nodes[_node]["scratch_taint_sources"] = list(
                        _scratch_facts[_load_key].taint_keys
                    )
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

    # -- shared indexes ----------------------------------------------------

    def entry_blocks(self) -> list:
        """Each file's entry block, in ``(file, line)`` order.

        Use this rather than ``[b for b in blocks if not b.predecessors]``. TEAL's
        entry is the FIRST block, and a program whose first block is a branch
        target (a top-level retry loop) has predecessors on it — so the pred-free
        spelling silently returns nothing for exactly those programs. That
        criterion is documented as wrong in ``cfg.dominance.program_entries`` and
        was still re-derived in three places, one of them incorrectly."""
        first: dict = {}
        for bb in self.blocks.values():
            cur = first.get(bb.file)
            if cur is None or bb.first_line < cur.first_line:
                first[bb.file] = bb
        return [first[f] for f in sorted(first)]

    def phi_users(self, value) -> list:
        """Every ``Phi`` that takes ``value`` as an argument.

        ``SSAVar.uses`` records OP consumers only, never phi-argument references,
        so a consumer walking uses alone loses a value at the merge that carries
        it. Four call sites rebuilt this index by hand — two of them
        byte-identically — and one carried a HAZARD comment about the trap.
        Cached; call ``_invalidate_phi_users`` if phi args are rewritten."""
        idx = getattr(self, "_phi_users_index", None)
        if idx is None:
            idx = {}
            for p in self.phis.values():
                seen_args: set[int] = set()
                for a in p.args:
                    if id(a) in seen_args:
                        continue
                    seen_args.add(id(a))
                    idx.setdefault(id(a), []).append(p)
            try:
                self._phi_users_index = idx
            except AttributeError:      # only if SSAProgram ever gains __slots__
                idx = idx
        return idx.get(id(value), [])

    def _invalidate_phi_users(self) -> None:
        """Drop the :meth:`phi_users` cache — after any pass that rewrites
        ``Phi.args`` (the lift's dead-edge prune does, then restores)."""
        try:
            self._phi_users_index = None
        except AttributeError:
            pass

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
