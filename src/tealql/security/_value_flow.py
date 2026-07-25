"""Value-flow bridges shared by the detector layer: the per-program
PathPredicateAnalysis cache, the interprocedural frame-param map, and the
MUST-flow walk (phi / scratch / proto-frame) from a seed-var set.

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Phi, SSAProgram, SSAVar



def cached_path_predicates(prog: SSAProgram) -> PathPredicateAnalysis:
    """One :class:`PathPredicateAnalysis` per program, memoised on ``prog``.

    The OnCompletion / field-guard family (is-deletable, is-updatable,
    unprotected-*, delete-funds-check, timelock-upgrade, rekey-to, …) each need
    path predicates; building them once and sharing avoids re-running the whole
    branch/assert analysis per detector — the bulk of a scan's per-contract cost.
    Detectors that accept a caller-SEEDED ``path_predicates`` (the cross-contract
    runner) still pass their own; only the default is cached. Sound because the
    analysis is a pure read of ``prog``'s CFG, unaffected by additive passes."""
    pp = getattr(prog, "_sec_path_predicates", None)
    if pp is None:
        pp = PathPredicateAnalysis(prog)
        try:
            prog._sec_path_predicates = pp
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return pp




def _frame_param_sources_cached(prog: SSAProgram) -> dict:
    """``frame_param_sources(prog)`` (the interprocedural ``frame_dig`` output ->
    caller-arg map), memoised on the program so the per-BB path walk doesn't
    rebuild it. Cheap to compute, but called once per comparison operand."""
    cache = getattr(prog, "_sec_frame_param_sources", None)
    if cache is None:
        from tealql.tealtools.passes.frame_flow import frame_param_sources
        cache = frame_param_sources(prog)
        try:
            prog._sec_frame_param_sources = cache
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return cache




def _operand_flows_from_field_var(
    prog: SSAProgram,
    operand,
    field_vars: set,
    *,
    seen: Optional[set] = None,
) -> bool:
    """True if ``operand`` provably reads from one of the SSAVars in
    ``field_vars``, allowing for SSA-level bridges:

      - direct: operand is the SSAVar itself.
      - phi join: every arg flows from a field var (MUST semantics).
      - scratch: operand is a ``load N`` output whose every may-influencing
        store wrote a field-flowing SSAVar (MUST semantics, mirrors
        :meth:`SSAProgram.propagate_scratch_constants`).
      - frame (interprocedural): operand is a ``frame_dig`` param read whose
        every caller-bound argument flows from a field var (MUST). This is what
        lets a guard living *inside a proto subroutine* (``frame_dig -1; global
        ZeroAddress; ==; assert``, the field read happening in the caller and
        passed as a proto arg) count as protecting the field — without it the
        whole approval-exit family is blind across the callsub boundary and
        reports a cross-sub guard as absent (a false positive).

    Termination: ``on_path`` (the nodes on the CURRENT walk) breaks cycles by
    answering False for a back-edge — sound under the MUST ``all(...)``
    semantics, since an unprovable arm just fails the conjunction. There is
    deliberately no recursion-depth cap: the old ``depth=4`` limit only
    suppressed *real* field-flows sitting behind deep scratch / phi
    indirection (common in compiled Puya / ABI output), which made a present
    guard look absent — a false-positive source.

    NOTE the cycle-break set is NOT a memo. It used to be one shared ``seen``
    set doing both jobs, which silently broke DIAMONDS: a node reached by a
    second conjunct — a value computed once and joined at a phi, the single
    most common shape in compiled output — was "already seen" and answered
    False, collapsing the whole ``all(...)`` and hiding a guard that is
    plainly there. ``memo`` caches genuine results (and skips caching any
    answer that a cycle-cut influenced, since that one is context-dependent),
    so a re-reached node is re-used rather than refuted.
    """
    if operand is None:
        return False
    memo: dict = {}
    on_path: set = set(seen) if seen else set()

    def _expand(node) -> "tuple[list, bool]":
        """``(operands that must ALL flow, is_a_bridge)``. ``is_a_bridge``
        False means the node has no incoming bridge at all (⇒ not a flow)."""
        if isinstance(node, Phi):
            return list(node.args), bool(node.args)
        # Scratch bridge: load N reads from a slot. Every may-influencing
        # store must have written a field-flowing SSAVar.
        if node.defined_by is not None and node.defined_by.op == "load":
            stores = _scratch_stores_for(prog, node)
            if not stores:
                return [], False
            return [prog.var(*s) for s in stores], True
        # Frame bridge: a `frame_dig` param read flows from the field iff every
        # caller argument bound to that param does (MUST). The fat-frame SSA has
        # no def-use edge across the proto boundary; `frame_param_sources` is the
        # precise interprocedural layer that supplies the caller-arg set.
        args = _frame_param_sources_cached(prog).get(node)
        return (list(args), True) if args else ([], False)

    def _walk(node) -> "tuple[bool, bool]":
        """``(flows, depended_on_a_cycle_cut)``."""
        if node is None:
            return False, False
        if node in field_vars:
            return True, False
        if not isinstance(node, (SSAVar, Phi)):
            return False, False
        if node in memo:
            return memo[node], False
        if node in on_path:
            return False, True                 # back edge: conservative, uncacheable
        on_path.add(node)
        try:
            parts, bridged = _expand(node)
            if not bridged:
                result, cut = False, False
            else:
                result, cut = True, False
                for part in parts:
                    flows, part_cut = _walk(part)
                    cut = cut or part_cut
                    if not flows:
                        result = False
                        break
        finally:
            on_path.discard(node)
        if not cut:
            memo[node] = result
        return result, cut

    return _walk(operand)[0]




def _scratch_stores_index(prog: SSAProgram) -> dict:
    """``{(file, start_line): scratch_stores}`` over the op graph, built once per
    program. :func:`_scratch_stores_for` used to LINEAR-SCAN ``prog._graph.nodes``
    on every lookup — ~0.25 ms per call on a real contract (tens of thousands of
    nodes) — from inside both the MUST-flow walk and the user-input taint
    fixpoint, i.e. inside two nested loops."""
    idx = getattr(prog, "_sec_scratch_store_index", None)
    if idx is None:
        prog._ensure_scratch_influence()
        idx = {}
        for n in prog._graph.nodes:
            loc = getattr(n, "location", None)
            if loc is None:
                continue
            stores = prog._graph.nodes[n].get("scratch_stores")
            if stores is not None:
                idx.setdefault((loc.file, loc.start_line), stores)
        try:
            prog._sec_scratch_store_index = idx
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return idx


def _scratch_stores_for(prog: SSAProgram, load_var: SSAVar) -> Optional[list]:
    """``g.nodes[load_node]["scratch_stores"]`` for the ``load`` opcode
    that produced ``load_var``. Returns the raw list of
    ``(file, line, output_idx)`` tuples that
    :func:`tealql.tealtools.graph.load_graph` populated, or ``None`` when the
    load isn't covered (dynamic-slot ``loads`` op, or the scratch
    influence query found no stores)."""
    if load_var.defined_by is None or load_var.defined_by.op != "load":
        return None
    return _scratch_stores_index(prog).get((load_var.file, load_var.line))
