"""Value-flow bridges shared by the detector layer: per-program path predicates,
frame provenance caches, and the MUST-flow walk (phi / scratch / proto-frame).
Import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import Phi, SSAProgram, SSAVar



def cached_path_predicates(prog: SSAProgram) -> PathPredicateAnalysis:
    """One :class:`PathPredicateAnalysis` per program, memoised on ``prog`` — the
    guard-family detectors would otherwise each re-run the branch/assert analysis,
    the bulk of a scan's per-contract cost. Sound because the analysis is a pure
    read of the CFG; a caller-SEEDED ``path_predicates`` bypasses the cache."""
    pp = getattr(prog, "_sec_path_predicates", None)
    if pp is None:
        pp = PathPredicateAnalysis(prog)
        try:
            prog._sec_path_predicates = pp
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return pp




def _frame_param_sources_cached(prog: SSAProgram) -> dict:
    """``frame_param_sources(prog)`` memoised — cheap, but called once per operand.

    PARAM sources only, deliberately. :func:`field_flows`' walk below is MUST
    ("every operand must flow"), and "every caller pins this arg" is a different
    claim from "every write to this slot flows" — so it must not be handed the
    unioned map. MAY consumers want :func:`_frame_gap_sources_cached`."""
    cache = getattr(prog, "_sec_frame_param_sources", None)
    if cache is None:
        from tealql.tealtools.passes.frame_flow import frame_param_sources
        cache = frame_param_sources(prog)
        try:
            prog._sec_frame_param_sources = cache
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return cache


def _frame_value_sources_cached(prog: SSAProgram) -> dict:
    """Memoised complete compatibility map: params and written locals.

    Retained for callers that consume the established API. Internal MAY walks
    use :func:`_frame_gap_sources_cached` because canonical SSA already carries
    ordinary resolved frame edges.
    """
    cache = getattr(prog, "_sec_frame_value_sources", None)
    if cache is None:
        from tealql.tealtools.passes.frame_flow import frame_value_sources
        cache = frame_value_sources(prog)
        try:
            prog._sec_frame_value_sources = cache
        except AttributeError:      # only if SSAProgram ever gains __slots__
            pass
    return cache


def _frame_gap_sources_cached(prog: SSAProgram) -> dict:
    """Only MAY frame edges not already present in normal SSA def-use."""
    cache = getattr(prog, "_sec_frame_gap_sources", None)
    if cache is None:
        from tealql.tealtools.ssa.frame_slots import gap_sources
        cache = gap_sources(prog)
        try:
            prog._sec_frame_gap_sources = cache
        except AttributeError:
            pass
    return cache




def _operand_flows_from_field_var(
    prog: SSAProgram,
    operand,
    field_vars: set,
    *,
    seen: Optional[set] = None,
) -> bool:
    """``operand`` provably reads from one of ``field_vars``, over three MUST-semantics
    bridges: a phi whose every arg flows, a ``load N`` whose every may-influencing
    store wrote a flowing var, and a ``frame_dig`` param whose every caller-bound
    arg flows (which is what sees a guard living inside a proto subroutine).

    HAZARD: ``on_path`` (cycle-break) and ``memo`` (results) MUST stay separate
    sets. One set doing both jobs breaks DIAMONDS — a value computed once and
    joined at a phi is "already seen" on the second conjunct, answers False, and
    collapses the whole ``all(...)``, hiding a guard that is plainly there. An
    answer influenced by a cycle-cut is context-dependent and is never memoised.

    There is deliberately NO recursion-depth cap: a cap only suppresses real
    field-flows behind deep scratch/phi indirection, making present guards absent.
    """
    if operand is None:
        return False
    memo: dict = {}
    on_path: set = set(seen) if seen else set()

    def _expand(node) -> "tuple[list, bool]":
        """``(operands that must ALL flow, is_a_bridge)``; ``is_a_bridge`` False
        means no incoming bridge at all, hence not a flow."""
        if isinstance(node, Phi):
            return list(node.args), bool(node.args)
        # Scratch bridge: every may-influencing store must have written a
        # field-flowing SSAVar.
        if node.defined_by is not None and node.defined_by.op == "load":
            stores = _scratch_stores_for(prog, node)
            if not stores:
                return [], False
            return [prog.var(*s) for s in stores], True
        # MUST reasoning needs the complete caller set even though canonical
        # SSA carries ordinary per-value frame provenance.
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




def resolve_through_copies(prog: SSAProgram, value, _seen=None):
    """Follow ``value`` back through VALUE-PRESERVING copies — a ``load N`` whose
    every may-influencing store wrote the SAME SSAVar, or a phi whose every arg
    resolves to the same one — else return it unchanged. MUST-semantics: an
    unprovable step stops the walk.

    HAZARD: any consumer inspecting ``value.defined_by`` for a comparison must go
    through this. Path predicates record the operand the branch actually consumed,
    so ``<cmp>; store 0; load 0; assert`` leaves the predicate on the LOAD output
    and a joined ``<cmp>`` leaves it on the PHI — reading either directly finds no
    comparison and declares a present guard absent."""
    if _seen is None:
        _seen = set()
    if isinstance(value, SSAVar):
        if value in _seen:
            return value
        _seen.add(value)
        d = value.defined_by
        if d is not None and d.op == "load":
            stores = _scratch_stores_for(prog, value)
            if stores:
                sources = [prog.var(*s) for s in stores]
                first = sources[0]
                if (first is not None and first is not value
                        and all(s is first for s in sources)):
                    return resolve_through_copies(prog, first, _seen)
        return value
    if isinstance(value, Phi):
        if value in _seen or not value.args:
            return value
        _seen.add(value)
        resolved = [resolve_through_copies(prog, a, _seen) for a in value.args]
        first = resolved[0]
        if first is not value and all(r is first for r in resolved):
            return first
    return value


def _scratch_stores_index(prog: SSAProgram) -> dict:
    """``{(file, start_line): scratch_stores}``, built once per program — the
    lookup sits inside two nested fixpoint loops, so a linear graph scan per call
    dominates the runtime."""
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
    """The ``(file, line, output_idx)`` store tuples reaching the ``load`` that
    produced ``load_var``, or ``None`` when it isn't covered (dynamic-slot
    ``loads``, or no stores found)."""
    if load_var.defined_by is None or load_var.defined_by.op != "load":
        return None
    return _scratch_stores_index(prog).get((load_var.file, load_var.line))
