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
        except Exception:
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
        except Exception:
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

    Termination is bounded by ``seen``: each SSAVar / Phi in the finite
    def-use graph is visited at most once, and a repeat visit returns
    False — sound under the MUST ``all(...)`` semantics (an unprovable
    arm just fails the conjunction). There is deliberately no separate
    recursion-depth cap: the old ``depth=4`` limit was redundant with
    ``seen`` for termination and only suppressed *real* field-flows
    sitting behind deep scratch / phi indirection (common in compiled
    Puya / ABI output), which made a present guard look absent — a
    false-positive source.
    """
    if operand is None:
        return False
    if seen is None:
        seen = set()
    if operand in field_vars:
        return True
    if isinstance(operand, SSAVar):
        if operand in seen:
            return False
        seen.add(operand)
        # Scratch bridge: load N reads from a slot. Every may-influencing
        # store must have written a field-flowing SSAVar.
        if operand.defined_by is not None and operand.defined_by.op == "load":
            stores = _scratch_stores_for(prog, operand)
            if not stores:
                return False
            return all(
                _operand_flows_from_field_var(
                    prog, prog.var(*s), field_vars, seen=seen,
                )
                for s in stores
            )
        # Frame bridge: a `frame_dig` param read flows from the field iff every
        # caller argument bound to that param does (MUST). The fat-frame SSA has
        # no def-use edge across the proto boundary; `frame_param_sources` is the
        # precise interprocedural layer that supplies the caller-arg set.
        frame_src = _frame_param_sources_cached(prog)
        args = frame_src.get(operand)
        if args:
            return all(
                _operand_flows_from_field_var(prog, a, field_vars, seen=seen)
                for a in args
            )
        return False
    if isinstance(operand, Phi):
        if operand in seen or not operand.args:
            return False
        seen.add(operand)
        return all(
            _operand_flows_from_field_var(
                prog, arg, field_vars, seen=seen,
            )
            for arg in operand.args
        )
    return False




def _scratch_stores_for(prog: SSAProgram, load_var: SSAVar) -> Optional[list]:
    """``g.nodes[load_node]["scratch_stores"]`` for the ``load`` opcode
    that produced ``load_var``. Returns the raw list of
    ``(file, line, output_idx)`` tuples that
    :func:`tealql.tealtools.graph.load_graph` populated, or ``None`` when the
    load isn't covered (dynamic-slot ``loads`` op, or the scratch
    influence query found no stores)."""
    if load_var.defined_by is None or load_var.defined_by.op != "load":
        return None
    prog._ensure_scratch_influence()
    for n in prog._graph.nodes:
        loc = getattr(n, "location", None)
        if loc is None:
            continue
        if loc.file == load_var.file and loc.start_line == load_var.line:
            return prog._graph.nodes[n].get("scratch_stores")
    return None
