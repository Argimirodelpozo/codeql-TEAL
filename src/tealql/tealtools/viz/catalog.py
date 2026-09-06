"""Complete, executable visualization catalog for the tealtools pipeline.

The catalog is intentionally data, not a hand-written sequence in the CLI.
Adding a representation, whole-program analysis, or named transformation now
requires a visualization decision: annotated text, a DOT graph when the result
has topology, and a concrete explanation when it does not.  Tests audit that
contract and the known analysis/pass inventories.

Individual builders are best-effort at the report boundary.  Their underlying
analyses keep their normal never-fail/never-lie contracts; a failed optional
layer is represented as unavailable and cannot hide the other views.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class ViewKind(str, Enum):
    REPRESENTATION = "representation"
    ANALYSIS = "analysis"
    PASS = "pass"


TextBuilder = Callable[["VisualizationContext"], str]
DotBuilder = Callable[["VisualizationContext"], str]


@dataclass(frozen=True)
class ViewSpec:
    """One maintained visualization decision."""

    key: str
    title: str
    kind: ViewKind
    description: str
    text: TextBuilder = field(compare=False, repr=False)
    dot: Optional[DotBuilder] = field(default=None, compare=False, repr=False)
    graph_reason: Optional[str] = None
    requires_registry: bool = False
    requires_group: bool = False

    @property
    def has_graph(self) -> bool:
        return self.dot is not None


@dataclass(frozen=True)
class RenderedView:
    spec: ViewSpec
    text: str
    dot: Optional[str]
    text_error: Optional[str] = None
    graph_error: Optional[str] = None


class VisualizationContext:
    """Lazy products shared by every view in one dump.

    A full dump may ask for forty views, but it constructs the canonical SSA,
    fact domains, taint graph, and lifted IR at most once each.
    """

    def __init__(self, source, *, registry=None, group_members=None):
        self.source = source
        self.registry = registry
        self.group_members = group_members
        self._cache: dict[object, object] = {}

    def cached(self, key, build: Callable[[], object]):
        if key not in self._cache:
            self._cache[key] = build()
        return self._cache[key]

    @property
    def prog(self):
        from ..ssa import SSAProgram

        return self.cached("ssa", lambda: SSAProgram(self.source))

    @property
    def graph(self):
        from ..frontend.graph import load_graph

        return self.cached("graph", lambda: load_graph(self.source))

    def derived(self, profile):
        from ..analysis import derived_program

        return self.cached(("derived", profile), lambda: derived_program(self.prog, profile))

    def facts(self, domain):
        return self.cached(("facts", domain), lambda: self.prog.facts(domain))

    def ssa_pass_artifact(self, name: str) -> tuple[str, str, int, int]:
        artifacts = self.cached("ssa-pass-artifacts", lambda: _build_ssa_pass_artifacts(self))
        return artifacts[name]

    @property
    def pre_ir(self):
        from ..lift import lift

        return self.cached("pre-ir", lambda: lift(self.prog))

    @property
    def structure(self):
        from ..cfg.structure import analyze_structure

        return self.cached("structure", lambda: analyze_structure(self.prog))

    @property
    def path_predicates(self):
        from ..cfg.path_predicates import PathPredicateAnalysis

        return self.cached("path-predicates", lambda: PathPredicateAnalysis(self.prog))

    @property
    def taint_graph(self):
        from ..dataflow.taint_graph import TaintGraph

        return self.cached("taint-graph", lambda: TaintGraph.of(self.prog))


def _source_text(ctx: VisualizationContext) -> str:
    from ..frontend.sources import ProgramSources

    files = ProgramSources.load(ctx.source)
    return "\n\n".join(f"# {unit.name}\n{unit.text()}" for unit in files.files)


def _graph_text(ctx: VisualizationContext) -> str:
    graph = ctx.graph
    nodes = sorted(
        graph.nodes,
        key=lambda node: (
            getattr(node, "file", ""),
            getattr(getattr(node, "location", None), "start_line", 0),
        ),
    )
    return (
        f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges\n"
        + "\n".join(repr(node) for node in nodes)
    )


def _cfg_text(ctx: VisualizationContext) -> str:
    from ..cfg import CFG

    lines = []
    for block in CFG.of(ctx.prog).blocks:
        preds = ", ".join(f"L{p.first_line}" for p in block.predecessors) or "-"
        succs = ", ".join(f"L{s.first_line}" for s in block.successors) or "-"
        lines.append(
            f"BB L{block.first_line}-L{block.last_line}  "
            f"preds=[{preds}] succs=[{succs}]"
        )
    return "\n".join(lines)


def _render_ssa_program_text(prog) -> str:
    from ..ssa import render as ssa_render
    from .annotated import annotate_bytes_inline

    text = ssa_render.functional_by_block(prog, show_ranges=True)
    return annotate_bytes_inline(prog, text)


def _ssa_text(ctx: VisualizationContext, profile=None) -> str:
    prog = ctx.prog if profile is None else ctx.derived(profile)
    return _render_ssa_program_text(prog)


def _value_note(value) -> str:
    notes: list[str] = []
    constant = getattr(value, "const_value", None)
    if constant is not None:
        notes.append(f"const={constant.value}")
    rng = getattr(value, "range", None)
    if rng is not None:
        notes.append(f"range=[{rng.lo},{rng.hi}]")
    value_type = getattr(value, "type", None)
    if value_type is not None:
        if getattr(value_type, "byte_length", None) is not None:
            notes.append(f"len={value_type.byte_length}")
        if getattr(value_type, "byte_length_range", None) is not None:
            notes.append(f"len-range={value_type.byte_length_range}")
        if getattr(value_type, "int_value_range", None) is not None:
            notes.append(f"bigint={value_type.int_value_range}")
    return ", ".join(notes)


def _render_ssa_program_dot(prog, *, title: str = "SSA") -> str:
    from ..ssa import render as ssa_render

    def note(assignment) -> Optional[str]:
        rows = [f"{value}: {_value_note(value)}" for value in assignment.outputs
                if _value_note(value)]
        return "\n".join(rows) or None

    dot = ssa_render.to_dot(prog, assignment_note=note)
    return dot.replace("digraph TEAL_SSA {", f'digraph TEAL_SSA {{\n  label="{title}"; labelloc=t;')


def _ssa_dot(ctx: VisualizationContext, profile=None, *, title: str = "SSA") -> str:
    prog = ctx.prog if profile is None else ctx.derived(profile)
    return _render_ssa_program_dot(prog, title=title)


def _analysis_state(prog) -> tuple[dict, dict]:
    """Stable fact and operand-expression snapshots for pass deltas."""
    values = {}
    for value in [*prog.vars.values(), *prog.phis.values()]:
        key_fn = getattr(value, "_key", None)
        key = key_fn() if callable(key_fn) else repr(value)
        values[key] = (
            repr(getattr(value, "const_value", None)),
            repr(getattr(value, "range", None)),
            repr(getattr(value, "type", None)),
        )
    assignments = {
        (item.location.file, item.location.line, item.op): item.functional(
            resolve_consts=False,
            propagate_consts=False,
        )
        for item in prog.assignments
    }
    return values, assignments


def _changed(before: dict, after: dict) -> int:
    return sum(before.get(key) != value for key, value in after.items()) + sum(
        key not in after for key in before
    )


def _build_ssa_pass_artifacts(ctx: VisualizationContext) -> dict:
    """Run the real mutating implementation pipeline on one isolated program.

    The copy is never returned. Text and DOT are frozen immediately after each
    boundary, so later stages cannot retroactively alter an earlier pass view.
    """
    from ..analysis.context import _copy_program
    from ..analysis._input_aliases import propagate_inputs
    from ..analysis._range_refinement import propagate_assert_ranges
    from ..analysis._scratch import propagate_scratch_values
    from ..ssa.presentation import cleanup_unused_ssavars
    from ..ssa.value_rewrite import propagate_stack_shuffles

    prog = _copy_program(ctx.prog)
    artifacts = {}

    def inputs() -> None:
        propagate_inputs(prog)
        prog._rebuild_uses()
        prog._invalidate_value_relations()

    def scratch_values() -> None:
        prog._ensure_scratch_influence()
        propagate_scratch_values(prog)
        prog._rebuild_uses()

    def shuffles() -> None:
        propagate_stack_shuffles(prog)
        prog._rebuild_uses()

    stages = (
        ("constants", prog.propagate_constants),
        ("scratch_constants", prog.propagate_scratch_constants),
        ("range_seeds", prog.propagate_ranges),
        ("range_arithmetic", prog.propagate_range_arithmetic),
        ("input_aliases", inputs),
        ("scratch_values", scratch_values),
        ("stack_shuffles", shuffles),
        ("assert_ranges", lambda: propagate_assert_ranges(prog)),
        ("byte_lengths", prog.propagate_byte_lengths),
        ("bytemath_ranges", prog.propagate_bytemath_ranges),
        ("cleanup_unused_ssavars", lambda: cleanup_unused_ssavars(prog)),
    )
    before_values, before_assignments = _analysis_state(prog)
    for name, run in stages:
        run()
        after_values, after_assignments = _analysis_state(prog)
        artifacts[name] = (
            _render_ssa_program_text(prog),
            _render_ssa_program_dot(prog, title=f"SSA pass: {name}"),
            _changed(before_values, after_values),
            _changed(before_assignments, after_assignments),
        )
        before_values, before_assignments = after_values, after_assignments
    artifacts["run_all"] = artifacts["cleanup_unused_ssavars"]
    return artifacts


def _pyssa_text(ctx: VisualizationContext) -> str:
    from ..ssa.relations import shared_execution_blocks
    py = ctx.prog._pyssa
    rows = [py.render()]
    for block, entries in shared_execution_blocks(ctx.prog).items():
        rows.append(f"# Shared block L{block.key[1]}-{block.key[2]} execution operands")
        for entry in entries:
            context = py._stack_result.contexts.get(entry)
            rows.append(f"  routine L{entry.key[1]}")
            for op in block.ops:
                args = context.args.get(id(op), ()) if context else ()
                rows.append(f"    L{op.line} {op.op}: {args!r}")
    return '\n'.join(rows)


def _pre_ir_text(ctx: VisualizationContext) -> str:
    stats = ", ".join(f"{name}={count}" for name, count in ctx.pre_ir.pass_stats.items())
    return f"lift pass firings: {stats or '(none)'}\n\n{ctx.pre_ir.render()}"


def _puya_text(ctx: VisualizationContext) -> str:
    from ..lift import to_puya_ir

    return to_puya_ir.render(ctx.prog, optimize_ir=False)


def _fact_rows(ctx: VisualizationContext, domain) -> tuple[list[str], object]:
    facts = ctx.facts(domain)
    rows: list[str] = []
    for key, fact in sorted(facts.facts.items()):
        values = []
        if fact.constant is not None:
            values.append(f"const={fact.constant.value}")
        if fact.int_range is not None:
            values.append(f"range=[{fact.int_range.lo},{fact.int_range.hi}]")
        if fact.type is not None:
            if fact.type.byte_length is not None:
                values.append(f"len={fact.type.byte_length}")
            if fact.type.byte_length_range is not None:
                values.append(f"len-range={fact.type.byte_length_range}")
            if fact.type.int_value_range is not None:
                values.append(f"bigint={fact.type.int_value_range}")
        if values:
            rows.append(f"{key}: {', '.join(values)}")
    if facts.aliases:
        rows.append("aliases:")
        rows.extend(f"  {source} -> {target}" for source, target in sorted(
            facts.aliases.items(), key=lambda item: repr(item[0])
        ))
    return rows, facts


def _facts_text(ctx: VisualizationContext, domain) -> str:
    rows, _facts = _fact_rows(ctx, domain)
    return f"immutable {domain.value} facts ({len(rows)} annotated row(s)):\n" + (
        "\n".join(rows) if rows else "  (no non-top facts)"
    )


def _facts_dot(ctx: VisualizationContext, domain) -> str:
    facts = ctx.facts(domain)

    def note(assignment) -> Optional[str]:
        rows = []
        for value in assignment.outputs:
            fact = facts.fact(value)
            parts = []
            if fact.constant is not None:
                parts.append(f"const={fact.constant.value}")
            if fact.int_range is not None:
                parts.append(f"range=[{fact.int_range.lo},{fact.int_range.hi}]")
            if fact.type is not None:
                if fact.type.byte_length is not None:
                    parts.append(f"len={fact.type.byte_length}")
                if fact.type.int_value_range is not None:
                    parts.append(f"bigint={fact.type.int_value_range}")
            if parts:
                rows.append(f"{value}: {', '.join(parts)}")
        return "\n".join(rows) or None

    from ..ssa import render as ssa_render

    return ssa_render.to_dot(ctx.prog, assignment_note=note)


def _path_dot(ctx: VisualizationContext) -> str:
    from .graphs import annotated_cfg_dot

    annotations = {
        block: [repr(pred) for pred in sorted(preds, key=repr)]
        for block, preds in ctx.path_predicates.bb_preds.items()
        if preds
    }
    return annotated_cfg_dot(ctx.prog, annotations, title="path predicates in force")


def _dominance_text(ctx: VisualizationContext) -> str:
    from ..cfg import CFG

    cfg = CFG.of(ctx.prog)
    rows = []
    for block in cfg.blocks:
        doms = sorted(cfg.dominators(block), key=lambda item: item.first_line)
        post = sorted(cfg.post_dominators(block), key=lambda item: item.first_line)
        rows.append(
            f"L{block.first_line}: dom={','.join('L' + str(x.first_line) for x in doms)} "
            f"postdom={','.join('L' + str(x.first_line) for x in post)}"
        )
    return "\n".join(rows)


def _dominance_dot(ctx: VisualizationContext) -> str:
    from ..cfg import CFG
    from .graphs import annotated_cfg_dot

    cfg = CFG.of(ctx.prog)
    annotations = {}
    for block in cfg.blocks:
        ident = cfg.immediate_dominator(block)
        post = cfg.immediate_post_dominator(block)
        annotations[block] = [
            f"idom: {'L' + str(ident.first_line) if ident else '-'}",
            f"ipdom: {'L' + str(post.first_line) if post else '-'}",
        ]
    return annotated_cfg_dot(ctx.prog, annotations, title="dominance / post-dominance")


def _control_text(ctx: VisualizationContext) -> str:
    from ..cfg import CFG

    cfg = CFG.of(ctx.prog)
    rows = []
    for block, guards in cfg.control_dependence().items():
        body = ", ".join(
            f"L{guard.first_line}:{polarity or '?'}"
            for guard, polarity in sorted(guards, key=lambda item: item[0].first_line)
        ) or "unconditional"
        rows.append(f"L{block.first_line}: {body}")
    return "\n".join(rows)


def _scratch_text(ctx: VisualizationContext) -> str:
    from ..ssa.scratch_influence import compute_scratch_facts

    facts = compute_scratch_facts(ctx.prog)
    if not facts:
        return "(no scratch loads)"
    rows = []
    for (file, line), fact in sorted(facts.items()):
        rows.append(
            f"{file}:L{line}: values={sorted(fact.values)!r}; "
            f"selectors={sorted(fact.selectors)!r}; zero={fact.zero_initialized}; "
            f"unknown={fact.unknown}"
        )
    return "\n".join(rows)


def _scratch_dot(ctx: VisualizationContext) -> str:
    from ..ssa.scratch_influence import compute_scratch_facts
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for (_file, line), fact in compute_scratch_facts(ctx.prog).items():
        block = next((b for b in ctx.prog.blocks.values()
                      if b.first_line <= line <= b.last_line), None)
        if block is not None:
            annotations.setdefault(block, []).append(
                f"scratch L{line}: {len(fact.values)} value(s), "
                f"{len(fact.selectors)} selector(s)"
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="scratch reaching influence")


def _frame_text(ctx: VisualizationContext) -> str:
    layouts = ctx.prog.frame_resolution()
    if not layouts:
        return "(no declared frames)"
    rows = []
    for sub, layout in layouts.items():
        rows.append(f"{sub.name or 'sub@L' + str(sub.entry_bb.first_line)}:")
        rows.append(f"  parameter reads: {len(layout.dig_param)}")
        rows.append(f"  local reads: {len(layout.dig_local)}")
        rows.append(f"  buries: {len(layout.bury)}")
        rows.append(f"  pushed cells: {len(layout.pushed)}")
        rows.append(f"  final versions: {layout.final}")
    py_analysis = getattr(ctx.prog._pyssa, "_frame_analysis", None)
    if py_analysis is not None:
        rows.append(
            f"canonical plan: {len(py_analysis.reads)} read merge(s), "
            f"{len(py_analysis.returns)} return plan(s), "
            f"{len(py_analysis.poisoned)} poisoned block(s)"
        )
    return "\n".join(rows)


def _frame_dot(ctx: VisualizationContext) -> str:
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for sub, layout in ctx.prog.frame_resolution().items():
        for block in sub.body:
            annotations.setdefault(block, []).append(
                f"frame {sub.name or 'sub'}: params={len(layout.dig_param)}, "
                f"locals={len(layout.dig_local)}"
            )
    poisoned = set(getattr(ctx.prog._pyssa, "_height_poisoned", ()) or ())
    for block in ctx.prog.blocks.values():
        if block._key() in poisoned:
            annotations.setdefault(block, []).append("bottom anchor: poisoned/refusal")
    return annotated_cfg_dot(ctx.prog, annotations, title="frame-slot analysis")


def _callee_text(ctx: VisualizationContext) -> str:
    pyssa = ctx.prog._pyssa
    summaries = getattr(pyssa, "_effect_summaries", {}) or {}
    unsafe = getattr(pyssa, "_unsafe_callee_blocks", set()) or set()
    divergent = getattr(pyssa, "_divergent_legacy", set()) or set()
    rows = [
        f"unsafe/clobber callees: {len(unsafe)}",
        f"exact below-band summaries: {len(summaries)}",
        f"divergent legacy entries: {len(divergent)}",
    ]
    for entry, summary in summaries.items():
        rows.append(f"  {entry!r}: reaches {summary.reach} caller cell(s), "
                    f"{len(summary.paths)} exit path(s)")
    return "\n".join(rows)


def _callee_dot(ctx: VisualizationContext) -> str:
    from .graphs import structure_to_dot

    return structure_to_dot(ctx.structure)


def _inner_fields_text(ctx: VisualizationContext) -> str:
    ctx.prog._ensure_inner_txn_fields()
    rows = ctx.prog._graph.graph.get("inner_txn_fields") or []
    return "\n".join(str(row) for row in rows) if rows else "(no inner-transaction fields)"


def _inner_fields_dot(ctx: VisualizationContext) -> str:
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for assignment in ctx.prog.assignments:
        if assignment.op.startswith("itxn_") and assignment.basic_block is not None:
            annotations.setdefault(assignment.basic_block, []).append(
                f"L{assignment.location.line}: {assignment.op} {assignment.immediates}".rstrip()
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="inner-transaction grouping")


def _resource_demand_result(ctx: VisualizationContext):
    from ..analysis.resource_demand import resource_demand

    return ctx.cached("resource-demand", lambda: resource_demand(ctx.prog))


def _resource_demand_text(ctx: VisualizationContext) -> str:
    import json

    return json.dumps(_resource_demand_result(ctx).to_dict(), indent=2, sort_keys=True)


def _resource_requirements_text(ctx):
    from ..analysis.resource_requirements import resource_requirements
    return '\n'.join(f'{r.status} {r.dimension}: {r.requirement}'
                     for r in resource_requirements(ctx.prog))


def _box_permissions_text(ctx):
    from ..analysis.box_permissions import box_access_permissions
    results = box_access_permissions(ctx.prog, (), (), application_refs={})
    lines = [f'INCOMPLETE: {msg}' for msg in results.health.messages()]
    lines.extend(f'{location}: box {key}; UNKNOWN: {result.value.reason}'
                 for location, key, result in results.value)
    return '\n'.join(lines) or '(no box accesses)'


def _resource_demand_dot(ctx: VisualizationContext) -> str:
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for site in _resource_demand_result(ctx).sites:
        assignment = next(
            (item for item in ctx.prog.assignments
             if item.location.file == site.file and item.location.line == site.line
             and item.op == site.op),
            None,
        )
        if assignment is not None and assignment.basic_block is not None:
            detail = f": {site.field}" if site.field is not None else ""
            annotations.setdefault(assignment.basic_block, []).append(
                f"L{site.line} {site.category}{detail}"
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="resource demand")


def _auth_text(ctx: VisualizationContext) -> str:
    from ..analysis.auth import AuthDominationDetector

    findings = AuthDominationDetector(ctx.prog, path_predicates=ctx.path_predicates).detect()
    return "\n".join(item.pretty() for item in findings) or "(all configured sinks guarded)"


def _auth_dot(ctx: VisualizationContext) -> str:
    from ..analysis.auth import AuthDominationDetector
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for finding in AuthDominationDetector(
        ctx.prog, path_predicates=ctx.path_predicates
    ).detect():
        block = finding.sink.basic_block
        if block is not None:
            annotations.setdefault(block, []).append(
                f"UNGUARDED L{finding.line}: {finding.sink.op}"
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="auth domination verdicts")


def _taint_text(ctx: VisualizationContext) -> str:
    from ..dataflow.taint_query import TaintQuery

    query = ctx.cached("taint-query", lambda: TaintQuery(ctx.prog))
    hits = query.tainted_sinks()
    return "\n".join(hit.render() for hit in hits) or "(no attacker-input -> sensitive-sink flow)"


def _byte_taint_text(ctx: VisualizationContext) -> str:
    from ..dataflow.byte_taint import byte_taint

    result = ctx.cached("byte-taint", lambda: byte_taint(ctx.prog, validate=True))
    return result.render() + "\n\n" + result.render_provenance()


def _byte_taint_dot(ctx: VisualizationContext) -> str:
    from ..dataflow.byte_taint import byte_taint
    from ..ssa import render as ssa_render

    result = ctx.cached("byte-taint", lambda: byte_taint(ctx.prog, validate=True))

    def note(assignment) -> Optional[str]:
        rows = []
        for value in assignment.outputs:
            intervals = result.tainted_bytes(value)
            if intervals:
                rows.append(f"{value}: tainted bytes {intervals}")
            elif result.is_scalar_tainted(value):
                rows.append(f"{value}: attacker-tainted scalar")
        return "\n".join(rows) or None

    return ssa_render.to_dot(ctx.derived(_guarded()), assignment_note=note)


def _bounds_text(ctx: VisualizationContext) -> str:
    from ..dataflow.bounds import check_bounds

    sites = check_bounds(ctx.prog, speculative=True)
    return "\n".join(
        f"L{site.line} {site.op}: {site.reason}" for site in sites
    ) or "(no byte-access sites)"


def _bounds_dot(ctx: VisualizationContext) -> str:
    from ..dataflow.bounds import check_bounds
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for site in check_bounds(ctx.prog, speculative=True):
        assignment = next((a for a in ctx.prog.assignments
                           if a.location.line == site.line and a.op == site.op), None)
        if assignment is not None and assignment.basic_block is not None:
            annotations.setdefault(assignment.basic_block, []).append(
                f"L{site.line} {site.op}: {site.reason}"
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="byte-access bounds")


def _flow_report(ctx: VisualizationContext, family: str) -> str:
    if family == "box":
        from ..dataflow.box import (
            detect_correlated_flows,
            detect_into_box_flows,
            detect_out_of_box_flows,
        )
        groups = [
            ("into box", detect_into_box_flows(ctx.prog)),
            ("out of box", detect_out_of_box_flows(ctx.prog)),
            ("correlated", detect_correlated_flows(ctx.prog)),
        ]
    else:
        from ..dataflow.state import (
            detect_correlated_state_flows,
            detect_out_of_state_flows,
        )
        groups = [
            ("out of state", detect_out_of_state_flows(ctx.prog)),
            ("correlated", detect_correlated_state_flows(ctx.prog)),
        ]
    rows = []
    for name, findings in groups:
        rows.append(f"{name}: {len(findings)}")
        rows.extend(f"  {item.pretty()}" for item in findings)
    return "\n".join(rows)


def _predicate_filter_text(ctx: VisualizationContext) -> str:
    from ..dataflow.box import detect_into_box_flows
    from ..dataflow.predicate_aware import filter_validated

    violations = detect_into_box_flows(ctx.prog)
    remaining, suppressed = filter_validated(
        violations,
        ctx.prog,
        pp=ctx.path_predicates,
    )
    rows = [
        f"input violations: {len(violations)}",
        f"remaining: {len(remaining)}",
        f"suppressed by value-pinning predicate: {len(suppressed)}",
    ]
    rows.extend(f"  kept: {item.pretty()}" for item in remaining)
    rows.extend(f"  suppressed: {item.pretty()}" for item in suppressed)
    return "\n".join(rows)


def _cost_text(ctx: VisualizationContext) -> str:
    from ..budget.costs import block_cost, block_stack_delta

    rows = []
    for block in sorted(ctx.prog.blocks.values(), key=lambda item: item.first_line):
        cost = block_cost(block)
        quality = "exact" if cost.exact else "lower-bound"
        rows.append(
            f"L{block.first_line}-L{block.last_line}: cost {cost.lower} "
            f"({quality}), stack delta {block_stack_delta(block)}"
        )
    return "\n".join(rows)


def _cost_dot(ctx: VisualizationContext) -> str:
    from ..budget.costs import block_cost, block_stack_delta
    from .graphs import annotated_cfg_dot

    annotations = {}
    for block in ctx.prog.blocks.values():
        cost = block_cost(block)
        annotations[block] = [
            f"cost: {'=' if cost.exact else '>='}{cost.lower}",
            f"stack delta: {block_stack_delta(block)}",
        ]
    return annotated_cfg_dot(ctx.prog, annotations, title="opcode cost / stack effects")


def _loops_text(ctx: VisualizationContext) -> str:
    from ..budget import render

    return render(ctx.prog)


def _methods_text(ctx: VisualizationContext) -> str:
    from ..budget import summarize_methods

    rows = []
    for method in summarize_methods(ctx.prog):
        cost = method.minimum_required
        rendered = "unreachable/unknown" if cost is None else (
            str(cost.lower) if cost.exact else f">={cost.lower}"
        )
        rows.append(
            f"{method.name}: min approval cost {rendered}; "
            f"{len(method.loops)} loop(s); infeasible={method.proven_infeasible}"
        )
    return "\n".join(rows) or "(no handler components)"


def _budget_guards_text(ctx: VisualizationContext) -> str:
    from ..budget import analyze_opcode_budget_guards

    guards = analyze_opcode_budget_guards(ctx.prog)
    return "\n".join(
        f"L{g.enforcement.location.line}: budget {g.relation} {g.threshold}; "
        f"credit>={g.guaranteed_credit}; downstream="
        f"[{g.downstream_lower},{g.downstream_upper}] -> {g.verdict}"
        for g in guards
    ) or "(no OpcodeBudget guards)"


def _budget_guards_dot(ctx: VisualizationContext) -> str:
    from ..budget import analyze_opcode_budget_guards
    from .graphs import annotated_cfg_dot

    annotations: dict = {}
    for guard in analyze_opcode_budget_guards(ctx.prog):
        block = guard.enforcement.basic_block
        if block is not None:
            annotations.setdefault(block, []).append(
                f"OpcodeBudget >= {guard.guaranteed_credit}: {guard.verdict}"
            )
    return annotated_cfg_dot(ctx.prog, annotations, title="opcode budget guards")


def _budget_exhaustion_text(ctx: VisualizationContext) -> str:
    from ..budget import find_budget_exhaustion_candidates

    findings = find_budget_exhaustion_candidates(ctx.prog)
    return "\n".join(
        f"L{item.loop.header.first_line}: {item.reason}" for item in findings
    ) or "(no attacker-controlled budget-exhaustion candidates)"


def _group_text(ctx: VisualizationContext) -> str:
    from ..cfg.group import analyze, analyze_layout, analyze_per_exit

    return (
        "common shape:\n" + analyze(ctx.prog, ctx.path_predicates).render()
        + "\n\nper approving exit:\n"
        + analyze_per_exit(ctx.prog, ctx.path_predicates).render()
        + "\n\nlayout:\n"
        + analyze_layout(ctx.prog).render()
    )


def _group_dot(ctx: VisualizationContext) -> str:
    from ..cfg.group import per_block_constraints
    from .graphs import annotated_cfg_dot

    constraints = per_block_constraints(ctx.prog, ctx.path_predicates)
    return annotated_cfg_dot(
        ctx.prog,
        {block: [item.render() for item in items]
         for block, items in constraints.items()},
        title="group constraints in force",
    )


def _inner_report_text(ctx: VisualizationContext) -> str:
    from ..reporting.inner_transactions import InnerTxnReport

    return InnerTxnReport(ctx.prog).render()


def _health_text(ctx: VisualizationContext) -> str:
    health = ctx.prog.health(deep=True)
    if health.complete:
        return "complete: no known analysis degradation"
    return "\n".join(
        f"{item.code}: {item.message}"
        + (f" ({item.file}:L{item.line})" if item.file else "")
        for item in health.degradations
    )


def _source_map(ctx: VisualizationContext) -> dict:
    from ..frontend.source_map import source_map_for

    return ctx.cached("source-map", lambda: source_map_for(ctx.prog))


def _source_map_text(ctx: VisualizationContext) -> str:
    mapping = _source_map(ctx)
    if not mapping:
        return "(no compiler source map)"
    return "\n".join(
        f"{teal_file}:L{teal_line} -> {source_file}:L{source_line}"
        for (teal_file, teal_line), (source_file, source_line) in sorted(mapping.items())
    )


def _source_map_dot(ctx: VisualizationContext) -> str:
    from .._utils.dot import escape

    mapping = _source_map(ctx)
    out = [
        "digraph SOURCE_MAP {",
        '  rankdir=LR; label="TEAL to high-level source map"; labelloc=t;',
        '  node [shape=box, fontname="Monospace", fontsize=9];',
    ]
    for (teal_file, teal_line), (source_file, source_line) in sorted(mapping.items()):
        teal = escape(f"TEAL:{teal_file}:L{teal_line}")
        source = escape(f"SOURCE:{source_file}:L{source_line}")
        out.append(f'  "{teal}" [label="{escape(teal_file)}:L{teal_line}"];')
        out.append(f'  "{source}" [label="{escape(source_file)}:L{source_line}"];')
        out.append(f'  "{teal}" -> "{source}";')
    out.append("}")
    return "\n".join(out)


def _storage_text(ctx: VisualizationContext) -> str:
    from ..lift import to_puya_ir
    from ..lift.box_recovery import recover_storage_schema

    main, subs = to_puya_ir.to_puya(ctx.prog)
    schema = recover_storage_schema(main, subs)
    return "\n".join(item.render() for item in schema) or "(no app storage)"


def _abi_text(ctx: VisualizationContext) -> str:
    from ..lift import to_puya_ir

    main, subs = to_puya_ir.to_puya(ctx.prog)
    guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)
    flows = to_puya_ir.abi_address_fund_flows(main, subs)
    rows = [f"encoded-type guesses: {len(guesses)}"]
    rows.extend(
        f"  object#{key}: {value} ({'confident' if confident.get(key) else 'speculative'})"
        for key, value in guesses.items()
    )
    rows.append(f"address -> fund/asset sink flows: {len(flows)}")
    rows.extend(
        f"  {item['subroutine']} {item['field']}: {item['encoding']}; "
        f"caller_supplied={item['caller_supplied']}; guarded={item['guarded']}"
        for item in flows
    )
    return "\n".join(rows)


def _supercfg(ctx: VisualizationContext):
    from ..cfg import SuperCFG
    from ..intercontract.analysis import find_appcall_sites, load_registry

    if ctx.registry is None:
        return None
    registry = (
        ctx.registry if isinstance(ctx.registry, dict) else load_registry(ctx.registry)
    )
    if not find_appcall_sites(ctx.prog, registry):
        return None
    return ctx.cached("supercfg", lambda: SuperCFG.build(ctx.prog, registry))


def _supercfg_text(ctx: VisualizationContext) -> str:
    graph = _supercfg(ctx)
    if graph is None:
        return "(registry absent or no resolvable app-call sites)"
    return "\n".join(
        [f"{len(list(graph.blocks()))} super-block(s)",
         f"{len(graph.inter_edges)} inter-contract edge(s)"]
        + [f"  {edge.kind}: {edge.src!r} -> {edge.dst!r}" for edge in graph.inter_edges]
    )


def _supercfg_dot(ctx: VisualizationContext) -> str:
    graph = _supercfg(ctx)
    if graph is None:
        raise ValueError("registry absent or no resolvable app-call sites")
    return graph.to_dot(with_assignments=True)


def _xcontract_taint(ctx: VisualizationContext):
    from ..dataflow.xcontract_taint_graph import XContractTaintGraph

    if ctx.registry is None:
        return None
    return ctx.cached(
        "xcontract-taint",
        lambda: XContractTaintGraph.build(ctx.prog, ctx.registry),
    )


def _xcontract_taint_text(ctx: VisualizationContext) -> str:
    from ..dataflow.xcontract_taint_graph import (
        cross_taint_findings,
        render_cross_taint,
    )

    graph = _xcontract_taint(ctx)
    if graph is None:
        return "(AppID registry required)"
    return render_cross_taint(cross_taint_findings(graph))


def _xcontract_taint_dot(ctx: VisualizationContext) -> str:
    from .graphs import networkx_to_dot

    graph = _xcontract_taint(ctx)
    if graph is None:
        raise ValueError("AppID registry required")
    return networkx_to_dot(graph.g, title="cross-contract taint")


def _xcontract_graph(ctx: VisualizationContext):
    from ..intercontract.analysis import XContractGraph, load_registry

    if ctx.registry is None:
        return None
    registry = (
        ctx.registry if isinstance(ctx.registry, dict) else load_registry(ctx.registry)
    )
    return ctx.cached(
        "xcontract-analysis",
        lambda: XContractGraph.build(ctx.prog, registry),
    )


def _xcontract_text(ctx: VisualizationContext) -> str:
    from ..intercontract.analysis import render_xcontract

    graph = _xcontract_graph(ctx)
    if graph is None:
        return "(AppID registry required)"
    edges = "\n".join(f"  {edge.render()}" for edge in graph.edges)
    return (
        f"transitive app-call edges: {len(graph.edges)}\n{edges}\n\n"
        + render_xcontract(graph.sites, graph.analyses)
    )


def _xcontract_health_text(ctx: VisualizationContext) -> str:
    from ..intercontract.health import call_graph_health
    graph = _xcontract_graph(ctx)
    if graph is None:
        return 'UNKNOWN: an AppID registry is required to check omitted and unresolved call edges'
    health = call_graph_health(graph)
    return '\n'.join(health.messages()) or 'complete: every identified call edge is resolved'


def _cross_auth_text(ctx: VisualizationContext) -> str:
    from ..intercontract.analysis import cross_auth_findings

    graph = _xcontract_graph(ctx)
    if graph is None:
        return "(AppID registry required)"
    findings = cross_auth_findings(graph)
    return "\n".join(
        finding.render(graph.callee_sources[finding.app_id]) for finding in findings
    ) or "(no cross-contract auth findings)"


def _caller_guard_text(ctx: VisualizationContext) -> str:
    from ..cfg.super_auth import caller_guard_bypass_findings

    graph = _supercfg(ctx)
    if graph is None:
        return "(AppID registry required or no resolvable app-call sites)"
    findings = caller_guard_bypass_findings(graph)
    return "\n".join(item.pretty() for item in findings) or (
        "(no caller-guard bypass findings)"
    )


def _group_taint(ctx: VisualizationContext):
    from ..dataflow.group_taint_graph import GroupTaintGraph
    from ..ssa import SSAProgram

    if not ctx.group_members:
        return None
    return ctx.cached(
        "group-taint",
        lambda: GroupTaintGraph.build([SSAProgram(source) for source in ctx.group_members]),
    )


def _group_taint_text(ctx: VisualizationContext) -> str:
    from ..dataflow.group_taint_graph import group_taint_findings, render_group_taint

    graph = _group_taint(ctx)
    if graph is None:
        return "(ordered group members required)"
    return render_group_taint(group_taint_findings(graph))


def _group_taint_dot(ctx: VisualizationContext) -> str:
    from .graphs import networkx_to_dot

    graph = _group_taint(ctx)
    if graph is None:
        raise ValueError("ordered group members required")
    return networkx_to_dot(graph.g, title="cross-member atomic-group taint")


def _pass_text(ctx: VisualizationContext, name: str, profile) -> str:
    body, _dot, fact_changes, expression_changes = ctx.ssa_pass_artifact(name)
    return (
        f"pass: {name}\n"
        f"immutable target profile: {profile.value}\n"
        f"fact/type values changed at this boundary: {fact_changes}\n"
        f"assignment expressions changed at this boundary: {expression_changes}\n"
        "The canonical SSA is unchanged; this exact boundary was executed on "
        "an isolated construction copy.\n\n"
        + body
    )


def _pass_dot(ctx: VisualizationContext, name: str) -> str:
    return ctx.ssa_pass_artifact(name)[1]


def _lift_pass_text(
    ctx: VisualizationContext, name: str, stat_key: Optional[str],
) -> str:
    count = (
        str(ctx.pre_ir.pass_stats.get(stat_key, 0))
        if stat_key is not None
        else "not separately instrumented"
    )
    return (
        f"lift pass: {name}\nfired: {count}\n\n"
        "The final pre-IR is shown because lift transformations are atomic and "
        "do not expose unsafe intermediate programs. The firing count makes a "
        "refused/idle pass explicit.\n\n"
        + ctx.pre_ir.render()
    )


def _guarded():
    from ..analysis import DerivedProfile

    return DerivedProfile.GUARDED


def _build_catalog() -> tuple[ViewSpec, ...]:
    from ..analysis import DerivedProfile, FactDomain
    from ..budget import to_dot as loop_dot
    from ..cfg import CFG
    from . import render as graph_render
    from .graphs import pre_ir_to_dot, pyssa_to_dot, structure_to_dot
    from .policy_views import authority_text, congruences_text, numeric_calls_text, resource_bounds_text

    views: list[ViewSpec] = [
        ViewSpec("repr.source", "Source snapshot", ViewKind.REPRESENTATION,
                 "Immutable multi-file source snapshot.", _source_text,
                 graph_reason="Source text has ordering but no graph topology."),
        ViewSpec("repr.ast", "Parsed opcode graph", ViewKind.REPRESENTATION,
                 "Parsed AST/opcodes and source-level control edges.", _graph_text,
                 lambda c: graph_render.to_dot(c.graph)),
        ViewSpec("repr.cfg", "Basic-block CFG", ViewKind.REPRESENTATION,
                 "Canonical basic blocks and control-flow edges.", _cfg_text,
                 lambda c: CFG.of(c.prog).to_dot()),
        ViewSpec("repr.pyssa", "Construction SSA", ViewKind.REPRESENTATION,
                 "Retained stack-simulation SSA before public-model translation.",
                 _pyssa_text, lambda c: pyssa_to_dot(c.prog._pyssa)),
        ViewSpec("repr.ssa.canonical", "Canonical SSA", ViewKind.REPRESENTATION,
                 "Unrewritten detector-facing SSA.", lambda c: _ssa_text(c),
                 lambda c: _ssa_dot(c, title="canonical SSA")),
        ViewSpec("repr.ssa.value", "Value-normalized SSA", ViewKind.REPRESENTATION,
                 "Private identity/scratch/shuffle-normalized view.",
                 lambda c: _ssa_text(c, DerivedProfile.VALUE),
                 lambda c: _ssa_dot(c, DerivedProfile.VALUE, title="value SSA")),
        ViewSpec("repr.ssa.guarded", "Guard-refined SSA", ViewKind.REPRESENTATION,
                 "Private value view plus dominating assert refinements.",
                 lambda c: _ssa_text(c, DerivedProfile.GUARDED),
                 lambda c: _ssa_dot(c, DerivedProfile.GUARDED, title="guarded SSA")),
        ViewSpec("repr.ssa.presentation", "Presentation SSA", ViewKind.REPRESENTATION,
                 "Private guarded view with functional dead-value cleanup.",
                 lambda c: _ssa_text(c, DerivedProfile.PRESENTATION),
                 lambda c: _ssa_dot(c, DerivedProfile.PRESENTATION,
                                    title="presentation SSA")),
        ViewSpec("repr.pre_ir", "Typed mutable pre-IR", ViewKind.REPRESENTATION,
                 "Puya-shaped working IR produced by the precise lift.", _pre_ir_text,
                 lambda c: pre_ir_to_dot(c.pre_ir)),
        ViewSpec("repr.puya_ir", "Puya IR", ViewKind.REPRESENTATION,
                 "Backend-native lowered IR.", _puya_text,
                 lambda c: pre_ir_to_dot(
                     c.pre_ir, title="Puya IR control topology (from pre-IR bridge)"
                 )),
        ViewSpec("repr.structure", "Program structure", ViewKind.REPRESENTATION,
                 "Routing, handlers, call sites, and subroutine ownership.",
                 lambda c: c.structure.render(show_ranges=True),
                 lambda c: structure_to_dot(c.structure)),
        ViewSpec("repr.supercfg", "Cross-contract SuperCFG", ViewKind.REPRESENTATION,
                 "Caller/callee control graph when an AppID registry is supplied.",
                 _supercfg_text, _supercfg_dot, requires_registry=True),
    ]

    for domain in FactDomain:
        views.append(ViewSpec(
            f"analysis.facts.{domain.value}",
            f"Value facts: {domain.value}",
            ViewKind.ANALYSIS,
            "Immutable facts keyed by stable SSA identities.",
            lambda c, d=domain: _facts_text(c, d),
            lambda c, d=domain: _facts_dot(c, d),
        ))

    views.extend([
        ViewSpec("analysis.authority", "Authority provenance", ViewKind.ANALYSIS,
                 "Address and storage-writer evidence with initialization/history premises.",
                 authority_text, graph_reason='Conditional proofs are attached to individual source values.'),
        ViewSpec("analysis.congruences", "Inductive numeric residues", ViewKind.ANALYSIS,
                 "Exact values and modular invariants on successful arithmetic.",
                 congruences_text, graph_reason='Each SSA value has a scalar modulus/residue fact.'),
        ViewSpec("analysis.numeric_calls", "Numeric call summaries", ViewKind.ANALYSIS,
                 "Call-specific return bounds, congruences and explicit refusal reasons.",
                 numeric_calls_text, graph_reason='Results are indexed by call instruction and ABI return slot.'),
        ViewSpec("analysis.resource_bounds", "Quantitative resource bounds", ViewKind.ANALYSIS,
                 "Conservative trace requirements with unknown environmental credit.",
                 resource_bounds_text, graph_reason='Available credit and retry state must be supplied to the Python resource API.'),
        ViewSpec("analysis.xcontract_health", "Call graph completeness", ViewKind.ANALYSIS,
                 "Unresolved, omitted and depth-limited inner application calls.",
                 _xcontract_health_text, graph_reason='Completeness diagnostics describe omitted call edges.', requires_registry=True),
        ViewSpec("analysis.scratch", "Scratch influence", ViewKind.ANALYSIS,
                 "MAY reaching values and dynamic selector influence.",
                 _scratch_text, _scratch_dot),
        ViewSpec("analysis.frame", "Frame-slot provenance", ViewKind.ANALYSIS,
                 "Canonical poisoned-region plan and compatibility layout.",
                 _frame_text, _frame_dot),
        ViewSpec("analysis.callee_effects", "Callee effects", ViewKind.ANALYSIS,
                 "Divergent/unsafe callee classification and exact below-band summaries.",
                 _callee_text, _callee_dot),
        ViewSpec("analysis.inner_txn_fields", "Inner-txn field grouping",
                 ViewKind.ANALYSIS,
                 "Field definitions grouped between begin/next/submit boundaries.",
                 _inner_fields_text, _inner_fields_dot),
        ViewSpec("analysis.resource_demand", "Resource demand", ViewKind.ANALYSIS,
                 "Conservative fields, identities, boxes, and inner-txn syntax.",
                 _resource_demand_text, _resource_demand_dot),
        ViewSpec("analysis.resource_requirements", "Resource requirements", ViewKind.ANALYSIS,
                 "Conditional obligations for availability, fees, budget, balance, and recovery.",
                 _resource_requirements_text, graph_reason='Requirements are a flat set of environmental obligations.'),
        ViewSpec("analysis.box_permissions", "Box permission obligations", ViewKind.ANALYSIS,
                 "Box access sites requiring an explicit application and call-frame environment.",
                 _box_permissions_text, graph_reason='App identities and call frames must be supplied to the Python permission API.'),
        ViewSpec("analysis.dominance", "Dominance", ViewKind.ANALYSIS,
                 "Dominators, post-dominators, and immediate parents.",
                 _dominance_text, _dominance_dot),
        ViewSpec("analysis.control_dependence", "Control dependence",
                 ViewKind.ANALYSIS,
                 "Branches whose outcomes gate each basic block.", _control_text,
                 lambda c: CFG.of(c.prog).control_dependence_dot()),
        ViewSpec("analysis.path_predicates", "Path predicates", ViewKind.ANALYSIS,
                 "Predicates true on every path reaching each block.",
                 lambda c: c.path_predicates.render(), _path_dot),
        ViewSpec("analysis.group", "Atomic-group constraints", ViewKind.ANALYSIS,
                 "Common, per-exit, and per-position group shapes.",
                 _group_text, _group_dot),
        ViewSpec("analysis.auth", "Auth domination", ViewKind.ANALYSIS,
                 "Sensitive sinks without a recognized dominating auth guard.",
                 _auth_text, _auth_dot),
        ViewSpec("analysis.taint", "Coarse taint reachability", ViewKind.ANALYSIS,
                 "User-input to sensitive-sink reachability and channel graph.",
                 _taint_text, lambda c: c.taint_graph.to_dot()),
        ViewSpec("analysis.group_taint", "Cross-member group taint",
                 ViewKind.ANALYSIS,
                 "Ordered group members joined over gload/log channels.",
                 _group_taint_text, _group_taint_dot, requires_group=True),
        ViewSpec("analysis.xcontract_taint", "Cross-contract taint",
                 ViewKind.ANALYSIS,
                 "Caller/callee taint joined over app-call arguments, sender, and logs.",
                 _xcontract_taint_text, _xcontract_taint_dot, requires_registry=True),
        ViewSpec("analysis.byte_taint", "Byte-interval taint", ViewKind.ANALYSIS,
                 "Tainted byte ranges, validation, and provenance.",
                 _byte_taint_text, _byte_taint_dot),
        ViewSpec("analysis.bounds", "Byte-access bounds", ViewKind.ANALYSIS,
                 "Sound in-bounds/OOB proofs and attributed speculative verdicts.",
                 _bounds_text, _bounds_dot),
        ViewSpec("analysis.box_flow", "Box dataflow", ViewKind.ANALYSIS,
                 "Into/out-of/correlated box flow families.",
                 lambda c: _flow_report(c, "box"), lambda c: c.taint_graph.to_dot()),
        ViewSpec("analysis.state_flow", "State dataflow", ViewKind.ANALYSIS,
                 "Out-of/correlated application-state flow families.",
                 lambda c: _flow_report(c, "state"), lambda c: c.taint_graph.to_dot()),
        ViewSpec("analysis.predicate_validation", "Predicate-aware validation",
                 ViewKind.ANALYSIS,
                 "Taint findings partitioned by a dominating value-pinning predicate.",
                 _predicate_filter_text, _path_dot),
        ViewSpec("analysis.relational_lengths", "Relational length domain",
                 ViewKind.ANALYSIS,
                 "Difference-bound length/index relations materialized as access verdicts.",
                 _bounds_text, _bounds_dot),
        ViewSpec("analysis.block_costs", "Opcode costs and stack effects",
                 ViewKind.ANALYSIS,
                 "Langspec cost facts and exact canonical block stack deltas.",
                 _cost_text, _cost_dot),
        ViewSpec("analysis.loop_bounds", "Loop and budget bounds", ViewKind.ANALYSIS,
                 "Loop regions, cost floors, stack growth, and execution ceilings.",
                 _loops_text, lambda c: loop_dot(c.prog)),
        ViewSpec("analysis.method_budget", "Per-handler budget", ViewKind.ANALYSIS,
                 "Minimum approval cost and loop membership per handler.",
                 _methods_text, lambda c: loop_dot(c.prog)),
        ViewSpec("analysis.opcode_budget_guards", "OpcodeBudget guards",
                 ViewKind.ANALYSIS,
                 "Guard credit compared with downstream cost bounds.",
                 _budget_guards_text, _budget_guards_dot),
        ViewSpec("analysis.budget_exhaustion", "Budget exhaustion candidates",
                 ViewKind.ANALYSIS,
                 "Attacker-controlled loop continuation not pre-empted by stack failure.",
                 _budget_exhaustion_text, lambda c: loop_dot(c.prog)),
        ViewSpec("analysis.inner_transactions", "Inner-transaction report",
                 ViewKind.ANALYSIS,
                 "Submit groups, fields, and resolved caller/frame values.",
                 _inner_report_text, _inner_fields_dot),
        ViewSpec("analysis.abi", "ABI recovery and fund-flow leads",
                 ViewKind.ANALYSIS,
                 "Speculative encoded types and recovered address-to-sink flows.",
                 _abi_text,
                 graph_reason="This product is a scored table of type guesses and sink leads; "
                              "its underlying def-use topology is shown by analysis.taint."),
        ViewSpec("analysis.storage", "Recovered storage schema", ViewKind.ANALYSIS,
                 "Global/local/box keys and map schemas.", _storage_text,
                 graph_reason="A storage schema is a keyed table, not a flow graph."),
        ViewSpec("analysis.health", "Analysis health", ViewKind.ANALYSIS,
                 "Parse/model degradations that qualify all other answers.", _health_text,
                 graph_reason="Health is a flat diagnostic set, not graph-shaped."),
        ViewSpec("analysis.source_map", "Compiler source map", ViewKind.ANALYSIS,
                 "TEAL instruction locations mapped back to high-level source.",
                 _source_map_text, _source_map_dot),
        ViewSpec("analysis.xcontract_predicates", "Cross-contract predicates",
                 ViewKind.ANALYSIS,
                 "Seeded callee path predicates and approving-exit summaries.",
                 _xcontract_text, _supercfg_dot, requires_registry=True),
        ViewSpec("analysis.xcontract_auth", "Cross-contract auth",
                 ViewKind.ANALYSIS,
                 "Callee auth findings under caller-supplied argument seeds.",
                 _cross_auth_text, _supercfg_dot, requires_registry=True),
        ViewSpec("analysis.caller_guard_bypass", "Caller-guard bypass",
                 ViewKind.ANALYSIS,
                 "Callee sinks gated only by a bypassable caller-side guard.",
                 _caller_guard_text, _supercfg_dot, requires_registry=True),
    ])

    ssa_passes = (
        ("constants", DerivedProfile.VALUE),
        ("scratch_constants", DerivedProfile.VALUE),
        ("range_seeds", DerivedProfile.VALUE),
        ("range_arithmetic", DerivedProfile.VALUE),
        ("input_aliases", DerivedProfile.VALUE),
        ("scratch_values", DerivedProfile.VALUE),
        ("stack_shuffles", DerivedProfile.VALUE),
        ("assert_ranges", DerivedProfile.GUARDED),
        ("byte_lengths", DerivedProfile.GUARDED),
        ("bytemath_ranges", DerivedProfile.GUARDED),
        ("cleanup_unused_ssavars", DerivedProfile.PRESENTATION),
        ("run_all", DerivedProfile.PRESENTATION),
    )
    for name, profile in ssa_passes:
        views.append(ViewSpec(
            f"pass.ssa.{name}", f"SSA pass: {name}", ViewKind.PASS,
            "Exact pass boundary executed and frozen on an isolated SSA copy.",
            lambda c, n=name, p=profile: _pass_text(c, n, p),
            lambda c, n=name: _pass_dot(c, n),
        ))

    # Public transform functions use their real function names. Builder-only
    # structural phases retain the stable pass_stats key. Several established
    # transforms predate per-pass counters; their visualization says so rather
    # than turning an absent counter into the false claim "fired zero times".
    lift_passes = (
        ("splice_subroutines", "splice_subs"),
        ("splice_call_sites", "splice_sites"),
        ("apply_doomed_edges", "doomed_edges"),
        ("build_frame_position_phis", "frame_position_phis"),
        ("record_frame_slot_refusals", "frame_slot_refusals"),
        ("prune_dead_phis", None),
        ("isolate_cross_group_phis", None),
        ("sink_mixed_phi_scratch_stores", "sink_mixed_scratch"),
        ("recover_types", None),
        ("finalize_types", None),
        ("specialize_polymorphic_returns", "specialize_returns"),
        ("tail_duplicate_mixed_joins", "tail_dup_joins"),
        ("split_mixed_phis", "split_mixed_phis"),
        ("materialize_phi_consts", "phi_arms_given_up"),
        ("duplicate_cross_subroutine_blocks", "dup_cross_sub_blocks"),
        ("duplicate_pure_shared_sinks", "dup_cross_sub_blocks"),
        ("simplify_trivial_phis", None),
        ("lower_to_puya", None),
        ("optimize_puya", None),
    )
    for name, stat_key in lift_passes:
        views.append(ViewSpec(
            f"pass.lift.{name}", f"Lift pass: {name}", ViewKind.PASS,
            "Guarded pre-IR transformation with an explicit firing/refusal count.",
            lambda c, n=name, s=stat_key: _lift_pass_text(c, n, s),
            lambda c, n=name: pre_ir_to_dot(c.pre_ir, title=f"lift pass: {n}"),
        ))
    return tuple(views)


CATALOG: tuple[ViewSpec, ...] = _build_catalog()
CATALOG_BY_KEY = {view.key: view for view in CATALOG}


def render_views(
    source,
    *,
    keys: Optional[list[str] | tuple[str, ...]] = None,
    registry=None,
    group_members=None,
    graphs: bool = True,
) -> list[RenderedView]:
    """Build selected catalog views, isolating failures per text/graph layer."""
    selected = CATALOG if keys is None else tuple(CATALOG_BY_KEY[key] for key in keys)
    ctx = VisualizationContext(
        source,
        registry=registry,
        group_members=group_members,
    )
    out = []
    for spec in selected:
        text_error = graph_error = None
        try:
            body = spec.text(ctx) or "(empty)"
        except Exception as error:  # report boundary: one optional layer must not hide others
            text_error = f"{type(error).__name__}: {error}"
            body = f"(unavailable: {text_error})"
        dot = None
        context_missing = (
            (spec.requires_registry and registry is None)
            or (spec.requires_group and not group_members)
        )
        if graphs and spec.dot is not None and not context_missing:
            try:
                dot = spec.dot(ctx)
            except Exception as error:
                graph_error = f"{type(error).__name__}: {error}"
        out.append(RenderedView(spec, body, dot, text_error, graph_error))
    return out


__all__ = [
    "CATALOG",
    "CATALOG_BY_KEY",
    "RenderedView",
    "ViewKind",
    "ViewSpec",
    "VisualizationContext",
    "render_views",
]
