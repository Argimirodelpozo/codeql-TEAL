"""Coverage of the supplied call graph, including omitted and unresolved edges."""
from ..diagnostics.health import AnalysisDegradation, AnalysisHealth, health_for
from ..reporting.inner_transactions import InnerTxnReport


def call_graph_health(graph):
    from .analysis import _const_only, _const_app_id
    edges = {(e.caller_app_id, e.site.file, e.site.submit_line, e.site.app_id) for e in graph.edges}
    notes = []
    for app_id, program in [(None, graph.caller), *graph.callees.items()]:
        notes.extend(health_for(program, deep=True).degradations)
        for group in InnerTxnReport(program):
            for txn in group.txns:
                types = txn.fields_by_name().get('TypeEnum', ())
                values = [_const_only(f.possible_values()) for f in types]
                if values and all(v is not None and v != '6' for v in values):
                    continue
                target = _const_app_id(txn, program) if values and set(values) == {'6'} else None
                if (app_id, group.file, group.submit_line, target) in edges:
                    continue
                message = ('inner application target is not proved'
                           if target is None else f'inner application {target} was not traversed')
                notes.append(AnalysisDegradation('unresolved-call', message,
                                                group.file, group.submit_line))
    return AnalysisHealth(tuple(dict.fromkeys(notes)))
