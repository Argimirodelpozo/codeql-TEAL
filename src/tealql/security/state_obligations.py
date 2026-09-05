"""Temporal storage proofs for bounded acyclic, call-free approval fragments.

Results concern executions reaching a selected instruction. Initial ledger
contents and preservation across revisions remain explicit premises.
"""
from __future__ import annotations

import networkx as nx

from tealql.tealtools.analysis.authority import authority_for
from tealql.tealtools.cfg.dominance import AssertDominance, all_blocks, program_entries
from tealql.tealtools.language.avm import op_arity
from tealql.tealtools.language.effects import STATE_EFFECTS
from tealql.tealtools.ssa import Const

from .encoding import encoding_leaves


class _FlowWindow:
    def __init__(self, context, *, max_nodes=4096):
        self.context = context
        self.graph = nx.DiGraph()
        self.reachable = set()
        self.dominance = None
        self.complete = len(context.program.assignments) <= max_nodes and context.health.complete
        if not self.complete:
            return
        self.complete &= not any(a.op in {'callsub', 'retsub', 'itxn_submit', 'app_params_set'}
                                 for a in context.program.assignments)
        self.complete &= all(len(a.inputs) >= max(0, op_arity(a.op, a.immediates)[0])
                             for a in context.program.assignments)
        if not self.complete:
            return
        blocks = all_blocks(context.program)
        self.graph.add_nodes_from(blocks)
        self.graph.add_edges_from((block, successor) for block in blocks for successor in block.successors)
        self.complete &= nx.is_directed_acyclic_graph(self.graph)
        for entry in program_entries(blocks):
            self.reachable.update(nx.descendants(self.graph, entry) | {entry})
        self.dominance = AssertDominance(context.program)

    def dominates(self, before, after):
        return bool(self.complete and before and after and after.basic_block in self.reachable
                    and self.dominance.dominates(before.basic_block, after.basic_block,
                                                 before.location.line, after.location.line))

    def between(self, before, after):
        if not self.dominates(before, after):
            return None
        forward = nx.descendants(self.graph, before.basic_block) | {before.basic_block}
        backward = nx.ancestors(self.graph, after.basic_block) | {after.basic_block}
        return [a for a in self.context.program.assignments if a.basic_block in forward & backward
                and (a.basic_block != before.basic_block or a.location.line > before.location.line)
                and (a.basic_block != after.basic_block or a.location.line < after.location.line)]


def _read(context, policy, name='read_line'):
    if type(policy[name]) is not int or type(policy.get('output', 1)) is not int:
        raise ValueError('authority read line and output must be integers')
    assignment = context.by_line.get(policy[name])
    index = policy.get('output', 1) - 1
    return (assignment, assignment.outputs[index]) if assignment and 0 <= index < len(assignment.outputs) else (None, None)


def _key(context, assignment):
    effect = STATE_EFFECTS.get(assignment.op)
    index = effect.key_index if effect else 0
    return context.facts.constant(assignment.inputs[index]) if index is not None and len(assignment.inputs) > index else None


def authority_freshness(context, policy):
    read, value = _read(context, policy)
    use = context.by_line.get(policy['line'])
    provenance = authority_for(context.program).address(value)
    ok = bool(read and use and provenance.preserved
              and context.proves(policy['line'], 'txn Sender', 'eq', context.expression(value)))
    reason = 'authority provenance, its sender guard, or the exact storage read is unproved'
    if ok and provenance.assumptions:
        # Storage aliases behind phis or non-exact copies need a disjunctive
        # temporal proof; this fragment requires one identifiable read.
        value = context.facts.resolve(value)
        read = getattr(value, 'defined_by', None)
        ok = bool(read and read.op in {'app_global_get', 'app_local_get', 'app_global_get_ex', 'app_local_get_ex'})
        if ok:
            window = _FlowWindow(context).between(read, use)
            key = _key(context, read)
            storage = 'global' if read.op.startswith('app_global') else 'local'
            ok = window is not None and isinstance(key, Const) and key.kind == 'bytes'
            if not ok:
                reason = 'the exact storage read or acyclic window to its guarded use is unproved'
            for writer in window or ():
                effect = STATE_EFFECTS.get(writer.op)
                if effect and effect.storage == storage and (_key(context, writer) is None or _key(context, writer) == key):
                    ok = False
                    reason = f'potential authority change at line {writer.location.line}'
    return context.result('authority-freshness', str(policy['read_line']), policy['line'], ok,
                          'authority identity is unchanged between its read and guarded use' if ok else reason,
                          provenance.assumptions)


def replay_protection(context, policy):
    """Infer a monotone consumed-key invariant and its signed-field binding."""
    from .obligations import crypto_binding
    read = context.by_line.get(policy['read_line'])
    consume = context.by_line.get(policy['consume_line'])
    use = context.by_line.get(policy['line'])
    flow = _FlowWindow(context)
    signature = crypto_binding(context, {**policy, 'line': policy['consume_line']})
    ok = bool(signature.status == 'PROVED' and read and read.op == 'app_global_get' and read.outputs
              and consume and consume.op == 'app_global_put' and len(consume.inputs) == 2
              and flow.dominates(read, consume) and flow.dominates(consume, use))
    if ok:
        read_key = encoding_leaves(context, read.inputs[0])
        write_key = encoding_leaves(context, consume.inputs[1])
        signed = {(context.annotation(row['value']), row['width']) for row in policy['fields']}
        ok &= bool(read_key and read_key == write_key and all(
            isinstance(field, str) and field.startswith('bytes:') or (field, width) in signed
            for field, width in read_key))
        # Matching flattened fields does not equate different hash/concat
        # layouts. Require the exact key value or an equal folded constant.
        ok &= context.expression(read.inputs[0]) == context.expression(consume.inputs[1])
        ok &= context.proves(consume.location.line, context.expression(read.outputs[0]), 'eq', 0)
        expected = Const('int', '1')
        ok &= context.facts.constant(consume.inputs[0]) == expected
        key_constant = _key(context, read)
        for writer in context.program.assignments:
            effect = STATE_EFFECTS.get(writer.op)
            if effect is None or effect.storage != 'global':
                continue
            other = _key(context, writer)
            if key_constant is not None and other is not None and other != key_constant:
                continue
            # Even a dynamic alias preserves consumption when every possible
            # write is the same nonzero marker. Deletion/reset cannot pass.
            ok &= (writer.op == 'app_global_put' and len(writer.inputs) == 2
                   and context.facts.constant(writer.inputs[0]) == expected)
    return context.result('replay', str(policy['consume_line']), policy['line'], ok,
        'signed fields determine the consumed key; zero check and monotone marker prevent reuse across successful invocations'
        if ok else 'signed key binding, zero guard, consumption order, or monotone writer invariant is unproved',
        (*signature.assumptions, 'consumed global keys persist across the evaluated invocation sequence and program revisions',
         'this proves at-most-once acceptance for a key, not storage capacity or availability'))


def proposal_invariant(context, policy):
    """Infer atomic, creator-authorized writes of the exact proposal/time pair."""
    from .obligations import lifecycle_obligation
    lifecycle = lifecycle_obligation(context, policy)
    reads = [context.by_line.get(policy[name]) for name in ('proposal_line', 'proposed_at_line')]
    flow = _FlowWindow(context)
    ok = lifecycle.status == 'PROVED' and flow.complete
    keys = [_key(context, read) if read else None for read in reads]
    ok &= all(key is not None and key.kind == 'bytes' for key in keys) and keys[0] != keys[1]
    for read in reads:
        window = flow.between(read, context.by_line.get(policy['line']))
        ok &= window is not None
        for writer in window or ():
            effect = STATE_EFFECTS.get(writer.op)
            if effect and effect.storage == 'global' and (_key(context, writer) is None or _key(context, writer) in keys):
                ok = False
    pairs = {}
    for writer in context.program.assignments:
        effect = STATE_EFFECTS.get(writer.op)
        if effect is None or effect.storage != 'global':
            continue
        key = _key(context, writer)
        if key is None:
            ok = False
        if key not in keys:
            continue
        ok &= writer.op == 'app_global_put' and len(writer.inputs) == 2
        pairs.setdefault(writer.basic_block, [[], []])[keys.index(key)].append(writer)
    ok &= bool(pairs)
    for proposals, times in pairs.values():
        if len(proposals) != 1 or len(times) != 1:
            ok = False
            continue
        proposal, timestamp = proposals[0], times[0]
        ok &= bool(timestamp.inputs and context.expression(timestamp.inputs[0]) == 'global LatestTimestamp')
        # The initial fragment roots writer permission in an immutable identity;
        # storage-authority initialization remains a separate obligation.
        ok &= all(context.proves(writer.location.line, 'txn Sender', 'eq', 'global CreatorAddress')
                  for writer in (proposal, timestamp))
    return context.result('proposal-invariant', str(policy['line']), policy['line'], ok,
        'every possibly aliasing proposal/time writer forms an atomic creator-authorized pair; upgrade checks bind the stored pair'
        if ok else 'proposal/time writer pairing, creator authorization, read freshness, or upgrade checks are unproved',
        ('initial proposal/time state was established by this writer invariant; revisions preserve it',
         'clear-program binding and application-specific proposal validity remain separate obligations'))
