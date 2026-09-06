"""Bounded disjunctive return summaries for legacy recursive call components.

The least fixed point starts with no known terminating calls. No approximation
is published until the entire component stabilizes. Each alternative retains
its physical depth and source values; unknown flags take both branch outcomes.
Ordinary instructions use the canonical stack transfer in :mod:`stacksim`.
Frame operations and below-band accesses refuse the proof for the whole cycle.
"""
from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from ..language.avm import SIG
from .execution_contexts import execution_bodies
from .return_shapes import ReturnShapes


@dataclass
class Refinement:
    returns: dict = field(default_factory=dict)
    refused: dict = field(default_factory=dict)
    bodies: object = None
    contexts_complete: bool = True


class _Refuse(Exception):
    pass


def analyze(blocks, partition, proto_io, return_point, arity, divergent,
            edge_polarity=None, *, max_steps=100_000, max_variants=32,
            max_cells=4096):
    """Complete summaries for recursive divergent components and their callees.

    Work and retained return cells are bounded across the entire query. Each
    routine walk also bounds retained local states. Exhaustion discards the
    unfinished component; callers cannot borrow its currently known base cases.
    """
    from . import stacksim

    result = Refinement()
    if not divergent:
        return result
    bodies, complete = execution_bodies(
        blocks, partition,
        lambda b: stacksim._isucc(b, (), return_point, owned_only=False))
    result.bodies, result.contexts_complete = bodies, complete
    if not complete:
        return result
    graph = nx.DiGraph()
    graph.add_nodes_from(s for s in bodies if s is not None)
    for sub, body in bodies.items():
        if sub is None:
            continue
        for block in body:
            if block.ops and block.ops[-1].op == 'callsub':
                callee = stacksim._callee_of(block, partition)
                if callee in graph:
                    graph.add_edge(sub, callee)
    components = nx.condensation(graph)
    targets = set()
    for _, data in components.nodes(data=True):
        members = data['members']
        cyclic = len(members) > 1 or any(graph.has_edge(s, s) for s in members)
        if cyclic and members & divergent:
            targets.update(members)
    if not targets:
        return result

    needed, work = set(targets), list(targets)
    while work:
        for callee in graph.successors(work.pop()):
            if callee not in needed:
                needed.add(callee)
                work.append(callee)
    constants = ReturnShapes(blocks, edge_polarity).constants
    polarity = edge_polarity or {}
    params = {}
    summaries, failures = {}, {}
    steps = retained = 0

    def tick():
        nonlocal steps
        steps += 1
        if steps > max_steps:
            raise _Refuse('work bound exhausted')

    def walk(sub, current):
        if sub in proto_io:
            raise _Refuse('frame-based callee requires its existing frame proof')
        if not 0 <= arity[sub][0] <= max_cells:
            raise _Refuse('argument cell bound exhausted')
        if sub not in params:
            params[sub] = tuple(stacksim._Param(sub.key, i) for i in range(arity[sub][0]))
        body = set(bodies[sub])
        seen, queue, exits = {}, deque(), {}
        cells = 0
        scratch = stacksim._Result()

        def enqueue(block, values):
            nonlocal cells
            tick()
            if block not in body:
                raise _Refuse('call continuation is unavailable')
            state = tuple(values)
            states = seen.setdefault(block, set())
            if state in states:
                return
            cells += len(state)
            if len(states) >= max_variants or cells > max_cells:
                raise _Refuse('local state bound exhausted')
            states.add(state)
            queue.append((block, state))

        enqueue(sub, params[sub])
        while queue:
            block, initial = queue.popleft()
            stack = list(initial)
            branch_flag = None
            for index, op in enumerate(block.ops):
                tick()
                if op.op in {'proto', 'frame_dig', 'frame_bury'}:
                    raise _Refuse('frame operations require a separate frame proof')
                if op.op == 'callsub':
                    if index != len(block.ops) - 1:
                        raise _Refuse('call is not a block terminator')
                    callee = stacksim._callee_of(block, partition)
                    if callee not in current:
                        raise _Refuse('callee has no complete return summary')
                    count = arity[callee][0]
                    if count > len(stack):
                        raise _Refuse('call may consume caller-owned cells')
                    args = stack[len(stack) - count:] if count else []
                    base = stack[:len(stack) - count] if count else stack
                    for returned in current[callee]:
                        values = [args[v.index] if isinstance(v, stacksim._Param)
                                  and v.sub_key == callee.key else v for v in returned]
                        enqueue(return_point.get(block), base + values)
                    break
                if op.op == 'retsub':
                    exits[tuple(stack)] = None
                    if len(exits) > max_variants:
                        raise _Refuse('return alternative bound exhausted')
                    break
                if op.op in {'return', 'err'}:
                    break              # whole-program halt cannot return to a caller
                if op.op not in SIG and op.op not in {'byte', 'addr', 'method'}:
                    raise _Refuse('unknown instruction stack effect')
                if op.n_in > len(stack):
                    raise _Refuse('instruction may consume caller-owned cells')
                if op.op in {'assert', 'bz', 'bnz'}:
                    branch_flag = constants.get(stack[-1]) if stack else None
                    if op.op == 'assert' and branch_flag == 0:
                        break          # no normally returning execution on this path
                stacksim._exec(op, block, stack, len(params[sub]), scratch,
                               partition, {}, arity, None)
                if len(stack) > max_cells:
                    raise _Refuse('stack cell bound exhausted')
            else:
                for successor in stacksim._isucc(block, body, return_point):
                    labels = polarity.get((block.key, successor.key))
                    if (block.ops and block.ops[-1].op in {'bz', 'bnz'}
                            and branch_flag is not None
                            and labels in (frozenset({'true'}), frozenset({'false'}))
                            and bool(branch_flag) != (labels == frozenset({'true'}))):
                        continue
                    enqueue(successor, stack)
        return exits

    for component in reversed(list(nx.topological_sort(components))):
        members = components.nodes[component]['members'] & needed
        if not members:
            continue
        current = {s: {} for s in sorted(members, key=lambda s: s.key)}
        try:
            while True:
                changed = False
                for sub in current:
                    for state in walk(sub, summaries | current):
                        if state in current[sub]:
                            continue
                        retained += len(state)
                        if len(current[sub]) >= max_variants or retained > max_cells:
                            raise _Refuse('return summary bound exhausted')
                        current[sub][state] = None
                        changed = True
                if not changed:
                    break
            if not all(current.values()):
                raise _Refuse('no complete normally returning alternatives')
            if any(max(map(len, states)) != arity[s][1] for s, states in current.items()):
                raise _Refuse('return depths disagree with the inferred call width')
        except _Refuse as error:
            failures.update((s, str(error)) for s in members)
            continue
        summaries.update((s, tuple(states)) for s, states in current.items())
    result.returns = summaries
    result.refused = {s: failures[s] for s in targets if s in failures}
    return result
