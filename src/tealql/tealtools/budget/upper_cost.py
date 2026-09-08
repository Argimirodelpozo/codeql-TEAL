"""Finite execution-cost upper bounds from independent induction certificates.

Count every reachable block, including rejecting paths, and compose nested
loop visit bounds and matched calls. Summing alternative blocks is deliberately
conservative. Opcode-credit ceilings never participate in this proof.
"""
from dataclasses import dataclass

import networkx as nx

from ..analysis import FactDomain
from ..ssa.operands import canonical_assignments, terminator_op
from .costs import CostModel, sum_costs


@dataclass(frozen=True)
class ExecutionUpper:
    upper: int | None
    reasons: tuple[str, ...] = ()


class UpperCost:
    def __init__(self, prog, *, model=None, analysis=None, max_blocks=4096):
        self.prog = prog
        self.model = model or CostModel(prog)
        self.analysis = analysis or prog.facts(FactDomain.RANGES).loop_analysis()
        self.graph = self.analysis.graph
        self.max_blocks = max_blocks
        self.cache = {}
        self.active = set()

    def from_block(self, start):
        self.analysis.facts.resolve(None)
        if start in self.cache:
            return self.cache[start]
        if start in self.active or len(self.active) >= 64:
            return ExecutionUpper(None, ('recursive or deep call cost has no finite proof',))
        if start not in self.graph:
            return ExecutionUpper(None, ('execution entry is absent from the loop graph',))
        self.active.add(start)
        try:
            result = self._region({start} | nx.descendants(self.graph, start))
            self.cache[start] = result
            return result
        finally:
            self.active.remove(start)

    def _region(self, blocks):
        if len(blocks) > self.max_blocks:
            return ExecutionUpper(None, ('execution-cost block budget exhausted',))
        counts = dict.fromkeys(blocks, 1)
        cut = self.graph.subgraph(blocks).copy()
        for region in self.analysis.regions:
            if not (region.body & blocks):
                continue
            proof = self.analysis.summary(region)
            if not proof.complete:
                return ExecutionUpper(None, ('reachable cycle: ' + proof.reason,))
            # Include an initial/final partial lap, early exits, and header tests.
            for block in region.body & blocks:
                counts[block] *= proof.trip_bound + 1
                if counts[block].bit_length() > 256:
                    return ExecutionUpper(None, ('nested loop count exceeds arithmetic budget',))
            cut.remove_edges_from(region.back_edges)
        if not nx.is_directed_acyclic_graph(cut):
            return ExecutionUpper(None, ('cyclic region has no complete induction cover',))
        info = self.model._subroutine_info()
        # The assembler may prepend intcblock/bytecblock for source literals,
        # including literals outside this region. Charging both per invocation
        # also safely overcounts them for callee-only and suffix queries.
        total = 2
        for block in blocks:
            fact = self.model.block_cost(block)
            if fact.upper is None:
                return ExecutionUpper(None, fact.reasons or ('opcode upper cost is unknown',))
            own = fact.upper
            if terminator_op(block) == 'callsub':
                callee = info['callsub_target'].get(block)
                if callee is None or info['continuations'].get(block) is None:
                    return ExecutionUpper(None, ('call target or continuation is unavailable',))
                nested = self.from_block(callee)
                if nested.upper is None:
                    return nested
                own += nested.upper
            total += own * counts[block]
        return ExecutionUpper(total)

    def after_read(self, read):
        block = read.basic_block
        # A callee's return does not end the caller's budget obligation.
        main = set()
        for entry in self.analysis.cfg.entries:
            if entry in self.graph:
                main.update({entry} | nx.descendants(self.graph, entry))
        if block not in main:
            return ExecutionUpper(None, ('budget guard needs its caller continuation context',))
        result = self.from_block(block)
        if result.upper is None:
            return result
        stream = canonical_assignments(block)
        index = stream.index(read)
        prefix = sum_costs(self.model.assignment_cost(a) for a in stream[:index + 1])
        # Only subtract a guaranteed prefix, and only on the initial visit.
        return ExecutionUpper(max(0, result.upper - prefix.lower))
