"""Bounded canonical instruction trace for one branch-free approval path."""
from __future__ import annotations

from dataclasses import dataclass

from ..cfg.dominance import all_blocks, program_entries
from ..diagnostics.health import health_for
from ..language.avm import op_arity


@dataclass(frozen=True)
class ExecutionTrace:
    operations: tuple
    complete: bool
    reason: str = ''


def execution_trace(program, *, max_steps=1024):
    if not health_for(program, deep=True).complete:
        return ExecutionTrace((), False, 'program facts are incomplete')
    entries = program_entries(all_blocks(program))
    if len(entries) != 1:
        return ExecutionTrace((), False, 'one program entry is required')
    block, seen, operations = entries[0], set(), []
    while block not in seen:
        seen.add(block)
        for assignment in block.stack_assignments:
            if len(operations) >= max_steps:
                return ExecutionTrace(tuple(operations), False, 'instruction budget exhausted')
            if assignment.op in {'bz', 'bnz', 'switch', 'match', 'callsub', 'retsub', 'proto'}:
                return ExecutionTrace(tuple(operations), False, 'conditional or subroutine control flow is unsupported')
            if len(assignment.inputs) < max(0, op_arity(assignment.op, assignment.immediates)[0]):
                return ExecutionTrace(tuple(operations), False, 'instruction operands are incomplete')
            operations.append(assignment)
            if assignment.op in {'return', 'err'}:
                return ExecutionTrace(tuple(operations), True)
        if len(block.successors) != 1:
            return ExecutionTrace(tuple(operations), False, 'an explicit program exit is required')
        block = block.successors[0]
    return ExecutionTrace(tuple(operations), False, 'cyclic control flow is unsupported')
