"""Implementation equivalence for a bounded straight-line instruction fragment."""
from __future__ import annotations

from dataclasses import replace
import re

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.analysis.execution_trace import execution_trace
from tealql.tealtools.language.avm import op_arity
from tealql.tealtools.ssa import Const
from tealql.tealtools.ssa.const_fold import try_fold_outputs
from tealql.tealtools.ssa.models import _canon_shuffle

from .obligations import ObligationResult

_SHUFFLES = {'dup', 'dup2', 'dupn', 'swap', 'cover', 'uncover', 'dig', 'bury'}
_LITERALS = {'int', 'byte', 'addr', 'method', 'pushint', 'pushbytes', 'pushints', 'pushbytess',
             'intc', 'intc_0', 'intc_1', 'intc_2', 'intc_3', 'bytec', 'bytec_0', 'bytec_1', 'bytec_2', 'bytec_3'}
_COMMUTATIVE = {'+', '*', '==', '!=', '&', '|', '^', '&&', '||'}


class _Symbols:
    def __init__(self):
        self.nodes, self.constants = {}, {}

    def intern(self, key):
        if key not in self.nodes:
            self.nodes[key] = len(self.nodes)
        return self.nodes[key]

    def literal(self, value):
        if value is None or value.kind not in {'int', 'bytes'}:
            raise ValueError('unresolved literal')
        if value.kind == 'int':
            if not 0 <= int(value.value) < 2 ** 64:
                raise ValueError('literal outside uint64')
            value = Const('int', str(int(value.value)))
        else:
            raw = bytes.fromhex(value.value.removeprefix('0x'))
            if len(raw) > 4096:
                raise ValueError('oversized byte literal')
            value = Const('bytes', '0x' + raw.hex())
        index = self.intern(('constant', value.kind, value.value))
        self.constants[index] = value
        return index


def _normal_form(program, symbols, max_steps):
    trace = execution_trace(program, max_steps=max_steps)
    if not trace.complete:
        raise ValueError(trace.reason)
    files = program._graph.graph['sources'].files
    if len(files) != 1:
        raise ValueError('one source version is required')
    match = re.search(rb'^\s*#pragma\s+version\s+(\d+)', files[0].normalized, re.MULTILINE)
    version = int(match[1]) if match else 1
    facts = program.facts(FactDomain.CONSTANTS)
    stack, events, tables = [], [], set()
    scratch = {}
    for assignment in trace.operations:
        op, immediate = assignment.op, assignment.immediates.strip()
        if op.startswith(('itxn', 'gitxn', 'app_params_', 'app_box_', 'gload')) or op in {'loads', 'stores'}:
            raise ValueError('external calls, program metadata, foreign boxes, or dynamic scratch are unsupported')
        if op == 'global' and immediate == 'OpcodeBudget':
            raise ValueError('opcode-budget observations depend on instruction layout')
        if op == 'ed25519verify':
            raise ValueError('signature verification implicitly binds the executing program hash')
        if op in {'intcblock', 'bytecblock'}:
            tables.add(op)
            continue
        if op == 'b':
            continue
        if op in _SHUFFLES:
            count, mapping = _canon_shuffle(op, immediate)
            if mapping is None or count > len(stack):
                raise ValueError('invalid stack shuffle')
            operands = [stack.pop() for _ in range(count)]
            stack.extend(reversed([operands[index] for index in mapping]))
        elif op in _LITERALS:
            for family in ('intc', 'bytec'):
                if op.startswith(family) and family + 'block' not in tables:
                    raise ValueError('constant table has not executed')
            stack.extend(symbols.literal(facts.constant(value)) for value in reversed(assignment.outputs))
        else:
            count, outputs = op_arity(op, immediate)
            if count < 0 or outputs < 0 or count > len(stack):
                raise ValueError('unknown or incomplete stack effect')
            operands = [stack.pop() for _ in range(count)]
            if op in {'pop', 'popn'}:
                continue
            if op in {'store', 'load'}:
                slot = int(immediate)
                if not 0 <= slot < 256:
                    raise ValueError('invalid scratch slot')
                if op == 'store':
                    scratch[slot] = operands[0]
                    events.append(('store', str(slot), tuple(operands)))
                else:
                    stack.append(scratch.get(slot, symbols.literal(Const('int', '0'))))
                    if len(stack) > 1000:
                        raise ValueError('stack exceeds the fixed protocol limit')
                continue
            if op in _COMMUTATIVE:
                operands.sort()
            folded = None
            if all(index in symbols.constants for index in operands):
                folded = try_fold_outputs(replace(assignment, inputs=[symbols.constants[index] for index in operands]))
            if folded is not None:
                stack.extend(symbols.literal(value) for value in reversed(folded))
            elif op in {'txn', 'global'}:
                # Epochs conservatively distinguish reads across state/log changes.
                stack.append(symbols.intern(('field', op, immediate, len(events))))
            else:
                event = op, immediate, tuple(operands)
                events.append(event)  # Keep every possible trap, even if its output is discarded.
                stack.extend(symbols.intern(('value', event, len(events), index)) for index in reversed(range(outputs)))
        if len(stack) > 1000:
            raise ValueError('stack exceeds the fixed protocol limit')
    return version, tuple(events)


def _constant_outcome(events, constants):
    logs = []
    for op, _immediate, values in events:
        if op == 'err':
            return False, ()
        if any(value not in constants for value in values):
            return None
        operands = [constants[value] for value in values]
        if op in {'assert', 'return'} and len(operands) == 1 and operands[0].kind == 'int':
            accepted = int(operands[0].value) != 0
            if not accepted or op == 'return':
                return accepted, tuple(logs) if accepted else ()
        elif op == 'log' and len(operands) == 1 and operands[0].kind == 'bytes':
            logs.append(operands[0].value)
            if len(logs) > 32 or sum(len(value.removeprefix('0x')) // 2 for value in logs) > 1024:
                return False, ()
        else:
            return None
    return None


def compare_programs(before, after, *, max_steps=1024):
    """Compare implementations under identical existing-app NoOp inputs/state.

    Canonical events preserve traps, state reads/writes, logs, and exported
    scratch. Supported literal folding and stack copies need no supplied schema
    summary. Both revisions must use the same AVM version and have sufficient
    resource budgets; this does not establish migration or metadata compatibility.
    """
    symbols = _Symbols()
    assumptions = ('identical atomic group, existing-app NoOp invocation, round and initial ledger state except the replaced approval code',
                   'the same protocol, zero initial own scratch and unchanged non-program app metadata',
                   'both installed revisions have sufficient resource budgets; migration is a separate obligation')
    try:
        old, new = (_normal_form(program, symbols, max_steps) for program in (before, after))
    except (ValueError, KeyError) as error:
        return ObligationResult('compatibility', 'implementation', 'UNKNOWN', str(error), assumptions=assumptions)
    if old[0] != new[0]:
        return ObligationResult('compatibility', 'implementation', 'UNKNOWN', 'source AVM versions differ', assumptions=assumptions)
    first, second = (_constant_outcome(events, symbols.constants) for events in (old[1], new[1]))
    if old == new or first is not None and first == second:
        status, reason = 'PROVED', 'canonical effects/traps or fully constant execution outcomes agree'
    elif first is not None and second is not None:
        status, reason = 'REFUTED', 'constant executions have different approval outcomes or committed logs'
    else:
        status, reason = 'UNKNOWN', 'implementation traces differ outside the established equivalences'
    return ObligationResult('compatibility', 'implementation', status, reason, assumptions=assumptions)
