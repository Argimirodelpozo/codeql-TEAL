"""Quantitative resource bounds for a closed straight-line AVM 13 fragment.

The supplied environment describes available credit and the initial own-box
inventory. This proves resource bounds, not input validity or application
acceptance. A retry witness keeps box state unchanged and supplies new credit.
"""
from __future__ import annotations

from dataclasses import dataclass

from .context import FactDomain
from .execution_trace import execution_trace
from ..diagnostics.health import AnalysisDegradation, AnalysisHealth, AnalysisResult
from ..language.avm import op_arity
from ..language.spec import opcode_spec
from ..ssa import const_int

_LITERALS = {'int', 'byte', 'addr', 'method'}
_PLAIN = _LITERALS | {
    'pushint', 'pushbytes', 'pushints', 'pushbytess', 'intcblock', 'bytecblock',
    'intc', 'intc_0', 'intc_1', 'intc_2', 'intc_3', 'bytec', 'bytec_0', 'bytec_1', 'bytec_2', 'bytec_3',
    'txn', 'txna', 'txnas', 'gtxn', 'gtxna', 'gtxns', 'gtxnsa', 'gtxnas', 'gtxnsas', 'global',
    '+', '-', '*', '/', '%', 'addw', 'mulw', 'divw', 'divmodw', 'exp', 'expw', 'sqrt',
    '&', '|', '^', '~', 'shl', 'shr', '==', '!=', '<', '<=', '>', '>=', '!', '&&', '||',
    'concat', 'itob', 'btoi', 'len', 'getbyte', 'setbyte', 'getbit', 'setbit', 'bitlen',
    'substring', 'substring3', 'extract', 'extract3', 'extract_uint16', 'extract_uint32', 'extract_uint64',
    'bzero', 'sha256', 'sha512_256', 'keccak256', 'ed25519verify', 'ed25519verify_bare',
    'store', 'load', 'stores', 'loads', 'pop', 'popn', 'dup', 'dup2', 'dupn', 'dig', 'bury',
    'cover', 'uncover', 'swap', 'select', 'assert', 'return', 'err', 'b',
}
_BOXES = {'box_create', 'box_put', 'box_get', 'box_len', 'box_del', 'box_resize'}
_INNER = {'itxn_begin', 'itxn_next', 'itxn_field', 'itxn_submit'}
_ASSUMPTIONS = (
    'AVM 13 under the pinned go-algorand protocol; this is an outer application approval',
    'the app and outer sender accounts already exist and meet their initial minimum balances',
    'the environment accurately supplies all initial own-box references/sizes and remaining pooled credits',
)


@dataclass(frozen=True)
class ResourceBound:
    dimension: str
    required: int | None
    available: int | None
    status: str
    reason: str
    assumptions: tuple[str, ...] = _ASSUMPTIONS


def resource_sufficiency(program, environment, *, retry=None, max_steps=1024):
    """Return conservative resource upper bounds and an optional retry proof.

    Environment fields: opcode_budget, fee_credit (after outer minimum fees),
    spendable_balance (above initial minimum balance), box_io_budget (remaining
    read/write credit), inner_transaction_credit (remaining pooled count), and
    boxes (available hex names -> initial length/None).
    All credit refers to this invocation. External application calls, foreign
    boxes, mutable application parameters, and nonconstant inner amounts refuse.
    """
    if not isinstance(environment, dict) or not isinstance(environment.get('boxes', {}), dict):
        raise ValueError('resource environment and its boxes inventory must be maps')
    trace = execution_trace(program, max_steps=max_steps)
    facts = program.facts(FactDomain.CONSTANTS)
    notes = []

    def fail(message):
        notes.append(AnalysisDegradation('resource-fragment', message))

    def uint(value):
        return value if type(value) is int and 0 <= value < 2 ** 64 else None

    boxes = dict(environment.get('boxes', {}))
    sizes = dict(boxes)
    for key, size in boxes.items():
        try:
            name = bytes.fromhex(key.removeprefix('0x'))
            valid = key == '0x' + name.hex() and 1 <= len(name) <= 64
        except (AttributeError, ValueError):
            valid = False
        if not valid or size is not None and (uint(size) is None or size > 32768):
            fail('invalid own-box inventory')
    if not trace.complete:
        fail(trace.reason)
    # The assembler may prepend one intcblock and one bytecblock for source
    # literals, including literals outside the selected execution trace.
    cost = 2
    height = peak_stack = debits = minimum_delta = peak_balance = 0
    io = logs = log_bytes = inner_count = 0
    available_boxes = set()
    required_boxes = set()
    pending = None
    read_lengths = {}

    def constant(value):
        return facts.constant(value)

    def byte_length(value):
        memo, remaining = {}, [128]

        def visit(value, depth=0):
            if depth >= 32 or remaining[0] <= 0:
                return None
            value = facts.resolve(value)
            if id(value) in memo:
                return memo[id(value)]
            remaining[0] -= 1
            cv = constant(value)
            length = None
            if cv is not None and cv.kind == 'bytes':
                length = len(cv.value.removeprefix('0x')) // 2
            elif value in read_lengths:
                length = read_lengths[value]
            elif (op := getattr(value, 'defined_by', None)) is not None:
                if op.op == 'itob':
                    length = 8
                elif op.op in {'sha256', 'sha512_256', 'keccak256'}:
                    length = 32
                elif op.op == 'concat' and len(op.inputs) == 2:
                    lengths = [visit(v, depth + 1) for v in op.inputs]
                    length = sum(lengths) if all(n is not None for n in lengths) else None
            memo[id(value)] = length
            return length

        return visit(value)

    if not notes:
        for assignment in trace.operations:
            op = assignment.op
            spec = opcode_spec(op)
            price = '1' if op in _LITERALS else spec.cost if spec else ''
            if not price.isdecimal() or op not in _PLAIN | _BOXES | _INNER | {'log'}:
                fail(f'unsupported resource operation or cost at {assignment.location}')
                break
            cost += int(price)
            n_in, n_out = op_arity(op, assignment.immediates)
            if n_in < 0 or n_out < 0 or height < n_in:
                fail('stack extent is unproved')
                break
            height += n_out - n_in
            peak_stack = max(peak_stack, height)
            if op == 'log':
                length = byte_length(assignment.inputs[0])
                if length is None:
                    fail('log size is unproved')
                    break
                logs += 1
                log_bytes += length
            elif op in _BOXES:
                key_index = 1 if op in {'box_put', 'box_create', 'box_resize'} else 0
                key = constant(assignment.inputs[key_index])
                if key is None or key.kind != 'bytes':
                    fail('box name is dynamic')
                    break
                required_boxes.add(key.value)
                if key.value not in sizes:
                    fail('box reference or initial size is missing')
                    break
                available_boxes.add(key.value)
                old = sizes[key.value]
                new = old
                if op == 'box_get' and len(assignment.outputs) == 2:
                    read_lengths[facts.resolve(assignment.outputs[1])] = old or 0
                if op == 'box_put':
                    new = byte_length(assignment.inputs[0])
                elif op in {'box_create', 'box_resize'}:
                    new = const_int(constant(assignment.inputs[0]))
                elif op == 'box_del':
                    new = None
                if op in {'box_put', 'box_create', 'box_resize'} and (uint(new) is None or new > 32768):
                    fail('box allocation size is unproved')
                    break
                if op in {'box_put', 'box_create'} and old is not None and new != old or op == 'box_resize' and old is None:
                    fail('box operation conflicts with supplied initial sizes')
                    break
                flat = 2500 + 400 * (len(key.value.removeprefix('0x')) // 2)
                before = flat + 400 * old if old is not None else 0
                after = flat + 400 * new if new is not None else 0
                minimum_delta += after - before
                sizes[key.value] = new
                # Charging each access's full extent dominates actual dirty-box
                # accounting, including repeated reads/writes and resize peaks.
                io += max(old or 0, new or 0)
            elif op == 'itxn_begin':
                if pending is not None:
                    fail('nested unsubmitted inner builder')
                    break
                pending = [{}]
            elif op == 'itxn_next':
                if pending is None or len(pending) >= 16:
                    fail('inner group is incomplete or oversized')
                    break
                pending.append({})
            elif op == 'itxn_field':
                if pending is None or assignment.immediates.strip() not in {'TypeEnum', 'Amount', 'Receiver', 'Sender', 'Fee', 'CloseRemainderTo', 'RekeyTo'}:
                    fail('inner transaction field is unsupported')
                    break
                pending[-1][assignment.immediates.strip()] = assignment.inputs[0]
            elif op == 'itxn_submit':
                if pending is None:
                    fail('inner submit has no builder')
                    break
                for transaction in pending:
                    amount = const_int(constant(transaction.get('Amount'))) if 'Amount' in transaction else 0
                    fee = const_int(constant(transaction.get('Fee'))) if 'Fee' in transaction else None
                    kind = const_int(constant(transaction.get('TypeEnum')))
                    receiver = facts.resolve(transaction.get('Receiver'))
                    receiver_op = getattr(receiver, 'defined_by', None)
                    known_receiver = receiver_op is not None and (
                        receiver_op.op == 'txn' and receiver_op.immediates.strip() == 'Sender'
                        or receiver_op.op == 'global' and receiver_op.immediates.strip() == 'CurrentApplicationAddress')
                    if kind != 1 or uint(amount) is None or fee != 0 or any(
                            field in transaction for field in ('Sender', 'CloseRemainderTo', 'RekeyTo')) or not known_receiver:
                        fail('requires constant inner payments to the existing caller or app, from this app with zero fees')
                        break
                    inner_count += 1
                    debits += amount  # Self-payments may make this an overestimate.
                pending = None
            peak_balance = max(peak_balance, debits + minimum_delta)
            if notes:
                break
    initial_read = sum(size or 0 for size in boxes.values()) if not notes else 0
    inner_credit = uint(environment.get('inner_transaction_credit', 0))
    requirements = {'opcode-budget': (cost, uint(environment.get('opcode_budget'))),
                    'fees': (1000 * inner_count, uint(environment.get('fee_credit'))),
                    'spendable-balance': (peak_balance, uint(environment.get('spendable_balance'))),
                    'box-io': (max(io, initial_read), uint(environment.get('box_io_budget'))),
                    'box-availability': (len(required_boxes), len(available_boxes)),
                    'stack': (peak_stack, 1000), 'log-count': (logs, 32), 'log-bytes': (log_bytes, 1024),
                    'inner-count': (inner_count, min(inner_credit, 256) if inner_credit is not None else None)}
    rows = [ResourceBound(dimension, None if notes else required, available,
                         'PROVED' if not notes and available is not None and required <= available else 'UNKNOWN',
                         notes[0].message if notes else
                         'conservative bound for the complete trace; application input validity and assertions are separate')
            for dimension, (required, available) in requirements.items()]
    if retry is not None:
        witness = resource_sufficiency(program, retry, max_steps=max_steps)
        recovered = (witness.complete and boxes == retry.get('boxes', {})
                     and all(row.status == 'PROVED' for row in witness.value))
        rows.append(ResourceBound('resource-retry', None, None, 'PROVED' if recovered else 'UNKNOWN',
            'supplied retry credit covers the unchanged trace and box state; feasibility of supplying credit and application acceptance are separate'))
    return AnalysisResult(tuple(rows), AnalysisHealth(tuple(dict.fromkeys(notes))))
