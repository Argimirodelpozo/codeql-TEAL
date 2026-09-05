"""Constant state-backed call targets with a same-invocation initialization proof.

A write somewhere in an approval program does not establish ledger contents.
This bounded fragment requires a dominating write in this invocation and
agreement of all possibly aliasing writers. It never treats an existence flag
as stored data, a value as a key, or a dynamic key as a distinct slot.
"""
from __future__ import annotations

from ..analysis import FactDomain
from ..cfg.dominance import AssertDominance, reachable_avoiding
from ..language.effects import STATE_EFFECTS
from ..ssa import const_bytes, const_int


def _read(value, facts):
    value = facts.resolve(value)
    read = getattr(value, 'defined_by', None)
    if read is None:
        return None
    if read.op == 'btoi' and len(read.inputs) == 1:
        value = facts.resolve(read.inputs[0])
        read = getattr(value, 'defined_by', None)
        if read is None or read.op != 'box_get' or value.index != 2:
            return None
        storage, account = 'box', None
    elif read.op in {'app_global_get', 'app_local_get',
                     'app_global_get_ex', 'app_local_get_ex'}:
        storage = 'global' if read.op.startswith('app_global') else 'local'
        if read.op.endswith('_ex') and (value.index != 2 or len(read.inputs) < 2
                or const_int(facts.constant(read.inputs[1])) != 0):
            return None
        account = read.inputs[-1] if storage == 'local' and len(read.inputs) >= 2 else None
        if storage == 'local' and account is None:
            return None
    else:
        return None
    key = const_bytes(facts.constant(read.inputs[0])) if read.inputs else None
    return (read, storage, key, account) if key is not None else None


def resolve_state_app_id(program, operand):
    facts = program.facts(FactDomain.CONSTANTS)
    slot = _read(operand, facts)
    if slot is None:
        return None
    read, storage, key, account = slot
    dominance = AssertDominance(program)
    if read.basic_block not in reachable_avoiding(dominance._entries, None):
        return None
    values, initialized = set(), False
    for write in program.assignments:
        effect = STATE_EFFECTS.get(write.op)
        if (effect is None or effect.storage != storage
                or write.location.file != read.location.file):
            continue
        if effect.key_index >= len(write.inputs):
            return None
        written_key = const_bytes(facts.constant(write.inputs[effect.key_index]))
        if written_key is not None and written_key != key:
            continue
        # An unknown owner may be this app. A known nonzero foreign reference
        # is still conservative here: its actual app ID may name this app.
        own = effect.owner_index is None or (
            effect.owner_index < len(write.inputs)
            and const_int(facts.constant(write.inputs[effect.owner_index])) == 0)
        if (written_key is None or effect.action != 'put'
                or effect.value_index >= len(write.inputs)):
            return None
        constant = facts.constant(write.inputs[effect.value_index])
        if storage == 'box':
            raw = const_bytes(constant)
            if raw is None or not raw.startswith('0x'):
                return None
            try:
                data = bytes.fromhex(raw[2:])
            except ValueError:
                return None
            value = int.from_bytes(data, 'big') if len(data) <= 8 else None
        else:
            value = const_int(constant)
        if value is None:
            return None
        values.add(value)
        same_account = account is None or (
            len(write.inputs) >= 3 and (
                facts.resolve(account) is facts.resolve(write.inputs[2])
                or facts.constant(account) is not None
                and facts.constant(account) == facts.constant(write.inputs[2])))
        if (own and same_account and read.basic_block is not None
                and dominance.dominates(write.basic_block, read.basic_block,
                                        write.location.line, read.location.line)
                # Global/local writes are confined to the running app and the
                # AVM forbids app re-entry. Shared boxes need a call-effect proof.
                and (storage != 'box' or write.basic_block is read.basic_block
                     and not any(a.op == 'itxn_submit'
                        and write.location.line < a.location.line < read.location.line
                        for a in read.basic_block.assignments))):
            initialized = True
    return next(iter(values)) if initialized and len(values) == 1 else None
