"""Bridge lifted address identities to the shared storage-writer analysis."""
from ..analysis.authority import AddressAuthority, authority_for, literal_authority
from ..diagnostics.evidence import GuardEvidence
from ..language.avm import is_current_sender_read
from ..ssa import Const
from . import pre_ir
from .taint_flow import _intr


def sender_identity(value, definitions, returns=None):
    """An exact Sender alias; a computation merely containing Sender is not one."""
    budget = 128

    def visit(value, active):
        nonlocal budget
        budget -= 1
        if budget < 0 or id(value) in active or not isinstance(value, pre_ir.Register):
            return False
        active = active | {id(value)}
        operation = definitions.get(id(value))
        source = _intr(operation)
        incoming = (returns or {}).get(id(value), ())
        if incoming:
            return all(visit(v, active) for v in incoming)
        if isinstance(operation, pre_ir.Phi):
            return bool(operation.args) and all(visit(a.value, active) for a in operation.args)
        if source is None and isinstance(operation, pre_ir.Assignment):
            return visit(operation.source, active)
        if source is None:
            return False
        index = source.args[0].value if (source.op == 'txnas' and source.args
                and isinstance(source.args[0], pre_ir.UInt64Constant)) else None
        return is_current_sender_read(source.op, source.immediates or [], index)

    return visit(value, frozenset())


def address_authority(value, definitions, returns=None):
    budget = 128

    def visit(value, active):
        nonlocal budget
        budget -= 1
        if budget < 0 or id(value) in active:
            return AddressAuthority(False, 'lifted authority dependency is cyclic or exceeds the work budget')
        if isinstance(value, pre_ir.BytesConstant):
            return literal_authority(Const('bytes', value.value))
        if not isinstance(value, pre_ir.Register):
            return AddressAuthority(False, 'not an established address')
        active = active | {id(value)}
        operation = definitions.get(id(value))
        source = _intr(operation)
        incoming = (returns or {}).get(id(value), ())
        if incoming:
            parts = [visit(v, active) for v in incoming]
        elif isinstance(operation, pre_ir.Phi):
            parts = [visit(arg.value, active) for arg in operation.args]
        elif source is None and isinstance(operation, pre_ir.Assignment):
            return visit(operation.source, active)
        else:
            origin = getattr(source, 'origin', None)
            program = getattr(definitions, 'authority_program', None)
            if source is not None and origin is not None and program is not None:
                index = next((i for i, target in enumerate(operation.targets) if target is value), -1)
                if source.op == origin.op and 0 <= index < len(origin.outputs):
                    return authority_for(program).address(origin.outputs[index])
            if source is not None and source.op == 'global' and tuple(source.immediates) == ('CreatorAddress',):
                return AddressAuthority(True, 'immutable application creator', (GuardEvidence(
                    str(value), 'authority-controlled', 'global CreatorAddress', basis='constant'),))
            return AddressAuthority(False, 'lifted address has no established source authority')
        return AddressAuthority(bool(parts) and all(p.preserved for p in parts),
            'every incoming address must preserve authority',
            tuple(dict.fromkeys(e for p in parts for e in p.evidence)))

    result = visit(value, frozenset())
    evidence = getattr(definitions, 'authority_evidence', None)
    if evidence is not None:
        evidence.add(result)
    return result
