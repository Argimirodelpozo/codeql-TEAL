"""Bridge lifted address identities to the shared storage-writer analysis."""
from ..analysis.authority import AddressAuthority, authority_for, literal_authority
from ..diagnostics.evidence import GuardEvidence
from ..language.avm import is_current_sender_read, is_group_signer_read
from ..ssa import Const
from . import pre_ir
from .taint_flow import _intr


def sender_identity(value, definitions, returns=None, *, signer=False):
    """An exact Sender alias; a computation merely containing Sender is not one.

    ``signer``: also accept the sender of a FIXED-position group member
    (``gtxn K Sender``) — an AUTHORISATION identity only (see
    :func:`avm.is_group_signer_read`), never the caller's."""
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
        index = source.args[0].value if (source.op in ('txnas', 'gtxns') and source.args
                and isinstance(source.args[0], pre_ir.UInt64Constant)) else None
        if signer:
            return is_group_signer_read(source.op, source.immediates or [], index)
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


def _const_int(value, definitions, budget=16):
    """The uint64 constant ``value`` is, through plain copies, else ``None``."""
    while budget > 0:
        budget -= 1
        if isinstance(value, pre_ir.UInt64Constant):
            return value.value
        if not isinstance(value, pre_ir.Register):
            return None
        operation = definitions.get(id(value))
        if isinstance(operation, pre_ir.Assignment) and _intr(operation) is None:
            value = operation.source
            continue
        source = _intr(operation)
        if (source is not None and source.op == 'btoi' and len(source.args) == 1
                and isinstance(source.args[0], pre_ir.BytesConstant)):
            raw = source.args[0].value
            try:
                data = bytes.fromhex(raw.removeprefix('0x')) if isinstance(raw, str) else bytes(raw)
            except (ValueError, TypeError):
                return None
            return int.from_bytes(data, 'big') if len(data) <= 8 else None
        return None
    return None


def caller_app_pin(args, definitions):
    """``args`` (a comparison's two operands) pin ``global CallerApplicationID``
    to a NON-ZERO constant: only that fixed app can be this call's inner-txn
    caller. Returns the authority (with the premise that app preserves the
    invariant) or ``None``."""
    if len(args) != 2:
        return None
    for a, b in ((args[0], args[1]), (args[1], args[0])):
        operation = definitions.get(id(a)) if isinstance(a, pre_ir.Register) else None
        while isinstance(operation, pre_ir.Assignment) and _intr(operation) is None \
                and isinstance(operation.source, pre_ir.Register):
            operation = definitions.get(id(operation.source))
        source = _intr(operation)
        if (source is None or source.op != 'global'
                or tuple(source.immediates) != ('CallerApplicationID',)):
            continue
        k = _const_int(b, definitions)
        if k:
            return AddressAuthority(True, 'only the fixed caller application can make this call',
                (GuardEvidence(str(a), 'authority-controlled', f'global CallerApplicationID == {k}',
                    basis='verified-obligation',
                    assumptions=(f'application {k} (the pinned CallerApplicationID) '
                                 'preserves the authority invariant',)),))
    return None


def signer_principal(value, definitions, returns=None):
    """The lifted face of :meth:`AuthorityAnalysis.signer_principal`: through
    copies / phis / call returns to ``global CreatorAddress`` or an SSA origin
    the shared analysis accepts."""
    budget = 64

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
        if source.op == 'global' and tuple(source.immediates) == ('CreatorAddress',):
            return True
        origin = getattr(source, 'origin', None)
        program = getattr(definitions, 'authority_program', None)
        if origin is not None and program is not None and source.op == origin.op:
            index = next((i for i, t in enumerate(operation.targets) if t is value), -1)
            if 0 <= index < len(origin.outputs):
                return authority_for(program).signer_principal(origin.outputs[index])
        return False

    return visit(value, frozenset())
