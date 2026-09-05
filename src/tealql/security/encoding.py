"""Exact ordered fields of a bounded fixed-width cryptographic preimage."""


def encoding_leaves(context, value, *, max_nodes=128):
    leaves = []
    remaining = max_nodes

    def walk(value, active):
        nonlocal remaining
        remaining -= 1
        value = context.facts.resolve(value)
        if remaining < 0 or id(value) in active:
            return False
        assignment = getattr(value, 'defined_by', None)
        if assignment and assignment.op in {'sha256', 'sha512_256', 'keccak256', 'concat'}:
            arity = 2 if assignment.op == 'concat' else 1
            return len(assignment.inputs) == arity and all(
                walk(item, active | {id(value)}) for item in reversed(assignment.inputs))
        expression = context.expression(value)
        width = None
        if assignment and assignment.op == 'itob' and len(assignment.inputs) == 1:
            expression, width = context.expression(assignment.inputs[0]), 8
        else:
            constant = context.facts.constant(value)
            if constant is not None and constant.kind == 'bytes':
                width = len(constant.value.removeprefix('0x')) // 2
            elif expression in {'txn Sender', 'global CreatorAddress', 'global CurrentApplicationAddress'}:
                width = 32
        leaves.append((expression, width))
        return expression is not None and width is not None

    return tuple(leaves) if walk(value, frozenset()) else None
