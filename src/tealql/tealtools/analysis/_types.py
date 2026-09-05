"""Coarse AVM types do not require an inferred numeric interval."""
from ..language.avm import _field_type, _multi_out_type, avm
from ..language.spec import result_type
from ..ssa import TealType, const_int


def propagate_types(prog):
    for assignment in prog.assignments:
        for index, output in enumerate(assignment.outputs):
            if output.type is not None:
                continue
            kind = (_field_type(assignment.op, assignment.immediates)
                    if len(assignment.outputs) == 1 else
                    _multi_out_type(assignment.op, assignment.immediates, index))
            kind = kind or result_type(assignment.op, index)
            if const_int(getattr(output, 'const_value', None)) is not None:
                kind = 'uint64'
            family = avm(kind)
            if family in {'u', 'b'}:
                output.type = TealType('uint64' if family == 'u' else 'bytes')
