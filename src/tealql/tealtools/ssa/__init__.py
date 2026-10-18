"""Canonical SSA facade with demand-driven public re-exports."""
from importlib import import_module


_LAZY_EXPORTS = {
    # AVM classification metadata historically re-exported here.
    "_OP_RANGE_SEEDS": ("..language.avm", "_OP_RANGE_SEEDS"),
    "_STACK_SHUFFLE_OPS": ("..language.avm", "_STACK_SHUFFLE_OPS"),
    # Models.
    "Assignment": (".models", "Assignment"),
    "BasicBlock": (".models", "BasicBlock"),
    "Const": (".models", "Const"),
    "IntRange": (".models", "IntRange"),
    "Location": (".models", "Location"),
    "Operand": (".models", "Operand"),
    "Phi": (".models", "Phi"),
    "SSAVar": (".models", "SSAVar"),
    "TealType": (".models", "TealType"),
    "_shuffle_mapping": (".models", "_shuffle_mapping"),
    "_canon_shuffle": (".models", "_canon_shuffle"),
    # Operand and producer helpers.
    "binary_operands": (".operands", "binary_operands"),
    "const_bytes": (".operands", "const_bytes"),
    "const_byte_length": (".operands", "const_byte_length"),
    "const_int": (".operands", "const_int"),
    "source_operands": (".operands", "source_operands"),
    "is_const": (".operands", "is_const"),
    "operand_const": (".operands", "operand_const"),
    "is_field_var": (".producers", "is_field_var"),
    "producing_op": (".producers", "producing_op"),
    # Program and builders.
    "SSAProgram": (".program", "SSAProgram"),
    "PyPhi": (".ssa", "PyPhi"),
    "PySSA": (".ssa", "PySSA"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    value = getattr(import_module(module_name, __name__), attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
