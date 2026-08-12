"""Immutable SSA facts for security checks on inner-transaction fields."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import Assignment, SSAProgram, SSAVar, const_int

from ._program_shape import file_match, global_field_reads
from ._value_flow import _constant_facts_cached, _operand_flows_from_field_var


@dataclass(frozen=True)
class InnerTxnFieldSet:
    """One ``itxn_field FIELD`` assignment and the SSA value it writes."""

    assignment: Assignment
    field: str
    value: object


def inner_txn_field_assigns(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[InnerTxnFieldSet]:
    """Return all file-matched ``itxn_field`` writes."""
    return [
        InnerTxnFieldSet(a, a.immediates.strip(), a.inputs[0])
        for a in prog.assignments
        if file_match(a.location.file, file) and a.op == "itxn_field" and a.inputs
    ]


def value_is_zero_address(
    prog: SSAProgram, value, *, file: Optional[str] = None,
) -> bool:
    """Whether immutable facts prove ``value`` is AVM's zero address."""
    constant = _constant_facts_cached(prog).constant(value)
    if constant is not None and constant.kind == "bytes":
        hexpart = constant.value[2:] if constant.value.startswith("0x") else constant.value
        if len(hexpart) == 64 and set(hexpart) <= {"0"}:
            return True
    seeds = {
        output
        for assignment in global_field_reads(prog, "ZeroAddress", file=file)
        for output in assignment.outputs
        if isinstance(output, SSAVar)
    }
    return bool(seeds and _operand_flows_from_field_var(prog, value, seeds))


def inner_txn_sets_nonzero_fee(
    prog: SSAProgram, field_set: InnerTxnFieldSet,
) -> bool:
    """Whether a ``Fee`` write is provably a non-zero integer constant."""
    if field_set.field != "Fee":
        return False
    value = const_int(_constant_facts_cached(prog).constant(field_set.value))
    return value is not None and value != 0
