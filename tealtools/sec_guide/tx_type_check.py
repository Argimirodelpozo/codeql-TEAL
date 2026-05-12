"""sec-guide/tx-type-check: missing transaction-type restriction.

Mirrors ``txTypeCheck.ql``. Validating *either* ``TypeEnum`` or
``Type`` on every approval path counts as fixed.
"""
from __future__ import annotations

from ._field_validated import _FieldValidatedDetector, _FieldValidatedViolation


class TxTypeCheckViolation(_FieldValidatedViolation):
    pass


class TxTypeCheckDetector(_FieldValidatedDetector):
    name = "sec-guide/tx-type-check"
    field = ("TypeEnum", "Type")
    message = (
        "Contract does not restrict the transaction type "
        "— any transaction type is accepted, allowing unintended operations."
    )
    violation_cls = TxTypeCheckViolation
