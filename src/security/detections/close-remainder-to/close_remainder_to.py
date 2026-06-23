"""sec-guide/close-remainder-to: missing CloseRemainderTo validation.

Strict-dominance form.
"""
from __future__ import annotations

from security._field_validated import _FieldValidatedDetector, _FieldValidatedViolation


class CloseRemainderToViolation(_FieldValidatedViolation):
    pass


class CloseRemainderToDetector(_FieldValidatedDetector):
    name = "sec-guide/close-remainder-to"
    field = ("CloseRemainderTo",)
    message = (
        "Contract does not validate txn CloseRemainderTo "
        "— the account's entire ALGO balance can be drained."
    )
    violation_cls = CloseRemainderToViolation
