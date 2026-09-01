"""Conservative resource demand extracted from canonical SSA.

This module deliberately answers a narrower question than ledger modelling:
which resource identities, fields, state keys, boxes, and inner-transaction
fields are syntactically observed or affected by these programs?  It never
uses result liveness to remove an access.  Unclassified input widens the result
and records an unknown, so uncertainty cannot be mistaken for an empty demand.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from ..language.avm import (
    ADDRESS_GLOBAL_FIELDS,
    BOX_RESOURCE_OPS,
    FOREIGN_APP_STATE_OPS,
    INNER_TXN_BUILD_OPS,
    ITXN_SOURCE_OPS,
    LOCAL_ACCOUNT_STATE_OPS,
    PARAMS_FIELDS_BY_OP,
    RESOURCE_ACCESS_OPS,
    RESOURCE_ARRAY_COUNT_FIELDS,
    RESOURCE_PARAM_OPS,
    TXN_FIELD_NAMES,
    TXN_FIELD_OPS,
    TXN_RESOURCE_IDENTITY_FIELDS,
    TXN_SOURCE_OPS,
    is_known_op,
    txn_field_name,
)
from ..ssa import Const, SSAProgram, producing_op
from .context import FactDomain, ValueFacts


RESOURCE_DEMAND_SCHEMA_VERSION = 1

ResourceFamily = Literal["Accounts", "Assets", "Applications", "Boxes"]
ReferenceKind = Literal["position", "address", "identity", "implicit", "dynamic"]
StateScope = Literal["global", "local", "optin"]

_IDENTITY_FAMILIES: frozenset[ResourceFamily] = frozenset({
    "Accounts", "Assets", "Applications",
})


@dataclass(frozen=True, order=True)
class DemandSite:
    """One source location explaining an entry in a resource demand."""

    file: str
    line: int
    op: str
    category: str
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "op": self.op,
            "category": self.category,
            "field": self.field,
        }


@dataclass(frozen=True, order=True)
class ForeignStateRead:
    """A foreign application-state observation.

    ``self_only`` is ``True`` only when the application operand is proven to
    denote the current application, ``False`` only when proven otherwise, and
    ``None`` for a soundly classified but unresolved reference.
    """

    scope: StateScope
    key: str | None
    dynamic_key: bool
    self_only: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "key": self.key,
            "dynamic_key": self.dynamic_key,
            "self_only": self.self_only,
        }


@dataclass(frozen=True, order=True)
class ResourceReference:
    """A resource identity form observed by an operation.

    A ``position`` is a proven transaction-array position.  ``address`` and
    ``identity`` are raw/symbolic account and integer identities respectively;
    these are also reflected in :attr:`ResourceDemand.dynamic_refs` because
    they are not closed over a fixed transaction-array position.
    """

    family: ResourceFamily
    kind: ReferenceKind
    value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"family": self.family, "kind": self.kind, "value": self.value}


@dataclass(frozen=True, order=True)
class BoxAccess:
    """A box/access-list name, or a dynamic name when it is unresolved."""

    key: str | None
    dynamic_key: bool

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "dynamic_key": self.dynamic_key}


@dataclass(frozen=True)
class ResourceDemand:
    """Deterministic, conservative demand certificate for one program set.

    ``complete`` means every observed operation was classified by this schema.
    It does *not* mean the named transaction arrays contain the complete ledger
    inventory.  A verifier must validate accesses and add its own semantic
    closure before relying on this optimization hint.
    """

    account_fields: frozenset[str]
    asset_fields: frozenset[str]
    application_fields: frozenset[str]
    holding_fields: frozenset[str]
    foreign_app_state: tuple[ForeignStateRead, ...]
    resource_arrays: frozenset[str]
    dynamic_refs: frozenset[str]
    inner_txn_fields: frozenset[str]
    uses_inner_transactions: bool
    unknowns: tuple[str, ...]
    sites: tuple[DemandSite, ...]

    # Explicit additions to the suggested boundary model.  Parameter getters
    # and holdings demand their did-exist facts, while identity form and box
    # names would otherwise be lost in field-only output.
    existence_checks: frozenset[str]
    references: tuple[ResourceReference, ...]
    box_accesses: tuple[BoxAccess, ...]

    @property
    def complete(self) -> bool:
        return not self.unknowns

    def to_dict(self) -> dict[str, Any]:
        """Return stable, JSON-compatible output for caching/IPC boundaries."""
        return {
            "schema_version": RESOURCE_DEMAND_SCHEMA_VERSION,
            "complete": self.complete,
            "account_fields": sorted(self.account_fields),
            "asset_fields": sorted(self.asset_fields),
            "application_fields": sorted(self.application_fields),
            "holding_fields": sorted(self.holding_fields),
            "foreign_app_state": [read.to_dict() for read in self.foreign_app_state],
            "resource_arrays": sorted(self.resource_arrays),
            "dynamic_refs": sorted(self.dynamic_refs),
            "inner_txn_fields": sorted(self.inner_txn_fields),
            "uses_inner_transactions": self.uses_inner_transactions,
            "unknowns": list(self.unknowns),
            "sites": [site.to_dict() for site in self.sites],
            "existence_checks": sorted(self.existence_checks),
            "references": [ref.to_dict() for ref in self.references],
            "box_accesses": [access.to_dict() for access in self.box_accesses],
        }


# Public for the metadata drift test.  The actual handler below is generic for
# txn field families and table-driven for parameter fields, but keeping this
# independently assembled view makes a canonical family addition fail until
# the analysis' dispatch policy is consciously reviewed.
CLASSIFIED_RESOURCE_OPS: frozenset[str] = (
    TXN_SOURCE_OPS | ITXN_SOURCE_OPS | RESOURCE_PARAM_OPS
    | FOREIGN_APP_STATE_OPS | LOCAL_ACCOUNT_STATE_OPS
    | BOX_RESOURCE_OPS | INNER_TXN_BUILD_OPS
)


def _site_key(site: DemandSite) -> tuple:
    return (site.file, site.line, site.op, site.category, site.field or "")


def _state_key(read: ForeignStateRead) -> tuple:
    self_rank = 2 if read.self_only is None else int(read.self_only)
    return (read.scope, read.key or "", read.dynamic_key, self_rank)


def _ref_key(ref: ResourceReference) -> tuple:
    return (ref.family, ref.kind, ref.value or "")


def _box_key(access: BoxAccess) -> tuple:
    return (access.dynamic_key, access.key or "")


def _token_int(token: str) -> int | None:
    try:
        value = int(token)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


class _Collector:
    def __init__(self) -> None:
        self.account_fields: set[str] = set()
        self.asset_fields: set[str] = set()
        self.application_fields: set[str] = set()
        self.holding_fields: set[str] = set()
        self.foreign_app_state: set[ForeignStateRead] = set()
        self.resource_arrays: set[str] = set()
        self.dynamic_refs: set[str] = set()
        self.inner_txn_fields: set[str] = set()
        self.uses_inner_transactions = False
        self.unknowns: set[str] = set()
        self.sites: set[DemandSite] = set()
        self.existence_checks: set[str] = set()
        self.references: set[ResourceReference] = set()
        self.box_accesses: set[BoxAccess] = set()

    def finish(self) -> ResourceDemand:
        return ResourceDemand(
            account_fields=frozenset(self.account_fields),
            asset_fields=frozenset(self.asset_fields),
            application_fields=frozenset(self.application_fields),
            holding_fields=frozenset(self.holding_fields),
            foreign_app_state=tuple(sorted(self.foreign_app_state, key=_state_key)),
            resource_arrays=frozenset(self.resource_arrays),
            dynamic_refs=frozenset(self.dynamic_refs),
            inner_txn_fields=frozenset(self.inner_txn_fields),
            uses_inner_transactions=self.uses_inner_transactions,
            unknowns=tuple(sorted(self.unknowns)),
            sites=tuple(sorted(self.sites, key=_site_key)),
            existence_checks=frozenset(self.existence_checks),
            references=tuple(sorted(self.references, key=_ref_key)),
            box_accesses=tuple(sorted(self.box_accesses, key=_box_key)),
        )

    def site(self, assignment, category: str, field: str | None = None) -> None:
        self.sites.add(DemandSite(
            assignment.location.file,
            assignment.location.line,
            assignment.op,
            category,
            field,
        ))

    def _widen_family(self, family: ResourceFamily) -> None:
        if family == "Accounts":
            self.account_fields.update(PARAMS_FIELDS_BY_OP["acct_params_get"])
            self.account_fields.update(PARAMS_FIELDS_BY_OP["voter_params_get"])
            self.existence_checks.add("account")
        elif family == "Assets":
            self.asset_fields.update(PARAMS_FIELDS_BY_OP["asset_params_get"])
            self.existence_checks.add("asset")
        elif family == "Applications":
            self.application_fields.update(PARAMS_FIELDS_BY_OP["app_params_get"])
            self.existence_checks.add("application")
            self.foreign_app_state.update({
                ForeignStateRead("global", None, True, None),
                ForeignStateRead("local", None, True, None),
                ForeignStateRead("optin", None, False, None),
            })
        else:
            self.existence_checks.add("box")
            self.box_accesses.add(BoxAccess(None, True))
        if family in _IDENTITY_FAMILIES:
            self.resource_arrays.add(family)
        self.dynamic_refs.add(family)
        self.references.add(ResourceReference(family, "dynamic"))

    def widen_all(self) -> None:
        for family in (*sorted(_IDENTITY_FAMILIES), "Boxes"):
            self._widen_family(family)  # type: ignore[arg-type]
        self.holding_fields.update(PARAMS_FIELDS_BY_OP["asset_holding_get"])
        self.existence_checks.add("holding")
        self.inner_txn_fields.update(TXN_FIELD_NAMES)
        self.uses_inner_transactions = True

    def unknown(self, assignment, reason: str, *families: ResourceFamily) -> None:
        where = f"{assignment.location.file}:{assignment.location.line}:{assignment.op}"
        self.unknowns.add(f"{where}: {reason}")
        self.site(assignment, "unknown", reason)
        if families:
            for family in families:
                self._widen_family(family)
        else:
            self.widen_all()

    def partial_program(self, diagnostic) -> None:
        self.unknowns.add(
            f"{diagnostic.file}:{diagnostic.start_line}:parse: unparsed TEAL span"
        )
        self.sites.add(DemandSite(
            diagnostic.file,
            diagnostic.start_line,
            "<parse>",
            "unknown",
            "unparsed TEAL span",
        ))
        self.widen_all()

    def add_reference(
        self,
        family: ResourceFamily,
        kind: ReferenceKind,
        value: str | None,
        assignment,
    ) -> ResourceReference:
        ref = ResourceReference(family, kind, value)
        self.references.add(ref)
        if kind in {"address", "identity", "dynamic"}:
            self.dynamic_refs.add(family)
        self.site(
            assignment,
            "resource-reference",
            f"{family}:{kind}" + (f":{value}" if value is not None else ""),
        )
        return ref

    @staticmethod
    def _constant(operand, facts: ValueFacts) -> Const | None:
        value = facts.constant(operand)
        return value if isinstance(value, Const) else None

    def _array_reference(
        self,
        assignment,
        family: ResourceFamily,
        facts: ValueFacts,
    ) -> ResourceReference | None:
        op = assignment.op
        tokens = assignment.immediates.split()
        txn_label: str
        array_index: int | None
        dynamic = False

        if op in {"txna", "itxna"}:
            if len(tokens) != 2 or (array_index := _token_int(tokens[1])) is None:
                self.unknown(assignment, "invalid immediate array index", family)
                return None
            txn_label = "txn" if op == "txna" else "itxn"
        elif op in {"txnas", "itxnas"}:
            if len(tokens) != 1 or len(assignment.inputs) != 1:
                self.unknown(assignment, "missing stack array index", family)
                return None
            value = self._constant(assignment.inputs[0], facts)
            array_index = (
                _token_int(value.value) if value is not None and value.kind == "int" else None
            )
            dynamic = array_index is None
            txn_label = "txn" if op == "txnas" else "itxn"
        elif op in {"gtxna", "gitxna"}:
            if (len(tokens) != 3
                    or (txn_index := _token_int(tokens[0])) is None
                    or (array_index := _token_int(tokens[2])) is None):
                self.unknown(assignment, "invalid immediate transaction/array index", family)
                return None
            txn_label = f"{'gtxn' if op == 'gtxna' else 'gitxn'}[{txn_index}]"
        elif op in {"gtxnas", "gitxnas"}:
            if len(tokens) != 2 or len(assignment.inputs) != 1:
                self.unknown(assignment, "missing stack array index", family)
                return None
            txn_index = _token_int(tokens[0])
            if txn_index is None:
                self.unknown(assignment, "invalid immediate transaction index", family)
                return None
            value = self._constant(assignment.inputs[0], facts)
            array_index = (
                _token_int(value.value) if value is not None and value.kind == "int" else None
            )
            dynamic = array_index is None
            txn_label = f"{'gtxn' if op == 'gtxnas' else 'gitxn'}[{txn_index}]"
        elif op == "gtxnsa":
            if (len(tokens) != 2 or len(assignment.inputs) != 1
                    or (array_index := _token_int(tokens[1])) is None):
                self.unknown(assignment, "missing stack transaction index", family)
                return None
            value = self._constant(assignment.inputs[0], facts)
            txn_index = (
                _token_int(value.value) if value is not None and value.kind == "int" else None
            )
            dynamic = txn_index is None
            txn_label = f"gtxn[{txn_index if txn_index is not None else '*'}]"
        elif op == "gtxnsas":
            if len(tokens) != 1 or len(assignment.inputs) != 2:
                self.unknown(assignment, "missing stack transaction/array index", family)
                return None
            array_value = self._constant(assignment.inputs[0], facts)
            txn_value = self._constant(assignment.inputs[1], facts)
            array_index = (
                _token_int(array_value.value)
                if array_value is not None and array_value.kind == "int" else None
            )
            txn_index = (
                _token_int(txn_value.value)
                if txn_value is not None and txn_value.kind == "int" else None
            )
            dynamic = array_index is None or txn_index is None
            txn_label = f"gtxn[{txn_index if txn_index is not None else '*'}]"
        else:
            self.unknown(assignment, "resource array used through a scalar accessor", family)
            return None

        value = (
            f"{txn_label}.{family}"
            f"[{array_index if array_index is not None else '*'}]"
        )
        return self.add_reference(
            family,
            "dynamic" if dynamic else "position",
            value,
            assignment,
        )

    def txn_access(self, assignment, facts: ValueFacts) -> None:
        field = txn_field_name(assignment.op, assignment.immediates)
        if field is None or field not in TXN_FIELD_NAMES:
            self.unknown(
                assignment,
                "unknown or missing transaction field",
                "Accounts", "Assets", "Applications",
            )
            return

        count_family = RESOURCE_ARRAY_COUNT_FIELDS.get(field)
        if count_family is not None:
            family: ResourceFamily = count_family  # type: ignore[assignment]
            label, dynamic = self._scalar_txn_source(assignment, facts, family)
            if label is None:
                return
            self.resource_arrays.add(family)
            self.site(assignment, "resource-array-count", family)
            if dynamic:
                self.add_reference(family, "dynamic", label, assignment)
            return

        if field in _IDENTITY_FAMILIES:
            family = field  # type: ignore[assignment]
            self.resource_arrays.add(family)
            self.site(assignment, "resource-array", family)
            self._array_reference(assignment, family, facts)
            return

        family = next(
            (candidate for candidate in sorted(_IDENTITY_FAMILIES)
             if field in TXN_RESOURCE_IDENTITY_FIELDS[candidate]),
            None,
        )
        if family is None:
            return
        label, _dynamic = self._scalar_txn_source(assignment, facts, family)
        if label is None:
            return
        if family == "Accounts":
            kind: ReferenceKind = "address"
        elif (family == "Applications" and assignment.op == "txn"
              and field == "ApplicationID"):
            kind = "implicit"
            label = "current"
        else:
            kind = "identity"
        self.add_reference(family, kind, f"{label}.{field}" if label != "current" else label,
                           assignment)

    def _scalar_txn_source(
        self,
        assignment,
        facts: ValueFacts,
        family: ResourceFamily,
    ) -> tuple[str | None, bool]:
        """Return ``(transaction label, dynamic txn index)`` for scalar reads."""
        op = assignment.op
        tokens = assignment.immediates.split()
        if op in {"txn", "itxn"}:
            if len(tokens) != 1:
                self.unknown(assignment, "invalid scalar transaction field", family)
                return None, False
            return op, False
        if op in {"gtxn", "gitxn"}:
            if len(tokens) != 2 or (index := _token_int(tokens[0])) is None:
                self.unknown(assignment, "invalid immediate transaction index", family)
                return None, False
            return f"{op}[{index}]", False
        if op == "gtxns":
            if len(tokens) != 1 or len(assignment.inputs) != 1:
                self.unknown(assignment, "missing stack transaction index", family)
                return None, False
            value = self._constant(assignment.inputs[0], facts)
            index = (
                _token_int(value.value) if value is not None and value.kind == "int" else None
            )
            return f"gtxn[{index if index is not None else '*'}]", index is None
        self.unknown(assignment, "scalar resource field used through an array accessor", family)
        return None, False

    def reference(
        self,
        assignment,
        operand,
        family: ResourceFamily,
        facts: ValueFacts,
    ) -> ResourceReference:
        constant = self._constant(operand, facts)
        if constant is not None:
            if family == "Accounts" and constant.kind == "bytes":
                return self.add_reference(family, "address", constant.value, assignment)
            if constant.kind == "int":
                if family == "Accounts":
                    return self.add_reference(
                        family, "position", f"txn.Accounts[{constant.value}]", assignment
                    )
                index = _token_int(constant.value)
                if family == "Applications" and index == 0:
                    return self.add_reference(family, "implicit", "current", assignment)
                # AVM deliberately makes resource IDs below 256 invalid, so
                # small uints are unambiguously legacy array offsets.  A scalar
                # ``int i`` resolves EXACTLY like ``txna <family> i`` does
                # (for Applications, 0 is the current app — handled above —
                # and i>=1 is ForeignApps[i-1], which is what ``txna
                # Applications i`` returns), so both forms must emit the SAME
                # label: a shifted one made ``int 3`` and ``txna Applications
                # 3`` (the same app) read as two different apps.
                if index is not None and index < 256:
                    return self.add_reference(
                        family, "position", f"txn.{family}[{index}]", assignment
                    )
                return self.add_reference(family, "identity", constant.value, assignment)

        resolved = facts.resolve(operand)
        producer = producing_op(resolved)
        if producer is not None:
            field = txn_field_name(producer.op, producer.immediates)
            if field == family:
                ref = self._array_reference(producer, family, facts)
                if ref is not None:
                    return ref
            if (family == "Accounts" and producer.op == "global"
                    and producer.immediates.strip() in ADDRESS_GLOBAL_FIELDS):
                return self.add_reference(
                    family, "address", f"global.{producer.immediates.strip()}", assignment
                )
            if (family == "Applications" and producer.op == "global"
                    and producer.immediates.strip() == "CurrentApplicationID"):
                return self.add_reference(family, "implicit", "current", assignment)
            if field in TXN_RESOURCE_IDENTITY_FIELDS[family]:
                label, _dynamic = self._scalar_txn_source(producer, facts, family)
                if label is None:
                    return self.add_reference(family, "dynamic", None, assignment)
                if family == "Accounts":
                    kind: ReferenceKind = "address"
                elif (family == "Applications" and producer.op == "txn"
                      and field == "ApplicationID"):
                    kind = "implicit"
                    label = "current"
                else:
                    kind = "identity"
                return self.add_reference(
                    family, kind, f"{label}.{field}" if label != "current" else label,
                    assignment,
                )
        return self.add_reference(family, "dynamic", None, assignment)

    def application_self_only(self, operand, facts: ValueFacts) -> bool | None:
        constant = self._constant(operand, facts)
        if constant is not None and constant.kind == "int":
            value = _token_int(constant.value)
            if value == 0:
                return True
            if value is not None and value < 256:
                return False
            return None
        resolved = facts.resolve(operand)
        producer = producing_op(resolved)
        if producer is None:
            return None
        field = txn_field_name(producer.op, producer.immediates)
        if ((producer.op == "global" and producer.immediates.strip() == "CurrentApplicationID")
                or (producer.op == "txn" and field == "ApplicationID")):
            return True
        if field == "Applications":
            # An Applications array element is an application ID, not the
            # special offset 0.  It may equal the current app, so do not guess.
            self._array_reference(producer, "Applications", facts)
            return None
        return None

    def parameter_get(self, assignment, facts: ValueFacts) -> None:
        op = assignment.op
        if op in {"balance", "min_balance"}:
            field = "AcctBalance" if op == "balance" else "AcctMinBalance"
            self.account_fields.add(field)
            self.existence_checks.add("account")
            self.site(assignment, "account-field", field)
            if len(assignment.inputs) != 1:
                self.unknown(assignment, "missing account operand", "Accounts")
            else:
                self.reference(assignment, assignment.inputs[0], "Accounts", facts)
            return

        tokens = assignment.immediates.split()
        expected = PARAMS_FIELDS_BY_OP.get(op, frozenset())
        if len(tokens) != 1 or tokens[0] not in expected:
            if op in {"acct_params_get", "voter_params_get"}:
                families = ("Accounts",)
            elif op == "asset_params_get":
                families = ("Assets",)
            elif op == "app_params_get":
                families = ("Applications",)
            else:
                families = ("Accounts", "Assets")
            self.unknown(assignment, "unknown or missing parameter field", *families)
            if op == "asset_holding_get":
                self.holding_fields.update(PARAMS_FIELDS_BY_OP[op])
                self.existence_checks.add("holding")
            return
        field = tokens[0]

        if op in {"acct_params_get", "voter_params_get"}:
            self.account_fields.add(field)
            self.existence_checks.add("account")
            self.site(assignment, "account-field", field)
            if len(assignment.inputs) == 1:
                self.reference(assignment, assignment.inputs[0], "Accounts", facts)
            else:
                self.unknown(assignment, "missing account operand", "Accounts")
        elif op == "asset_params_get":
            self.asset_fields.add(field)
            self.existence_checks.add("asset")
            self.site(assignment, "asset-field", field)
            if len(assignment.inputs) == 1:
                self.reference(assignment, assignment.inputs[0], "Assets", facts)
            else:
                self.unknown(assignment, "missing asset operand", "Assets")
        elif op == "app_params_get":
            self.application_fields.add(field)
            self.existence_checks.add("application")
            self.site(assignment, "application-field", field)
            if len(assignment.inputs) == 1:
                self.reference(assignment, assignment.inputs[0], "Applications", facts)
            else:
                self.unknown(assignment, "missing application operand", "Applications")
        else:
            self.holding_fields.add(field)
            self.existence_checks.update({"account", "asset", "holding"})
            self.site(assignment, "holding-field", field)
            if len(assignment.inputs) != 2:
                self.unknown(
                    assignment, "missing holding account/asset operand", "Accounts", "Assets"
                )
            else:
                self.reference(assignment, assignment.inputs[1], "Accounts", facts)
                self.reference(assignment, assignment.inputs[0], "Assets", facts)

    def foreign_state(self, assignment, facts: ValueFacts) -> None:
        op = assignment.op
        scope: StateScope = (
            "global" if op == "app_global_get_ex"
            else "local" if op == "app_local_get_ex"
            else "optin"
        )
        required = 2 if scope in {"global", "optin"} else 3
        if len(assignment.inputs) != required:
            self.unknown(assignment, "missing foreign application-state operand", "Applications")
            if scope in {"local", "optin"}:
                self._widen_family("Accounts")
            return

        app_operand = assignment.inputs[0] if scope == "optin" else assignment.inputs[1]
        key_operand = None if scope == "optin" else assignment.inputs[0]
        key_const = self._constant(key_operand, facts) if key_operand is not None else None
        key = key_const.value if key_const is not None else None
        read = ForeignStateRead(
            scope,
            key,
            key_operand is not None and key_const is None,
            self.application_self_only(app_operand, facts),
        )
        self.foreign_app_state.add(read)
        self.existence_checks.add("application")
        self.site(assignment, "foreign-app-state", scope)
        self.reference(assignment, app_operand, "Applications", facts)
        if scope in {"local", "optin"}:
            self.existence_checks.add("account")
            self.reference(assignment, assignment.inputs[-1], "Accounts", facts)

    def local_account_state(self, assignment, facts: ValueFacts) -> None:
        if assignment.op in FOREIGN_APP_STATE_OPS:
            return
        account_index = {
            "app_local_get": 1,
            "app_local_put": 2,
            "app_local_del": 1,
        }.get(assignment.op)
        if account_index is None:
            return
        if len(assignment.inputs) <= account_index:
            self.unknown(assignment, "missing local-state account operand", "Accounts")
            return
        self.existence_checks.add("account")
        self.reference(assignment, assignment.inputs[account_index], "Accounts", facts)

    def box_access(self, assignment, facts: ValueFacts) -> None:
        key_index = {
            "box_get": 0, "box_del": 0, "box_len": 0,
            "box_create": 1, "box_put": 1, "box_resize": 1,
            "box_replace": 2, "box_extract": 2, "box_splice": 3,
        }.get(assignment.op)
        if key_index is None or len(assignment.inputs) <= key_index:
            self.unknown(assignment, "missing or unclassified box-name operand", "Boxes")
            return
        key_const = self._constant(assignment.inputs[key_index], facts)
        key = key_const.value if key_const is not None else None
        dynamic = key_const is None
        self.box_accesses.add(BoxAccess(key, dynamic))
        self.existence_checks.add("box")
        if dynamic:
            self.dynamic_refs.add("Boxes")
        self.site(assignment, "box-access", key)

    def inner_transaction(self, assignment) -> None:
        self.uses_inner_transactions = True
        if assignment.op == "itxn_field":
            tokens = assignment.immediates.split()
            if len(tokens) != 1 or tokens[0] not in TXN_FIELD_NAMES:
                self.unknowns.add(
                    f"{assignment.location.file}:{assignment.location.line}:itxn_field: "
                    "unknown or missing inner-transaction field"
                )
                self.inner_txn_fields.update(TXN_FIELD_NAMES)
                self.site(assignment, "unknown", "unknown inner-transaction field")
                return
            self.inner_txn_fields.add(tokens[0])
            self.site(assignment, "inner-transaction-field", tokens[0])
        else:
            self.site(assignment, "inner-transaction", assignment.op)

    def scan(self, program: SSAProgram) -> None:
        for diagnostic in program.parse_diagnostics:
            self.partial_program(diagnostic)

        facts = program.facts(FactDomain.CONSTANTS)
        for assignment in program.assignments:
            op = assignment.op
            if not is_known_op(op):
                self.unknown(assignment, "opcode is unknown to this AVM metadata")
            elif op in TXN_FIELD_OPS:
                self.txn_access(assignment, facts)
            elif op in RESOURCE_PARAM_OPS:
                self.parameter_get(assignment, facts)
            elif op in FOREIGN_APP_STATE_OPS:
                self.foreign_state(assignment, facts)
            elif op in LOCAL_ACCOUNT_STATE_OPS:
                self.local_account_state(assignment, facts)
            elif op in BOX_RESOURCE_OPS:
                self.box_access(assignment, facts)
            elif op in INNER_TXN_BUILD_OPS:
                self.inner_transaction(assignment)


def resource_demand(
    main: SSAProgram,
    subs: Iterable[SSAProgram] = (),
) -> ResourceDemand:
    """Compute conservative syntactic/dataflow resource demand.

    Every supplied program is scanned, regardless of apparent reachability, and
    no access is discarded because its result is unused.  This is an
    optimization certificate only: consumers must independently validate it
    while encoding and add any ledger-semantic dependencies they require.
    """
    if not isinstance(main, SSAProgram):
        raise TypeError("main must be an SSAProgram")
    programs = (main, *tuple(subs))
    if any(not isinstance(program, SSAProgram) for program in programs):
        raise TypeError("subs must contain only SSAProgram instances")

    collector = _Collector()
    for program in programs:
        collector.scan(program)
    return collector.finish()


assert CLASSIFIED_RESOURCE_OPS == RESOURCE_ACCESS_OPS


__all__ = [
    "BoxAccess",
    "CLASSIFIED_RESOURCE_OPS",
    "DemandSite",
    "ForeignStateRead",
    "RESOURCE_DEMAND_SCHEMA_VERSION",
    "ResourceDemand",
    "ResourceReference",
    "resource_demand",
]
