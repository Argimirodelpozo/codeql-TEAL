"""ARC-56 app-spec ingestion — the richest source of HIGH-LEVEL info, when the
user PROVIDES the spec file.

An ARC-56 JSON declares, authoritatively, a contract's methods (arg/return ABI
types incl. *named struct* types), its global/local/box state keys and box maps
— none of it recoverable from bytecode. Optional: everything downstream works on
raw TEAL without a spec; a spec just sharpens it, feeding the same consumers as
the source-text :mod:`.abi` table but richer.

HAZARD: we NEVER reverse a selector. The method table resolves each DECLARED
signature (structs expanded to their tuple encoding) and computes the selector
FORWARD (``sha512_256``), exactly as :mod:`.abi` does for source ``method "sig"``.

Tolerant by design: a partial / non-conforming spec yields whatever sections
parse and empty for the rest; :func:`load` raises only on non-JSON input.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .abi import AbiMethod, method_selector

#: ARC-56 "AVM native" storage encodings (not ABI types) that a state key can use.
_AVM_TYPES = frozenset({"AVMBytes", "AVMString", "AVMUint64"})


@dataclass(frozen=True)
class StateEntry:
    """One declared state key (global / local / box) or box map, with its resolved
    value type — a fixed key carries ``key_b64``, a map ``prefix_b64``."""

    name: str
    value_type: str
    key_type: Optional[str] = None
    key_b64: Optional[str] = None
    prefix_b64: Optional[str] = None
    is_map: bool = False


@dataclass(frozen=True)
class Arc56Spec:
    """A parsed ARC-56 app spec; every collection is empty when its section is
    absent, so a partial spec degrades cleanly."""

    name: str
    methods: tuple = ()                    # tuple[AbiMethod, ...] (structs resolved)
    structs: dict = field(default_factory=dict)   # name -> resolved ABI tuple type
    global_state: tuple = ()               # tuple[StateEntry, ...]
    local_state: tuple = ()
    box_state: tuple = ()                  # box keys AND box maps

    def method_table(self) -> dict:
        """``{selector_hex: AbiMethod}`` — same shape as
        :func:`tealql.tealtools.metadata.abi.extract_method_table`, so a spec is a drop-in
        richer method source (last-write-wins on a selector collision)."""
        return {m.selector_hex: m for m in self.methods}


def _resolve_type(t: str, field_types: dict, _seen: Optional[frozenset] = None) -> str:
    """Resolve a declared type to its canonical ABI type string — a struct name
    expands to the tuple of its recursively resolved field types, anything else
    passes through; cycle-safe (a self-referential struct resolves to its own
    name rather than recursing forever)."""
    _seen = _seen or frozenset()
    if t not in field_types or t in _seen:
        return t
    nxt = _seen | {t}
    return "(" + ",".join(
        _resolve_type(ft, field_types, nxt) for ft in field_types[t]) + ")"


def _parse_structs(raw: dict) -> tuple[dict, dict]:
    """``(field_type_lists, resolved_tuple_types)`` from the spec's ``structs`` —
    the ORDERED field types for resolution, plus the resolved tuple string."""
    field_types: dict = {}
    for name, fields in (raw or {}).items():
        if isinstance(fields, list):
            field_types[name] = [
                f.get("type") for f in fields
                if isinstance(f, dict) and f.get("type")
            ]
    resolved = {name: _resolve_type(name, field_types) for name in field_types}
    return field_types, resolved


def _method_from_spec(m: dict, field_types: dict) -> Optional[AbiMethod]:
    """Build an :class:`AbiMethod` from an ARC-56 method object, resolving struct
    arg/return types to their ABI encoding and computing the selector FORWARD."""
    name = m.get("name")
    if not name:
        return None
    args = m.get("args") or []
    arg_types = tuple(_resolve_type(a.get("type", ""), field_types)
                      for a in args if isinstance(a, dict))
    arg_names = tuple(a.get("name", "") for a in args if isinstance(a, dict))
    ret = (m.get("returns") or {}).get("type") or "void"
    ret = _resolve_type(ret, field_types)
    signature = f"{name}({','.join(arg_types)}){ret}"
    return AbiMethod(
        name=name, arg_types=arg_types, return_type=ret, signature=signature,
        selector=method_selector(signature), arg_names=arg_names,
    )


def _state_entries(keys: dict, maps: dict, field_types: dict) -> tuple:
    """Flatten one scope's ``keys`` (fixed) and ``maps`` (prefix) into
    :class:`StateEntry` records with resolved value types."""
    out: list = []
    for nm, k in (keys or {}).items():
        if not isinstance(k, dict):
            continue
        out.append(StateEntry(
            name=nm,
            value_type=_resolve_type(k.get("valueType", ""), field_types),
            key_type=k.get("keyType"),
            key_b64=k.get("key"),
        ))
    for nm, mp in (maps or {}).items():
        if not isinstance(mp, dict):
            continue
        out.append(StateEntry(
            name=nm,
            value_type=_resolve_type(mp.get("valueType", ""), field_types),
            key_type=mp.get("keyType"),
            prefix_b64=mp.get("prefix"),
            is_map=True,
        ))
    return tuple(out)


def from_dict(data: dict) -> Arc56Spec:
    """Parse an already-loaded ARC-56 JSON object into an :class:`Arc56Spec`,
    skipping absent sections and dropping malformed method entries."""
    # A valid-JSON spec may carry a non-dict where a dict is expected (`"state": []`);
    # coerce to {} to hold the "never raises on a partial spec" contract.
    def _dict(v):
        return v if isinstance(v, dict) else {}

    field_types, resolved = _parse_structs(_dict(data.get("structs")))
    methods = tuple(
        mm for mm in (
            _method_from_spec(m, field_types)
            for m in (data.get("methods") or []) if isinstance(m, dict)
        ) if mm is not None
    )
    state = _dict(data.get("state"))
    keys = _dict(state.get("keys"))
    maps = _dict(state.get("maps"))
    return Arc56Spec(
        name=data.get("name") or _dict(data.get("contract")).get("name") or "",
        methods=methods,
        structs=resolved,
        global_state=_state_entries(keys.get("global"), maps.get("global"), field_types),
        local_state=_state_entries(keys.get("local"), maps.get("local"), field_types),
        box_state=_state_entries(keys.get("box"), maps.get("box"), field_types),
    )


def load(path) -> Arc56Spec:
    """Load and parse an ARC-56 app-spec JSON file — raises only when the file is
    missing or not valid JSON."""
    return from_dict(json.loads(Path(path).read_text()))


def load_optional(path) -> Optional[Arc56Spec]:
    """:func:`load`, but ``None`` on any failure — a bad or absent spec must degrade
    to no enrichment, never error."""
    if not path:
        return None
    try:
        return load(path)
    except Exception:
        return None
