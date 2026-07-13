"""ARC-56 app-spec ingestion — the richest, standardized source of the HIGH-LEVEL
info the analysis can use, when the user PROVIDES the spec file.

An ARC-56 JSON (a superset of ARC-32/ARC-4) declares, authoritatively, a
contract's methods (name + arg/return ABI types, including *named struct* types),
its global/local/box state keys with their value types, and its box maps. None of
this is recoverable from compiled bytecode — it is the DECLARED contract. So this
is a VERY OPTIONAL enrichment: everything downstream works on raw disassembled
TEAL without a spec; a provided spec simply sharpens it (authoritative ABI arg
typing for the relational bounds domain, box/state schema, method names in
findings — the same consumers the source-text :mod:`.abi` table feeds, but richer
and more reliable).

We NEVER reverse a selector: the method table is built by resolving each declared
signature (structs expanded to their tuple encoding) and computing the selector
FORWARD (``sha512_256``), exactly as :mod:`.abi` does for source ``method "sig"``
text — so an ARC-56 method table is a drop-in, higher-fidelity replacement for it.

Tolerant by design: a partial / non-conforming spec yields whatever sections
parse and empty for the rest, and :func:`load` raises only on input that isn't
JSON at all. Nothing here imports the SSA/lift layers, so it is a pure, cheap
front-end that any layer can consume.
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
    """One declared state key (global / local / box), or a box map, with its
    resolved value type. ``key_b64`` is the base64 key bytes for a fixed key (a
    map has ``prefix_b64`` instead); ``value_type`` / ``key_type`` are resolved
    ABI type strings (or an AVM-native ``AVM*`` encoding)."""

    name: str
    value_type: str
    key_type: Optional[str] = None
    key_b64: Optional[str] = None
    prefix_b64: Optional[str] = None
    is_map: bool = False


@dataclass(frozen=True)
class Arc56Spec:
    """A parsed ARC-56 app spec. Every collection is empty when the corresponding
    section is absent, so a partial spec degrades cleanly."""

    name: str
    methods: tuple = ()                    # tuple[AbiMethod, ...] (structs resolved)
    structs: dict = field(default_factory=dict)   # name -> resolved ABI tuple type
    global_state: tuple = ()               # tuple[StateEntry, ...]
    local_state: tuple = ()
    box_state: tuple = ()                  # box keys AND box maps

    def method_table(self) -> dict:
        """``{selector_hex: AbiMethod}`` — the same shape as
        :func:`tealql.tealtools.abi.extract_method_table`, so a provided spec is a
        drop-in, richer method source (last-write-wins on a selector collision)."""
        return {m.selector_hex: m for m in self.methods}


def _resolve_type(t: str, field_types: dict, _seen: Optional[frozenset] = None) -> str:
    """Resolve a declared type to its canonical ABI type string: a struct name
    expands to the tuple of its (recursively resolved) field types; anything else
    is returned unchanged. ``field_types`` maps a struct name to its ordered list
    of field type strings. Cycle-safe (a self-referential struct resolves to its
    own name rather than recursing forever)."""
    _seen = _seen or frozenset()
    if t not in field_types or t in _seen:
        return t
    nxt = _seen | {t}
    return "(" + ",".join(
        _resolve_type(ft, field_types, nxt) for ft in field_types[t]) + ")"


def _parse_structs(raw: dict) -> tuple[dict, dict]:
    """``(field_type_lists, resolved_tuple_types)`` from the spec's ``structs``.
    A struct value is a list of ``{name, type}`` fields (ARC-56); we keep the
    ordered field TYPES for resolution and the fully-resolved tuple string."""
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
    arg/return types to their ABI encoding and computing the selector forward."""
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
    """Flatten one scope's ARC-56 ``keys`` (fixed keys) and ``maps`` (prefix maps)
    into :class:`StateEntry` records with resolved value types."""
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
    """Parse an already-loaded ARC-56 JSON object into an :class:`Arc56Spec`.
    Tolerant: unknown/absent sections are skipped, malformed method entries are
    dropped (never raises on a partial spec)."""
    field_types, resolved = _parse_structs(data.get("structs") or {})
    methods = tuple(
        mm for mm in (
            _method_from_spec(m, field_types)
            for m in (data.get("methods") or []) if isinstance(m, dict)
        ) if mm is not None
    )
    state = data.get("state") or {}
    keys = state.get("keys") or {}
    maps = state.get("maps") or {}
    return Arc56Spec(
        name=data.get("name") or data.get("contract", {}).get("name") or "",
        methods=methods,
        structs=resolved,
        global_state=_state_entries(keys.get("global"), maps.get("global"), field_types),
        local_state=_state_entries(keys.get("local"), maps.get("local"), field_types),
        box_state=_state_entries(keys.get("box"), maps.get("box"), field_types),
    )


def load(path) -> Arc56Spec:
    """Load and parse an ARC-56 app-spec JSON file. Raises only if the file is
    missing or not valid JSON; a valid-JSON-but-partial spec parses to whatever
    sections are present."""
    return from_dict(json.loads(Path(path).read_text()))


def load_optional(path) -> Optional[Arc56Spec]:
    """:func:`load`, but ``None`` on any failure — for the optional CLI/analysis
    path where a bad or absent spec must degrade to no enrichment, never error."""
    if not path:
        return None
    try:
        return load(path)
    except Exception:
        return None
