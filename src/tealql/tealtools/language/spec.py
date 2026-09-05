"""Versioned mechanical AVM specification, independent of optional compilers.

Generated from go-algorand v5.0.0-stable, revision
 da5946a14568c0cbaa2c9daf4241882de12f3c16. This specifies supported language
semantics, not the currently activated protocol of any network.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType

_DATA = json.loads(Path(__file__).with_name('op_specs.json').read_text())
SPEC_REVISION = _DATA['revision']
SPEC_VERSION = _DATA['version']
SPEC_SOURCE_HASHES = MappingProxyType(_DATA['source_sha256'])


@dataclass(frozen=True)
class OpSpec:
    name: str
    since: int
    args: tuple[str, ...]
    returns: tuple[str, ...]
    modes: int
    cost: str
    immediates: tuple[tuple[str, str], ...]
    fields: object

    @property
    def arity(self) -> tuple[int, int]:
        """Fixed signature only; shuffles/calls have explicit custom transfers."""
        return len(self.args), len(self.returns)

    def permits(self, version: int, mode: str, field: str | None = None) -> bool:
        flag = {'logicsig': 1, 'app': 2}.get(mode, 0)
        if not self.since <= version <= SPEC_VERSION or not self.modes & flag:
            return False
        if field is None:
            return True
        detail = self.fields.get(field)
        return detail is not None and detail[1] <= version and bool(detail[2] & flag)


SPECS = MappingProxyType({name: tuple(OpSpec(
    name, row['since'], tuple(row['args']), tuple(row['returns']), row['modes'],
    row['cost'], tuple(tuple(i) for i in row['immediates']),
    MappingProxyType({k: tuple(v) for k, v in row['fields'].items()}),
) for row in variants) for name, variants in _DATA['ops'].items()})


del _DATA


def opcode_spec(name: str, version: int = SPEC_VERSION) -> OpSpec | None:
    if not 1 <= version <= SPEC_VERSION:
        return None
    return next((spec for spec in reversed(SPECS.get(name, ())) if spec.since <= version), None)


def type_kind(kind: str | None) -> str | None:
    """Project spec types onto the analyzer's value families."""
    if kind in {'uint64', 'bool'}:
        return kind
    if kind == 'address':
        return 'account'
    if kind == 'bigint':
        return 'biguint'
    if kind and ('byte' in kind or kind in {'boxName', 'biguint'}):
        return 'bytes' if kind != 'biguint' else kind
    return None


def operand_type(op, index, version=SPEC_VERSION):
    spec = opcode_spec(op, version)
    return type_kind(spec.args[-index - 1]) if spec and 0 <= index < len(spec.args) else None


def result_type(op, index=0, version=SPEC_VERSION):
    spec = opcode_spec(op, version)
    return type_kind(spec.returns[-index - 1]) if spec and 0 <= index < len(spec.returns) else None


# Pinned Puya 5.7 has no members for these v13 operations. Analysis supports
# their mechanical signatures; backend compilation must report unsupported.
PUYA_57_UNSUPPORTED = frozenset(name for name in SPECS
                               if name.startswith('app_box_') or name in {'poseidon2', 'app_params_set'})


def support_inventory(version=SPEC_VERSION) -> dict:
    return {'version': version, 'supported': 1 <= version <= SPEC_VERSION,
            'revision': SPEC_REVISION,
            'extensions': {'sumhash512': 'legacy extension outside the pinned consensus spec'},
            'opcodes': {
        name: {'analysis': 'custom' if name in {'callsub', 'retsub', 'proto', 'dig', 'bury',
                    'cover', 'uncover', 'popn', 'dupn', 'match', 'pushints', 'pushbytess',
                    'frame_dig', 'frame_bury'} else 'generic',
               'puya_5_7': 'unsupported' if name in PUYA_57_UNSUPPORTED else 'opcode-present',
               'modes': spec.modes, 'fields': sorted(spec.fields),
               'puya_5_7_unsupported_fields': sorted(field for field, detail in spec.fields.items() if detail[1] > 12)}
        for name in SPECS if (spec := opcode_spec(name, version)) is not None}}
