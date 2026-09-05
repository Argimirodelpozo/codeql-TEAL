"""Structural contracts between revisions, with explicit semantic limitations."""
from __future__ import annotations

from .obligations import ObligationResult
from .semantic_compatibility import compare_programs  # noqa: F401


def compare_contracts(before, after):
    """Compare normalized ABI/storage/effect contracts (not arbitrary ARC-56 JSON).

    Every contract must declare all four dimensions. Effects are per-method
    allowed effect labels; adding an effect violates that declared contract.
    Policy names/permissions compare exactly. Added methods/storage are allowed.
    """
    dimensions = {'methods', 'storage', 'permissions', 'effects'}
    for spec in (before, after):
        if not isinstance(spec, dict) or set(spec) != dimensions or any(
                not isinstance(spec[k], dict) for k in dimensions):
            raise ValueError('revision contract requires methods, storage, permissions, and effects maps')
        if set(spec['effects']) != set(spec['methods']):
            raise ValueError('every method must declare its effect set')
        if any(not isinstance(v, list) or any(not isinstance(e, str) for e in v)
               for v in spec['effects'].values()):
            raise ValueError('method effects must be lists of labels')
    out = []
    for dimension in sorted(dimensions):
        for key, old in sorted(before[dimension].items()):
            new = after[dimension].get(key)
            ok = key in after[dimension] and (set(new) <= set(old) if dimension == 'effects' else new == old)
            out.append(ObligationResult('compatibility', f'{dimension}:{key}',
                'PROVED' if ok else 'REFUTED', 'declared structural contract preserved' if ok else 'declared contract changed or removed',
                assumptions=('both revision contracts accurately describe their implementations',)))
    out.append(ObligationResult('compatibility', 'semantics', 'UNKNOWN',
               'ABI/schema compatibility does not prove behavioral equivalence or safe migration'))
    return tuple(out)
