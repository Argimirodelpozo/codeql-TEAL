"""Shared builders for the pure-unit pass tests that bypass SSA construction
and hand-build :class:`Assignment` / :class:`SSAVar` nodes plus a
``SimpleNamespace`` SSAProgram stand-in (the range / byte-length / const-fold
kernel tests). Importable — conftest puts tests/ on sys.path.
"""
from __future__ import annotations

from types import SimpleNamespace

from tealtools.ssa import Assignment, Location, SSAVar


def mk_var(line: int = 10, index: int = 0) -> SSAVar:
    return SSAVar("t.teal", line, index)


def mk_asn(op, *, imm="", inputs=(), outputs=(), const=None) -> Assignment:
    """Build a single-line ``Assignment`` and back-link each SSAVar output's
    ``defined_by`` to it (what a pass's def-use walk expects)."""
    a = Assignment(outputs=list(outputs), op=op, immediates=imm, inputs=list(inputs),
                   location=Location("t.teal", 1), ast_code="", const=const)
    for o in outputs:
        if isinstance(o, SSAVar):
            o.defined_by = a
    return a


def mk_prog(assignments, phis=(), **flags) -> SimpleNamespace:
    """Minimal SSAProgram surface a pass reads: a flat assignment list, a phi
    dict, and ``_consts_propagated=True`` so it skips ``propagate_constants``.
    Extra ``flags`` (e.g. ``_ranges_propagated=True``) set further skip-gates."""
    ns = SimpleNamespace(
        assignments=list(assignments),
        phis={i: p for i, p in enumerate(phis)},
        _consts_propagated=True,
    )
    for k, v in flags.items():
        setattr(ns, k, v)
    return ns
