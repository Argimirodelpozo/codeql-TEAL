"""`PySSA._try_remove_trivial` (Braun trivial-phi collapse) must be iterative:
a long cascade through the phi web would otherwise overflow the stack. Builds a
synthetic depth-N cascade (each phi becomes trivial only once its predecessor
collapses) under a LOW recursion limit — a recursive implementation would raise
RecursionError; the iterative worklist collapses the whole chain.
"""
from __future__ import annotations

import sys

from tealql.tealtools.ssa.ssa import PySSA, PyPhi, PyVar


def test_try_remove_trivial_deep_cascade_is_iterative():
    N = 2000                                   # >> any sane recursion limit
    ss = PySSA.__new__(PySSA)                  # bare instance — only the maps matter
    ss._replaced = {}
    ss.phis = {}
    ss.blocks = []                             # -> _bb_by_key computes to {} (cleanup skipped)
    ss._phi_users = {}

    leaf = PyVar("f.teal", 0, 1)
    phis = [PyPhi(("f.teal", i + 1, i + 1), 1) for i in range(N)]
    for p in phis:
        ss.phis[(p.bb_key, p.slot)] = p
    # phi_0 = phi(leaf, leaf) is trivial; phi_i = phi(phi_{i-1}, leaf) becomes
    # trivial only AFTER phi_{i-1} collapses to leaf -> a depth-N cascade.
    phis[0].args = [leaf, leaf]
    for i in range(1, N):
        phis[i].args = [phis[i - 1], leaf]
        ss._phi_users.setdefault(id(phis[i - 1]), set()).add(phis[i])

    old = sys.getrecursionlimit()
    sys.setrecursionlimit(200)                 # a recursive depth-2000 cascade overflows
    try:
        result = ss._try_remove_trivial(phis[0])
    finally:
        sys.setrecursionlimit(old)

    assert result is leaf                      # the head collapses to the leaf value
    assert ss.phis == {}                       # every trivial phi removed
    assert all(id(p) in ss._replaced for p in phis)
