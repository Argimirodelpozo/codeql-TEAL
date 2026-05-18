"""Experimental analyses built on top of :mod:`tealtools.control_tree`.

These reuse the structural-analysis machinery (typed regions,
interprocedural subroutine summaries, DAG-folded improper regions)
to compute per-line metrics besides opcode cost. The fold framework
in :mod:`tealtools.experimental.tree_fold` does the recursive
plumbing; individual analyses (:mod:`stack_depth`, :mod:`itxn_count`,
:mod:`auth_dominance`, :mod:`recursion`) just plug in per-region
handlers.

Stability not promised — these are exploratory.
"""
