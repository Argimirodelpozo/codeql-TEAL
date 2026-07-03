"""TealQL — pure-Python static analysis for TEAL (the Algorand AVM language).

One installable package, three subpackages:

  - :mod:`tealql.tealtools` — the analysis substrate: parse -> graph -> SSA,
    dataflow/taint, passes, and the Puya-IR lift.
  - :mod:`tealql.security` — the detection layer (detector registry, scanner,
    cross-contract driver). Depends on ``tealtools``, never the reverse.
  - :mod:`tealql.cli`      — the ``tealql`` console entry point.

Subpackages are intentionally NOT imported here: ``import tealql`` must stay
free of import-time work (the CLI and library entry points import what they
need directly).
"""
