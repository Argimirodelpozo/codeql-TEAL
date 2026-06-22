"""Internal utility helpers that aren't part of the core analysis pipeline.

  - :mod:`tealtools._utils.chain` — the only network-touching module in the
    library (fetches deployed approval programs off chain for cross-contract
    auto-discovery and the behavioural-lift corpus).
  - :mod:`tealtools._utils.dot` — Graphviz primitives (``escape`` / ``render``)
    shared by the CFG / SSA / structure renderers.
"""
