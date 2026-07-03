"""``tealql`` command-line interface.

A top-level package (``cli/``), kept separate from the ``tealtools``
analysis library it drives. The CLI is a thin layer — it imports
everything it needs from ``tealql.tealtools.*`` and owns no analysis logic.

Entry points:
  - console script ``tealql`` → :func:`cli.main.main`
  - ``python -m tealql.cli``
"""
