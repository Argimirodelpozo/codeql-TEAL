# The AST node types live in `ast.py` inside this package and are re-exported
# here, so `from tealql.tealtools.ast import Opcode` reaches them directly.
# `ast.py` declares `__all__`, so this star import re-exports exactly the node
# types, `Location` and `node_class_for_mnemonic` -- it previously also handed
# out `dataclass`, `ClassVar`, `Optional` and `annotations`, which are only that
# module's own imports.
#
# Deliberately no module docstring: the second line below rebinds `__doc__` to
# `ast.py`'s, which is the one worth showing in `help()`. Anything written here
# as a docstring is discarded at import time -- one was, and it justified this
# shim as keeping *external* imports working after a file move. There are no
# external importers to keep working: the package is 0.1.0 and its own README
# calls the API "a research surface, not a stable interface".
from .ast import *  # noqa: F401,F403
from .ast import __doc__ as __doc__
