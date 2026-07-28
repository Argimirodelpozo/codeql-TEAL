# Re-exports `ast.py` so `from tealql.tealtools.ast import Opcode` works; its
# `__all__` bounds the star import to the node types, `Location` and
# `node_class_for_mnemonic`. No module docstring on purpose — the second line
# rebinds `__doc__` to `ast.py`'s and would discard one written here.
from .ast import *  # noqa: F401,F403
from .ast import __doc__ as __doc__
