"""AST types package — re-exports the contents of :mod:`tealtools.ast.ast`
so external imports (``from tealtools.ast import Opcode``) keep working
unchanged after the file was moved inside a folder."""
from .ast import *  # noqa: F401,F403
from .ast import __doc__  # preserve module docstring on the package
