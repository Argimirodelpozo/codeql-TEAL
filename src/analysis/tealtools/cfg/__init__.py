"""CFG package — re-exports the contents of :mod:`tealtools.cfg.cfg` so
external imports (``from tealtools.cfg import CFG``) keep working
unchanged after the file was moved inside a folder."""
from .cfg import *  # noqa: F401,F403
from .cfg import __doc__  # preserve module docstring on the package
from .supercfg import SuperCFG, SuperBlock, SuperEdge  # noqa: F401
