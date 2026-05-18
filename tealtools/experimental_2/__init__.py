"""Fresh-start experimental sandbox — second iteration.

Built on the existing :mod:`tealtools.ssa` substrate. The first thing
this package does is run every available SSA cleanup / propagation
pass and expose the resulting program in its existing flat
``functional()`` form. Later analyses build from there.

See :mod:`tealtools.experimental_2.passes`.
"""

from .passes import run_all_passes, functional_dump
from .printer import structured_dump

__all__ = ["run_all_passes", "functional_dump", "structured_dump"]
