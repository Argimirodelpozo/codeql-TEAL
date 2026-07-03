"""Render TEAL source as real Puya IR.

    python -m tealql.tealtools.lift <teal-source> [--optimize]
"""
import sys

from ..ssa import SSAProgram
from .to_puya_ir import render


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    paths = [a for a in argv if not a.startswith("-")]
    if not paths:
        print("usage: python -m tealql.tealtools.lift <teal-source> [--optimize]")
        return 2
    prog = SSAProgram(paths[0])
    prog.propagate_constants()
    print(render(prog, optimize_ir="--optimize" in argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
