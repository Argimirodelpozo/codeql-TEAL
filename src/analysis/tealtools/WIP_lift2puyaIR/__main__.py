"""Render a CodeQL TEAL database as real Puya IR.

    python -m tealtools.WIP_lift2puyaIR <db-path> [--optimize]
"""
import sys

from ..ssa import SSAProgram
from .to_puya_ir import render


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    paths = [a for a in argv if not a.startswith("-")]
    if not paths:
        print("usage: python -m tealtools.WIP_lift2puyaIR <db-path> [--optimize]")
        return 2
    prog = SSAProgram(paths[0], verbose=False)
    prog.propagate_constants()
    print(render(prog, optimize_ir="--optimize" in argv))
    return 0


raise SystemExit(main())
