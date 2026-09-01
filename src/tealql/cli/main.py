"""``tealql`` — unified CLI for the TealQL static-analysis toolkit.

Each subcommand takes one ``<target>`` (a ``.teal`` file or a directory of them)
and reconstructs everything from that source — nothing to build or cache.
Subcommands live in per-area modules (``reports`` / ``budget`` / ``lifted`` /
``security_cmds``), each exposing ``register(sub, add)``; shared plumbing and
the EXIT-CODE CONTRACT live in :mod:`._common`.
"""
from __future__ import annotations

import argparse
import sys

from tealql.tealtools.diagnostics.errors import TealQLError

from ._common import _configure_logging, make_add


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tealql",
        description="TEAL static-analysis toolkit. Each subcommand "
                    "runs one analysis or report against a target "
                    "(.teal file or directory of .teal files).",
    )
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")
    add = make_add(sub)
    from . import budget, lifted, reports, security_cmds
    reports.register(sub, add)
    budget.register(sub, add)
    lifted.register(sub, add)
    security_cmds.register(sub, add)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))
    try:
        return args.handler(args)
    except (TealQLError, FileNotFoundError) as e:
        # Every EXPECTED failure exits 2 with a clean message (see the
        # module-level exit-code contract); genuine bugs still traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
