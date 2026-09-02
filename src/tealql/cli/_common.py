"""Shared CLI plumbing: logging, target resolution, program loading, output.

HAZARD — the exit-code contract, uniform across every subcommand:

  ``0``  clean — analysis ran, no findings
  ``1``  findings — at least one detector reported something
  ``2``  error — bad target, unparseable source under ``--strict``, or any other
         expected failure (clean message on stderr; genuine bugs still traceback)

CI depends on 1 meaning "findings", so a handler must never return 1 for an
error, nor 0 when it found something.
"""
from __future__ import annotations

import argparse
import json as _json
import logging
import sys
from pathlib import Path
from typing import Callable, Iterable

from tealql.tealtools._utils.targets import resolve_target
from tealql.tealtools.diagnostics.errors import TealParseError

logger = logging.getLogger("tealql.tealtools.cli")


def _configure_logging(verbosity: int) -> None:
    """Attach the one stderr handler for the whole ``tealql`` logger hierarchy,
    at WARNING / INFO / DEBUG per the ``-v`` count."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    root = logging.getLogger("tealql")
    root.setLevel(level)
    # Replace, don't append: `main()` runs repeatedly in-process (tests, library
    # embedding), and appending multiplied every log line by the call count.
    for existing in [h for h in root.handlers
                     if getattr(h, "_tealql_cli", False)]:
        root.removeHandler(existing)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    handler._tealql_cli = True                    # type: ignore[attr-defined]
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _add_common_flags(sp: argparse.ArgumentParser) -> None:
    """The non-positional flags every subcommand shares (output + parse health)."""
    sp.add_argument("--json", action="store_true",
                    dest="json_out",
                    help="emit JSON instead of text")
    sp.add_argument("-v", "--verbose", action="count", default=0,
                    help="progress logging to stderr; repeat (-vv) for "
                         "per-pass timings")
    sp.add_argument("--strict", action="store_true",
                    help="exit 2 if any TEAL failed to parse instead of "
                         "analyzing the partial program with a warning")


def _add_target_args(sp: argparse.ArgumentParser, *, dest: str = "target",
                     optional: bool = False) -> None:
    """Add the universal ``<target>`` positional plus the common flags;
    ``optional`` is for commands that can run without a target."""
    if optional:
        sp.add_argument(dest, nargs="?", default=None,
                        help="path to a .teal file or a directory of .teal files")
    else:
        sp.add_argument(
            dest,
            help="path to a .teal file or a directory of .teal files",
        )
    _add_common_flags(sp)


def _resolve(args) -> Path:
    """Validate the target path (raises if it isn't TEAL source)."""
    return resolve_target(args.target)


def _check_parse_health(prog, args) -> None:
    """Warn (or, under ``--strict``, raise → exit 2) about anything the analysis
    silently lost.

    HAZARD: the parser DROPS unparseable spans and an opcode unknown to this
    build is modelled with a (0, 0) stack effect that corrupts the whole
    simulation. Both must be surfaced — a partial contract must never read as
    clean. Read the PER-PROGRAM set the builder recorded, not the process-wide
    ``avm.unknown_opcodes()`` union — in one run over many contracts the union
    blames every later program for the first one's exotic opcode."""
    unknown = sorted(getattr(prog, "unknown_ops", ()))
    if unknown:
        logger.warning(
            "%d opcode(s) unknown to this build were modelled with NO stack "
            "effect, so results for programs using them are unreliable "
            "(%s). This build may predate the contract's AVM version.",
            len(unknown), ", ".join(unknown[:8]),
        )
    health = getattr(prog, "health", None)
    if callable(health):
        others = [d for d in health().degradations
                  if d.code not in ("parse-diagnostic", "unknown-opcode")]
        for d in others:                     # e.g. multiple-constant-blocks
            where = f"{d.file}:{d.line}: " if d.file and d.line else ""
            logger.warning("analysis degraded (%s): %s%s", d.code, where, d.message)
    diags = getattr(prog, "parse_diagnostics", ())
    if not diags:
        return
    if getattr(args, "strict", False):
        raise TealParseError(diags)
    logger.warning(
        "%d TEAL span(s) failed to parse and were EXCLUDED from analysis — "
        "results may be incomplete (first: %s). Use --strict to make this "
        "fatal.", len(diags), diags[0],
    )


def _load(args):
    """Resolve target → :class:`SSAProgram`."""
    from tealql.tealtools.ssa import SSAProgram
    source = _resolve(args)
    logger.info("building SSA program from %s", source)
    prog = SSAProgram(str(source), strict=False)
    # Construction only tags direct pushes. Cross-contract discovery keys on
    # CONSTANT AppIDs, so without this the callees are silently missed.
    prog.propagate_constants()
    logger.info("SSA program ready (%d assignments)", len(prog.assignments))
    _check_parse_health(prog, args)
    return prog


def _load_programs(args) -> "list[tuple]":
    """Resolve target → ``[(SSAProgram, file_filter), …]``, ONE program per
    ``.teal`` file, each const-propagated as :func:`_load` does.

    HAZARD: never merge a directory into one program. The AVM runs each program
    independently, so dominance / path-predicate detectors give WRONG answers
    once several programs' entries and exits are pooled. ``file_filter`` is the
    basename (so detectors scope to it), or ``None`` for a single file."""
    from tealql.tealtools._utils.targets import _discover_teal_files
    from tealql.tealtools.ssa import SSAProgram
    source = _resolve(args)
    teal_files = _discover_teal_files(Path(source))
    single = len(teal_files) == 1
    progs: list[tuple] = []
    for teal in teal_files:
        logger.info("building SSA program from %s", teal)
        prog = SSAProgram(str(teal), strict=False)
        prog.propagate_constants()
        _check_parse_health(prog, args)
        progs.append((prog, None if single else teal.name))
    return progs


def _emit_findings(findings: Iterable, *, json_out: bool) -> int:
    """Render finding-style output; returns the exit code (1 = findings)."""
    findings = list(findings)
    if json_out:
        from tealql.tealtools._utils.serialize import finding_to_dict
        print(_json.dumps([finding_to_dict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("(no violations)")
        else:
            for v in findings:
                print(v.pretty())
    return 1 if findings else 0


def _emit_dict(payload: dict, *, json_out: bool, text: str) -> int:
    """Render report-style output; the caller pre-computes both forms."""
    print(_json.dumps(payload, indent=2) if json_out else text)
    return 0


def make_add(sub) -> Callable:
    """The per-module subparser factory: ``add(name, help, handler)`` wires the
    universal ``<target>`` positional + common flags and the handler."""
    def add(name: str, help_: str, handler: Callable, *,
            optional_target: bool = False) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        _add_target_args(sp, optional=optional_target)
        sp.set_defaults(handler=handler)
        return sp
    return add
