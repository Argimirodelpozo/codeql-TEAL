"""Rewrite TEAL assembler pseudo-ops into canonical ops in the folks sources.

==============================  WHY THIS EXISTS  ==============================
The prebuilt CodeQL TEAL extractor (`.codeql-extractors/teal`, a binary we
cannot edit here) SILENTLY DROPS the `int` / `byte` / `method` assembler
pseudo-ops -- it only emits nodes for the canonical forms (`pushint`,
`pushbytes`, `intc*`, `bytec*`). The folks contracts were compiled with the
pseudo-op forms, so every constant they push (method selectors, OnCompletion
enums, state keys, the ARC4 return prefix) VANISHES from the extracted graph.
Downstream that starves whatever consumed the constant: the method-dispatch
`==` comparisons lose an operand, `app_global_put` loses its key/value, and a
`dupn` of a dropped `byte ""` is left with no input -- so the folks DBs cannot
be lifted to a faithful SSA / Puya IR.

This script is the AGREED INTERIM WORKAROUND (chosen 2026-06-02, over a runtime
source-recovery pre-pass): we patch the *source* so the extractor sees ops it
understands. Each pseudo-op is rewritten to the equivalent canonical push and
TAGGED INLINE with `// [pseudo-op-patch] was: <original>` so it is unmistakable
in the source that these lines were rewritten, and the original is recoverable.
The rewrite is semantically identical TEAL (just not the space-optimal
intcblock/bytecblock form an assembler would pick), so the contract behaviour --
and thus the analysis -- is unchanged. Re-running is idempotent (patched lines
no longer start with a pseudo-op). The proper fix remains rebuilding the
extractor to emit these pseudo-ops; this unblocks folks until then.

Run:  python3 test-projects/folks-finance/patch_pseudo_ops.py
Then rebuild the folks DBs from the patched sources (see this dir's README).
=============================================================================
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEAL_DIR = HERE / "teal-compiled"
# The approval programs carry all the dispatch/state logic (the clear programs
# are trivial and use no pseudo-ops).
TARGETS = [
    "consensus_v2_approval.teal",
    "consensus_v3_approval.teal",
    "xgov_registry_approval_program.teal",
]

# `int <name>` named constants. OnCompletion and TypeEnum share no names, so a
# single map is unambiguous. (Algorand TEAL spec, langspec named integer consts.)
NAMED_INT = {
    # OnCompletion
    "NoOp": 0, "OptIn": 1, "CloseOut": 2, "ClearState": 3,
    "UpdateApplication": 4, "DeleteApplication": 5,
    # TypeEnum
    "unknown": 0, "pay": 1, "keyreg": 2, "acfg": 3, "axfer": 4,
    "afrz": 5, "appl": 6,
}

_MARK = "[pseudo-op-patch]"
_INT = re.compile(r'^(\s*)int\s+(\S+)\s*(?://.*)?$')
_BYTE_STR = re.compile(r'^(\s*)byte\s+"([^"]*)"\s*(?://.*)?$')
_BYTE_HEX = re.compile(r'^(\s*)byte\s+(0x[0-9a-fA-F]+)\s*(?://.*)?$')
_METHOD = re.compile(r'^(\s*)method\s+"([^"]*)"\s*(?://.*)?$')


def _method_selector(sig: str) -> str:
    """ARC4 method selector: first 4 bytes of SHA-512/256 of the signature."""
    return "0x" + hashlib.new("sha512_256", sig.encode()).digest()[:4].hex()


def convert(line: str) -> str | None:
    """Canonical rewrite of one pseudo-op line, or None if it isn't one."""
    raw = line.rstrip("\n")
    if _MARK in raw:
        return None                                   # already patched

    m = _INT.match(raw)
    if m:
        indent, arg = m.group(1), m.group(2)
        val = NAMED_INT.get(arg)
        if val is None:
            val = int(arg, 0)                         # decimal or 0x literal
        return f"{indent}pushint {val} // {_MARK} was: int {arg}"

    m = _BYTE_STR.match(raw)
    if m:
        indent, s = m.group(1), m.group(2)
        return (f'{indent}pushbytes 0x{s.encode().hex()} '
                f'// {_MARK} was: byte "{s}"')

    m = _BYTE_HEX.match(raw)
    if m:
        indent, hx = m.group(1), m.group(2)
        return f"{indent}pushbytes {hx} // {_MARK} was: byte {hx}"

    m = _METHOD.match(raw)
    if m:
        indent, sig = m.group(1), m.group(2)
        return (f'{indent}pushbytes {_method_selector(sig)} '
                f'// {_MARK} was: method "{sig}"')

    return None


def patch_file(path: Path) -> int:
    lines = path.read_text().splitlines()
    out, n = [], 0
    for line in lines:
        new = convert(line)
        if new is None:
            out.append(line)
        else:
            out.append(new)
            n += 1
    if n:
        path.write_text("\n".join(out) + "\n")
    return n


def main() -> None:
    total = 0
    for name in TARGETS:
        path = TEAL_DIR / name
        n = patch_file(path)
        total += n
        print(f"{name}: rewrote {n} pseudo-ops")
    print(f"total: {total} pseudo-ops rewritten to canonical form")


if __name__ == "__main__":
    main()
