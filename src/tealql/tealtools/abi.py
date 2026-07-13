"""ABI method-table recovery from HIGH-LEVEL info in the source — the sound,
optional counterpart to the (impossible) "reverse the selector" idea.

An ABI method selector in a compiled contract is ``sha512_256("name(args)ret")[:4]``
— a hash, NOT reversible. But the signature itself survives as SOURCE TEXT: a
compiler emits ``pushbytes 0x03b5c0af // method "add_one(uint64)uint64"`` (and a
multi-selector router as ``pushbytess 0x.. 0x.. // method "a()..", method "b()...``),
and hand-written / higher-level TEAL uses ``method "sig"`` pseudo-ops verbatim. So
we READ the signature from the source and compute its selector forward; nothing is
reverse-engineered.

This is a VERY OPTIONAL enrichment: raw disassembled bytecode carries no
``method "…"`` text, so :func:`extract_method_table` returns ``{}`` and every
consumer degrades cleanly to its no-high-level-info behaviour. When the info IS
present it yields the ABI method table (name / arg types / return type per
selector) — the SOUND source for ABI arg typing (arg N is a 32-byte ``address``
*because the declared contract says so*), for buffer-length seeding in the
relational bounds domain, box/state schema, and human-readable finding messages.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

# Every `method "..."` occurrence — the pseudo-op operand AND the trailing
# `// method "..."` comment a compiler leaves on the lowered `pushbytes`/
# `pushbytess` selector both match, so one scan over the raw source finds all.
_METHOD_RE = re.compile(r'method\s+"([^"]+)"')


@dataclass(frozen=True)
class AbiMethod:
    """One ARC-4 ABI method recovered from a ``name(arg,arg,...)ret`` signature."""

    name: str
    arg_types: tuple            # ABI type strings, in declaration order
    return_type: str            # "void" or an ABI type
    signature: str              # the canonical signature text
    selector: bytes             # sha512_256(signature)[:4]

    @property
    def selector_hex(self) -> str:
        """``0x``-prefixed 4-byte selector, matching a ``pushbytes 0x..`` operand."""
        return "0x" + self.selector.hex()


def method_selector(signature: str) -> bytes:
    """The 4-byte ARC-4 method selector for a canonical signature (forward hash)."""
    return hashlib.new("sha512_256", signature.encode()).digest()[:4]


def _split_top_level(s: str) -> list:
    """Split ``s`` on top-level commas, respecting nested ``()`` / ``[]`` (so a
    tuple or array element with its own commas stays one item)."""
    s = s.strip()
    if not s:
        return []
    out, cur, depth = [], [], 0
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return out


def parse_signature(signature: str) -> Optional[AbiMethod]:
    """Parse ``name(arg,arg,...)ret`` into an :class:`AbiMethod`, or ``None`` if it
    isn't a well-formed signature. The return type may itself be a tuple, so the
    argument list is delimited by balancing the FIRST ``(`` (not by the last
    ``)``)."""
    signature = signature.strip()
    op = signature.find("(")
    if op <= 0:                                  # no args paren, or empty name
        return None
    name = signature[:op]
    depth, close = 0, -1
    for i in range(op, len(signature)):
        if signature[i] == "(":
            depth += 1
        elif signature[i] == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close < 0:                                # unbalanced
        return None
    args = tuple(_split_top_level(signature[op + 1:close]))
    ret = signature[close + 1:].strip() or "void"
    return AbiMethod(name=name, arg_types=args, return_type=ret,
                     signature=signature, selector=method_selector(signature))


def abi_type_byte_length(t: str) -> Optional[int]:
    """The ARC-4 ENCODED byte length of a fixed-size type, or ``None`` when it is
    dynamic (``string`` / ``byte[]`` / ``T[]``) or a reference/transaction type
    (``account`` / ``asset`` / ``application`` / ``pay`` / ``appl`` …) that isn't
    packed into the ApplicationArgs bytes at all. Consecutive ``bool`` are
    bit-packed (ARC-4), so tuples/arrays account for that. Sound: never returns a
    wrong length — only an exact one or ``None``."""
    t = t.strip()
    if t == "bool":
        return 1
    if t in ("byte", "uint8"):
        return 1
    if t == "address":
        return 32
    m = re.fullmatch(r"uint(\d+)", t)
    if m:
        n = int(m.group(1))
        return n // 8 if n % 8 == 0 and 8 <= n <= 512 else None
    m = re.fullmatch(r"ufixed(\d+)x\d+", t)
    if m:
        n = int(m.group(1))
        return n // 8 if n % 8 == 0 and 8 <= n <= 512 else None
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)        # static array T[N]
    if m:
        elem, n = m.group(1).strip(), int(m.group(2))
        if elem == "bool":
            return (n + 7) // 8                   # bit-packed
        es = abi_type_byte_length(elem)
        return es * n if es is not None else None
    if t.startswith("(") and t.endswith(")"):     # tuple
        parts = _split_top_level(t[1:-1])
        total, i = 0, 0
        while i < len(parts):
            if parts[i] == "bool":                # a run of consecutive bools packs
                run = 0
                while i < len(parts) and parts[i] == "bool":
                    run += 1
                    i += 1
                total += (run + 7) // 8
                continue
            es = abi_type_byte_length(parts[i])
            if es is None:
                return None
            total += es
            i += 1
        return total
    return None                                   # dynamic / reference / txn type


def extract_method_table(source: str) -> dict:
    """``{selector_hex: AbiMethod}`` for every ``method "sig"`` found in ``source``
    (pseudo-op operands AND ``// method "sig"`` comments). ``{}`` when the source
    has no high-level ABI info (e.g. raw disassembled bytecode) — the caller then
    degrades to its non-enriched behaviour. Keyed by ``0x``-selector so a
    ``pushbytes 0x..`` / ``pushbytess 0x..`` operand in the program maps straight
    to its method."""
    table: dict = {}
    for sig in set(_METHOD_RE.findall(source)):
        m = parse_signature(sig)
        if m is not None:
            table[m.selector_hex] = m
    return table
