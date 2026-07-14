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

#: ARC-4 TRANSACTION arg types — passed as preceding GROUP txns, so they carry NO
#: ApplicationArgs bytes and SHIFT the ApplicationArgs index of the args after them.
TXN_ARG_TYPES = frozenset({
    "txn", "pay", "keyreg", "acfg", "axfer", "afrz", "appl",
})
#: ARC-4 REFERENCE arg types — encoded as a uint8 index into the txn's foreign
#: array, so they DO occupy one ApplicationArgs byte (unlike transaction args).
REFERENCE_ARG_TYPES = frozenset({"account", "asset", "application"})


@dataclass(frozen=True)
class AbiMethod:
    """One ARC-4 ABI method recovered from a ``name(arg,arg,...)ret`` signature."""

    name: str
    arg_types: tuple            # ABI type strings, in declaration order
    return_type: str            # "void" or an ABI type
    signature: str              # the canonical signature text
    selector: bytes             # sha512_256(signature)[:4]
    # Argument names, in declaration order, when a richer source (an ARC-56 spec)
    # carries them — empty for signatures recovered from bare `method "sig"` text.
    arg_names: tuple = ()

    @property
    def selector_hex(self) -> str:
        """``0x``-prefixed 4-byte selector, matching a ``pushbytes 0x..`` operand."""
        return "0x" + self.selector.hex()

    @property
    def app_arg_types(self) -> tuple:
        """The arg types carried in ``ApplicationArgs``, in order — transaction-type
        args (``pay`` / ``axfer`` / …) are dropped (they ride as group txns, not
        encoded bytes). ``ApplicationArgs[k]`` (1-based) is ``app_arg_types[k-1]``,
        except that ARC-4 packs the 16th-onward encoded args into a tuple at index 15."""
        return tuple(a for a in self.arg_types if a not in TXN_ARG_TYPES)

    def app_arg_byte_length(self, n: int) -> Optional[int]:
        """The ARC-4 encoded byte length of ``txna ApplicationArgs n`` (``n`` >= 1,
        the selector is index 0), or ``None`` when unknown/dynamic/ambiguous.
        Conservatively declines the packed 15th slot (>15 encoded args). This is
        the WELL-FORMED-ABI byte length: the AVM router only checks the selector,
        not arg lengths, so a consumer must treat it as a speculative assumption."""
        args = self.app_arg_types
        if n < 1 or n - 1 >= len(args):
            return None
        if len(args) > 15 and n >= 15:            # packed-tuple slot — ambiguous
            return None
        return abi_type_byte_length(args[n - 1])


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
    dynamic (``string`` / ``byte[]`` / ``T[]``) or a TRANSACTION type
    (``pay`` / ``axfer`` / …, which rides as a group txn — no encoded bytes).
    REFERENCE types (``account`` / ``asset`` / ``application``) encode as a
    ``uint8`` index -> 1 byte. Consecutive ``bool`` are bit-packed (ARC-4), so
    tuples/arrays account for that. Never returns a wrong length — only an exact
    one or ``None``."""
    t = t.strip()
    if t == "bool":
        return 1
    if t in ("byte", "uint8"):
        return 1
    if t == "address":
        return 32
    if t in REFERENCE_ARG_TYPES:                  # account/asset/application -> uint8 index
        return 1
    if t in TXN_ARG_TYPES:                         # a group txn, not an encoded value
        return None
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


# --- source-line attribution: which ABI method a finding sits in -------------

# A label definition line: ``foo:`` / ``main_get_address_route@14:`` at col 0.
_LABEL_DEF_RE = re.compile(r"^([A-Za-z_][\w@]*):\s*$")
#: Ops whose operands are a POSITIONAL list of branch targets, paired 1:1 with the
#: selectors of the immediately-preceding ``pushbytess ... // method ...`` line.
_DISPATCH_OPS = ("match", "switch")
#: Single-selector branch: ``pushbytes SEL // method "sig"`` then ``==`` then one of these.
_COND_BRANCH_OPS = ("bnz", "bz", "b")
#: The selector-pushing ops whose operands are the router's method selectors.
_PUSH_OPS = ("pushbytess", "pushbytes")


def _dispatch_methods(line: str, method_table: "dict | None"):
    """The ordered list of :class:`AbiMethod` (or ``None`` per slot) a selector-
    pushing router line declares — from its ``// method "sig"`` comments, or, when
    those were stripped, from resolving the line's ``0x``-selector operands through
    ``method_table`` (an ARC-56 spec). ``[]`` if the line pushes no selectors."""
    sigs = _METHOD_RE.findall(line)
    if sigs:
        return [parse_signature(s) for s in sigs]
    toks = line.split("//", 1)[0].split()
    if not method_table or not toks or toks[0] not in _PUSH_OPS:
        return []
    hits = [method_table.get(t.lower()) for t in toks[1:] if t.startswith("0x")]
    return hits if any(hits) else []


def method_line_ranges(source: str, method_table: "dict | None" = None):
    """``[(start_line, end_line, AbiMethod), ...]`` — the source-line span each ABI
    method OWNS, from the router's selector→target-label pairing (``match`` /
    ``switch`` positional targets, or a single ``pushbytes SEL // method`` followed
    by a conditional branch). A method's span runs from its entry label to just
    before the next *boundary* label (another method entry or a ``callsub`` target),
    so internal branch blocks stay with the method while shared helper subroutines
    do not. Spans are disjoint; 1-based inclusive. ``[]`` when the source has no
    dispatch info to attribute from — the OPTIONAL enrichment simply contributes
    nothing. Source-text only (no CFG), and conservative: an unrecognised dispatch
    shape yields no attribution rather than a wrong one.

    ``method_table`` (``{selector_hex: AbiMethod}`` from an ARC-56 spec) lets the
    selector→name mapping survive even when the compiler's ``// method "sig"``
    comments were stripped: the ``0x``-selector OPERANDS of the router's push are
    resolved through it. It's the authoritative name source (the source comments,
    when present, are used directly)."""
    lines = source.splitlines()

    label_order = []                       # (line_1based, label) in file order
    for i, ln in enumerate(lines, 1):
        m = _LABEL_DEF_RE.match(ln)
        if m:
            label_order.append((i, m.group(1)))

    boundaries = set()                     # labels that END a preceding method span
    for ln in lines:                       # every callsub target is a subroutine start
        toks = ln.strip().split()
        if len(toks) >= 2 and toks[0] == "callsub":
            boundaries.add(toks[1])

    entry_method = {}                      # target_label -> AbiMethod
    for i, ln in enumerate(lines):
        methods = _dispatch_methods(ln, method_table)   # ordered, aligned w/ targets
        if not methods:
            continue
        for j in range(i, min(i + 8, len(lines))):   # find the dispatch op below
            toks = lines[j].strip().split()
            if not toks:
                continue
            if toks[0] in _DISPATCH_OPS:
                for meth, tgt in zip(methods, toks[1:]):
                    if meth is not None:
                        entry_method.setdefault(tgt, meth)
                        boundaries.add(tgt)
                break
            if len(methods) == 1 and toks[0] in _COND_BRANCH_OPS and len(toks) >= 2:
                if methods[0] is not None:
                    entry_method.setdefault(toks[1], methods[0])
                    boundaries.add(toks[1])
                break

    ranges = []
    ordered = sorted(label_order)          # by line
    for idx, (ln_no, lbl) in enumerate(ordered):
        meth = entry_method.get(lbl)
        if meth is None:
            continue
        end = len(lines)
        for ln2, lbl2 in ordered[idx + 1:]:
            if lbl2 in boundaries:
                end = ln2 - 1
                break
        ranges.append((ln_no, end, meth))
    return ranges


def method_at_line(ranges, line: Optional[int]) -> Optional[AbiMethod]:
    """The :class:`AbiMethod` whose span contains ``line`` (from
    :func:`method_line_ranges`), or ``None``. Spans are disjoint, so the first
    hit is the answer."""
    if line is None:
        return None
    for start, end, meth in ranges:
        if start <= line <= end:
            return meth
    return None
