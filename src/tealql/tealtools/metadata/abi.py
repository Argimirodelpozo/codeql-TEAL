"""ABI method-table recovery from HIGH-LEVEL info in the source.

HAZARD: a method selector is ``sha512_256("name(args)ret")[:4]`` — a hash, NOT
invertible. The signature is READ from source text (``method "sig"`` pseudo-ops,
and the ``// method "sig"`` comments a compiler leaves on the lowered
``pushbytes`` / ``pushbytess`` selector) and its selector computed FORWARD;
nothing is ever reverse-engineered from the selector.

An optional enrichment: raw disassembled bytecode carries no ``method "…"``
text, so :func:`extract_method_table` returns ``{}`` and consumers degrade to
their no-high-level-info behaviour. When present it is the SOUND source for ABI
arg typing, buffer-length seeding, box/state schema and finding messages.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from ..language.avm import COND_BRANCH_OPS

# Matches both forms — the pseudo-op operand and the compiler's trailing
# `// method "..."` comment — so one scan over the raw source finds all.
_METHOD_RE = re.compile(r'method\s+"([^"]+)"')

#: ARC-4 TRANSACTION arg types — passed as preceding GROUP txns, so they carry NO
#: ApplicationArgs bytes and SHIFT the ApplicationArgs index of the args after them.
TXN_ARG_TYPES = frozenset({
    "txn", "pay", "keyreg", "acfg", "axfer", "afrz", "appl",
})
#: ARC-4 REFERENCE arg types — a uint8 index into the txn's foreign array, so they
#: DO occupy one ApplicationArgs byte (unlike transaction args).
REFERENCE_ARG_TYPES = frozenset({"account", "asset", "application"})


@dataclass(frozen=True)
class AbiMethod:
    """One ARC-4 ABI method recovered from a ``name(arg,arg,...)ret`` signature."""

    name: str
    arg_types: tuple            # ABI type strings, in declaration order
    return_type: str            # "void" or an ABI type
    signature: str              # the canonical signature text
    selector: bytes             # sha512_256(signature)[:4]
    # Declaration order; only a richer source (an ARC-56 spec) carries names, so
    # empty for signatures recovered from bare `method "sig"` text.
    arg_names: tuple = ()

    @property
    def selector_hex(self) -> str:
        """``0x``-prefixed 4-byte selector, matching a ``pushbytes 0x..`` operand."""
        return "0x" + self.selector.hex()

    @property
    def app_arg_types(self) -> tuple:
        """The arg types carried in ``ApplicationArgs``, in order — transaction-type
        args are dropped, since they ride as group txns rather than encoded bytes.

        HAZARD: ``ApplicationArgs[k]`` (1-based) is ``app_arg_types[k-1]``, except
        that ARC-4 packs the 16th-onward encoded args into a tuple at index 15."""
        return tuple(a for a in self.arg_types if a not in TXN_ARG_TYPES)

    def app_arg_byte_length(self, n: int) -> Optional[int]:
        """The ARC-4 encoded byte length of ``txna ApplicationArgs n`` (``n`` >= 1,
        the selector being index 0), or ``None`` when unknown / dynamic / the packed
        15th slot.

        HAZARD: this is the WELL-FORMED-ABI length — the AVM router checks only the
        selector, never arg lengths, so a consumer must treat it as a speculative
        assumption, not a proven bound."""
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
    """Split ``s`` on top-level commas, respecting nested ``()`` / ``[]`` so a tuple
    or array element with its own commas stays one item."""
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
    """Parse ``name(arg,arg,...)ret`` into an :class:`AbiMethod`, or ``None`` if
    malformed — the arg list is delimited by BALANCING the first ``(``, not by the
    last ``)``, since the return type may itself be a tuple."""
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
    """The ARC-4 ENCODED byte length of a fixed-size type, or ``None`` when dynamic
    (``string`` / ``byte[]`` / ``T[]``) or a TRANSACTION type (rides as a group txn,
    no encoded bytes); REFERENCE types encode as a ``uint8`` index -> 1 byte.

    HAZARD: consecutive ``bool`` are BIT-PACKED in ARC-4 (tuples/arrays account for
    that). Never returns a wrong length — only an exact one or ``None``."""
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
    """``{selector_hex: AbiMethod}`` for every ``method "sig"`` in ``source``, keyed
    by ``0x``-selector so a ``pushbytes 0x..`` operand maps straight to its method;
    ``{}`` when the source carries no high-level ABI info."""
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
#: Single-selector branch: ``pushbytes SEL // method "sig"``, ``==``, then one of
#: these — the two-way conditionals (from the avm spec set) plus the plain jump.
_SELECTOR_BRANCH_OPS = COND_BRANCH_OPS | {"b"}
#: The selector-pushing ops whose operands are the router's method selectors.
_PUSH_OPS = ("pushbytess", "pushbytes")


def _dispatch_methods(line: str, method_table: "dict | None"):
    """The ORDERED :class:`AbiMethod` list (``None`` per unresolved slot) a
    selector-pushing router line declares — from its ``// method "sig"`` comments,
    else by resolving its ``0x`` operands through ``method_table``; order matters,
    the dispatch op's targets pair with it positionally."""
    sigs = _METHOD_RE.findall(line)
    if sigs:
        return [parse_signature(s) for s in sigs]
    # The assembler's tokenizer, not `split("//")`: a `//` inside a base64
    # selector payload is data, and a comment glued to the last operand is not.
    from ..ast.literals import tokenize_operands
    toks = tokenize_operands(line)
    if not method_table or not toks or toks[0] not in _PUSH_OPS:
        return []
    hits = [method_table.get(t.lower()) for t in toks[1:] if t.startswith("0x")]
    return hits if any(hits) else []


_BRANCH_OPS = frozenset(COND_BRANCH_OPS | {"b", "match", "switch", "callsub"})


def method_line_ranges(source: str, method_table: "dict | None" = None):
    """``[(start_line, end_line, AbiMethod), ...]`` — the disjoint, 1-based-inclusive
    source-line spans each ABI method OWNS.

    A method's span runs from its router-dispatched entry label to just before
    the next *boundary* label: another method entry, a label the router prologue
    itself branches to (Puya's bare-create / fall-through arms, which share no
    method), or a subroutine start (any ``callsub`` target). A subroutine called
    from exactly ONE method's span is then attributed to that method too, and
    so on transitively — a PuyaPy/TEALScript method body lives in a ``callsub``
    target behind a thin route arm, and the sinks a finding points at are in
    that body. A subroutine called from several methods (a shared helper) stays
    unattributed.

    Source-text only (no CFG) and conservative: an unrecognised dispatch shape
    yields NO attribution rather than a wrong one, and ``[]`` when the source has
    no dispatch info. ``method_table`` (from an ARC-56 spec) keeps the
    selector→name mapping alive when the ``// method "sig"`` comments were
    stripped, by resolving the router's ``0x``-selector operands."""
    lines = source.splitlines()

    label_order = []                       # (line_1based, label) in file order
    for i, ln in enumerate(lines, 1):
        m = _LABEL_DEF_RE.match(ln)
        if m:
            label_order.append((i, m.group(1)))

    def _toks(ln: str) -> list:
        return ln.split("//", 1)[0].strip().split()

    boundaries = set()                     # labels that END a preceding method span
    sub_callers: dict[str, list[int]] = {}  # callsub target -> call-site lines
    for i, ln in enumerate(lines, 1):      # every callsub target is a subroutine start
        toks = _toks(ln)
        if len(toks) >= 2 and toks[0] == "callsub":
            boundaries.add(toks[1])
            sub_callers.setdefault(toks[1], []).append(i)

    entry_method = {}                      # target_label -> AbiMethod
    first_dispatch = None                  # line of the first router dispatch op
    for i, ln in enumerate(lines):
        methods = _dispatch_methods(ln, method_table)   # ordered, aligned w/ targets
        if not methods:
            continue
        for j in range(i, min(i + 8, len(lines))):   # find the dispatch op below
            toks = _toks(lines[j])
            if not toks:
                continue
            if toks[0] in _DISPATCH_OPS:
                for meth, tgt in zip(methods, toks[1:]):
                    if meth is not None:
                        entry_method.setdefault(tgt, meth)
                        boundaries.add(tgt)
                if first_dispatch is None:
                    first_dispatch = j + 1
                break
            if len(methods) == 1 and toks[0] in _SELECTOR_BRANCH_OPS and len(toks) >= 2:
                if methods[0] is not None:
                    entry_method.setdefault(toks[1], methods[0])
                    boundaries.add(toks[1])
                if first_dispatch is None:
                    first_dispatch = j + 1
                break
    if not entry_method:
        return []

    # Labels the router PROLOGUE (everything before the first dispatch) branches
    # to are routing arms of their own — bare-create handlers, "no args"
    # fall-throughs — never part of the method dispatched next to them.
    if first_dispatch is not None:
        for ln in lines[:first_dispatch]:
            toks = _toks(ln)
            if toks and toks[0] in _BRANCH_OPS:
                boundaries.update(toks[1:])

    ordered = sorted(label_order)          # by line
    span_of: dict[str, tuple[int, int]] = {}
    for idx, (ln_no, lbl) in enumerate(ordered):
        if lbl not in boundaries and lbl not in entry_method:
            continue
        end = len(lines)
        for ln2, lbl2 in ordered[idx + 1:]:
            if lbl2 in boundaries:
                end = ln2 - 1
                break
        span_of[lbl] = (ln_no, end)

    ranges = [(span_of[lbl][0], span_of[lbl][1], meth)
              for lbl, meth in entry_method.items() if lbl in span_of]

    # Unique-caller closure: a subroutine whose every call site lies in ONE
    # method's attributed spans belongs to that method; iterate to a fixpoint so
    # helpers of helpers follow.
    owner: dict[str, AbiMethod] = {lbl: m for lbl, m in entry_method.items()}
    changed = True
    while changed:
        changed = False
        for sub, sites in sub_callers.items():
            if sub in owner or sub not in span_of:
                continue
            owners = set()
            for site in sites:
                hit = None
                for lbl, (lo, hi) in span_of.items():
                    if lbl in owner and lo <= site <= hi:
                        hit = owner[lbl]
                        break
                if hit is None:
                    owners = None
                    break
                owners.add(hit)
            if owners and len(owners) == 1:
                owner[sub] = next(iter(owners))
                ranges.append((span_of[sub][0], span_of[sub][1], owner[sub]))
                changed = True
    ranges.sort()
    return ranges


def method_at_line(ranges, line: Optional[int]) -> Optional[AbiMethod]:
    """The :class:`AbiMethod` from :func:`method_line_ranges` whose span contains
    ``line``, or ``None``; spans are disjoint, so the first hit is the answer."""
    if line is None:
        return None
    for start, end, meth in ranges:
        if start <= line <= end:
            return meth
    return None


def method_at_line_or_partition(ranges, line: Optional[int], *, partitions=None,
                                file: Optional[str] = None) -> Optional[AbiMethod]:
    """:func:`method_at_line`, falling back — only when the source-line spans
    find nothing — to trace partitioning
    (:meth:`.cfg.partition.PartitionedPredicates.method_at`): the finding's
    block is attributed only when exactly ONE method partition reaches it."""
    hit = method_at_line(ranges, line)
    if hit is not None or partitions is None or file is None:
        return hit
    return partitions.method_at(file, line)
