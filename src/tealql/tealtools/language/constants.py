"""Resolved literal constants per SSAVar output — one ``(file, line, out_idx,
kind, value)`` row per constant a pushing opcode produces (ints as decimal
strings, bytes as canonical ``0x<hex>``).

A file with more than one ``intcblock`` / ``bytecblock`` resolves NOTHING
rather than guessing which one dominates a given ``intc``.
"""
from __future__ import annotations

from typing import Optional

from ..ast import Opcode
from ..ast.literals import (
    NAMED_INT_CONSTANTS, decode_byte_literal, is_recognized_byte_literal,
    is_template_variable, strip_inline_comment, tokenize_operands,
)


def _opname(n) -> str:
    code = n.code or n.node_class or ""
    return code.split(None, 1)[0] if code else ""


def _imms(n) -> str:
    # HAZARD: a tail-recovered opcode's ``.code`` spans to end of line, so it
    # can carry a trailing ``// comment`` — ``int 0x10 // sixteen`` must
    # resolve as ``0x10``, not silently fail on the whole text.
    code = strip_inline_comment(n.code or "")
    parts = code.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


_DIGITS_FOR_BASE = {2: "01", 8: "01234567", 10: "0123456789",
                    16: "0123456789abcdef"}


def _underscore_ok(s: str) -> bool:
    """Go ``strconv.underscoreOK``: a ``_`` may only follow a digit or a base
    prefix and must be followed by a digit (``1_0``, ``0x_10``, ``0_7`` yes;
    ``_1``, ``1_``, ``1__0`` no)."""
    saw = "^"
    i = 0
    is_hex = False
    if len(s) >= 2 and s[0] == "0" and s[1].lower() in "box":
        i, saw, is_hex = 2, "0", s[1].lower() == "x"
    while i < len(s):
        c = s[i].lower()
        if c.isdigit() or (is_hex and c in "abcdef"):
            saw = "0"
        elif c == "_":
            if saw != "0":
                return False
            saw = "_"
        else:
            if saw == "_":
                return False
            saw = "!"
        i += 1
    return saw != "_"


def _to_int(tok: str) -> Optional[int]:
    """Parse an integer literal exactly as the assembler does —
    ``strconv.ParseUint(s, 0, 64)`` — or ``None`` where it would reject.

    Base is implied by the prefix (``0x`` / ``0o`` / ``0b``, either case) and a
    bare leading ``0`` means OCTAL: ``int 010`` is 8, verified against ``goal``
    (``intcblock 1 16 7 8`` for ``1 0x10 07 010``). No sign, ``_`` only between
    digits or after the prefix, and the value must fit in 64 bits; ``08``,
    ``-1``, ``2**64``, ``1__0`` are all assembler errors. A decimal-first
    ``int()`` read ``010`` as 10 and accepted every one of those — a wrong or
    fabricated constant on which every downstream comparison then relied.
    No named constants here."""
    tok = tok.strip()
    if not tok or tok[0] in "+-" or not _underscore_ok(tok):
        return None
    base, body = 10, tok
    if len(tok) >= 2 and tok[0] == "0":
        prefix = tok[1].lower()
        if prefix in "xob":
            base, body = {"x": 16, "o": 8, "b": 2}[prefix], tok[2:]
        else:
            base, body = 8, tok[1:]
    body = body.replace("_", "").lower()
    if not body or any(c not in _DIGITS_FOR_BASE[base] for c in body):
        return None
    value = int(body, base)
    return value if value < (1 << 64) else None


def _resolve_int_immediate(tok: str) -> Optional[int]:
    """An ``int`` immediate: a numeric literal OR a named AVM constant
    (``DeleteApplication`` -> 5); a template variable has no static value -> ``None``."""
    v = _to_int(tok)
    if v is not None:
        return v
    return NAMED_INT_CONSTANTS.get(tok.strip())


def _split_int_tokens(imms: str) -> list[str]:
    return imms.split()


def _split_byte_literals(imms: str) -> list[str]:
    """Split a ``bytecblock``/``pushbytess`` literal list into one raw-text token
    per literal (``b64 <data>`` folded into one)."""
    return tokenize_operands(imms, fold_byte_keywords=True)


def _canonical_bytes(literal: str) -> "str | None":
    """A bytes literal as canonical ``0x<hex>``, or ``None`` if undecodable.

    ONE representation per value: consumers compare these for equality (xcontract
    matches state keys, ``_bytes_const_to_int`` accepts only ``0x``), so raw source
    text would make ``byte "cfg"`` and ``pushbytes "cfg"`` silently unequal.

    HAZARD: only recognised literal shapes resolve. The decoder's utf-8
    fallback for a bare token (``pushbytes TMPL_X``) fabricates a constant —
    the token's own text — that every downstream comparison then trusts."""
    literal = literal.strip()
    if not is_recognized_byte_literal(literal):
        return None
    try:
        raw, _kind = decode_byte_literal(literal)
    except Exception:
        return None
    return f"0x{raw.hex()}"


def _resolvable_byte_literal(tok) -> bool:
    """False for a const-block slot holding a deployment TEMPLATE.

    HAZARD: a template has no value until deploy — emitting its raw text as a
    bytes constant fabricates a value every downstream comparison then trusts."""
    return tok is not None and not is_template_variable(tok)


def compute_const_values(g) -> list[tuple]:
    """Resolved-constant rows ``(file, line, out_idx, kind, value)`` from the
    loaded graph's AST nodes."""
    opcodes = [n for n in g.nodes if isinstance(n, Opcode)]

    # HAZARD: constant blocks are PER FILE — `intc_1` resolves against its OWN
    # file's table. Pooling across the graph (a directory target is approval +
    # clear) resolves one file's `intc` against another's table: a silently
    # WRONG constant.
    intc_by_file: dict[str, Optional[list]] = {}
    bytec_by_file: dict[str, Optional[list]] = {}
    _intcblocks: dict[str, list] = {}
    _bytecblocks: dict[str, list] = {}
    for n in opcodes:
        op = _opname(n)
        if op == "intcblock":
            _intcblocks.setdefault(n.location.file, []).append(n)
        elif op == "bytecblock":
            _bytecblocks.setdefault(n.location.file, []).append(n)
    for f_, blocks in _intcblocks.items():
        intc_by_file[f_] = (
            [_to_int(t) for t in _split_int_tokens(_imms(blocks[0]))]
            if len(blocks) == 1 else None
        )
    for f_, blocks in _bytecblocks.items():
        bytec_by_file[f_] = (
            _split_byte_literals(_imms(blocks[0])) if len(blocks) == 1 else None
        )

    rows: list[tuple] = []
    for n in opcodes:
        op = _opname(n)
        f = n.location.file
        ln = n.location.start_line
        intc_vals: Optional[list] = intc_by_file.get(f)
        bytec_vals: Optional[list] = bytec_by_file.get(f)

        if op in ("int", "pushint"):
            v = _resolve_int_immediate(_imms(n))
            if v is not None:
                rows.append((f, ln, 1, "int", str(v)))

        elif op == "intc":
            idx = _to_int(_imms(n))
            if (idx is not None and intc_vals is not None
                    and 0 <= idx < len(intc_vals)
                    and intc_vals[idx] is not None):
                rows.append((f, ln, 1, "int", str(intc_vals[idx])))

        elif op in ("intc_0", "intc_1", "intc_2", "intc_3"):
            idx = int(op[-1])
            if (intc_vals is not None and idx < len(intc_vals)
                    and intc_vals[idx] is not None):
                rows.append((f, ln, 1, "int", str(intc_vals[idx])))

        elif op == "pushbytes":
            # exactly one byte literal — the whole immediate text.
            imm = _canonical_bytes(_imms(n)) if _imms(n) else None
            if imm:
                rows.append((f, ln, 1, "bytes", imm))

        elif op == "bytec":
            idx = _to_int(_imms(n))
            if (idx is not None and bytec_vals is not None
                    and 0 <= idx < len(bytec_vals)
                    and _resolvable_byte_literal(bytec_vals[idx])
                    and (_cb := _canonical_bytes(bytec_vals[idx])) is not None):
                rows.append((f, ln, 1, "bytes", _cb))

        elif op in ("bytec_0", "bytec_1", "bytec_2", "bytec_3"):
            idx = int(op[-1])
            if (bytec_vals is not None and idx < len(bytec_vals)
                    and _resolvable_byte_literal(bytec_vals[idx])
                    and (_cb := _canonical_bytes(bytec_vals[idx])) is not None):
                rows.append((f, ln, 1, "bytes", _cb))

        elif op == "pushints":
            # HAZARD: the LAST token is pushed last and so is the TOP output,
            # and ``output_index 1`` is the TOPMOST value (models.py). Number
            # the tokens back-to-front: token i (0-based) → out_idx ``N - i``.
            toks = _split_int_tokens(_imms(n))
            for i, tok in enumerate(toks):
                v = _to_int(tok)
                if v is not None:
                    rows.append((f, ln, len(toks) - i, "int", str(v)))

        elif op == "pushbytess":
            toks = _split_byte_literals(_imms(n))
            for i, tok in enumerate(toks):
                cb = _canonical_bytes(tok)
                if cb is not None:
                    rows.append((f, ln, len(toks) - i, "bytes", cb))

    return rows
