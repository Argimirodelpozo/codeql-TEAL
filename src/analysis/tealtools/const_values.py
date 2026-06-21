"""Resolved literal constants per SSAVar output, for the
constant-pushing opcodes.

Emits one ``(file, line, out_idx, kind, value)`` row per produced
constant:

  - ``int`` / ``pushint``     → out_idx=1, kind="int", decimal value.
    Named constants (``int pay``) yield NO row: decimal-only parsing
    has no result on non-numeric / non-decimal text (so ``int 0x10``
    is also dropped).
  - ``intc`` / ``intc_0..3``  → out_idx=1, kind="int", value from the
    single ``intcblock`` at the given index.
  - ``pushbytes``             → out_idx=1, kind="bytes", raw literal text.
  - ``bytec`` / ``bytec_0..3``→ out_idx=1, kind="bytes", raw literal text
    from the single ``bytecblock`` at the given index.
  - ``pushints``              → out_idx=1..N, kind="int".
  - ``pushbytess``            → out_idx=1..N, kind="bytes", raw literal text.

Value forms: ints are decimal strings; bytes are the raw source token
text (``0xdeadbeef``, ``"hello"``, ``b64 AAAA``) — NOT decoded bytes.

``intc``/``bytec`` resolution assumes there's only one block; we
implement the single-block case and rely on the differential parity
test to flag any multi-block fixture that would need real dominance.
"""
from __future__ import annotations

from typing import Optional

from .ast import Opcode

_BYTE_ENC_KW = frozenset({"b64", "base64", "b32", "base32"})


def _opname(n) -> str:
    code = n.code or n.node_class or ""
    return code.split(None, 1)[0] if code else ""


def _imms(n) -> str:
    code = n.code or ""
    parts = code.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def _to_int(tok: str) -> Optional[int]:
    """Decimal-only int parse (no ``0x``, no named constants)."""
    try:
        return int(tok)
    except (ValueError, TypeError):
        return None


def _split_int_tokens(imms: str) -> list[str]:
    return imms.split()


def _split_byte_literals(imms: str) -> list[str]:
    """Split a whitespace-separated list of TEAL byte literals into one
    string per literal, preserving the raw source text of each.

    Handles: ``0x..`` / ``base64(..)`` (single token), ``"..."`` quoted
    strings (may contain spaces / ``\\"`` escapes), and the two-token
    ``b64 <data>`` / ``base64 <data>`` / ``b32 <data>`` / ``base32 <data>``
    forms (joined into one literal).
    """
    out: list[str] = []
    i, n = 0, len(imms)
    while i < n:
        c = imms[i]
        if c.isspace():
            i += 1
            continue
        if c == '"':
            j = i + 1
            while j < n and imms[j] != '"':
                if imms[j] == "\\":
                    j += 1
                j += 1
            out.append(imms[i:min(j + 1, n)])
            i = j + 1
            continue
        # bare token
        j = i
        while j < n and not imms[j].isspace():
            j += 1
        tok = imms[i:j]
        i = j
        # ``b64 <data>`` style: keyword followed by its data token.
        if tok in _BYTE_ENC_KW:
            k = i
            while k < n and imms[k].isspace():
                k += 1
            m = k
            while m < n and not imms[m].isspace():
                m += 1
            if m > k:
                out.append(tok + " " + imms[k:m])
                i = m
                continue
        out.append(tok)
    return out


def compute_const_values(g) -> list[tuple]:
    """Return resolved-constant rows as ``(file, line, out_idx, kind,
    value)`` tuples, computed from the loaded graph's AST nodes."""
    opcodes = [n for n in g.nodes if isinstance(n, Opcode)]

    intcblocks = [n for n in opcodes if _opname(n) == "intcblock"]
    bytecblocks = [n for n in opcodes if _opname(n) == "bytecblock"]
    intc_vals: Optional[list] = (
        [_to_int(t) for t in _split_int_tokens(_imms(intcblocks[0]))]
        if len(intcblocks) == 1 else None
    )
    bytec_vals: Optional[list] = (
        _split_byte_literals(_imms(bytecblocks[0]))
        if len(bytecblocks) == 1 else None
    )

    rows: list[tuple] = []
    for n in opcodes:
        op = _opname(n)
        f = n.location.file
        ln = n.location.start_line

        if op in ("int", "pushint"):
            v = _to_int(_imms(n))
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
            imm = _imms(n)
            if imm:
                rows.append((f, ln, 1, "bytes", imm))

        elif op == "bytec":
            idx = _to_int(_imms(n))
            if (idx is not None and bytec_vals is not None
                    and 0 <= idx < len(bytec_vals)):
                rows.append((f, ln, 1, "bytes", bytec_vals[idx]))

        elif op in ("bytec_0", "bytec_1", "bytec_2", "bytec_3"):
            idx = int(op[-1])
            if bytec_vals is not None and idx < len(bytec_vals):
                rows.append((f, ln, 1, "bytes", bytec_vals[idx]))

        elif op == "pushints":
            for i, tok in enumerate(_split_int_tokens(_imms(n))):
                v = _to_int(tok)
                if v is not None:
                    rows.append((f, ln, i + 1, "int", str(v)))

        elif op == "pushbytess":
            for i, tok in enumerate(_split_byte_literals(_imms(n))):
                rows.append((f, ln, i + 1, "bytes", tok))

    return rows
