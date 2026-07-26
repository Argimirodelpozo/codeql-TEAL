"""Resolved literal constants per SSAVar output, for the
constant-pushing opcodes.

Emits one ``(file, line, out_idx, kind, value)`` row per produced
constant:

  - ``int`` / ``pushint``     → out_idx=1, kind="int", value via
    ``_resolve_int_immediate`` — decimal, ``0x`` / ``0o`` / ``0b``
    literals (``int 0x10`` → 16), AND named constants (``int pay`` →
    1, from ``NAMED_INT_CONSTANTS``). Only genuinely unresolvable text
    yields no row.
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
from .ast.literals import (
    NAMED_INT_CONSTANTS, is_template_variable, tokenize_operands,
)


def _opname(n) -> str:
    code = n.code or n.node_class or ""
    return code.split(None, 1)[0] if code else ""


def _imms(n) -> str:
    code = n.code or ""
    parts = code.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def _to_int(tok: str) -> Optional[int]:
    """Parse an integer literal — decimal, or a ``0x`` / ``0o`` / ``0b`` prefixed
    literal (all accepted by ``goal`` / puya, e.g. ``int 0x10``). No named
    constants. Decimal is tried first so leading-zero decimals still parse (``int``
    with base 0 would reject them)."""
    tok = tok.strip()
    try:
        return int(tok)
    except (ValueError, TypeError):
        pass
    try:
        return int(tok, 0)              # 0x.. / 0o.. / 0b.. prefixed
    except (ValueError, TypeError):
        return None


def _resolve_int_immediate(tok: str) -> Optional[int]:
    """An ``int`` immediate: a decimal / ``0x`` / ``0o`` / ``0b`` literal OR a
    named AVM constant (``DeleteApplication`` -> 5, ``pay`` -> 1). Template
    variables still yield ``None`` (no statically-known value)."""
    v = _to_int(tok)
    if v is not None:
        return v
    return NAMED_INT_CONSTANTS.get(tok.strip())


def _split_int_tokens(imms: str) -> list[str]:
    return imms.split()


def _split_byte_literals(imms: str) -> list[str]:
    """Split a ``bytecblock``/``pushbytess`` literal list into one raw-text
    token per literal (``b64 <data>`` folded into one). Thin alias over the
    canonical :func:`tealql.tealtools.ast.literals.tokenize_operands`."""
    return tokenize_operands(imms, fold_byte_keywords=True)


def _resolvable_byte_literal(tok) -> bool:
    """A const-block slot holding a deployment TEMPLATE has no value until the
    app is deployed, so it must resolve to NOTHING. Emitting the raw text as a
    bytes constant would be a fabricated value every downstream comparison then
    trusts."""
    return tok is not None and not is_template_variable(tok)


def compute_const_values(g) -> list[tuple]:
    """Return resolved-constant rows as ``(file, line, out_idx, kind,
    value)`` tuples, computed from the loaded graph's AST nodes."""
    opcodes = [n for n in g.nodes if isinstance(n, Opcode)]

    # Constant blocks are PER FILE: each program carries its own intcblock /
    # bytecblock, and `intc_1` resolves against its OWN file's table. Pooling
    # them across the whole graph (the documented directory target is approval
    # + clear) meant two files each with a block resolved NOTHING in either,
    # and one block plus two files resolved the second file's `intc` against
    # the first file's table — a silently WRONG constant.
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
            imm = _imms(n)
            if imm:
                rows.append((f, ln, 1, "bytes", imm))

        elif op == "bytec":
            idx = _to_int(_imms(n))
            if (idx is not None and bytec_vals is not None
                    and 0 <= idx < len(bytec_vals)
                    and _resolvable_byte_literal(bytec_vals[idx])):
                rows.append((f, ln, 1, "bytes", bytec_vals[idx]))

        elif op in ("bytec_0", "bytec_1", "bytec_2", "bytec_3"):
            idx = int(op[-1])
            if (bytec_vals is not None and idx < len(bytec_vals)
                    and _resolvable_byte_literal(bytec_vals[idx])):
                rows.append((f, ln, 1, "bytes", bytec_vals[idx]))

        elif op == "pushints":
            # A multi-push emits N stack values; the LAST token is pushed last
            # and so is the TOP output — and the stack convention is that
            # ``output_index 1`` is the topmost value (see models.py). So number
            # the tokens back-to-front: token i (0-based) → out_idx ``N - i``.
            toks = _split_int_tokens(_imms(n))
            for i, tok in enumerate(toks):
                v = _to_int(tok)
                if v is not None:
                    rows.append((f, ln, len(toks) - i, "int", str(v)))

        elif op == "pushbytess":
            toks = _split_byte_literals(_imms(n))
            for i, tok in enumerate(toks):
                rows.append((f, ln, len(toks) - i, "bytes", tok))

    return rows
