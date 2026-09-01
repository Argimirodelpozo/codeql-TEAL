"""TEAL literal + operand parsing over raw opcode text — no IR / puya dependency."""
from __future__ import annotations

import re


#: A deployment template variable: ALL-CAPS ``PREFIX_NAME`` (``TMPL_DELETABLE``).
#: Not keyed on the literal ``TMPL_`` — that is only algokit's default prefix and
#: puya lets a contract choose its own (``PRFX_``), so a prefix test misses real ones.
_TEMPLATE_VAR_RE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")


def render_byte_constant(value: str) -> str:
    """Render a stored ``0x<hex>`` constant as ``"text"`` when it is printable ASCII.

    HAZARD: display ONLY. Bytes constants are stored canonically as ``0x<hex>`` so
    that two spellings of one value compare equal (``byte "hi"`` vs
    ``pushbytes "hi"``); feeding this output back into a comparison breaks that."""
    if not (isinstance(value, str) and value.startswith("0x")):
        return value
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError:
        return value
    if raw and all(0x20 <= c < 0x7F for c in raw):
        return '"' + raw.decode("ascii") + '"'
    return value


def is_template_variable(token: str) -> bool:
    """``token`` is a deployment template variable — no value until the app is deployed.

    HAZARD: callers must resolve such a token to NOTHING; emitting its text as a
    constant fabricates a value every downstream comparison then trusts."""
    return bool(token) and _TEMPLATE_VAR_RE.match(token.strip()) is not None


# `int` pseudo-op named constants — the OnCompletion / TxnType (TypeEnum) enums.
# HAZARD: the grammar's `int` rule accepts only a number, so `int DeleteApplication`
# parses as an ERROR node; parse.py recovers it and THIS table is where its
# const_value comes from. Derived from avm.TXN_ENUM_FIELD_NAMES, never re-listed —
# a second hand-kept copy would silently disagree about which guards resolve.
def _named_int_constants() -> dict[str, int]:
    from ..language.avm import TXN_ENUM_FIELD_NAMES

    out: dict[str, int] = {}
    for by_value in TXN_ENUM_FIELD_NAMES.values():
        for value, name in by_value.items():
            out.setdefault(name, value)
    return out


NAMED_INT_CONSTANTS: dict[str, int] = _named_int_constants()


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _teal_str_bytes(s: str) -> bytes:
    r"""Decode a TEAL ``byte "..."`` string body (handles \\ \" \n \r \t \xNN).

    HAZARD: non-ASCII encodes as UTF-8, matching the assembler — a per-character
    ``ord(c)`` decoder turns ``byte "café"`` into ``636166e9`` instead of the real
    ``636166c3a9`` and every comparison against it mis-evaluates. A malformed escape
    is emitted LITERALLY, never raised — this runs on untrusted source.
    """
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                # BOTH hex digits must be present and valid; a truncated `\x4`
                # is malformed, not 0x04.
                if i + 4 <= len(s) and set(s[i + 2:i + 4]) <= _HEX_DIGITS:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                out.extend(c.encode("utf-8"))      # malformed -> literal
                i += 1
                continue
            known = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34}.get(n)
            if known is not None:
                out.append(known)
            else:
                # Unknown escape: the escaped character itself, UTF-8 encoded —
                # ``ord`` would raise for a non-Latin-1 char, breaking the
                # never-raise contract, and mis-encode 128..255.
                out.extend(n.encode("utf-8"))
            i += 2
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    return bytes(out)


# TEAL omits `=` padding (an address is 52 chars), so both decoders re-pad first.
def _b64(s: str) -> bytes:
    import base64
    return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4))


def _b32(s: str) -> bytes:
    import base64
    return base64.b32decode(s.strip() + "=" * (-len(s.strip()) % 8))


def decode_byte_literal(v: str) -> tuple[bytes, str]:
    """Parse a TEAL byte literal -> ``(raw bytes, kind)``, kind being one of
    ``base16`` / ``utf8`` / ``base64`` / ``base32``.

    HAZARD: a malformed ``0x`` / ``b64`` / ``b32`` body RAISES (callers must catch),
    whereas an unrecognised bare token falls back SILENTLY to its utf-8 bytes."""
    v = v.strip()
    if v.startswith("0x"):
        return bytes.fromhex(v[2:]), "base16"
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _teal_str_bytes(v[1:-1]), "utf8"
    # All four spellings the assembler accepts per encoding: `b64 X`, `base64 X`,
    # `b64(X)`, `base64(X)`. A missed one does not fail — it falls through to the
    # utf-8 fallback and decodes to the literal text `b64(X)`, which a guard trusts.
    for kws, dec, kind in ((("b64", "base64"), _b64, "base64"),
                           (("b32", "base32"), _b32, "base32")):
        for kw in kws:
            if v.startswith(f"{kw} "):
                return dec(v.split(None, 1)[1]), kind
            if v.startswith(f"{kw}(") and v.endswith(")"):
                return dec(v[len(kw) + 1:-1]), kind
    try:
        return bytes.fromhex(v), "base16"
    except ValueError:
        return v.encode("utf-8"), "utf8"


# byte-encoding keywords that take a following data token (``b64 AAAA``).
_BYTE_ENC_KW = frozenset({"b64", "base64", "b32", "base32"})


def is_recognized_byte_literal(v: str) -> bool:
    """``v`` is one of the byte-literal spellings the assembler accepts
    (``0x..`` / ``"str"`` / ``b64|base64|b32|base32`` keyword or paren forms).

    A BARE token (a ``TMPL_*`` deployment template, a stray identifier) is NOT
    one: resolving it through :func:`decode_byte_literal`'s utf-8 fallback
    fabricates a constant — the text of the token — that every downstream
    comparison then trusts."""
    v = v.strip()
    if v.startswith("0x") or (len(v) >= 2 and v[0] == '"' and v[-1] == '"'):
        return True
    for kw in ("b64", "base64", "b32", "base32"):
        if v.startswith(f"{kw} ") or (v.startswith(f"{kw}(") and v.endswith(")")):
            return True
    return False


def quote_is_escaped(text: str, index: int) -> bool:
    """A quote at ``index`` is escaped iff an ODD run of backslashes precedes it.

    Looking only at the immediately preceding character mistakes the closing
    quote in ``"a\\\\"`` for an escaped quote: the first backslash escapes the
    second, so the quote actually terminates the literal.  Once quote state is
    wrong, operands merge and every constant index after them shifts."""
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def strip_inline_comment(code: str) -> str:
    """Drop a ``//`` inline comment that sits outside a quoted string, outside a
    parenthesised group, and at a TOKEN BOUNDARY.

    The token-boundary rule is what go-algorand does: split on whitespace, then
    ask whether a token STARTS with ``//``, so ``int 1// x`` is not a comment at
    all.  Quote state honors escaped quotes (see :func:`quote_is_escaped`), so a
    ``//`` inside ``byte "a//b"`` is data, not a comment."""
    q = False
    depth = 0
    for i in range(len(code) - 1):
        c = code[i]
        if c == '"' and not quote_is_escaped(code, i):
            q = not q
        elif q:
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif (depth == 0 and code[i:i + 2] == "//"
                and (i == 0 or code[i - 1].isspace())):
            return code[:i]
    return code


def tokenize_operands(text: str, *, fold_byte_keywords: bool = False) -> list:
    """Split the text after an opcode into tokens, honoring ``"quoted strings"``,
    parenthesised ``base64(..)`` groups and a between-token ``//`` comment.

    HAZARD: a ``bytecblock`` / ``intcblock`` literal list needs
    ``fold_byte_keywords=True`` — without it ``b64 AAAA`` splits into two tokens and
    every constant index after it shifts."""
    toks: list = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if text[i:i + 2] == "//":            # inline comment (between operands)
            break
        if c == '"':
            j = i + 1
            while j < n and not (text[j] == '"'
                                 and not quote_is_escaped(text, j)):
                j += 1
            toks.append(text[i:j + 1])
            i = j + 1
            continue
        j, depth = i, 0
        while j < n and (depth > 0 or not text[j].isspace()):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        tok = text[i:j]
        i = j
        if fold_byte_keywords and tok in _BYTE_ENC_KW:
            k = i
            while k < n and text[k].isspace():
                k += 1
            m = k
            while m < n and not text[m].isspace():
                m += 1
            if m > k:
                toks.append(tok + " " + text[k:m])
                i = m
                continue
        toks.append(tok)
    return toks
