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


#: go-algorand ``tokenSeparators``: blank, tab and ``;`` (the multi-op separator,
#: which is itself a token). Other whitespace is added only because a caller may
#: hand us a line still carrying its ``\r`` / ``\n`` — Go's line reader never does.
_TOKEN_SEPARATORS = frozenset(" \t;\r\n\f\v")
_BASE64_KEYWORDS = frozenset({"b64", "base64"})


def _is_separator(c: str) -> bool:
    return c in _TOKEN_SEPARATORS


def scan_line(text: str) -> "tuple[list[tuple[int, int]], int]":
    """Tokenize one TEAL source line exactly as go-algorand's assembler does
    (``assembler.go: tokensFromLine``) -> ``(token spans, comment start)``, the
    spans being ``(start, end)`` half-open indexes into ``text`` and the comment
    start the index of the ``//`` that ends the code (``-1`` when there is none).

    This is THE comment/tokenizer rule; every ``//`` decision in the parse floor
    must route through it, because the assembler's is not a "token-boundary"
    rule and every home-grown approximation drifted from it in a way that
    changed a constant:

    * ``//`` starts a comment ANYWHERE it is not inside a string or a base64
      payload — glued to a token too: ``byte "a"//c`` pushes ``"a"`` and
      ``method "x()void"//c`` hashes ``x()void`` (a tokenizer that kept the
      ``//c`` hashed a WRONG selector, silently).
    * ``inBase64`` — set after a bare ``b64`` / ``base64`` keyword token or on
      ``b64(`` / ``base64(``, cleared at the next separator or ``)`` — keeps a
      payload's leading ``//`` as data: ``bytecblock b64 //// base64(AA//)``
      are the constants ``0xffffff 0x000fff``, not a comment (reading them as one
      dropped the WHOLE constant block; every ``bytec_N`` then resolved to
      nothing).
    * A ``"`` opens a string only at a token start, and a ``"`` inside a string
      closes it unless the IMMEDIATELY preceding byte is a backslash — Go's
      rule, verified against ``goal``: ``pushbytess "a\\\\" "b"`` assembles to ONE
      constant, so an odd-run escape rule (which reads two) fabricates a stack
      shape the assembler never produces.
    * Whitespace ends a token even inside ``base64(..)``: ``base64(a b)`` is two
      tokens, and the assembler rejects it ("lacks closing parenthesis").

    Semantics only — no fabrication: on input the assembler rejects the split
    here is still the assembler's, so what follows refuses on the same shapes.
    """
    n = len(text)
    spans: list = []
    i = 0
    while i < n and _is_separator(text[i]):
        if text[i] == ";":
            spans.append((i, i + 1))
        i += 1
    start = i
    in_string = False                     # spaces and `//` are data inside
    in_base64 = False                     # `//` is payload inside
    while i < n:
        c = text[i]
        if not _is_separator(c):
            if c == '"':
                if not in_string:
                    if i == 0 or _is_separator(text[i - 1]):
                        in_string = True
                elif text[i - 1] != "\\":
                    in_string = False
            elif c == "/":
                if (i + 1 < n and text[i + 1] == "/"
                        and not in_base64 and not in_string):
                    if start != i:        # a comment glued to a token
                        spans.append((start, i))
                    return spans, i
            elif c == "(":
                if text[start:i] in _BASE64_KEYWORDS:
                    in_base64 = True
            elif c == ")":
                in_base64 = False
            i += 1
            continue
        # A separator ends the current token — unless it sits inside a string.
        if not in_string:
            tok = text[start:i]
            spans.append((start, i))
            if c == ";":
                spans.append((i, i + 1))
            if in_base64:
                in_base64 = False
            elif tok in _BASE64_KEYWORDS:
                in_base64 = True
        i += 1
        if not in_string:
            while i < n and _is_separator(text[i]):
                if text[i] == ";":
                    spans.append((i, i + 1))
                i += 1
            start = i
    if start < n:
        spans.append((start, n))
    return spans, -1


def strip_inline_comment(code: str) -> str:
    """Drop the ``//`` comment from a source line, by the assembler's own rule
    (:func:`scan_line`): a ``//`` outside a string and outside a base64 payload
    starts the comment wherever it sits, and one inside either is data."""
    _spans, cut = scan_line(code)
    return code if cut < 0 else code[:cut]


def tokenize_operands(text: str, *, fold_byte_keywords: bool = False) -> list:
    """Split the text after an opcode into the assembler's tokens
    (:func:`scan_line`): ``"quoted strings"`` stay whole, a ``//`` comment ends
    the list, and a ``//`` inside a base64 payload is data.

    HAZARD: a ``bytecblock`` / ``pushbytess`` literal list needs
    ``fold_byte_keywords=True`` — without it ``b64 AAAA`` splits into two tokens
    (as the assembler itself sees them) and every constant index after it
    shifts. Folding joins the keyword and its payload with ONE space, the form
    :func:`decode_byte_literal` accepts."""
    spans, _cut = scan_line(text)
    raw = [text[a:b] for a, b in spans]
    if not fold_byte_keywords:
        return raw
    toks: list = []
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok in _BYTE_ENC_KW and i + 1 < len(raw):
            toks.append(tok + " " + raw[i + 1])
            i += 2
            continue
        toks.append(tok)
        i += 1
    return toks
