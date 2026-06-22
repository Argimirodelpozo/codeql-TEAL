"""TEAL literal + operand parsing — pure text helpers, no IR / puya dependency.

The tree-sitter parse hands downstream the raw opcode text (the node ``code``);
these helpers recover the structured pieces a consumer needs from it:

  - :func:`tokenize_operands` — split the operand list (the text after the
    mnemonic) into tokens, honoring ``"quoted strings"`` and parenthesised
    ``base64(..)`` / ``base32(..)`` groups (which can contain spaces and ``/``).
  - :func:`decode_byte_literal` — decode a TEAL byte literal (``0x`` / ``"str"``
    / ``b64 ..`` / ``base64(..)`` / ``b32 ..`` / ``base32(..)``) to
    ``(raw_bytes, encoding_kind)``. ``encoding_kind`` is a neutral string
    (``"base16"`` / ``"utf8"`` / ``"base64"`` / ``"base32"``); a caller that
    needs puya's ``AVMBytesEncoding`` maps it itself, keeping this layer
    puya-free.

These live in the AST layer because they are TEAL-syntax parsing, even though
today only the lift consumes them (it would otherwise re-parse the raw text).
"""
from __future__ import annotations


def _teal_str_bytes(s: str) -> bytes:
    r"""Decode a TEAL ``byte "..."`` string body (handles \\ \" \n \r \t \xNN)."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s) + 1:
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            out.append({"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34}.get(n, ord(n)))
            i += 2
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    return bytes(out)


def _b64(s: str) -> bytes:
    import base64
    return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4))


def _b32(s: str) -> bytes:
    import base64                       # TEAL omits padding; addresses are 52 chars
    return base64.b32decode(s.strip() + "=" * (-len(s.strip()) % 8))


def decode_byte_literal(v: str) -> tuple[bytes, str]:
    """Parse a TEAL byte literal -> ``(raw bytes, encoding-kind name)``. Accepts
    the ``0x..`` / ``"str"`` / ``b64 ..`` / ``base64(..)`` / ``b32 ..`` /
    ``base32(..)`` forms. Base64/base32 bodies are re-padded (TEAL writes them
    without ``=``). The kind name is one of ``base16`` / ``utf8`` / ``base64``
    / ``base32``."""
    v = v.strip()
    if v.startswith("0x"):
        return bytes.fromhex(v[2:]), "base16"
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _teal_str_bytes(v[1:-1]), "utf8"
    if v.startswith(("b64 ", "base64 ")):
        return _b64(v.split(None, 1)[1]), "base64"
    if v.startswith("base64(") and v.endswith(")"):
        return _b64(v[7:-1]), "base64"
    if v.startswith(("b32 ", "base32 ")):
        return _b32(v.split(None, 1)[1]), "base32"
    if v.startswith("base32(") and v.endswith(")"):
        return _b32(v[7:-1]), "base32"
    try:
        return bytes.fromhex(v), "base16"
    except ValueError:
        return v.encode("utf-8"), "utf8"


# byte-encoding keywords that take a following data token (``b64 AAAA``).
_BYTE_ENC_KW = frozenset({"b64", "base64", "b32", "base32"})


def tokenize_operands(text: str, *, fold_byte_keywords: bool = False) -> list:
    """Split a TEAL operand list (the text after the opcode) into tokens,
    honoring ``"quoted strings"`` and parenthesised ``base64(..)`` /
    ``base32(..)`` groups (which can contain spaces and ``/``). Stops at an
    inline ``//`` comment that sits between tokens (depth 0, outside quotes).

    ``fold_byte_keywords=True`` additionally folds the two-token
    ``b64 <data>`` / ``base64 <data>`` / ``b32 <data>`` / ``base32 <data>``
    form into ONE token (``"b64 AAAA"``) — the shape a ``bytecblock`` /
    ``intcblock`` literal list uses, where each such pair is a single
    literal. (Without it the keyword and its data are separate tokens.)"""
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
            while j < n and not (text[j] == '"' and text[j - 1] != "\\"):
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
