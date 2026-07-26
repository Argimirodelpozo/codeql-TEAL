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

import re


#: A DEPLOYMENT TEMPLATE VARIABLE token: an ALL-CAPS ``PREFIX_NAME`` identifier
#: standing in for a value supplied at deploy time (``TMPL_DELETABLE``).
#: ``TMPL_`` is algokit's default prefix, but puya lets a contract choose its
#: own — the ``compile_HelloPrfx`` fixture uses ``PRFX_`` — so keying on the
#: literal ``TMPL_`` misses real ones.
_TEMPLATE_VAR_RE = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")


def render_byte_constant(value: str) -> str:
    """A bytes constant for HUMAN output.

    Bytes constants are STORED canonically as ``0x<hex>`` so two spellings of
    one value compare equal (`byte "hi"` and `pushbytes "hi"` used to resolve
    to different strings and silently fail an equality match in `xcontract`'s
    state-key resolution). But a finding that reads ``== 0x616c6c6f776564`` is
    worse than ``== "allowed"``, so printable ASCII is rendered back as a
    string for display. Display ONLY — the stored value stays canonical."""
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
    """``token`` is a deployment template variable — a value that does not
    exist until the app is deployed.

    ONE definition, consumed by the parser (recover the operand rather than
    drop it), ``const_values`` (resolve the slot to NOTHING rather than to the
    literal text) and the lift (lower to puya's ``TemplateVar``). It previously
    existed in three places in two different forms — a ``TMPL_`` prefix test
    and this regex — which disagree on every custom prefix.
    """
    return bool(token) and _TEMPLATE_VAR_RE.match(token.strip()) is not None


# TEAL `int` pseudo-op named constants -- the OnCompletion and TxnType (TypeEnum)
# enums the assembler resolves to fixed uint64 values. The tree-sitter grammar's
# `int` rule only accepts a numeric argument, so the named form (`int
# DeleteApplication`) parses as an ERROR; parse.py recovers the node and this
# table gives const_values the value. (AVM langspec named constants.)
# DERIVED from avm.TXN_ENUM_FIELD_NAMES rather than re-listed: avm.py is the
# single home for AVM metadata, and two hand-maintained copies of the same
# enums can disagree (a new OnCompletion added to one and not the other would
# silently change which guards resolve).
def _named_int_constants() -> dict[str, int]:
    from ..avm import TXN_ENUM_FIELD_NAMES

    out: dict[str, int] = {}
    for by_value in TXN_ENUM_FIELD_NAMES.values():
        for value, name in by_value.items():
            out.setdefault(name, value)
    return out


NAMED_INT_CONSTANTS: dict[str, int] = _named_int_constants()


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _teal_str_bytes(s: str) -> bytes:
    r"""Decode a TEAL ``byte "..."`` string body (handles \\ \" \n \r \t \xNN).

    Non-ASCII characters encode as UTF-8, matching the assembler — emitting
    ``ord(c)`` as one byte (as a former duplicate of this function in
    ``graph.py`` did) turns ``byte "café"`` into ``636166e9`` where the real
    constant is ``636166c3a9``, so every comparison against it mis-evaluates.

    A malformed escape is emitted literally rather than raising: this runs on
    untrusted / hand-written source, the assembler would reject such a file
    anyway, and a decode crash escaping as a non-LiftError reads as a genuine
    bug (see :mod:`tealql.tealtools.errors`).
    """
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                # Need BOTH hex digits present and valid (`i + 4 <= len(s)`);
                # the old bound `i + 3 < len(s) + 1` accepted a truncated
                # one-digit `\x4` and decoded it as 0x04.
                if i + 4 <= len(s) and set(s[i + 2:i + 4]) <= _HEX_DIGITS:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                out.extend(c.encode("utf-8"))      # malformed -> literal
                i += 1
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
    # Both spellings of each keyword, in BOTH the space form (`b64 AAAA`) and
    # the parenthesised form (`b64(AAAA)`) — the assembler accepts all four per
    # encoding. The abbreviated PARENTHESISED spellings (`b64(..)` / `b32(..)`)
    # used to be missing, so they fell through to the utf-8 fallback and
    # decoded to the literal ASCII text `b64(AAAA)`. That is worse than failing:
    # a guard comparing against the constant silently mis-evaluates against a
    # value the chain never produces.
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
