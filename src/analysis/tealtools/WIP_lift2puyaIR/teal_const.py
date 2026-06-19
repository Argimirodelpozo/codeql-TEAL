"""TEAL source / literal parsing — pure text helpers, no IR dependency (so both
`lift` and `to_puya_ir` import it without a cycle).

Load the `.teal` source (`_load_src`), recover a dropped template-var name
(`_tmpl_name`), parse byte literals (`_const_bytes`: 0x / "str" / base64 / base32)
and operand lists (`_tokenize_operands`).
"""
from __future__ import annotations

from puya.ir.types_ import AVMBytesEncoding

_SRC_CACHE: dict = {}


def _load_src(source: str) -> dict:
    """Map ``basename -> source lines`` from a ``.teal`` file/dir (cached).
    Delegates to the shared graph-layer resolver so the lift reads the same
    source the graph build does."""
    if source in _SRC_CACHE:
        return _SRC_CACHE[source]
    from ..graphs import _load_source_bytes
    m = {
        bn: data.decode("utf-8", "replace").splitlines()
        for bn, data in _load_source_bytes(source).items()
    }
    _SRC_CACHE[source] = m
    return m


def _tmpl_name(src_map: dict, line: int) -> str:
    """Recover the template-var operand (`TMPL_X`) at ``line`` from source."""
    if line and len(src_map) == 1:
        lines = next(iter(src_map.values()))
        if 1 <= line <= len(lines):
            parts = lines[line - 1].split("//")[0].strip().split(None, 1)
            if len(parts) == 2 and parts[1].strip():
                return parts[1].strip()
    return f"TMPL_anon_{line}" if line else "TMPL_anon"


def _teal_str_bytes(s: str) -> bytes:
    """Decode a TEAL ``byte "..."`` string body (handles \\\\ \\" \\n \\r \\t \\xNN)."""
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


def _const_bytes(v: str):
    """Parse a TEAL byte literal -> (raw bytes, AVM encoding). Accepts the
    `0x..` / `"str"` / `b64 ..` / `base64(..)` / `b32 ..` / `base32(..)` forms.
    Base64/base32 bodies are re-padded (TEAL writes them without `=`)."""
    v = v.strip()
    if v.startswith("0x"):
        return bytes.fromhex(v[2:]), AVMBytesEncoding.base16
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _teal_str_bytes(v[1:-1]), AVMBytesEncoding.utf8
    if v.startswith(("b64 ", "base64 ")):
        return _b64(v.split(None, 1)[1]), AVMBytesEncoding.base64
    if v.startswith("base64(") and v.endswith(")"):
        return _b64(v[7:-1]), AVMBytesEncoding.base64
    if v.startswith(("b32 ", "base32 ")):
        return _b32(v.split(None, 1)[1]), AVMBytesEncoding.base32
    if v.startswith("base32(") and v.endswith(")"):
        return _b32(v[7:-1]), AVMBytesEncoding.base32
    try:
        return bytes.fromhex(v), AVMBytesEncoding.base16
    except ValueError:
        return v.encode("utf-8"), AVMBytesEncoding.utf8


def _tokenize_operands(text: str) -> list:
    """Split a TEAL operand list (the text after the opcode) into operand
    tokens, honoring ``"quoted strings"`` and parenthesised ``base64(..)`` /
    ``base32(..)`` groups (which can contain spaces and ``/``). Stops at an
    inline ``//`` comment that sits between tokens (depth 0, outside quotes)."""
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
        toks.append(text[i:j])
        i = j
    return toks
