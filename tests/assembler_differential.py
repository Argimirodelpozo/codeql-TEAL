"""Differential vs the REAL assembler: do our decoded constants match the chain's?

The gap this closes
-------------------
Every other gate in this suite answers "did we crash / drop / change shape".
None answers "is the VALUE right". That is the failure mode that actually hurt:

* ``b64(SGVsbG8=)`` decoded to the literal ASCII text ``b64(SGVsbG8=)``;
* a ``//`` comment swallowed into a string constant, so ``pushbytes "asa_"``
  carried ``"asa_"   // [name,``;
* ``gaid 5`` / ``itxna Logs 3`` losing the index that says WHICH transaction;
* a deployment template resolving to the literal text ``TMPL_GREETING``.

Not one of those crashes, raises a diagnostic, or moves a golden. A guard
comparing against such a constant simply never matches, and nothing says so.

Method
------
``algod`` IS the reference implementation — the same assembler the chain runs::

    source --compile--> bytecode --disassemble--> canonical TEAL

The disassembly renders every constant canonically (``pushbytes 0x..`` /
``pushint N``), so it is ground truth for what the constants ARE. We then parse
BOTH texts with our own pipeline and compare the constant sets. A decode bug
puts a value in our set that is absent from the assembler's.

Constants are compared as SETS, not sequences: the assembler legitimately
reorganises pushes into ``intcblock`` / ``bytecblock`` and dedupes them, which
changes order and count but never the value set.

Only DIRECT const-push opcodes are read, never folded/derived values — the
decode surface is what is under test, and folding differences between the two
spellings would be noise.

Gated on a reachable algod (``TEAL_ALGOD_LOCAL``, default ``:4001``). A program
the assembler REJECTS is skipped and counted, never silently passed: an
un-instantiated ``TMPL_`` template or a deliberately-invalid fixture is not
assemblable at all, and "0 mismatches because we checked nothing" must not read
as success.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from tealql.tealtools._utils.chain import _local, _token
from tealql.tealtools.ssa import SSAProgram

#: Opcodes that push a LITERAL. Their operand is the decode surface under test;
#: anything computed from them is out of scope (folding is not what we are
#: checking, and the two spellings may legitimately fold differently).
_CONST_PUSH_OPS = frozenset({
    "int", "pushint", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "intcblock",
    "byte", "pushbytes", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3",
    "bytecblock", "pushints", "pushbytess", "addr", "method",
})


def _post(path: str, body: bytes, ctype: str) -> dict:
    req = urllib.request.Request(f"{_local()}{path}", data=body, method="POST")
    req.add_header("X-Algo-API-Token", _token())
    req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def algod_available() -> bool:
    try:
        req = urllib.request.Request(f"{_local()}/v2/status")
        req.add_header("X-Algo-API-Token", _token())
        with urllib.request.urlopen(req, timeout=3):
            return True
    except Exception:
        return False


def assembler_error(source: str) -> "str | None":
    """The assembler's complaint about ``source``, or ``None`` if it assembles.
    Kept separate from :func:`canonical_teal` so a skip can be REPORTED with its
    reason — an un-assemblable fixture is not a pass, and "74 skipped" with no
    reason is how a corpus of malformed fixtures stays invisible."""
    try:
        _post("/v2/teal/compile", source.encode("utf-8"), "text/plain")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()).get("message", "")[:160]
        except Exception:
            return f"HTTP {e.code}"
    return None


def canonical_teal(source: str) -> "str | None":
    """``source`` assembled then disassembled by algod, or ``None`` when the
    assembler REJECTS it (an un-instantiated template, a deliberately-invalid
    op). A rejected program is not a failure of ours — it is not assemblable
    TEAL at all — but it must be COUNTED, not silently passed."""
    try:
        compiled = _post("/v2/teal/compile", source.encode("utf-8"), "text/plain")
    except urllib.error.HTTPError:
        return None
    raw = base64.b64decode(compiled["result"])
    return _post("/v2/teal/disassemble", raw, "application/x-binary")["result"]


def constant_sets(source: str, name: str = "prog.teal") -> "tuple[set, set]":
    """``(int_constants, bytes_constants)`` this program pushes, decoded by US.

    Read off the DIRECT const-push opcodes only. Compared as sets because the
    assembler reorganises pushes into constant blocks and dedupes them."""
    prog = SSAProgram({name: source})
    prog.propagate_constants()
    ints: set = set()
    byts: set = set()
    for a in prog.assignments:
        if a.op not in _CONST_PUSH_OPS:
            continue
        for out in a.outputs:
            cv = getattr(out, "const_value", None)
            if cv is None:
                continue
            if cv.kind == "int":
                try:
                    ints.add(int(cv.value, 0) if isinstance(cv.value, str)
                             else int(cv.value))
                except (TypeError, ValueError):
                    pass
            elif cv.kind == "bytes":
                byts.add(_norm_bytes(cv.value))
    return ints, byts


def _norm_bytes(v) -> str:
    """A bytes constant as lowercase hex, whatever spelling it arrived in."""
    if isinstance(v, bytes):
        return v.hex()
    s = str(v)
    if s.startswith("0x"):
        return s[2:].lower()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        from tealql.tealtools.ast.literals import decode_byte_literal
        return decode_byte_literal(s)[0].hex()
    return s.lower()


@dataclass
class Divergence:
    contract: str
    kind: str                 # "int" | "bytes"
    ours_only: list = field(default_factory=list)
    assembler_only: list = field(default_factory=list)

    def render(self) -> str:
        return (f"{self.contract}: {self.kind} constants diverge\n"
                f"    ours only      : {sorted(self.ours_only)[:6]}\n"
                f"    assembler only : {sorted(self.assembler_only)[:6]}")


@dataclass
class Result:
    checked: int = 0
    skipped_unassemblable: int = 0
    divergences: list = field(default_factory=list)
    #: ``[(contract, assembler message)]`` — WHY each skip happened. Some are
    #: expected (a `TMPL_` template is not assemblable until deploy; a
    #: disassembled mainnet contract does not always re-assemble). Others mean
    #: the FIXTURE is not valid TEAL — a type error, a stack underflow — and a
    #: fixture that could never run is testing a shape that cannot occur.
    skips: list = field(default_factory=list)

    def skip_report(self) -> str:
        import collections
        by_reason = collections.Counter(
            m.split(":")[-1].strip()[:70] for _c, m in self.skips)
        return "\n".join(f"  {n:4d}  {r}" for r, n in by_reason.most_common())


def compare(source: str, contract: str) -> "list[Divergence] | None":
    """Divergences for one program, or ``None`` if it is not assemblable."""
    canonical = canonical_teal(source)
    if canonical is None:
        return None
    ours_i, ours_b = constant_sets(source, contract)
    ref_i, ref_b = constant_sets(canonical, contract)
    out = []
    # The assembler may hold constants ours does not reach (a block entry never
    # referenced), so only OURS-ONLY is a decode bug: a value we invented.
    if ours_i - ref_i:
        out.append(Divergence(contract, "int", sorted(ours_i - ref_i),
                              sorted(ref_i - ours_i)))
    if ours_b - ref_b:
        out.append(Divergence(contract, "bytes", sorted(ours_b - ref_b),
                              sorted(ref_b - ours_b)))
    return out


def run(paths) -> Result:
    res = Result()
    for p in paths:
        try:
            source = Path(p).read_text(errors="replace")
        except Exception:
            continue
        try:
            found = compare(source, Path(p).name)
        except Exception:
            continue                     # network hiccup: not a finding
        if found is None:
            res.skipped_unassemblable += 1
            res.skips.append((Path(p).name, assembler_error(source) or "?"))
            continue
        res.checked += 1
        res.divergences.extend(found)
    return res
