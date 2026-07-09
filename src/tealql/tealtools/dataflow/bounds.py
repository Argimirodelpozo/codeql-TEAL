"""Relational in-bounds analysis for byte-access ops — proving ``offset + width
<= len(buffer)`` for ``extract`` / ``substring`` / ``getbyte`` / ``extract_uint*``
/ ``setbyte`` (and the immediate forms).

This is the relation ABI-decode safety turns on, and the one the *non-relational*
domains cannot express alone: intervals bound the offset and the width separately,
and ``byte_length_prop`` bounds the buffer separately — none relates them. The
reasoning lives in :mod:`.relational` (a zone / difference-bound domain over
symbolic ``Len(buf)`` atoms, offsets, widths and assert-derived facts); this module
just decodes each access site into a ``(buffer, base, width)`` bound and asks it.

Three verdicts, each with the right soundness:
  * ``in_bounds`` — SOUND. Proven ``offset + width <= Len(buffer)`` from constant
    widths/offsets, ``len X`` equalities, and dominating asserts (e.g.
    ``extract3 X 0 (len X)`` whole-buffer reads, or ``assert(len X >= 32)`` then
    fixed-offset field reads).
  * ``proven_oob`` — SOUND, and only where the buffer length is UNAMBIGUOUS (a
    bytes literal, seeded as an exact ``Len == n``); a true over-read the AVM
    panics on. Never claimed off a possibly-under-counting ``byte_length``.
  * ``oob_risk`` — a HEURISTIC signal (a dynamic index we can't prove in-bounds),
    NOT a precise detector: most such sites are Puya's own bounds-checked accesses
    the relational facts still don't pin down.

Operand order is TOP-FIRST (``reference_ssa_inputs_top_first``): for the
stack-arg ops the array is pushed FIRST, so it is the LAST input
(``inputs[-1]``), and the numeric args count down from ``inputs[0]``. Read-only.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..ssa import SSAProgram
from ..ssa.operands import const_int
from ..passes import run_all_passes
from .relational import LengthRelations


@dataclass(frozen=True)
class BoundsSite:
    op: str
    line: int
    in_bounds: bool          # offset+width PROVABLY <= len(buffer) (sound)
    proven_oob: bool         # offset+width PROVABLY > an EXACT (unambiguous) length
    dynamic: bool            # the index/length is not a compile-time constant
    reason: str              # human-readable verdict

    @property
    def oob_risk(self) -> bool:
        """A crafted-input out-of-bounds risk: a dynamic index we cannot prove
        in-bounds (the AVM panics on OOB — DoS, or missing validation)."""
        return self.dynamic and not self.in_bounds


def _fold(base_operand, extra_c: int):
    """Normalise ``value(base_operand) + extra_c`` — collapse a constant base
    into the offset so the query has at most one symbolic term."""
    k = const_int(base_operand)
    if k is not None:
        return None, extra_c + k
    return base_operand, extra_c


def _access(a):
    """``(buffer, base_operand | None, extra_c | None, dynamic)`` for a
    byte-access assignment, or ``None``. The access reads up to byte
    ``value(base) + extra_c`` (``base is None`` ⇒ the constant ``extra_c``;
    ``extra_c is None`` ⇒ unbounded)."""
    op, ins, imm = a.op, a.inputs, (a.immediates or "").split()

    def _imm(i):
        try:
            return int(imm[i])
        except (IndexError, ValueError):
            return None

    if op == "extract" and len(ins) == 1 and len(imm) == 2:      # extract A B
        start, length = _imm(0), _imm(1)
        if start is None:
            return None
        # ``extract A 0`` reads [A, len) — the over-read condition is A > len.
        return (ins[0], None, start if length == 0 else start + length, False)
    if op == "substring" and len(ins) == 1 and len(imm) == 2:    # substring A B
        return (ins[0], None, _imm(1), False)                    # needs B <= len
    if op == "extract3" and len(ins) == 3:                       # extract3 X A B
        buf, start, cnt = ins[2], ins[1], ins[0]
        s_c, w_c = const_int(start) is not None, const_int(cnt) is not None
        if w_c:                                                  # const width
            b, c = _fold(start, const_int(cnt))
        elif s_c:                                                # const offset
            b, c = _fold(cnt, const_int(start))
        else:
            b, c = None, None                                    # both dynamic
        return (buf, b, c, not (s_c and w_c))
    if op == "substring3" and len(ins) == 3:                     # substring3 X A B
        buf, end = ins[2], ins[0]                                # needs B(end) <= len
        b, c = _fold(end, 0)
        return (buf, b, c, const_int(end) is None)
    if op == "getbyte" and len(ins) == 2:                        # getbyte X i
        buf, idx = ins[1], ins[0]
        b, c = _fold(idx, 1)
        return (buf, b, c, const_int(idx) is None)
    if op == "setbyte" and len(ins) == 3:                        # setbyte X i b
        buf, idx = ins[2], ins[1]
        b, c = _fold(idx, 1)
        return (buf, b, c, const_int(idx) is None)
    if op in ("extract_uint16", "extract_uint32", "extract_uint64") and len(ins) == 2:
        width = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}[op]
        buf, idx = ins[1], ins[0]
        b, c = _fold(idx, width)
        return (buf, b, c, const_int(idx) is None)
    return None


def check_bounds(prog: SSAProgram, *, run_passes: bool = True) -> list:
    """Every byte-access site with its in-bounds verdict. Runs the analysis
    pipeline first (idempotent) so ranges, byte-lengths and ``len`` equalities
    are populated, then asks the relational domain at each site."""
    if run_passes:
        run_all_passes(prog)

    sites = [(a, acc) for a in prog.assignments if (acc := _access(a)) is not None]
    rel = LengthRelations(prog)
    for _a, (buf, _b, _c, _dyn) in sites:      # seed ALL buffers before querying
        rel.seed_buffer(buf)

    out: list = []
    for a, (buf, base, extra_c, dynamic) in sites:
        if extra_c is None:
            in_bounds, proven_oob, reason = False, False, "offset+width unbounded"
        else:
            in_bounds, proven_oob = rel.verdict(
                buf, base, extra_c, a.basic_block, a.location.line)
            if in_bounds:
                reason = "in-bounds (offset+width <= len)"
            elif proven_oob:
                reason = "OUT OF BOUNDS (offset+width > exact len)"
            else:
                reason = "unproven (no relation offset+width <= len)"
        out.append(BoundsSite(a.op, a.location.line, in_bounds, proven_oob,
                              dynamic, reason))
    return out
