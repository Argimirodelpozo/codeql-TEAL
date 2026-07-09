"""Relational in-bounds analysis for byte-access ops — proving ``offset + width
<= len(buffer)`` for ``extract`` / ``substring`` / ``getbyte`` / ``extract_uint*``
/ ``setbyte`` (and the immediate forms).

This is the relation ABI-decode safety turns on, and the one the *non-relational*
domains cannot express on their own: intervals bound the offset and the width
separately, and ``byte_length_prop`` bounds the buffer length separately — none
relates them. This analysis COMBINES those facts at each access site: an access
``[offset, offset+width)`` is provably in-bounds when ``offset.hi + width.hi <=
len(buffer)``, using each operand's already-computed IntRange and the buffer's
byte-length. It runs the standard pass pipeline first so those facts are populated.

Three verdicts, each with the right soundness:
  * ``in_bounds`` — SOUND. ``access_hi <= byte_length``. (``byte_length`` can
    UNDER-count — a ``replace2``-built array — which is the safe direction here,
    since ``access <= underestimate <= true_len`` still holds.)
  * ``proven_oob`` — SOUND, and only when the buffer length is UNAMBIGUOUS (a
    bytes literal); ``access_hi > exact_len`` is then a true over-read the AVM
    would panic on. (Not claimed off a possibly-under-counting ``byte_length``.)
  * ``oob_risk`` — a HEURISTIC research signal (a dynamic index we can't prove
    in-bounds), NOT a precise detector: most such sites are Puya's own
    bounds-checked accesses we simply can't prove without a relational domain.

The headline measurement it enables — *what fraction of ABI-decode accesses is
provably in-bounds from non-relational facts?* — is deliberately a baseline: it is
low precisely because buffer length and offset are usually RELATED (the offset is
read from the buffer's own length prefix), which is the motivation for a relational
domain. Read-only.

Operand convention matches ``byte_length_prop``: ``inputs[0]`` is the buffer,
``inputs[1]`` the start/index, ``inputs[2]`` the count/end.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..ssa import SSAProgram, SSAVar, const_int, operand_const
from ..passes import run_all_passes


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
        """A crafted-input out-of-bounds risk: a dynamic index that we cannot
        prove in-bounds (the AVM panics on OOB — DoS, or missing validation)."""
        return self.dynamic and not self.in_bounds


def _buflen(operand) -> "tuple[int | None, bool]":
    """``(length, exact)`` for the buffer operand.

    A bytes CONSTANT gives an ``exact`` length (both bounds equal — an over-read
    past it is a true OOB). ``TealType.byte_length`` (set forward by
    ``byte_length_prop`` from ``extract``/``concat``/``itob``/``bzero``/…) is NOT
    marked exact: it can UNDER-count in practice (e.g. a ``replace2``-built array
    tracked shorter than it is), which is the SAFE direction for an in-bounds
    proof — ``access <= byte_length <= true_len`` still holds — but means
    ``access > byte_length`` is NOT a proven over-read (only unknown). And
    ``byte_length_range`` is excluded entirely: it carries the INVERSE lower bound
    a successful access itself implies (``extract3 X A B`` ⇒ ``len(X) >= A+B``), so
    using it to bound the same access is circular."""
    c = operand_const(operand)
    if c is not None and getattr(c, "kind", None) == "bytes":
        raw = c.value
        if isinstance(raw, str) and raw.startswith("0x"):
            return (len(raw) - 2) // 2, True
        if isinstance(raw, (bytes, bytearray)):
            return len(raw), True
    if isinstance(operand, SSAVar) and operand.type is not None \
            and operand.type.byte_length is not None:
        return operand.type.byte_length, False
    return None, None


def _uint_hi(operand) -> "tuple[int | None, bool]":
    """``(upper_bound, is_constant)`` for a uint64 operand — the largest value it
    can take. ``None`` upper bound = unknown (unbounded)."""
    n = const_int(operand_const(operand))
    if n is not None:
        return n, True
    if isinstance(operand, SSAVar) and operand.range is not None:
        return operand.range.hi, False
    return None, False


# op -> (buffer_idx, index_idx | None, count_idx | None, fixed_width | None)
# index/count None => taken from immediates; fixed_width for extract_uint*.
def _access(a):
    """``(buflen_min, access_hi, dynamic)`` for a byte-access assignment, or None
    if it isn't one. ``access_hi`` is the largest byte offset the op touches (so
    in-bounds iff ``access_hi <= buflen_min``)."""
    op = a.op
    ins = a.inputs
    imm = (a.immediates or "").split()

    def _imm(i):
        try:
            return int(imm[i])
        except (IndexError, ValueError):
            return None

    if op == "extract" and len(ins) == 1 and len(imm) == 2:      # extract A B
        start, length = _imm(0), _imm(1)
        if start is None:
            return None
        buf = ins[0]
        hi = start if length == 0 else (start + length if length else None)
        return (buf, hi, False)
    if op == "substring" and len(ins) == 1 and len(imm) == 2:    # substring A B
        end = _imm(1)
        return (ins[0], end, False)
    if op == "extract3" and len(ins) == 3:                       # extract3 X A B
        s_hi, s_c = _uint_hi(ins[1]); w_hi, w_c = _uint_hi(ins[2])
        hi = None if s_hi is None or w_hi is None else s_hi + w_hi
        return (ins[0], hi, not (s_c and w_c))
    if op == "substring3" and len(ins) == 3:                     # substring3 X A B
        e_hi, e_c = _uint_hi(ins[2])
        return (ins[0], e_hi, not e_c)
    if op == "getbyte" and len(ins) == 2:                        # getbyte X i
        i_hi, i_c = _uint_hi(ins[1])
        hi = None if i_hi is None else i_hi + 1
        return (ins[0], hi, not i_c)
    if op == "setbyte" and len(ins) == 3:                        # setbyte X i b
        i_hi, i_c = _uint_hi(ins[1])
        hi = None if i_hi is None else i_hi + 1
        return (ins[0], hi, not i_c)
    if op in ("extract_uint16", "extract_uint32", "extract_uint64") and len(ins) == 2:
        width = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}[op]
        i_hi, i_c = _uint_hi(ins[1])
        hi = None if i_hi is None else i_hi + width
        return (ins[0], hi, not i_c)
    return None


def check_bounds(prog: SSAProgram, *, run_passes: bool = True) -> list:
    """Every byte-access site with its in-bounds verdict. Runs the analysis
    pipeline first (idempotent) so ranges + byte-lengths are populated."""
    if run_passes:
        run_all_passes(prog)
    out: list = []
    for a in prog.assignments:
        acc = _access(a)
        if acc is None:
            continue
        buf_operand, access_hi, dynamic = acc
        buflen, exact = _buflen(buf_operand)
        in_bounds = proven_oob = False
        if buflen is None:
            reason = "buffer length unknown"
        elif access_hi is None:
            reason = "access offset/width unbounded"
        elif access_hi <= buflen:
            in_bounds, reason = True, f"in-bounds ({access_hi} <= len {buflen})"
        elif exact:
            proven_oob, reason = True, f"OUT OF BOUNDS ({access_hi} > exact len {buflen})"
        else:
            reason = f"unproven ({access_hi} > tracked len {buflen}; may under-count)"
        out.append(BoundsSite(a.op, a.location.line, in_bounds, proven_oob,
                              dynamic, reason))
    return out
