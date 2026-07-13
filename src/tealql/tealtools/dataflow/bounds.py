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
    in_bounds: bool          # offset+width PROVABLY <= len(buffer) (SOUND)
    proven_oob: bool         # offset+width PROVABLY > an EXACT (unambiguous) length
    dynamic: bool            # the index/length is not a compile-time constant
    reason: str              # human-readable verdict
    # in-bounds ONLY under an ARC-4 well-formedness ASSUMPTION (a recovered
    # fixed-size type gives the buffer's length) — an attributed guess, not a
    # proof. Set only in speculative mode; never overlaps a sound ``in_bounds``.
    in_bounds_speculative: bool = False
    speculative_confident: bool = False   # the recovery's own confidence in that guess

    @property
    def oob_risk(self) -> bool:
        """A crafted-input out-of-bounds risk: a dynamic index we cannot prove
        in-bounds (the AVM panics on OOB — DoS, or missing validation). A
        speculative in-bounds (a well-formed-ABI assumption) removes it from the
        residual risk set."""
        return self.dynamic and not self.in_bounds and not self.in_bounds_speculative


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


def _seed_all(rel, sites) -> None:
    for _a, (buf, base, _c, _dyn) in sites:    # seed ALL facts before querying
        rel.seed_buffer(buf)
        rel.seed_range(base)                   # bridge the offset/count interval


def _abi_arg_lengths(prog) -> dict:
    """``{ssa_key: (byte_length, confident)}`` for ``txna ApplicationArgs N``
    buffers whose ABI method — pinned by the router selector holding at the read's
    block — DECLARES a fixed-size arg. An OPTIONAL high-level enrichment: ``{}``
    when the source carries no ``method "sig"`` info (raw disassembled bytecode),
    so bounds degrades cleanly to the recovery-only speculative tier. The declared
    arg length is the WELL-FORMED-ABI assumption (the AVM router checks only the
    selector, not arg lengths), hence speculative — but it types the SOURCE
    ApplicationArgs directly, where the encoded-type recovery could not."""
    src_path = str(getattr(prog, "source_path", "") or "")
    if not src_path:
        return {}
    try:
        return _abi_arg_lengths_impl(prog, src_path)
    except Exception:                          # an optional layer must never break bounds
        return {}


def _abi_arg_lengths_impl(prog, src_path: str) -> dict:
    from pathlib import Path
    from ..abi import extract_method_table
    from ..path_predicates import PathPredicateAnalysis
    from ..ssa.operands import const_bytes

    p = Path(src_path)
    if p.is_dir():
        text = "\n".join(f.read_text(errors="ignore")
                         for f in sorted(p.rglob("*.teal")))
    elif p.exists():
        text = p.read_text(errors="ignore")
    else:
        return {}
    table = extract_method_table(text)
    if not table:                              # availability gate
        return {}
    pp = PathPredicateAnalysis(prog)

    def _method_at(block):
        for bc in pp.bb_preds.get(block, ()):
            if bc.kind == "eq" and bc.args and const_bytes(bc.args[0]) in table:
                return table[const_bytes(bc.args[0])]
        return None

    out: dict = {}
    for a in prog.assignments:
        if a.op != "txna" or not a.outputs:
            continue
        toks = (a.immediates or "").split()
        if len(toks) != 2 or toks[0] != "ApplicationArgs":
            continue
        try:
            n = int(toks[1])
        except ValueError:
            continue
        if n < 1:                              # index 0 is the selector, not an arg
            continue
        method = _method_at(a.basic_block)
        if method is None:
            continue
        bl = method.app_arg_byte_length(n)
        if bl is not None:
            k = getattr(a.outputs[0], "_key", None)
            if k is not None:
                out[k()] = (bl, True)
    return out


def check_bounds(prog: SSAProgram, *, run_passes: bool = True,
                 speculative: bool = False) -> list:
    """Every byte-access site with its in-bounds verdict. Runs the analysis
    pipeline first (idempotent) so ranges, byte-lengths and ``len`` equalities
    are populated, then asks the relational domain at each site.

    ``speculative`` opt-in: buffers whose length isn't soundly known are given a
    length from the ARC-4 encoded-type recovery (a fixed-size type ⇒ a lower
    bound) — an ASSUMPTION about well-formed ABI input, reported as the distinct
    ``in_bounds_speculative`` verdict (never merged into the sound ``in_bounds``,
    never affecting ``proven_oob``). Needs the lift (puya); degrades to sound-only
    if the contract doesn't lower."""
    if run_passes:
        run_all_passes(prog)

    sites = [(a, acc) for a in prog.assignments if (acc := _access(a)) is not None]
    rel = LengthRelations(prog)
    _seed_all(rel, sites)

    # Speculative pass: a SEPARATE relational store seeded with the sound facts
    # PLUS recovered fixed-size lengths (lower bounds only). Queried for in-bounds
    # only, on sites the sound pass left unproven.
    rel_spec = None
    if speculative:
        from ..lift import to_puya_ir
        # Two speculative length sources, both LOWER bounds (never taint proven_oob):
        # the encoded-type recovery, and — additively, when the source carries it —
        # declared ABI arg lengths from `method "sig"` info (types the source
        # ApplicationArgs directly; takes precedence as the DECLARED contract).
        fixed = {**to_puya_ir.recovered_min_lengths(prog), **_abi_arg_lengths(prog)}
        if fixed:
            rel_spec = LengthRelations(prog)
            _seed_all(rel_spec, sites)
            for _a, (buf, _base, _c, _dyn) in sites:
                k = getattr(buf, "_key", None)
                if k is not None and k() in fixed:
                    rel_spec.seed_length_lb(buf, fixed[k()][0])

            def _spec_len(buf):
                k = getattr(buf, "_key", None)
                return fixed.get(k()) if k is not None else None

    out: list = []
    for a, (buf, base, extra_c, dynamic) in sites:
        spec = spec_conf = False
        if extra_c is None:
            in_bounds, proven_oob, reason = False, False, "offset+width unbounded"
        else:
            in_bounds, proven_oob = rel.verdict(
                buf, base, extra_c, a.basic_block, a.location.line)
            # Only an UNCONDITIONAL static over-read is a sound proven-OOB. A
            # dynamic-index over-read (e.g. reading element `i` of an empty
            # array) is mathematically OOB for every i>=0 yet is typically a
            # LOOP BODY guarded by `i < len` — unreachable when empty. Without
            # reachability we can't tell, so we keep only the index-independent
            # (constant offset+width) case as proven; the rest stays oob_risk.
            proven_oob = proven_oob and not dynamic
            if in_bounds:
                reason = "in-bounds (offset+width <= len)"
            elif proven_oob:
                reason = "OUT OF BOUNDS (offset+width > exact len)"
            elif rel_spec is not None and (
                    spec := rel_spec.verdict(
                        buf, base, extra_c, a.basic_block, a.location.line)[0]):
                sl = _spec_len(buf)
                spec_conf = bool(sl and sl[1])
                reason = "in-bounds ASSUMING well-formed ARC-4 (recovered length)"
            else:
                reason = "unproven (no relation offset+width <= len)"
        out.append(BoundsSite(a.op, a.location.line, in_bounds, proven_oob,
                              dynamic, reason, in_bounds_speculative=bool(spec),
                              speculative_confident=spec_conf))
    return out
