"""Decode each byte-access site into a ``(buffer, base, width)`` bound and ask
:mod:`.relational` whether ``offset + width <= len(buffer)``.

Operand order is TOP-FIRST: for the stack-arg ops the array is pushed FIRST, so
it is the LAST input (``inputs[-1]``), and the numeric args count down from
``inputs[0]``.

HAZARD: the three verdicts do NOT carry the same weight. ``in_bounds`` is a
proof. ``proven_oob`` is a proof too, but only against an UNAMBIGUOUS length (a
bytes literal) — never claim it off a possibly-under-counting ``byte_length``.
``oob_risk`` is a heuristic "couldn't prove it", not a detection; most such sites
are ordinary bounds-checked accesses. Reporting one as another is a false
verdict in either direction."""
from __future__ import annotations

from dataclasses import dataclass

from ..ssa import SSAProgram
from ..ssa.operands import const_int
from ..analysis import DerivedProfile, derived_program
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
        """A dynamic index we cannot prove in-bounds; a speculative proof clears it."""
        return self.dynamic and not self.in_bounds and not self.in_bounds_speculative


def _fold(base_operand, extra_c: int):
    """Collapse a constant base into the offset, leaving at most one symbolic term."""
    k = const_int(base_operand)
    if k is not None:
        return None, extra_c + k
    return base_operand, extra_c


def _access(a):
    """``(buffer, base | None, extra_c | None, dynamic)`` for a byte access, else
    ``None``. Reads up to byte ``value(base) + extra_c``; ``base is None`` means
    the constant ``extra_c`` alone, ``extra_c is None`` means unbounded."""
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


def _abi_arg_lengths(prog, method_table: "dict | None" = None) -> dict:
    """``{ssa_key: (byte_length, confident)}`` for ``txna ApplicationArgs N`` reads
    whose selector-pinned ABI method declares a fixed-size arg.

    HAZARD: a DECLARED length is not a checked one — the AVM router matches the
    selector only, so an attacker can send a short arg. These lengths are the
    well-formed-ABI ASSUMPTION and belong to the speculative tier alone. Returns
    ``{}`` (never raises) when no spec or source signature info exists."""
    try:
        return _abi_arg_lengths_impl(prog, method_table)
    except Exception:                          # an optional layer must never break bounds
        return {}


def _abi_arg_lengths_impl(prog, method_table: "dict | None" = None) -> dict:
    from ..metadata.abi import extract_method_table
    from ..cfg.path_predicates import PathPredicateAnalysis
    from ..ssa.operands import const_bytes

    if method_table:                           # authoritative ARC-56 spec wins
        table = method_table
    else:
        sources = getattr(prog, "sources", None)
        if sources is None:
            return {}
        texts = [unit.text() for unit in sources.files]
        if not texts:
            return {}
        text = "\n".join(texts)
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
        if n < 1:                              # index 0 is the selector
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


def check_bounds(prog: SSAProgram, *,
                 speculative: bool = False, arc56=None) -> list:
    """Every byte-access site with its in-bounds verdict.

    HAZARD: ``speculative`` assumes well-formed ARC-4 input, giving unproven
    buffers a length from type recovery. It reports through the separate
    ``in_bounds_speculative`` field and must never be merged into the sound
    ``in_bounds`` or allowed to affect ``proven_oob``."""
    # Bounds still consumes annotation-oriented relational helpers.  Give it a
    # guarded PRIVATE view; never let its assertion facts, aliases, or cleanup
    # rewrite the scan-shared canonical program.
    prog = derived_program(prog, DerivedProfile.GUARDED)

    sites = [(a, acc) for a in prog.assignments if (acc := _access(a)) is not None]
    rel = LengthRelations(prog)
    _seed_all(rel, sites)

    # A SEPARATE relational store, so speculative lengths can never leak into the
    # sound verdicts. Both speculative sources supply LOWER bounds only.
    rel_spec = None
    if speculative:
        from ..lift import to_puya_ir
        mtable = None
        if arc56 is not None:
            from ..metadata.arc56 import Arc56Spec, load_optional
            spec = arc56 if isinstance(arc56, Arc56Spec) else load_optional(arc56)
            mtable = spec.method_table() if spec is not None else None
        fixed = {**to_puya_ir.recovered_min_lengths(prog),
                 **_abi_arg_lengths(prog, mtable)}
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
        # ``substring A B`` panics unconditionally when A > B, whatever the
        # buffer length. Must be caught BEFORE the relational query, which only
        # checks B <= len and would call ``substring 8 4`` in-bounds on a
        # 4-byte buffer.
        if a.op == "substring":
            toks = (a.immediates or "").split()
            A = int(toks[0]) if len(toks) == 2 and toks[0].lstrip("-").isdigit() else None
            B = int(toks[1]) if len(toks) == 2 and toks[1].lstrip("-").isdigit() else None
            if A is not None and B is not None and A > B:
                out.append(BoundsSite(
                    a.op, a.location.line, False, True, False,
                    "OUT OF BOUNDS (substring start > end)"))
                continue
        if extra_c is None:
            in_bounds, proven_oob, reason = False, False, "offset+width unbounded"
        else:
            in_bounds, proven_oob = rel.verdict(
                buf, base, extra_c, a.basic_block, a.location.line)
            # HAZARD: only an index-INDEPENDENT over-read is a sound proven-OOB.
            # Reading element `i` of an empty array is OOB for every i>=0 yet is
            # typically a loop body guarded by `i < len`, hence never executed;
            # without reachability we cannot tell, so dynamic sites stay oob_risk.
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
