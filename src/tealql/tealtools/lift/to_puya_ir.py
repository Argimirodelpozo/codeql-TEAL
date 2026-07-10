"""Lower the pre-IR (:mod:`pre_ir`) to *real* ``puya.ir.models``, then render /
optimise with Puya's own renderer and optimiser passes (:func:`optimize`).

:func:`to_puya` rebuilds the pre-IR with genuine Puya classes, respecting what
Puya enforces: intrinsic args in AVM order (our top-first inputs reversed),
bottom-first multi-result outputs, every used register defined by identity, wired
predecessor lists, real ``IRType``/``AVMOp``, a ``SourceLocation`` per block --
plus the types the lift adds that TEAL lacks (polymorphic ``load`` /
``app_global_get``, and source-recovered ``TemplateVar``s).
"""
from __future__ import annotations

import copy
import logging

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.avm import AVMType
from puya.ir.types_ import AVMBytesEncoding, PrimitiveIRType as PT
from puya.parse import SourceLocation

from . import pre_ir
from . import _puya_compat as _compat
from .lift import _Lifter
from .teal_const import _const_bytes, _load_src, _tmpl_name
from ..ast.literals import tokenize_operands as _tokenize_operands

logger = logging.getLogger("tealql.tealtools.lift")

# Neutral encoding-kind string (from teal_const, puya-free) -> puya's enum.
# The mapping lives HERE, not in teal_const, so the detector-facing lift path
# stays importable without puya (see teal_const's module docstring).
_AVM_ENCODING = {
    "base16": AVMBytesEncoding.base16,
    "utf8": AVMBytesEncoding.utf8,
    "base64": AVMBytesEncoding.base64,
    "base32": AVMBytesEncoding.base32,
}


def _bytes_const(literal: str) -> "M.BytesConstant":
    """A puya ``BytesConstant`` from a TEAL byte literal — decodes via the
    puya-free ``_const_bytes`` and maps its neutral kind to the puya enum."""
    raw, kind = _const_bytes(literal)
    return M.BytesConstant(source_location=None, value=raw,
                           encoding=_AVM_ENCODING[kind])


_IRT = {
    "uint64": PT.uint64, "bytes": PT.bytes, "bool": PT.bool,
    "account": PT.account, "asset": PT.uint64, "application": PT.uint64,
    # Last-resort default for a type recovery could NOT resolve. Recovery aims
    # to leave none (interprocedural param/return/state/phi unification); any
    # residual `?` is logged by type_recovery._warn_residual_unknowns so this
    # silent uint64 fallback can't quietly mistype a bytes value.
    "?": PT.uint64,
}

# Const-push pseudo-ops that survive the lift only when their immediate was a
# deploy-time template variable (`pushint TMPL_X`) -- the parser strips the
# operand, leaving an arg-less, immediate-less push. Puya models these as
# TemplateVar (a non-foldable constant), so the optimiser won't fold them away.
_PUSH_U64 = {"pushint", "intc", "intc_0", "intc_1", "intc_2", "intc_3"}
_PUSH_BYTES = {"pushbytes", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3"}



def _make_const(operand: str, is_u64: bool):
    """A recovered operand string -> a Puya constant / template var, or None."""
    operand = operand.strip()
    if operand.startswith("TMPL_"):
        return M.TemplateVar(source_location=None, name=operand,
                             ir_type=PT.uint64 if is_u64 else PT.bytes)
    if is_u64:
        try:
            return M.UInt64Constant(source_location=None, value=int(operand, 0))
        except ValueError:
            return None
    return _bytes_const(operand)


#: ``intc_N`` / ``bytec_N`` -> the const-block index N they load.
_INDEXED = {f"{p}_{i}": i for p in ("intc", "bytec") for i in range(4)}


def _sl(line: int) -> SourceLocation:
    return SourceLocation(file=None, line=line or 1)


def _line_of(bb) -> int:
    c = bb.comment or ""
    return int(c[1:]) if c.startswith("L") and c[1:].isdigit() else 1


class _Translator:
    def __init__(self, src_map: dict | None = None):
        self.regs: dict = {}      # id(pre-IR Register) -> M.Register
        self.blocks: dict = {}    # pre-IR block id -> M.BasicBlock
        self.subs: dict = {}      # pre-IR Subroutine.id -> M.Subroutine
        self.src: dict = src_map or {}
        self._block_cache: dict = {}   # (kind, line) -> recovered const block

    def ty(self, s):
        return _IRT.get(s, PT.uint64)

    def reg(self, r):
        k = id(r)
        if k not in self.regs:
            self.regs[k] = M.Register(
                source_location=None, ir_type=self.ty(r.ir_type),
                name=r.name, version=r.version)
        return self.regs[k]

    def val(self, v):
        if isinstance(v, pre_ir.Register):
            return self.reg(v)
        if isinstance(v, pre_ir.UInt64Constant):
            return M.UInt64Constant(source_location=None, value=v.value)
        if isinstance(v, pre_ir.BytesConstant):
            return _bytes_const(v.value or "0x")
        if isinstance(v, pre_ir.Undefined):
            return M.Undefined(source_location=None, ir_type=PT.uint64)
        raise TypeError(f"val: {type(v).__name__}")

    @staticmethod
    def _imm(i):
        s = str(i)
        return int(s) if s.lstrip("-").isdigit() else s

    def _src_lines(self) -> list:
        """The single source program's lines, or [] if ambiguous/absent."""
        return next(iter(self.src.values())) if len(self.src) == 1 else []

    def _operands_at(self, line: int) -> list:
        """Operand tokens on source ``line`` (after the opcode)."""
        lines = self._src_lines()
        if not (line and 1 <= line <= len(lines)):
            return []
        parts = lines[line - 1].strip().split(None, 1)
        return _tokenize_operands(parts[1]) if len(parts) == 2 else []

    def _const_block(self, kind: str, line: int) -> list:
        """The ``intcblock`` / ``bytecblock`` operand list in scope at ``line``
        (the latest definition at or before it), recovered from source. The
        parser truncates these blocks (drops ``TMPL_*`` / encoded entries),
        so the SSA can't resolve ``bytec N`` into a dropped slot -- source can."""
        key = (kind, line)
        if key in self._block_cache:
            return self._block_cache[key]
        op = kind + "block"
        best: list = []
        for idx, text in enumerate(self._src_lines(), start=1):
            t = text.strip()
            if t.startswith(op + " ") and (not line or idx <= line):
                best = _tokenize_operands(t[len(op):])
        self._block_cache[key] = best
        return best

    def _block_value(self, op_name: str, idx: int, line: int):
        """Resolve an ``intc_N`` / ``bytec_N`` / ``intc N`` / ``bytec N`` load
        whose const-block slot the parser dropped, from the source block."""
        kind = "intc" if op_name.startswith("intc") else "bytec"
        entries = self._const_block(kind, line)
        if 0 <= idx < len(entries):
            return _make_const(entries[idx], is_u64=(kind == "intc"))
        return None

    def vp(self, s, result_types=None):
        if isinstance(s, pre_ir.Intrinsic):
            # const-load by index (intc_N / bytec_N / `intc N` / `bytec N`)
            # whose const-block slot the parser dropped -> recover from source.
            idx = None
            if s.op in ("bytec", "intc") and len(s.immediates) == 1 and not s.args:
                idx = int(self._imm(s.immediates[0]))
            elif s.op in _INDEXED and not s.args:
                idx = _INDEXED[s.op]
            if idx is not None:
                v = self._block_value(s.op, idx, s.line)
                if v is not None:
                    return v
            # const-push whose inline operand the parser dropped (e.g.
            # `pushbytes base64(..)`): recover the literal, else a template var.
            if (s.op in _PUSH_U64 or s.op in _PUSH_BYTES) and not s.args \
                    and not s.immediates:
                is_u64 = s.op in _PUSH_U64
                ops = self._operands_at(s.line)
                if ops and not ops[0].startswith("TMPL_"):
                    v = _make_const(ops[0], is_u64)
                    if v is not None:
                        return v
                name = ops[0] if ops else _tmpl_name(self.src, s.line)
                return M.TemplateVar(source_location=None, name=name,
                                     ir_type=PT.uint64 if is_u64 else PT.bytes)
            kw = {} if result_types is None else {"types": result_types}
            return M.Intrinsic(
                source_location=None, op=AVMOp(s.op),
                immediates=[self._imm(i) for i in s.immediates],
                args=[self.val(a) for a in reversed(s.args)], **kw)
        if isinstance(s, pre_ir.InvokeSubroutine):
            # Subroutine args are positional (args[i] -> param i), NOT AVM-order
            # like Intrinsic args -- Puya builds them `for param in parameters`.
            return M.InvokeSubroutine(
                source_location=None, target=self.subs[s.target],
                args=[self.val(a) for a in s.args])
        if isinstance(s, pre_ir.ValueTuple):
            return M.ValueTuple(source_location=None,
                                values=[self.val(v) for v in s.values])
        return self.val(s)

    def op(self, o):
        if isinstance(o, pre_ir.Assignment):
            # Multi-const push (`pushbytess` / `pushints`) whose inline operands
            # the parser dropped: Puya has no such op, so split into one
            # `let target_i = <const_i>` per value (targets reversed to source
            # order). Recovered from source; only when counts line up.
            src = o.source
            if isinstance(src, pre_ir.Intrinsic) and src.op in ("pushbytess", "pushints") \
                    and not src.args:
                ops = self._operands_at(src.line)
                tgts = [self.reg(t) for t in o.targets][::-1]
                is_u64 = src.op == "pushints"
                if ops and len(ops) == len(tgts):
                    out = []
                    for tgt, operand in zip(tgts, ops):
                        out.append(M.Assignment(source_location=None, targets=[tgt],
                                                source=_make_const(operand, is_u64)))
                    return out
            targets = [self.reg(t) for t in o.targets]
            # Our outputs are top-first; Puya intrinsics return bottom-first
            # (AVM order), so a multi-output intrinsic's targets/types reverse.
            if isinstance(o.source, pre_ir.Intrinsic) and len(targets) > 1:
                targets = targets[::-1]
            return M.Assignment(
                source_location=None, targets=targets,
                source=self.vp(o.source, [t.ir_type for t in targets]))
        if isinstance(o, pre_ir.IntrinsicOp):
            if isinstance(o.intrinsic, pre_ir.Intrinsic) and o.intrinsic.op in (
                    "pop", "popn", "pushbytess", "pushints"):
                # pop/popn discard; a 0-output pushbytess/pushints is a phantom
                # push (operands dropped by the parser) whose values, if used,
                # are recovered elsewhere (e.g. match keys from source) -- no-op.
                return None
            return self.vp(o.intrinsic)          # side-effecting intrinsic = an Op
        if isinstance(o, pre_ir.Assert):
            return M.Assert(source_location=None, condition=self.val(o.condition),
                            message=o.message or "assert", explicit=True)
        raise TypeError(f"op: {type(o).__name__}")

    def _u64_cond(self, v):
        """A branch selector must be uint64. A bytes *constant* there is a
        reconstruction artifact for an undefined value -> a sensible uint64."""
        c = self.val(v)
        if isinstance(c, M.BytesConstant):
            return M.UInt64Constant(source_location=None,
                                    value=int.from_bytes(c.value[-8:], "big") if c.value else 0)
        return c

    def ctrl(self, t):
        B = self.blocks
        if isinstance(t, pre_ir.Goto):
            return M.Goto(source_location=None, target=B[t.target])
        if isinstance(t, pre_ir.ConditionalBranch):
            return M.ConditionalBranch(
                source_location=None, condition=self._u64_cond(t.condition),
                non_zero=B[t.non_zero], zero=B[t.zero])
        if isinstance(t, pre_ir.GotoNth):
            return M.GotoNth(source_location=None, value=self._u64_cond(t.value),
                             blocks=[B[b] for b in t.blocks], default=B[t.default])
        if isinstance(t, pre_ir.Switch):
            val = self.val(t.value)
            is_u64 = getattr(val, "ir_type", None) == PT.uint64
            cases = {}
            for lbl, blk in t.cases:
                if is_u64:                       # uint64-keyed match (e.g. OnCompletion)
                    key = M.UInt64Constant(source_location=None, value=int(str(lbl), 0))
                else:
                    key = _bytes_const(str(lbl))
                cases[key] = B[blk]
            return M.Switch(source_location=None, value=val,
                            cases=cases, default=B[t.default])
        if isinstance(t, pre_ir.SubroutineReturn):
            return M.SubroutineReturn(source_location=None,
                                      result=[self.val(v) for v in t.result])
        if isinstance(t, pre_ir.ProgramExit):
            r = self.val(t.result)
            # A constant-0 program exit is an unconditional reject. Puya's MIR
            # rewrites `exit 0` to `err` ("simplifying exit 0 to err") as a *new
            # explicit* check, which its TEAL optimiser then folds into the
            # surrounding `assert` -- tripping the "explicit condition check(s)
            # removed" invariant. Emit the reject as a non-explicit Fail directly
            # (same on-chain outcome -- both fail the txn) so the fold is allowed.
            if isinstance(r, M.UInt64Constant) and r.value == 0:
                return M.Fail(source_location=None, error_message="reject", explicit=False)
            return M.ProgramExit(source_location=None, result=r)
        if isinstance(t, pre_ir.Fail):
            # NOT explicit: a reconstructed reject/err path is control flow, not a
            # user-written check. Puya's TEAL optimiser legitimately folds
            # ``goto cond ? body : err`` into an equivalent ``assert cond`` (an
            # err-branch IS an assert) -- behaviourally identical -- but if the Err
            # were `explicit` that fold would drop it and trip Puya's "explicit
            # condition check(s) removed" invariant. (Assert above stays explicit so
            # a genuinely-dropped assert still surfaces rather than silently going.)
            return M.Fail(source_location=None,
                          error_message=t.error_message or "err", explicit=False)
        raise TypeError(f"ctrl: {type(t).__name__}")

    def phi(self, p):
        # One arg per predecessor: when a block reaches a successor by >1 edge
        # (e.g. two switch cases -> same target) the CFG-derived predecessor set
        # holds it once, but our phi has one arg per edge -> dedup by `through`
        # (the duplicate edges carry the same value).
        seen, args = set(), []
        for a in p.args:
            if not isinstance(a.value, pre_ir.Register) or a.through in seen:
                continue
            seen.add(a.through)
            args.append(M.PhiArgument(value=self.reg(a.value),
                                      through=self.blocks[a.through]))
        return M.Phi(register=self.reg(p.register), args=args)

    def subroutine(self, s):
        params = []
        for pp in s.parameters:
            par = M.Parameter(source_location=None, ir_type=self.ty(pp.register.ir_type),
                              name=pp.register.name, version=pp.register.version,
                              implicit_return=False)
            self.regs[id(pp.register)] = par     # param IS the register (identity)
            params.append(par)
        return params


def _term_targets(term):
    if isinstance(term, pre_ir.Goto):
        return [term.target]
    if isinstance(term, pre_ir.ConditionalBranch):
        return [term.non_zero, term.zero]
    if isinstance(term, pre_ir.GotoNth):
        return [*term.blocks, term.default]
    if isinstance(term, pre_ir.Switch):
        return [b for _, b in term.cases] + [term.default]
    return []


def _retarget_terminator(term, old: int, new: int) -> None:
    """Rewrite every ``old`` block-id target in ``term`` to ``new`` (in place)."""
    if isinstance(term, pre_ir.Goto):
        if term.target == old:
            term.target = new
    elif isinstance(term, pre_ir.ConditionalBranch):
        if term.non_zero == old:
            term.non_zero = new
        if term.zero == old:
            term.zero = new
    elif isinstance(term, pre_ir.GotoNth):
        term.blocks = [new if b == old else b for b in term.blocks]
        if term.default == old:
            term.default = new
    elif isinstance(term, pre_ir.Switch):
        term.cases = [(lbl, new if b == old else b) for lbl, b in term.cases]
        if term.default == old:
            term.default = new


def _duplicate_shared_epilogues(lifted):
    """Tail-duplicate a shared "epilogue" block reached by direct branches from
    more than one routine. Puya requires each block to belong to exactly one
    subroutine, but a compiler-shared exit block (e.g. a common ``exit 0`` reject
    that many handlers AND a subroutine's body jump to) is branched to from
    several routines -- so Puya's Subroutine validator rejects it ("predecessor
    block(s) outside of list").

    Only a PURE CONTROL SINK is duplicated: no phis, no ops, a terminal
    terminator (no successor blocks), and no register operands -- so there is
    nothing to merge or thread across the routine boundary and each consuming
    routine can get its own independent, identical copy. The shared original is
    removed and replaced by one fresh-id clone per caller routine, with that
    routine's edges retargeted to its clone. A block carrying any value is left
    untouched (it needs real tail-duplication with phi splitting, not done here).
    No-op for the overwhelmingly common case of no cross-routine-shared sink."""
    groups = [lifted.main, *lifted.subroutines]
    block_by_id = {bb.id: bb for g in groups for bb in g.body}
    if not block_by_id:
        return
    next_id = max(block_by_id) + 1

    def is_pure_sink(bb) -> bool:
        return (not bb.phis and not bb.ops
                and not _term_targets(bb.terminator)            # terminal
                and not any(isinstance(o, pre_ir.Register)
                            for o in pre_ir.operands(bb.terminator)))

    callers: dict = {}                       # block id -> caller groups (ordered, distinct)
    for g in groups:
        for bb in g.body:
            for succ in _term_targets(bb.terminator):
                lst = callers.setdefault(succ, [])
                if not any(cg is g for cg in lst):
                    lst.append(g)

    for bid, caller_groups in list(callers.items()):
        bb = block_by_id.get(bid)
        if bb is None or len(caller_groups) <= 1 or not is_pure_sink(bb):
            continue
        for g in groups:                     # drop the shared original
            if bb in g.body:
                g.body.remove(bb)
        for g in caller_groups:              # one private clone per caller routine
            clone = pre_ir.BasicBlock(id=next_id, phis=[], ops=[],
                                      terminator=copy.copy(bb.terminator),
                                      comment=bb.comment)
            next_id += 1
            g.body.append(clone)
            for src in g.body:
                _retarget_terminator(src.terminator, bid, clone.id)


def to_puya(prog):
    """SSAProgram -> (main, subroutines) as real puya.ir.models objects.

    Wraps :func:`_to_puya_impl` so a lowering failure surfaces as a typed
    :class:`tealql.tealtools.errors.LiftError` (stage ``"lower"``) with the cause
    chained. A ``LiftError`` from the inner build stage passes through with its
    original stage intact."""
    from ..errors import LiftError
    try:
        return _to_puya_impl(prog)
    except LiftError:
        raise
    except Exception as e:
        raise LiftError(f"{type(e).__name__}: {e}", stage="lower") from e


def _to_puya_impl(prog):
    main, subs, _lifter, _t = _to_puya_full(prog)
    return main, subs


def _to_puya_full(prog):
    """The full lower, additionally returning the ``lifter`` (SSAVar -> pre_ir
    Register maps) and ``t`` translator (id(pre_ir Register) -> M.Register), so a
    caller can bridge an SSA value to its lowered puya register (see
    :func:`recovered_fixed_lengths`). :func:`to_puya` returns only ``(main, subs)``."""
    # Pre-lift scratch simplification: forward compile-time-constant scratch loads to
    # their literal so the lift emits the constant directly. propagate_scratch_constants
    # only rewires the LOAD's consumers -- it KEEPS the store, which stays
    # gload-readable cross-group, so this is behaviour-preserving even for grouped
    # contracts (verified by the behavioural dryrun, incl. the gload contracts). This
    # reaches scratch (slot) redundancy Puya's context-free optimiser can't: its
    # slot_elimination is omitted because scratch isn't a sound local -- a `gload i N`
    # in a SIBLING program can read a slot this program never reads locally.
    try:
        prog.propagate_constants()
        prog.propagate_scratch_constants()
    except Exception as e:
        logger.debug("pre-lift scratch const-propagation skipped: %s", e)
    # Build via the lifter directly (not `lift()`) so we keep its SSAVar->Register
    # map for the byte-length sized-bytes bridge below.
    lifter = _Lifter(prog)
    lifted = lifter.build()
    # Collapse trivial / self-referential phis (`r = phi(r)`) before lowering:
    # Puya's own copy_propagation asserts on these (it can't represent a
    # register replaced by itself), but our reconstruction can emit them.
    from .transforms import simplify_trivial_phis
    simplify_trivial_phis(lifted)
    _duplicate_shared_epilogues(lifted)
    t = _Translator(_load_src(getattr(prog, "source_path", "")))
    groups = [lifted.main, *lifted.subroutines]

    # Pass 1: shells (empty body validates trivially), so control ops and
    # InvokeSubroutine can reference real block / subroutine objects.
    for s in groups:
        for bb in s.body:
            t.blocks[bb.id] = M.BasicBlock(source_location=_sl(_line_of(bb)),
                                           id=bb.id, ops=[], terminator=None)
    for s in lifted.subroutines:
        t.subs[s.id] = M.Subroutine(id=s.id, short_name=s.id, source_location=None,
                                    parameters=[], returns=[t.ty(r) for r in s.returns],
                                    body=[], inline=None)

    # Pass 2: fill registers / ops / terminators.
    main_body = None
    for s in groups:
        params = t.subroutine(s)
        for bb in s.body:
            mb = t.blocks[bb.id]
            mb.phis = [t.phi(p) for p in bb.phis]
            mb.ops = []
            for o in bb.ops:                     # op() may split into a list
                m = t.op(o)
                if m is None:
                    continue
                mb.ops.extend(m) if isinstance(m, list) else mb.ops.append(m)
            mb.terminator = t.ctrl(bb.terminator) if bb.terminator else None
        body = [t.blocks[bb.id] for bb in s.body]
        if s.is_main:
            main_body = body
        else:
            t.subs[s.id].parameters = params
            t.subs[s.id].body[:] = body

    # Pass 3: wire predecessors from the CFG edges (Puya validates these).
    for s in groups:
        for bb in s.body:
            mb = t.blocks[bb.id]
            for succ in _term_targets(bb.terminator):
                t.blocks[succ]._predecessors[mb] = None

    main = M.Subroutine(id=lifted.main.id, short_name="main", source_location=None,
                        parameters=[], returns=[], body=main_body, inline=None)
    subs = [t.subs[s.id] for s in lifted.subroutines]
    # Run byte-length propagation AFTER the lift (so it can't perturb the lift's
    # own coarse typing) and bridge the exact lengths into the recovery.
    try:
        prog.propagate_byte_lengths()
        bytelen = _byte_length_map(lifter, t)
    except Exception as e:
        logger.debug("byte-length sized-bytes bridge skipped: %s", e)
        bytelen = {}
    _recover_ir_types(main, subs, byte_lengths=bytelen)
    _recover_encoded_types(main, subs)
    return main, subs, lifter, t


def recovered_min_lengths(prog) -> dict:
    """``{ssa_key: (min_bytes, confident)}`` — a LOWER bound on the byte length of
    every SSA value the SPECULATIVE ARC-4 recovery gives an encoded type: a
    FIXED-size type (``arc4.Address`` -> 32, ``arc4.Bool`` -> 1, a static
    struct/array -> its total) contributes ``num_bytes``; a DYNAMIC (length-
    prefixed / offset-table) type contributes ``2`` — every well-formed dynamic
    ARC-4 value has at least a 2-byte length/offset head. Bridges the guess —
    keyed by the lowered ``M.Register`` — back to the SSA value via the lift's
    ``SSAVar -> pre_ir.Register`` and translator's ``id(pre_ir.Register) ->
    M.Register`` maps. ``confident`` is the recovery's own confidence (a forced
    idiom vs a shape that merely fits). This is an ASSUMPTION about well-formed ABI
    input, not a proof — the consumer (``dataflow.bounds``) reports any bound it
    enables as a distinct *speculative* verdict.

    Keyed by the SSA value's STABLE identity (``_key()`` = ``(file, line, index)``,
    not ``id()``) so the result maps onto a caller's own SSAProgram, and lifts a
    FRESH copy off ``prog.source_path`` (the lift mutates its input CFG) to keep the
    caller's program pristine. ``{}`` if the contract doesn't lower (puya absent /
    lift failure) or has no source path; never raises."""
    from ..ssa import SSAProgram
    src_path = str(getattr(prog, "source_path", "") or "")
    if not src_path:
        return {}
    try:
        fresh = SSAProgram(src_path)
        main, subs, lifter, t = _to_puya_full(fresh)
        guesses, confident = guess_encoded_types_scored(main, subs)
    except Exception as e:
        logger.debug("recovered_fixed_lengths: lower/recover skipped: %s", e)
        return {}
    reg_src: dict = {}
    reg_src.update(getattr(lifter, "regs", {}))
    reg_src.update(getattr(lifter, "frame_map", {}))
    out: dict = {}
    for ssa_val, pre in reg_src.items():
        key = getattr(ssa_val, "_key", None)
        if key is None:
            continue
        k = key()
        m = t.regs.get(id(pre))
        if m is None:
            continue
        g = guesses.get(id(m))
        if g is None:
            continue
        nb = getattr(g, "num_bytes", None)
        nb = 2 if nb is None else nb            # dynamic ⇒ >= 2-byte head
        prev = out.get(k)
        if prev is None or nb < prev[0]:        # disagreement: keep the SMALLER
            out[k] = (nb, bool(confident.get(id(m))))
    return out


def _byte_length_map(lifter, t) -> dict:
    """``{id(M.Register): exact_byte_length}`` composed from the lift's
    ``SSAVar -> pre_ir.Register`` maps and the translator's
    ``id(pre_ir.Register) -> M.Register`` map, for every SSA value the byte-length
    pass gave a known *exact* length. A register fed by SSA values of disagreeing
    exact lengths is dropped (ambiguous -> stays plain ``bytes``)."""
    out: dict = {}
    conflict: set = set()
    src: dict = {}
    src.update(lifter.regs)
    src.update(lifter.frame_map)
    for o, pre in src.items():
        ty = getattr(o, "type", None)
        bl = getattr(ty, "byte_length", None) if ty is not None else None
        if bl is None or getattr(ty, "kind", None) != "bytes":
            continue
        m = t.regs.get(id(pre))
        if m is None:
            continue
        key = id(m)
        if key in conflict:
            continue
        if key in out and out[key] != bl:
            del out[key]
            conflict.add(key)
        else:
            out[key] = bl
    return out


# Refined IR types we restore from Puya's langspec when the recovery flattened
# them to the coarse AVM divide. Each is INTERCHANGEABLE with its AVM base (same
# `avm_type`, no reinterpret cast in Puya's IR), so retyping is a pure precision
# refinement Puya's intrinsic validator (which checks `avm_type`) accepts:
#   bool      <- uint64  (a 0/1 result: cmp / verify / opted-in / getbit / ...)
#   biguint   <- bytes   (big-endian unbounded int: b+ b- b* b/ b% bsqrt)
#   account   <- bytes   (32-byte address: txn Sender, global ZeroAddress, ...)
#   bytes[N]  <- bytes   (a SizedBytesType: itob -> bytes[8], hashes -> bytes[32],
#                         sumhash/vrf -> bytes[64], txn TxID -> bytes[32], ...)
# Sized bytes were initially assumed unsafe (a hash/itob result folding into the
# generic `bytes` webs it flows through). Measured instead: with them on, the
# corpus + backend gate stays green AND the lowered TEAL is byte-identical (they
# share `avm_type=bytes`, so it's a pure annotation -- proven by diffing the
# backend output), and it matches Puya's own genuine IR more closely. So they're
# included; the guard below keeps any refinement on the same side of the AVM
# divide, so a langspec `bytes[32]` is only ever applied over a `bytes` (never a
# uint64 the recovery may have mislabelled -- that stays for the encoder to flag).
_REFINED_IR_TYPES = frozenset({PT.bool, PT.biguint, PT.account})

# The coarse base types the recovery leaves; only these get refined (never an
# already-specific type, and never `any`, which is strictly less specific).
_COARSE_BASE = frozenset({PT.uint64, PT.bytes})


def _is_refinable(rt) -> bool:
    """A langspec return type worth restoring: one of the interchangeable refined
    primitives, or any fixed-width ``SizedBytesType`` (all bytes-backed)."""
    from puya.ir.types_ import SizedBytesType
    return rt in _REFINED_IR_TYPES or isinstance(rt, SizedBytesType)


def _langspec_returns(intrinsic: "M.Intrinsic"):
    """Authoritative return IRTypes (bottom-first, matching Puya's target order)
    for an Intrinsic, from Puya's own ``AVMOpData`` signature -- resolving a
    field-keyed dynamic op (``global``/``txn``/...) by its immediate. ``None`` if
    the op has no static signature (or the immediate doesn't select a variant)."""
    from puya.ir.avm_ops_models import DynamicVariants, Variant
    v = _compat.langspec_variants(intrinsic.op)
    if isinstance(v, Variant):
        return v.signature.returns
    if isinstance(v, DynamicVariants):
        imms = intrinsic.immediates
        if imms and v.immediate_index < len(imms):
            var = v.variant_map.get(str(imms[v.immediate_index]))
            if var is not None:
                return var.signature.returns
    return None


def _address_operand_identities(main, subs) -> set:
    """The SSA identities ``(name, version)`` of every value FED to an operand the
    AVM REQUIRES to be a 32-byte address: the operand of ``itxn_field <F>`` for an
    account-typed field, or the account operand (``args[0]``) of a local-state /
    account-parameter op. Only ``bytes``-form operands are taken -- the same ops
    also accept a ``uint64`` account INDEX (0=sender, i=Accounts[i-1]), which is
    not an address -- so the ``avm_type == bytes`` filter keeps this sound."""
    out: set = set()
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic) or not src.args:
                    continue
                r = None
                if src.op is AVMOp.itxn_field and src.immediates \
                        and str(src.immediates[0]).strip() in _ACCOUNT_TXN_FIELDS:
                    r = src.args[0]
                elif src.op in _ACCOUNT_OPERAND_OPS:
                    r = src.args[0]
                if isinstance(r, M.Register) \
                        and r.ir_type.avm_type == PT.account.avm_type:
                    out.add((r.name, r.version))
    return out


def _recover_ir_types(main, subs, allow=_is_refinable, byte_lengths=None) -> int:
    """Refine each intrinsic result register from the coarse AVM type the recovery
    left (``uint64``/``bytes``) to the finer IR type Puya's langspec declares for
    that op -- but only the interchangeable ones ``allow`` accepts (see
    :func:`_is_refinable`), and only when the finer type shares the current one's
    ``avm_type`` (so a refinement never crosses the AVM divide).

    ``byte_lengths`` (``{id(M.Register): N}``) additionally refines a still-plain
    ``bytes`` result to ``SizedBytesType(N)`` when the byte-length pass proved its
    exact length (``concat`` / ``extract`` / ``bzero`` / ``replace`` / a fixed-width
    field, etc.) -- the same ``avm_type``-preserving annotation as the langspec
    sized-bytes, just sourced from length analysis instead of the op's own return.
    The intrinsic's ``types`` tuple is rebuilt to match. Returns the count refined."""
    from puya.ir.types_ import SizedBytesType
    byte_lengths = byte_lengths or {}
    n = 0
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)):
                    continue
                changed = False
                rets = _langspec_returns(o.source)
                if rets is not None:
                    for tgt, rt in zip(o.targets, rets):
                        cur = tgt.ir_type
                        if (allow(rt) and cur in _COARSE_BASE
                                and rt.avm_type == cur.avm_type):
                            _compat.set_ir_type(tgt, rt)
                            changed = True
                            n += 1
                # Byte-length sized-bytes: refine a target the langspec left as
                # plain `bytes` when its exact length is known.
                for tgt in o.targets:
                    if tgt.ir_type is PT.bytes and id(tgt) in byte_lengths:
                        _compat.set_ir_type(tgt, SizedBytesType(byte_lengths[id(tgt)]))
                        changed = True
                        n += 1
                if changed:
                    # Keep the intrinsic's declared result types in sync with the
                    # refined targets (see _puya_compat.set_intrinsic_types).
                    _compat.set_intrinsic_types(
                        o.source, (t.ir_type for t in o.targets))

    # USAGE-BACKWARD account recovery: the langspec pass above types addresses
    # FORWARD from producer ops (txn Sender, global ZeroAddress). This types them
    # from CONSUMPTION -- a value fed to an AVM-forced address operand IS a 32-byte
    # account, so its plain-`bytes` intrinsic definition refines to `account`. Same
    # avm_type (bytes), so still a free annotation; the neutrality gate measures it.
    addr_ids = _address_operand_identities(main, subs)
    if addr_ids:
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    if not (isinstance(o, M.Assignment)
                            and isinstance(o.source, M.Intrinsic)):
                        continue
                    hit = False
                    for tgt in o.targets:
                        if tgt.ir_type is PT.bytes \
                                and (tgt.name, tgt.version) in addr_ids:
                            _compat.set_ir_type(tgt, PT.account)
                            n += 1
                            hit = True
                    if hit:
                        _compat.set_intrinsic_types(
                            o.source, (t.ir_type for t in o.targets))
    return n


def _static_byte_len(value, reg_def: dict):
    """The statically-known byte length of an IR value, or ``None``: a bytes
    constant's literal length, a ``SizedBytesType`` register's width, or a register
    defined by ``bzero N`` with a constant ``N``."""
    from puya.ir.types_ import SizedBytesType
    if isinstance(value, M.BytesConstant):
        return len(value.value)
    if isinstance(value, M.Register):
        if isinstance(value.ir_type, SizedBytesType):
            return value.ir_type.num_bytes
        d = reg_def.get(id(value))
        if (d is not None and isinstance(d.source, M.Intrinsic)
                and d.source.op is AVMOp.bzero and d.source.args
                and isinstance(d.source.args[0], M.UInt64Constant)):
            return d.source.args[0].value
    return None


def _static_encoding_elements(value):
    """The element ``Encoding`` list of ``value`` IF it is a *static* (fixed-size)
    ABI element -- so a ``concat`` of statics can be recognised as a static tuple --
    else ``None``. Flattens a tuple operand into its elements so nested binary
    concats build one flat N-tuple. Confident element sources only:

      - a static ``EncodedType`` register (``num_bytes`` known; a dynamic encoding
        uses the head/tail offset layout, not a plain concat, so it's excluded);
      - an ``account`` register -> ``arc4.Address`` (``StaticArray<Byte, 32>``):
        ``account`` is unambiguously a 32-byte address and arc4.Address IS that
        static byte array, wire-identical. (The account register itself stays
        ``account`` -- only its tuple-element encoding is taken here.)

    NOT included (would be guesses, belong in the speculative tier): a plain
    ``bytes[N]`` / a bytes constant reinterpreted as ``StaticArray<Byte, N>`` -- the
    raw bytes don't disambiguate a byte array from a uint128 / hash / selector."""
    from puya.ir.encodings import ArrayEncoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    if not isinstance(value, M.Register):
        return None
    t = value.ir_type
    if isinstance(t, EncodedType):
        if t.num_bytes is None:
            return None
        enc = t.encoding
        return list(enc.elements) if isinstance(enc, TupleEncoding) else [enc]
    if t is PT.account:
        return [ArrayEncoding(element=UIntEncoding(8), size=32, length_header=False)]
    return None


def _is_bool_encoding(enc) -> bool:
    from puya.ir.encodings import Bool8Encoding, BoolEncoding
    return isinstance(enc, (Bool8Encoding, BoolEncoding))


def _confident_encoding_for(intrinsic: "M.Intrinsic", reg_def: dict):
    """The ARC4 / ABI ``EncodedType`` a producing op's *result wire-encodes*, or
    ``None`` -- the **CONFIDENT** tier: only idioms whose byte layout unambiguously
    IS the ABI encoding (the "byte layout == the type" standard), so the recovered
    structured type is faithful to the bytes regardless of the source's intent.
    These are applied to ``ir_type`` by :func:`_recover_encoded_types` and are proven
    TEAL-neutral. The *speculative* counterpart -- idioms that need a length/offset
    proof or a confidence score (dynamic arrays / strings / dynamic tuples) -- lives
    entirely separately in :func:`_guess_encoding_for` / :func:`_guess_encoded_types`
    and never touches ``ir_type``; do NOT add a non-wire-provable idiom here.

    Recognised so far:
      - ``itob X`` -> ``arc4.UInt64`` (``UIntEncoding(64)``): ``itob`` emits exactly
        the big-endian 8-byte encoding, which IS the ABI ``uint64`` wire format.
      - ``setbit base 0 b`` where ``base`` is a single byte (``bzero 1`` / a 1-byte
        ``0x00`` constant) -> ``arc4.Bool`` (``Bool8Encoding``): this writes the bool
        into the high bit of a lone byte, the standalone ABI ``bool`` form.
      - ``concat A B`` where A and B are BOTH already-recovered *static* encoded
        types -> a static ``arc4.Tuple`` (``TupleEncoding``): a static ABI tuple's
        wire format IS exactly the concatenation of its element encodings (no length
        prefix, no head/tail offset table -- those appear only for *dynamic*
        elements). Nested binary concats flatten into one N-tuple. EXCLUDED: a
        bool|bool boundary (the ABI packs runs of bools into shared bits, so
        ``concat(bool8, bool8)`` is NOT the tuple form) -- a single bool adjacent to
        a non-bool is fine (one byte, which IS how a lone tuple bool encodes).

    Speculative idioms (dynamic arrays / strings / dynamic tuples) do NOT go here --
    see :func:`_guess_encoding_for`."""
    from puya.ir.encodings import Bool8Encoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    op = intrinsic.op
    if op is AVMOp.itob:
        return EncodedType(UIntEncoding(64))
    if op is AVMOp.setbit and len(intrinsic.args) == 3:
        base, index, _value = intrinsic.args
        if (isinstance(index, M.UInt64Constant) and index.value == 0
                and _static_byte_len(base, reg_def) == 1):
            return EncodedType(Bool8Encoding())
    if op is AVMOp.concat and len(intrinsic.args) == 2:
        le = _static_encoding_elements(intrinsic.args[0])
        re = _static_encoding_elements(intrinsic.args[1])
        if le and re and not (_is_bool_encoding(le[-1]) and _is_bool_encoding(re[0])):
            return EncodedType(TupleEncoding([*le, *re]))
    if op is AVMOp.extract and len(intrinsic.args) == 1 \
            and len(intrinsic.immediates) == 2:
        # `extract START LEN <uintN encoding>` taking the LOW K bytes (the extract
        # reaches the end: START + K == width) -> the narrower arc4.UInt(K*8): a
        # big-endian UIntK's wire form IS the trailing K bytes of the wider uint.
        # (`itob x` -> Encoded(uint64), then `extract 6 2` -> arc4.UInt16, etc.)
        start, length = intrinsic.immediates
        base = intrinsic.args[0]
        if (isinstance(start, int) and isinstance(length, int)
                and isinstance(base, M.Register)
                and isinstance(base.ir_type, EncodedType)
                and isinstance(base.ir_type.encoding, UIntEncoding)
                and base.ir_type.num_bytes is not None):
            total = base.ir_type.num_bytes
            k = length if length > 0 else total - start
            if 0 < k < total and start + k == total:
                return EncodedType(UIntEncoding(k * 8))
    return None


def _same_register(a, b) -> bool:
    """SSA-value identity for two IR operands: the same ``Register`` object, or
    two ``Register`` instances naming the same ``name#version`` (frozen-attrs
    rebuilds can produce distinct objects for one SSA value)."""
    return (a is b) or (
        isinstance(a, M.Register) and isinstance(b, M.Register)
        and (a.name, a.version) == (b.name, b.version)
    )


def _def_intrinsic(value, reg_def: dict, op) -> "M.Intrinsic | None":
    """``value``'s defining :class:`M.Intrinsic` when it is a register produced
    by ``op``, else ``None`` -- the one-step def-walk the guess idioms chain."""
    if not isinstance(value, M.Register):
        return None
    d = reg_def.get(id(value))
    if d is not None and isinstance(d.source, M.Intrinsic) and d.source.op is op:
        return d.source
    return None


def _is_uint16_of_len(prefix, data, reg_def: dict) -> bool:
    """PROOF that ``prefix`` is the big-endian uint16 of ``len(data)`` -- the ABI
    dynamic length header. Recognised prefix chains (all ending in
    ``itob(len(data))``, whose low two bytes ARE ``uint16(len(data))``):

      - ``extract 6 2 (itob (len data))``   (immediate form)
      - ``extract3 (itob (len data)) 6 2``  (stack form, constant 6/2)
      - ``substring 6 8 (itob (len data))`` (pre-v5 spelling)
    """
    itob_arg = None
    ex = _def_intrinsic(prefix, reg_def, AVMOp.extract)
    if ex is not None and list(ex.immediates) == [6, 2] and ex.args:
        itob_arg = ex.args[0]
    if itob_arg is None:
        ex3 = _def_intrinsic(prefix, reg_def, AVMOp.extract3)
        if (ex3 is not None and len(ex3.args) == 3
                and isinstance(ex3.args[1], M.UInt64Constant)
                and isinstance(ex3.args[2], M.UInt64Constant)
                and ex3.args[1].value == 6 and ex3.args[2].value == 2):
            itob_arg = ex3.args[0]
    if itob_arg is None:
        ss = _def_intrinsic(prefix, reg_def, AVMOp.substring)
        if ss is not None and list(ss.immediates) == [6, 8] and ss.args:
            itob_arg = ss.args[0]
    if itob_arg is None:
        return False
    itob = _def_intrinsic(itob_arg, reg_def, AVMOp.itob)
    if itob is None or not itob.args:
        return False
    ln = _def_intrinsic(itob.args[0], reg_def, AVMOp.len_)
    return ln is not None and bool(ln.args) and _same_register(ln.args[0], data)


def _guess_encoding_for(intrinsic: "M.Intrinsic", reg_def: dict):
    """The ARC4 / ABI ``EncodedType`` a producing op's result is *most likely* but
    NOT provably encoded as, or ``None`` -- the **SPECULATIVE** producer-side tier,
    kept deliberately separate from :func:`_confident_encoding_for`.

    The bar here: a guess needs a NAMED idiom with a discharged local proof, but
    the byte layout still isn't *self-evidently* one ABI type (a program could
    hand-roll the same shape for a non-ABI format), so it stays out of ``ir_type``.

    Recognised:
      - ``concat(P, D)`` where ``P`` is PROVEN to be ``uint16(len(D))``
        (:func:`_is_uint16_of_len` -- the ``extract 6 2 (itob (len D))`` chain and
        its spellings) -> the ARC4 dynamic-sequence ENCODE idiom:
        ``ArrayEncoding(byte, length_header=True)`` (``arc4.DynamicBytes``-shaped).
        ``arc4.String`` is this plus a UTF-8 claim the dataflow can't make -- the
        constant tier (:func:`_guess_const_encoding`) handles the provable-text
        case.

    Still to mine (documented, not implemented): ``bytes[N]`` reinterpreted as
    ``arc4.StaticArray<Byte, N>`` / ``arc4.Address`` -- 32 bytes don't
    disambiguate an address from a hash, so that needs usage evidence, not a
    producer idiom.

    Anything added here is best-effort: it is collected into a SIDE-CHANNEL by
    :func:`_guess_encoded_types` and never written to a register's ``ir_type``, so
    a wrong guess can neither change codegen nor weaken the confident, TEAL-neutral
    IR. (Consumers that tolerate imprecision -- e.g. structure-aware fuzzing --
    read the side-channel; a verifier would treat a guess as a
    proposed-and-discharged obligation.)"""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    if intrinsic.op is AVMOp.concat and len(intrinsic.args) == 2:
        prefix, data = intrinsic.args
        if _is_uint16_of_len(prefix, data, reg_def):
            return EncodedType(ArrayEncoding(
                element=UIntEncoding(8), size=None, length_header=True))
    return None


def _guess_const_encoding(raw: bytes):
    """A bytes CONSTANT that is a self-describing ``arc4.String`` literal, or
    ``None``. STRICT-PROOF, all checkable from the constant alone (no data-flow):

      - a 2-byte big-endian length prefix that provably equals the remaining length
        (``uint16(raw[:2]) == len(raw) - 2``) -- the arc4.String / dynamic-array wire
        shape;
      - a non-empty payload that decodes as UTF-8;
      - NO embedded null byte; and the decoded text is PRINTABLE.

    The no-null + printable rules are what make it strict: a length-consistent
    constant whose payload parses as UTF-8 only because it is full of ``0x00`` (a
    zero buffer), contains its own inner length prefix (a NESTED structure, e.g.
    ``<13><0x000b "Hello World">``), or is control-byte binary (``0x010204``) is
    rejected -- a real flat text string is printable and almost never carries
    embedded nulls. Combined with the ~1/65536 odds of a random prefix matching, a
    survivor is very likely a genuine ``arc4.String``.

    Still a guess (a constant *could* coincidentally be a self-describing UTF-8 blob),
    so it lives only in the speculative side-channel, never in ``ir_type``."""
    from puya.ir.encodings import UTF8Encoding
    from puya.ir.types_ import EncodedType
    if len(raw) < 3 or int.from_bytes(raw[:2], "big") != len(raw) - 2:
        return None
    payload = raw[2:]
    if b"\x00" in payload:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():        # reject control-byte binary (e.g. 0x010204)
        return None
    return EncodedType(UTF8Encoding())


def _guess_decoded_dynamic(main, subs) -> dict:
    """Recognise a value being DECODED as a uint16-length-prefixed dynamic
    array/string and map it to the right ``arc4.DynamicArray<T>``: ``{id(Register):
    EncodedType}``.

    PROVABLE decode shape (#3): a value ``X`` is decoded that way when it is BOTH
      - read at offset 0 as a uint16 -- the length prefix, ``extract_uint16 X 0`` --
        AND
      - has its payload taken with ``extract X 2 0`` (start 2, length 0 = TO-END):
        strip the 2-byte length prefix, take the rest.
    The to-end payload extract is what makes it the canonical dynamic decode (a
    fixed-length slice from offset 2 would be a struct field, not a dynamic array),
    so this is much tighter than a bare ``slice-from-2`` co-occurrence.

    ELEMENT type (#1/#2): inferred from how the payload (the ``extract X 2 0``
    result -- or ``X`` itself, for the offset table) is then accessed:
      - ``extract_uint64`` -> ``DynamicArray<UInt64>``, ``extract_uint32`` -> ``<UInt32>``;
      - ``extract_uint16`` whose result is used as a slice START (an OFFSET into
        the head/tail layout) -> the elements are DYNAMIC: ``DynamicArray<DynamicBytes>``
        (the offset-table signature -- a dynamic tuple/array-of-dynamics; the exact
        element types are #3's full reconstruction, this is the approximation);
      - ``extract_uint16`` whose result is used as a VALUE -> ``DynamicArray<UInt16>``;
      - else ``Byte`` (a string / dynamic bytes).
    The uint16 value-vs-offset split (#2) is what resolves the ambiguity that left
    every uint16-accessed payload as ``Byte`` before.

    Uniquely valuable because it types INPUTS the producer-side recovery can't reach
    (``txna ApplicationArgs N`` / sub params). Best-effort (a struct whose first
    field is a uint16 and rest is a tail could still match), so side-channel only."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    len_read: set = set()        # id(X): extract_uint16(X, 0)  -- the count/length
    payload_of: dict = {}        # id(X): the `extract X 2 0` (to-end) result register
    elem_bits: dict = {}         # id(base): 64/32 from extract_uint64/32 chunking
    u16_elem: dict = {}          # id(base): [result id] for extract_uint16 at offset != 0
    slice_starts: set = set()    # id(reg) used as a slice START of extract3/substring3
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)):
                    continue
                src = o.source
                a = src.args
                if src.op is AVMOp.extract_uint16 and len(a) == 2 \
                        and isinstance(a[0], M.Register):
                    if isinstance(a[1], M.UInt64Constant) and a[1].value == 0:
                        len_read.add(id(a[0]))             # the count / length prefix
                    elif o.targets:                        # an element / offset read
                        u16_elem.setdefault(id(a[0]), []).append(id(o.targets[0]))
                elif (src.op is AVMOp.extract and a and isinstance(a[0], M.Register)
                        and len(src.immediates) >= 2 and src.immediates[0] == 2
                        and src.immediates[1] == 0 and o.targets):
                    payload_of[id(a[0])] = o.targets[0]
                elif (src.op is AVMOp.extract_uint64 and a
                        and isinstance(a[0], M.Register)):
                    elem_bits[id(a[0])] = 64
                elif (src.op is AVMOp.extract_uint32 and a
                        and isinstance(a[0], M.Register)):
                    elem_bits.setdefault(id(a[0]), 32)
                if src.op in (AVMOp.extract3, AVMOp.substring3) and len(a) >= 2 \
                        and isinstance(a[1], M.Register):
                    slice_starts.add(id(a[1]))
    def _dyn(element):
        return EncodedType(
            ArrayEncoding(element=element, size=None, length_header=True))
    dyn_byte = UIntEncoding(8)
    out: dict = {}
    for rid in len_read:
        pay = payload_of.get(rid)
        if pay is None:
            continue
        bases = (rid, id(pay))
        u16 = [r for b in bases for r in u16_elem.get(b, [])]
        bits = elem_bits.get(id(pay)) or elem_bits.get(rid)
        if any(r in slice_starts for r in u16):       # offset table -> dynamic elements
            out[rid] = _dyn(ArrayEncoding(
                element=dyn_byte, size=None, length_header=True))
        elif bits:                                    # static wide chunks
            out[rid] = _dyn(UIntEncoding(bits))
        elif u16:                                     # uint16 values -> UInt16 elements
            out[rid] = _dyn(UIntEncoding(16))
        else:                                         # string / dynamic bytes
            out[rid] = _dyn(dyn_byte)
    return out


def _guess_struct_encodings(main, subs, dynamic_guesses) -> dict:
    """Reconstruct a dynamic struct / dynamic *tuple* type from its decode, as
    ``{id(Register): EncodedType(TupleEncoding(...))}``.

    A value ``X`` is a struct (fixed-shape aggregate with >=1 dynamic field) when its
    head is read at MULTIPLE FIXED positions whose uint16 results are used as slice
    STARTS -- the offset table of a fixed shape (a dynamic ARRAY uses a count + a
    COMPUTED offset in a loop instead, so it's excluded here). Reconstruction:
      - ``extract_uint16(X, p_const)`` whose result is a slice start -> a DYNAMIC
        field at head position ``p`` (2-byte offset slot); its type is the bracket
        ``substring3(X, off_p, off_q)`` slice -- a NESTED struct (the bracket itself
        decoded as a struct) recurses, else a ``dynamic_guesses`` String/DynamicArray,
        else dynamic bytes;
      - ``extract_uintN(X, p_const)`` (used as a value) -> a static ``UIntN`` field;
      - fields ordered by head position, with any UNREAD head gap modeled as a
        ``uint8[gap]`` byte BLOB (we know the byte count from the positions, just not
        the type -- partial reconstruction, still useful).

    PARTIAL by nature (only decoded fields are seen; the tail beyond the last read is
    omitted), so speculative side-channel only -- never ``ir_type``."""
    from puya.ir.encodings import ArrayEncoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    slots: dict = {}             # id(X) -> {pos: (kind, head_size, info)}
    u16res: dict = {}            # id(result) -> (id(base), const pos or None)
    field_of: dict = {}          # id(offset result) -> field slice register
    slice_starts: set = set()
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)):
                    continue
                src = o.source
                a = src.args
                if src.op is AVMOp.extract_uint16 and len(a) == 2 \
                        and isinstance(a[0], M.Register) and o.targets:
                    pos = a[1].value if isinstance(a[1], M.UInt64Constant) else None
                    u16res[id(o.targets[0])] = (id(a[0]), pos)
                elif src.op is AVMOp.extract_uint64 and len(a) >= 2 \
                        and isinstance(a[0], M.Register) \
                        and isinstance(a[1], M.UInt64Constant):
                    slots.setdefault(id(a[0]), {}).setdefault(
                        a[1].value, ("static", 8, UIntEncoding(64)))
                elif src.op is AVMOp.extract_uint32 and len(a) >= 2 \
                        and isinstance(a[0], M.Register) \
                        and isinstance(a[1], M.UInt64Constant):
                    slots.setdefault(id(a[0]), {}).setdefault(
                        a[1].value, ("static", 4, UIntEncoding(32)))
                if src.op is AVMOp.substring3 and len(a) >= 2 \
                        and isinstance(a[1], M.Register):
                    slice_starts.add(id(a[1]))
                    if o.targets:
                        field_of[id(a[1])] = o.targets[0]
    for rid, (base, pos) in u16res.items():
        if pos is None:
            continue
        d = slots.setdefault(base, {})
        if rid in slice_starts:                      # offset slot -> dynamic field
            d[pos] = ("dyn", 2, rid)
        else:                                        # inlined uint16 value -> static field
            d.setdefault(pos, ("static", 2, UIntEncoding(16)))
    dyn_byte = ArrayEncoding(element=UIntEncoding(8), size=None, length_header=True)
    struct_bases = {
        b for b, sl in slots.items()
        if any(k == "dyn" for (k, _, _) in sl.values()) and len(sl) >= 2
    }
    memo: dict = {}                                  # id(base) -> TupleEncoding | None

    def _struct_enc(base, building):
        """The ``TupleEncoding`` reconstructed for a struct base, recursing on
        nested-struct fields (a dynamic field whose sliced-out value is itself
        decoded as a struct). ``None`` if the head reads are inconsistent."""
        if base in memo:
            return memo[base]
        if base in building:                         # cyclic (shouldn't happen) -> bail
            return None
        building = building | {base}
        fields = []
        expected = 0
        for pos in sorted(slots[base]):
            kind, size, info = slots[base][pos]
            if pos > expected:                       # unread head bytes -> byte blob
                fields.append(ArrayEncoding(
                    element=UIntEncoding(8), size=pos - expected, length_header=False))
            elif pos < expected:                     # overlapping reads -> inconsistent
                memo[base] = None
                return None
            if kind == "static":
                fields.append(info)
            else:                                    # dynamic field
                fld = field_of.get(info)
                nested = (_struct_enc(id(fld), building)
                          if fld is not None and id(fld) in struct_bases else None)
                if nested is not None:               # a NESTED struct field
                    fields.append(nested)
                elif fld is not None and id(fld) in dynamic_guesses:
                    fields.append(dynamic_guesses[id(fld)].encoding)
                else:
                    fields.append(dyn_byte)
            expected = pos + size
        enc = TupleEncoding(fields) if fields else None
        memo[base] = enc
        return enc

    out: dict = {}
    for base in struct_bases:
        enc = _struct_enc(base, set())
        if enc is not None:
            out[base] = EncodedType(enc)
    return out


def _guess_decoded_static_arrays(main, subs) -> dict:
    """Recognise a value DECODED as an ``arc4.StaticArray<UIntN, K>`` -- the
    consumer-side counterpart to :func:`_guess_static_arrays`. ``{id(Register):
    EncodedType}``.

    A value ``X`` is a static array when ALL of:
      - it is read only via same-width fixed-offset ``extract_uint64`` /
        ``extract_uint32`` (homogeneous element width ``w`` in {8, 4}) at >= 2
        distinct constant positions, each a multiple of ``w``;
      - it has NO ``extract_uint16(X, 0)`` read -- that offset-0 uint16 is the
        length prefix of a DYNAMIC array or the first offset of a struct table,
        both of which this must not swallow;
      - its total byte length ``M`` is STATICALLY KNOWN (:func:`_static_byte_len`
        -- a ``SizedBytesType`` register or a constant, which a fixed-length ABI
        static-array arg / ``extract Y a b`` slice is) and divisible by ``w``.
    Then ``K = M / w`` is EXACT (from the length, not the read count -- so partial
    element access still gives the true size) and every read lands inside ``[0,
    M)``.

    ``uint16`` elements are deliberately EXCLUDED: an offset-0 uint16 is
    indistinguishable from a length prefix / offset-table slot, so admitting it
    would misread dynamic arrays and structs. Homogeneous-but-actually-a-struct
    (e.g. ``Tuple<UInt64, UInt64>``) is the inherent speculation, hence
    side-channel only. Pairs with the struct recogniser, which only fires for a
    shape with >= 1 DYNAMIC field -- a pure-static homogeneous value is this."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType

    def kv(r):
        return (r.name, r.version)

    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o

    width = {AVMOp.extract_uint64: 8, AVMOp.extract_uint32: 4}
    reads: dict = {}                 # (name,version) -> set[(pos, w)]
    len_prefixed: set = set()        # (name,version) with an offset-0 uint16 read
    obj: dict = {}                   # (name,version) -> a representative Register
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic):
                    continue
                a = src.args
                if not (len(a) >= 2 and isinstance(a[0], M.Register)
                        and isinstance(a[1], M.UInt64Constant)):
                    continue
                if src.op is AVMOp.extract_uint16 and a[1].value == 0:
                    len_prefixed.add(kv(a[0]))
                elif src.op in width:
                    reads.setdefault(kv(a[0]), set()).add((a[1].value, width[src.op]))
                    obj.setdefault(kv(a[0]), a[0])

    out: dict = {}
    for k, rs in reads.items():
        if k in len_prefixed or len(rs) < 2:
            continue
        widths = {w for _, w in rs}
        if len(widths) != 1:
            continue
        w = next(iter(widths))
        if any(p % w for p, _ in rs):
            continue
        m = _static_byte_len(obj[k], reg_def)
        if m is None or m == 0 or m % w or m // w < 2:
            continue
        if any(p >= m for p, _ in rs):
            continue
        out[id(obj[k])] = EncodedType(ArrayEncoding(
            element=UIntEncoding(w * 8), size=m // w, length_header=False))
    return out


def _guess_static_arrays(main, subs) -> dict:
    """Recognise a producer-built ``arc4.StaticArray<T, N>`` -- ``{id(Register):
    EncodedType}``. A ``concat`` that flattens (nested binary concats included) to
    N >= 2 elements that are ALL the identical STATIC ABI encoding is, on the wire,
    exactly a static array of that element: identical layout to the homogeneous
    static ``Tuple`` the CONFIDENT tier already puts in ``ir_type``.

    Calling it an ARRAY rather than a homogeneous tuple is the SPECULATION (the
    bytes don't say which the author meant -- a ``Tuple<Address, Address>`` and an
    ``Address[2]`` are wire-identical), so it lives only in the side-channel. The
    exact element count N is KNOWN (every element is a visible concat operand); the
    idiom (``concat`` of identical statics) and its proof (the shared
    :func:`_static_encoding_elements` encoding) are discharged -- attributed
    speculation. N == 2 is the ambiguous case (a homogeneous pair is as likely a
    struct as an array), kept but inherently the weakest.

    Only the OUTERMOST concat is emitted: an inner concat whose result feeds
    another concat is an intermediate partial array, skipped (matched by SSA
    ``name#version`` identity, since a register duplicates as distinct objects)."""
    from puya.ir.encodings import ArrayEncoding
    from puya.ir.types_ import EncodedType

    def kv(r):
        return (r.name, r.version)

    fed_to_concat: set = set()
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(src, M.Intrinsic) and src.op is AVMOp.concat:
                    for a in src.args:
                        if isinstance(a, M.Register):
                            fed_to_concat.add(kv(a))

    out: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)
                        and o.source.op is AVMOp.concat
                        and len(o.source.args) == 2):
                    continue
                le = _static_encoding_elements(o.source.args[0])
                re = _static_encoding_elements(o.source.args[1])
                if le is None or re is None:
                    continue
                elems = le + re
                if len(elems) < 2 or len({str(e) for e in elems}) != 1:
                    continue
                et = EncodedType(ArrayEncoding(
                    element=elems[0], size=len(elems), length_header=False))
                for t in o.targets:
                    if isinstance(t, M.Register) and kv(t) not in fed_to_concat \
                            and t.ir_type.avm_type == et.avm_type:
                        out[id(t)] = et
    return out


def _account_txn_fields() -> frozenset:
    """The transaction fields whose value IS a 32-byte address, read from puya's
    own field registry (``wtype`` == account: Receiver / Sender / CloseRemainderTo
    / RekeyTo / the AssetXxx + ConfigAsset* address fields). Empty if the registry
    moves -- the usage-side guess then simply produces nothing."""
    try:
        from puya.awst.txn_fields import TxnField
        return frozenset(f.name for f in TxnField
                         if "account" in str(getattr(f, "wtype", "")).lower())
    except Exception as e:                               # registry moved / renamed
        logger.debug("account txn-field registry unavailable: %s", e)
        return frozenset()


_ACCOUNT_TXN_FIELDS = _account_txn_fields()

# Ops whose FIRST operand (``args[0]`` -- verified against the lift's arg order)
# is an account address: the local-state family + the account-parameter reads.
_ACCOUNT_OPERAND_OPS = (
    AVMOp.app_local_get, AVMOp.app_local_get_ex, AVMOp.app_local_put,
    AVMOp.app_opted_in, AVMOp.balance, AVMOp.min_balance,
    AVMOp.acct_params_get, AVMOp.asset_holding_get,
)


def _is_zero_address(a) -> bool:
    """``a`` is the 32-byte zero address constant (``global ZeroAddress``, which
    the lift const-folds to a ``BytesConstant`` of 32 null bytes)."""
    return isinstance(a, M.BytesConstant) and a.value == b"\x00" * 32


def _guess_address_usage(main, subs) -> dict:
    """USAGE-side speculative tier: a bytes value CONSUMED at a langspec ADDRESS
    operand position is guessed ``arc4.Address`` (``StaticArray<Byte, 32>``).
    Returns ``{id(Register): EncodedType}``.

    The complement of the producer / consumer / constant idioms: instead of
    reading how a value was BUILT, it reads how a value is USED. The named idioms,
    each with a discharged local proof (the operand position's langspec type):

      - the single operand of ``itxn_field <F>`` where ``F`` is an account-typed
        field (:data:`_ACCOUNT_TXN_FIELDS`) -- the AVM requires a 32-byte address
        there, so the value IS an address;
      - the account operand (``args[0]``) of a local-state / account-parameter op
        (:data:`_ACCOUNT_OPERAND_OPS`);
      - an operand compared for equality (``eq`` / ``neq``) against the zero
        address (:func:`_is_zero_address`) -- a canonical address presence check.

    Kept SPECULATIVE (not confident) because "it is an address value" is weaker
    than "it is ABI-encoded as ``arc4.Address``": the value may never be
    round-tripped through ABI. Side-channel only, and lowest priority in the merge
    (a producer/decode guess for the same register wins), then
    :func:`_propagate_guesses` -- including the backward-copy hop -- carries it
    from the use site back to the value's definition."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    address = EncodedType(ArrayEncoding(
        element=UIntEncoding(8), size=32, length_header=False))
    out: dict = {}

    def mark(a):
        if isinstance(a, M.Register) and a.ir_type.avm_type == address.avm_type:
            out.setdefault(id(a), address)

    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic) or not src.args:
                    continue
                op = src.op
                if op is AVMOp.itxn_field and src.immediates:
                    if str(src.immediates[0]).strip() in _ACCOUNT_TXN_FIELDS:
                        mark(src.args[0])
                elif op in _ACCOUNT_OPERAND_OPS:
                    mark(src.args[0])
                elif op in (AVMOp.eq, AVMOp.neq) \
                        and any(_is_zero_address(a) for a in src.args):
                    for a in src.args:
                        mark(a)
    return out


def _guess_encoded_types(main, subs) -> dict:
    """SPECULATIVE encoded-type recovery as a SIDE-CHANNEL ``{id(M.Register):
    EncodedType}`` map (never mutates ``ir_type``; not on :func:`to_puya`'s default
    path). The guesses only -- see :func:`guess_encoded_types_scored` for the same
    map plus, per guess, whether it is fully or only somewhat confident."""
    return guess_encoded_types_scored(main, subs)[0]


def guess_encoded_types_scored(main, subs):
    """The speculative recovery split into two honest confidence classes: returns
    ``(guesses, confident)`` where ``guesses`` is ``{id(Register): EncodedType}``
    and ``confident`` is ``{id(Register): bool}`` -- ``True`` = FULLY confident,
    ``False`` = SOMEWHAT confident. (Only two states; a finer scale would be
    invented precision.)

    ``True`` iff the idiom's proof FORCES the exact guessed type -- no other ABI
    value produces the same observable:
      - a self-describing ``arc4.String`` CONSTANT (strict: length + UTF-8 +
        printable + no-null), :func:`_guess_const_encoding`;
      - a value the AVM REQUIRES to be a 32-byte address at its operand position,
        :func:`_guess_address_usage` -> ``arc4.Address``.

    ``False`` (a structural shape that FITS but isn't forced -- an alternative ABI
    type carries the same bytes, so it's a lead, not a guarantee):
      - decoded length-prefixed dynamic arrays/strings, :func:`_guess_decoded_dynamic`
        (String vs DynamicBytes vs DynamicArray<T> all share the shape);
      - offset-table STRUCTS / tuples, :func:`_guess_struct_encodings` (partial);
      - static arrays, producer + decode (:func:`_guess_static_arrays` /
        :func:`_guess_decoded_static_arrays`) -- array vs homogeneous struct;
      - the length-proven ENCODE idiom, :func:`_guess_encoding_for` (element coarse).

    A later, more-specific source overrides the guess AND its class for a register.
    Then :func:`_propagate_guesses` flows each guess along identity-preserving
    relations; a derived guess stays confident only if the whole path preserves it
    (a copy inherits, a phi needs every arm confident, a state round-trip -- an
    assumption, not a proof -- is never confident)."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o

    guesses: dict = {}
    confident: dict = {}

    def bulk(d: dict, sure: bool):
        for rid, et in d.items():                  # overrides guess + class
            guesses[rid] = et
            confident[rid] = sure

    def bulk_default(d: dict, sure: bool):
        for rid, et in d.items():                  # gap-fill only
            if rid not in guesses:
                guesses[rid] = et
                confident[rid] = sure

    bulk(_guess_decoded_dynamic(main, subs), False)
    bulk(_guess_struct_encodings(main, subs, guesses), False)
    bulk(_guess_decoded_static_arrays(main, subs), False)
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not isinstance(o, M.Assignment):
                    continue
                src = o.source
                if isinstance(src, M.Intrinsic):
                    et, sure = _guess_encoding_for(src, reg_def), False
                elif isinstance(src, M.BytesConstant):
                    et, sure = _guess_const_encoding(src.value), True
                else:
                    et = None
                if et is None:
                    continue
                for tgt in o.targets:
                    if tgt.ir_type.avm_type == et.avm_type:
                        guesses[id(tgt)] = et       # producer wins over decode
                        confident[id(tgt)] = sure
    # Inline constants: the lift const-inlines aggressively, so a literal usually
    # appears as an INTRINSIC ARG, never as an assignment source.
    for s_ in (main, *subs):
        for bb in s_.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic):
                    continue
                for a in src.args:
                    if isinstance(a, M.BytesConstant) and id(a) not in guesses:
                        et = _guess_const_encoding(a.value)
                        if et is not None:
                            guesses[id(a)] = et
                            confident[id(a)] = True
    # Producer-side homogeneous static arrays: shape fits but array-vs-struct is
    # unforced -> somewhat.
    bulk(_guess_static_arrays(main, subs), False)
    # Usage-side address evidence -- the AVM forces a 32-byte address here, so the
    # 'it is an address' call is FULLY confident. Gap-fill (lowest priority).
    bulk_default(_guess_address_usage(main, subs), True)

    _propagate_guesses(main, subs, guesses, confident)
    return guesses, confident


# State-write ops whose (key, value) a get of the same key can inherit an
# encoding from (all-writes-agree). uint64/box put/del excluded -- box values
# are handled by the decode-side guesses, and del carries no value.
_STATE_PUT_OPS = (AVMOp.app_global_put, AVMOp.app_local_put)
_STATE_GET_OPS = (AVMOp.app_global_get, AVMOp.app_local_get,
                  AVMOp.app_global_get_ex, AVMOp.app_local_get_ex)


def _propagate_guesses(main, subs, guesses: dict, confident: dict = None) -> None:
    """Flow the per-register speculative encodings along IDENTITY-preserving
    relations, so a guess reaches the whole value web it feeds -- not just the
    one op that produced it. In-place: adds ``id(register) -> EncodedType``
    entries to ``guesses`` for every register-OBJECT whose SSA value carries a
    propagated encoding (registers duplicate as distinct objects for one
    ``name#version``, so propagation is keyed by that logical identity, then
    stamped onto every object).

    Relations (all preserve the value's bytes, hence its ARC4 encoding):
      - register COPY (``t = r``): ``t`` inherits ``r``'s encoding;
      - PHI: the joined register inherits iff every register arg has an
        encoding and they all AGREE (MUST -- a disagreeing or unknown arm
        blocks it);
      - state PUT->GET: a ``app_*_get KEY`` result inherits iff every
        ``app_*_put`` to that KEY wrote a value with the SAME encoding
        (all-writes-agree, mirroring the state-resolution soundness elsewhere).

    ``confident`` (optional ``{id: bool}``) is propagated in lock-step: a copy
    inherits the source class, a phi is confident only if EVERY agreeing arm is,
    and a state round-trip is never confident (all-writes-agree is an assumption,
    not a proof). A derived guess is never more confident than what it came from.

    Speculative + side-channel throughout: never touches ``ir_type``, so a
    wrong hop cannot affect lowering -- only what a tolerant consumer reads."""
    confident = confident if confident is not None else {}

    # SSA register names are unique only WITHIN a subroutine (params `p%i`, locals
    # `l%slot` recur across subs), so a propagation identity must include the
    # owning subroutine — else a guess on sub A's `p%0` stamps onto sub B's `p%0`
    # (a spurious cross-sub guess that surfaces as a wrong abi-audit/box-audit
    # finding). Map every register OBJECT to its sub; all copy/phi relations are
    # intra-sub, and state round-trips key on state-key-bytes, so per-sub keys are
    # both sufficient and correct.
    reg_sub: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                reg_sub[id(ph.register)] = s.id
                for pa in ph.args:
                    if isinstance(pa.value, M.Register):
                        reg_sub[id(pa.value)] = s.id
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        if isinstance(t, M.Register):
                            reg_sub[id(t)] = s.id
                if isinstance(src, M.Intrinsic):
                    for a in src.args:
                        if isinstance(a, M.Register):
                            reg_sub[id(a)] = s.id

    def key(r):
        return (reg_sub.get(id(r)), r.name, r.version)

    # Seed: logical-identity -> encoding (+ confident bool), from the base guesses.
    enc: dict = {}
    enc_conf: dict = {}                   # (sub,name,version) -> bool
    objs: dict = {}                       # (sub,name,version) -> [register objects]

    def note(r):
        if isinstance(r, M.Register):
            objs.setdefault(key(r), []).append(r)
            if id(r) in guesses and key(r) not in enc:
                enc[key(r)] = guesses[id(r)]
                enc_conf[key(r)] = confident.get(id(r), False)

    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                note(ph.register)
                for pa in ph.args:
                    note(pa.value)
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        note(t)
                if isinstance(src, M.Intrinsic):
                    for a in src.args:
                        note(a)

    # State keys: encodings written to each (key-bytes, op-family). A key whose
    # writes disagree (or any write is unguessed-but-present) is poisoned.
    def _key_const(args):
        for x in args:
            if isinstance(x, M.BytesConstant):
                return x.value
        return None

    def _run_state():
        writes: dict = {}                 # keybytes -> set(encodings) | None(poisoned)
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    src = o.source if isinstance(o, M.Assignment) else o
                    if not (isinstance(src, M.Intrinsic) and src.op in _STATE_PUT_OPS):
                        continue
                    kb = _key_const(src.args)
                    if kb is None or writes.get(kb, "unset") is None:
                        continue                     # unknown key or already poisoned
                    val = next((a for a in src.args if isinstance(a, M.Register)), None)
                    e = enc.get(key(val)) if val is not None else None
                    if e is None:
                        writes[kb] = None            # an unencoded write poisons the key
                    else:
                        writes.setdefault(kb, set()).add(e)
        se = {kb: next(iter(es)) for kb, es in writes.items()
              if isinstance(es, set) and len(es) == 1}
        # A state round-trip is an all-writes-agree ASSUMPTION, not a proof ->
        # never fully confident.
        sc = {kb: False for kb in se}
        return se, sc

    changed = True
    while changed:
        changed = False
        state_enc, state_conf = _run_state()
        for s in (main, *subs):
            for bb in s.body:
                for ph in bb.phis:
                    k = key(ph.register)
                    if k in enc:
                        continue
                    arms = [(enc.get(key(pa.value)), enc_conf.get(key(pa.value)))
                            for pa in ph.args if isinstance(pa.value, M.Register)]
                    arm_encs = [e for e, _ in arms]
                    if arm_encs and all(e is not None for e in arm_encs) \
                            and len(set(arm_encs)) == 1:
                        enc[k] = arm_encs[0]
                        enc_conf[k] = all(c for _, c in arms)   # confident iff every arm is
                        changed = True
                for o in bb.ops:
                    if not isinstance(o, M.Assignment):
                        continue
                    src = o.source
                    e = ec = None
                    if isinstance(src, M.Register):
                        e, ec = enc.get(key(src)), enc_conf.get(key(src))
                    elif isinstance(src, M.Intrinsic) and src.op in _STATE_GET_OPS:
                        kb = _key_const(src.args)
                        e, ec = state_enc.get(kb), state_conf.get(kb)
                    if e is None:
                        # BACKWARD copy (``t = r``): if the copy result already
                        # carries a guess (e.g. a use-site address stamp) but the
                        # source does not, the source -- the same bytes -- inherits
                        # it. This is what carries a usage-evidence guess back past
                        # a rename to the value's real definition.
                        if isinstance(src, M.Register) and key(src) not in enc:
                            te = [(enc.get(key(t)), enc_conf.get(key(t)))
                                  for t in o.targets if isinstance(t, M.Register)]
                            tenc = [x for x, _ in te]
                            if tenc and all(x is not None for x in tenc) \
                                    and len(set(tenc)) == 1 \
                                    and src.ir_type.avm_type == tenc[0].avm_type:
                                enc[key(src)] = tenc[0]
                                enc_conf[key(src)] = all(c for _, c in te)
                                changed = True
                        continue
                    for t in o.targets:
                        if isinstance(t, M.Register) and key(t) not in enc \
                                and t.ir_type.avm_type == e.avm_type:
                            enc[key(t)] = e
                            enc_conf[key(t)] = bool(ec)
                            changed = True

    # Stamp every register OBJECT of an encoded SSA value (incl. use-site copies).
    for k, e in enc.items():
        for r in objs.get(k, ()):
            if id(r) not in guesses and r.ir_type.avm_type == e.avm_type:
                guesses[id(r)] = e
                confident[id(r)] = enc_conf.get(k, False)


# Fund / asset-transfer itxn fields whose operand is an address the CONTRACT
# pays out to -- a recovered arc4.Address arriving here is a payout recipient.
_FUND_SINK_FIELDS = frozenset({
    "Receiver", "AssetReceiver", "CloseRemainderTo", "AssetCloseTo",
    "AssetSender", "RekeyTo",
})
# The transaction-arg reads that expose an ABI method argument (a caller-chosen
# value). ``txnas`` / ``gtxnas`` take the index off the stack; ``txna`` inlines it.
_ABI_ARG_OPS = (AVMOp.txna, AVMOp.txnas, AVMOp.gtxna, AVMOp.gtxnas)


def is_address_encoding(et) -> bool:
    """``et`` is the arc4.Address shape: a fixed 32-byte, header-less byte array
    (``StaticArray<Byte, 32>``)."""
    from puya.ir.encodings import ArrayEncoding
    return (isinstance(et.encoding, ArrayEncoding)
            and et.encoding.size == 32 and not et.encoding.length_header)


def abi_address_fund_flows(main, subs, guesses=None) -> list:
    """TYPE-DRIVEN security leads -- the first CONSUMER of the speculative ABI
    type side-channel. Reports every fund / asset-transfer sink
    (:data:`_FUND_SINK_FIELDS`) whose recipient operand is a value RECOVERED as
    ``arc4.Address``: the type recovery is precisely what tells us a 32-byte
    operand is a caller-meaningful ADDRESS rather than an opaque blob, which is
    what turns ``itxn_field Receiver`` into a 'who gets the money' question.

    Each lead is tagged over a BACKWARD SLICE of the recipient value (its def-use
    predecessors, transitively -- through intrinsic operands, register copies and
    phis, memoised, cycle-safe), so it survives the ABI-decode chain real
    compiled contracts interpose (the address is ``extract``-ed out of the args
    tuple, not read raw at the sink):
      - ``caller_supplied`` -- the slice roots in an ABI method-argument read
        (:data:`_ABI_ARG_OPS` on ``ApplicationArgs``): the caller chooses the
        address;
      - ``guarded`` -- some value on the slice is an ``eq`` / ``neq`` operand (a
        'was it pinned/validated' proxy).

    ``caller_supplied and not guarded`` is the arbitrary-recipient shape: the
    caller passes an ABI address and the contract pays it without checking. The
    slice is INTRA-procedural -- a value arriving as a subroutine frame parameter
    breaks the chain (documented gap; taint's interprocedural bridge is the fuller
    answer). Op-granular (Puya IR carries no source line on this path); returns
    dicts ``{field, subroutine, encoding, confident, caller_supplied, guarded}``,
    where ``confident`` (bool) is whether the recovered address type is fully or
    only somewhat confident (see :func:`guess_encoded_types_scored`). Side-channel
    in, report out -- never touches ``ir_type``."""
    if guesses is None:
        guesses, confident = guess_encoded_types_scored(main, subs)
    else:
        confident = {}

    def kv(r):
        return (r.name, r.version)

    # Backward def-use graph: each identity -> its predecessor identities, plus
    # the set of identities that ARE a raw ApplicationArgs read, and those used
    # as an eq/neq operand.
    preds: dict = {}
    is_arg: set = set()
    compared: set = set()
    origin_of: dict = {}                  # arg-read identity -> 'ApplicationArgs:N'

    def _add_pred(dst, srcs):
        bucket = preds.setdefault(dst, set())
        for s_ in srcs:
            if isinstance(s_, M.Register):
                bucket.add(kv(s_))

    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                _add_pred(kv(ph.register), [pa.value for pa in ph.args])
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    ins = ([o.source] if isinstance(o.source, M.Register)
                           else list(src.args) if isinstance(src, M.Intrinsic) else [])
                    for t in o.targets:
                        if isinstance(t, M.Register):
                            _add_pred(kv(t), ins)
                            if isinstance(src, M.Intrinsic) and src.op in _ABI_ARG_OPS \
                                    and src.immediates \
                                    and "ApplicationArgs" in str(src.immediates[0]):
                                is_arg.add(kv(t))
                                idx = (src.immediates[1]
                                       if len(src.immediates) > 1 else None)
                                if isinstance(idx, int):
                                    origin_of[kv(t)] = f"ApplicationArgs:{idx}"
                if isinstance(src, M.Intrinsic) and src.op in (AVMOp.eq, AVMOp.neq):
                    for a in src.args:
                        if isinstance(a, M.Register):
                            compared.add(kv(a))

    # Arg-origin closure over `compared`: comparing ONE read of ApplicationArgs N
    # validates the arg, so every (distinct-SSA) read of the same constant-index
    # arg counts as compared -- catches a `validate arg0` / `pay arg0` pattern
    # where the two reads are separate registers (uncommon post-CSE, but sound).
    compared_origins = {origin_of[x] for x in compared if x in origin_of}
    if compared_origins:
        for idn, org in origin_of.items():
            if org in compared_origins:
                compared.add(idn)

    _slice_cache: dict = {}

    def bslice(start):
        """The backward slice (set of identities) reachable from ``start``."""
        if start in _slice_cache:
            return _slice_cache[start]
        seen: set = set()
        stack = [start]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(preds.get(n, ()))
        _slice_cache[start] = seen
        return seen

    leads: list = []
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic) and src.op is AVMOp.itxn_field
                        and src.immediates and src.args):
                    continue
                field = str(src.immediates[0]).strip()
                if field not in _FUND_SINK_FIELDS:
                    continue
                a = src.args[0]
                if not (isinstance(a, M.Register) and id(a) in guesses
                        and is_address_encoding(guesses[id(a)])):
                    continue
                sl = bslice(kv(a))
                leads.append({
                    "field": field,
                    "subroutine": s.id,
                    "encoding": str(guesses[id(a)]),
                    "confident": bool(confident.get(id(a), False)),
                    "caller_supplied": bool(sl & is_arg),
                    "guarded": bool(sl & compared),
                })
    return leads


def _recover_encoded_types(main, subs) -> int:
    """**CONFIDENT** encoded-type recovery: refine a result register to the ARC4
    ``EncodedType`` its producing op provably wire-encodes
    (:func:`_confident_encoding_for`). Only moves a register whose ``avm_type``
    already matches (an ``EncodedType``'s ``avm_type`` is ``bytes`` for the
    byte-backed encodings, so it sits over the same ``bytes``/``bytes[N]`` the
    sized-bytes pass left), and rebuilds the intrinsic's ``types`` to match. This is
    the only encoded-type pass wired into :func:`to_puya`'s default IR.

    NOTE: unlike the scalar refinements, an ``EncodedType`` is *layout-bearing*, so
    this is the first recovery that is NOT guaranteed a free annotation by
    construction -- its TEAL-neutrality is established by the gate, not by the
    avm_type argument alone (measured 247/0). The SPECULATIVE tier
    (:func:`_guess_encoded_types`) is kept strictly separate and side-channelled so
    it can never reach this IR. Returns the count refined."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o
    # Iterate to a fixpoint: `concat` reads its operands' recovered types, so a
    # nested `concat(concat(a, b), c)` resolves over successive rounds. Monotonic
    # (a register only ever moves from a coarse/smaller encoding to a richer one of
    # the same avm_type), so it terminates.
    n = 0
    changed = True
    while changed:
        changed = False
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    if not (isinstance(o, M.Assignment)
                            and isinstance(o.source, M.Intrinsic)):
                        continue
                    et = _confident_encoding_for(o.source, reg_def)
                    if et is None:
                        continue
                    touched = False
                    for tgt in o.targets:
                        if tgt.ir_type.avm_type == et.avm_type and tgt.ir_type != et:
                            _compat.set_ir_type(tgt, et)
                            touched = changed = True
                            n += 1
                    if touched:
                        _compat.set_intrinsic_types(
                            o.source, (t.ir_type for t in o.targets))
    return n


def _opt_passes():
    """Puya optimiser passes that take no (or an unused) compile context AND are pure
    cleanups (do not alter the lowered TEAL beyond removing dead/duplicate work), so
    they run directly on our translated subroutines -- order roughly follows Puya's
    own pipeline. The CODEGEN-CHANGING simplifications (intrinsic_simplifier,
    encode_decode_pair_elimination) are opt-in via :func:`_aggressive_passes`;
    slot_elimination / inlining / box / itxn-field passes need a real context or the
    Slot abstraction we don't emit, so they stay omitted."""
    from puya.ir.optimize.assignments import copy_propagation
    from puya.ir.optimize.collapse_blocks import merge_blocks, remove_linear_jumps
    from puya.ir.optimize.constant_propagation import constant_replacer
    from puya.ir.optimize.control_op_simplification import simplify_control_ops
    from puya.ir.optimize.dead_code_elimination import (
        remove_unreachable_blocks, remove_unused_variables)
    from puya.ir.optimize.repeated_aggregate_reads_merge import merge_chained_aggregate_reads
    from puya.ir.optimize.repeated_code_elimination import repeated_expression_elimination
    from puya.ir.optimize.repeated_loads_elimination import (
        constant_reads_and_unobserved_writes_elimination)
    return [constant_replacer, copy_propagation, merge_chained_aggregate_reads,
            constant_reads_and_unobserved_writes_elimination,
            repeated_expression_elimination, simplify_control_ops,
            remove_unreachable_blocks, merge_blocks, remove_linear_jumps,
            remove_unused_variables]


def _aggressive_passes():
    """Extra Puya passes that genuinely SIMPLIFY the lowered TEAL (not pure
    annotations): ``intrinsic_simplifier`` (constant folding, strength reduction, and
    -- using our recovered sized-byte / account types -- ``len`` + comparison folding)
    and ``encode_decode_pair_elimination`` (redundant ARC4 encode∘decode round-trips).

    Opt-in (``optimize(aggressive=True)``) because they CHANGE codegen, so they are
    gated behaviourally (the lift behaves identically), NOT by byte-identity. Neither
    needs a real compile context: ``encode_decode_pair_elimination`` ignores its
    ``_context``, and ``intrinsic_simplifier`` reads only ``expand_all_bytes`` (a bool,
    supplied via a tiny shim) -- so the old "needs a real context" exclusion was
    overstated. ``intrinsic_simplifier`` is wrapped to take the uniform ``(ctx, sub)``
    shape so :func:`optimize` can call it like the rest."""
    import types

    from puya.ir.optimize.assignments import encode_decode_pair_elimination
    from puya.ir.optimize.intrinsic_simplification import intrinsic_simplifier
    shim = types.SimpleNamespace(expand_all_bytes=False)
    return [lambda _ctx, s: intrinsic_simplifier(shim, s),
            encode_decode_pair_elimination]


_BYTES_IRT = frozenset({PT.bytes, PT.account})


def _puya_zero(ir_type):
    if ir_type in _BYTES_IRT:
        return M.BytesConstant(source_location=None, value=b"",
                               encoding=AVMBytesEncoding.utf8)
    # A bytes-backed type that is NOT plain bytes/account -- e.g. an ARC4
    # ``EncodedType`` (uint64-tuple, address, fixed array). A uint64 zero is the
    # wrong AVM type for it, so emit a bytes zero of the type's fixed width and
    # type the constant AS the target so the orphan-default assignment type-checks
    # exactly (Puya rejects ``source=(uint64) target=(Encoded(...))`` otherwise).
    if getattr(ir_type, "avm_type", None) == AVMType.bytes:
        nb = getattr(ir_type, "num_bytes", None)
        n = nb if isinstance(nb, int) else 0
        return M.BytesConstant(source_location=None, value=b"\x00" * n,
                               encoding=AVMBytesEncoding.base16, ir_type=ir_type)
    return M.UInt64Constant(source_location=None, value=0)


def _define_named_orphan(subs, name: str, version: int) -> bool:
    """Define a register the optimiser rejected as undefined (a value the
    reconstruction lost to a frame / dynamic-scratch gap) as a typed zero at its
    subroutine's entry. Precise: only the exact register Puya names is touched,
    so a contract that optimises cleanly never reaches this."""
    for sub in subs:
        if not sub.body:
            continue
        match = next((r for r in _compat.get_used_registers(sub.body)
                      if r.name == name and r.version == version), None)
        if match is not None:
            sub.body[0].ops.insert(0, M.Assignment(
                source_location=None, targets=[match], source=_puya_zero(match.ir_type)))
            return True
    return False


def optimize(subs, *, max_rounds: int = 100, aggressive: bool = False) -> int:
    """Run Puya's context-free optimiser passes over ``subs`` to a fixpoint.
    Mutates the subroutines in place; returns the number of rounds taken. Puya's
    pass logging is silenced for the duration. If a pass rejects a register the
    reconstruction left undefined, define it (typed zero) and retry -- bounded,
    and only ever engaged by a contract that fails to optimise.

    ``aggressive`` adds the CODEGEN-CHANGING simplifications (:func:`_aggressive_passes`
    -- intrinsic folding + ARC4 encode/decode elimination). Default off, so the lift
    stays faithful / byte-identical for analysis; turn it on for a maximally-optimised
    lowering (gated behaviourally, since it alters the TEAL).

    Wraps :func:`_optimize_impl` so a failure the internal typed-zero retry can't
    resolve surfaces as a typed :class:`tealql.tealtools.errors.LiftError` (stage
    ``"optimize"``), cause chained."""
    from ..errors import LiftError
    try:
        return _optimize_impl(subs, max_rounds=max_rounds, aggressive=aggressive)
    except LiftError:
        raise
    except Exception as e:
        raise LiftError(f"{type(e).__name__}: {e}", stage="optimize") from e


def _optimize_impl(subs, *, max_rounds: int = 100, aggressive: bool = False) -> int:
    import logging
    from puya.errors import InternalError
    passes = _opt_passes() + (_aggressive_passes() if aggressive else [])
    log = logging.getLogger("puya")
    prev = log.level
    log.setLevel(logging.WARNING)
    try:
        for _attempt in range(40):
            try:
                for rnd in range(1, max_rounds + 1):
                    if not any(pz(None, s) for s in subs for pz in passes):
                        return rnd
                return max_rounds
            except InternalError as e:
                m = _compat.NOT_DEFINED_RE.search(str(e))
                if not (m and _define_named_orphan(subs, m.group(1), int(m.group(2)))):
                    raise
        return max_rounds
    finally:
        log.setLevel(prev)


def render(prog, *, optimize_ir: bool = False) -> str:
    """Render an SSAProgram as real Puya IR text, using Puya's own emitter. With
    ``optimize_ir`` set, Puya's optimiser passes run on the IR first."""
    TextEmitter, _render_body = _compat.text_emitter_and_render()

    main, subs = to_puya(prog)
    if optimize_ir:
        optimize([main, *subs])
    em = TextEmitter()
    em.append(f"main {main.id}:")
    with em.indent():
        _render_body(em, main.body)
    for sub in subs:
        em.append("")
        args = ", ".join(f"{r.name}: {r.ir_type.name}" for r in sub.parameters)
        rets = sub.returns
        ret = "void" if not rets else (rets[0].name if len(rets) == 1
                                       else f"<{', '.join(r.name for r in rets)}>")
        em.append(f"subroutine {sub.id}({args}) -> {ret}:")
        with em.indent():
            _render_body(em, sub.body)
    return "\n".join(em.lines)
