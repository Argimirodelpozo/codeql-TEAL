"""Lower the pre-IR (:mod:`pre_ir`) to *real* ``puya.ir.models``, then render /
optimise with Puya's own renderer and optimiser passes (:func:`optimize`).

HAZARD: Puya's operand order is the INVERSE of ours — intrinsic args go in AVM
order (our top-first inputs REVERSED) and multi-result outputs are bottom-first
(our top-first targets reversed). Puya additionally enforces every used register
defined by identity, wired predecessor lists, real ``IRType``/``AVMOp``, and a
``SourceLocation`` per block.
"""
from __future__ import annotations


import contextlib
import logging

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.avm import AVMType
from puya.ir.types_ import AVMBytesEncoding, PrimitiveIRType as PT
from puya.parse import SourceLocation

from . import pre_ir, transforms
from . import _puya_compat as _compat
from .lift import _Lifter
from .teal_const import _const_bytes, _load_src, _tmpl_name
from ..ast.literals import is_template_variable, tokenize_operands as _tokenize_operands
from . import arc4_recovery
# Re-exported so every `to_puya_ir.<name>` reference keeps resolving after the
# ARC-4 encoded-type recovery moved out to `arc4_recovery`.
_recover_encoded_types = arc4_recovery._recover_encoded_types
guess_encoded_types_scored = arc4_recovery.guess_encoded_types_scored
abi_address_fund_flows = arc4_recovery.abi_address_fund_flows
is_address_encoding = arc4_recovery.is_address_encoding
_ACCOUNT_TXN_FIELDS = arc4_recovery._ACCOUNT_TXN_FIELDS
_ACCOUNT_OPERAND_OPS = arc4_recovery._ACCOUNT_OPERAND_OPS

logger = logging.getLogger("tealql.tealtools.lift")

# Neutral encoding-kind string -> puya's enum. Lives HERE, not in teal_const, so
# the detector-facing lift path stays importable without puya.
_AVM_ENCODING = {
    "base16": AVMBytesEncoding.base16,
    "utf8": AVMBytesEncoding.utf8,
    "base64": AVMBytesEncoding.base64,
    "base32": AVMBytesEncoding.base32,
}


def _bytes_const(literal: str) -> "M.BytesConstant":
    """A puya ``BytesConstant`` from a TEAL byte literal."""
    raw, kind = _const_bytes(literal)
    return M.BytesConstant(source_location=None, value=raw,
                           encoding=_AVM_ENCODING[kind])


_IRT = {
    "uint64": PT.uint64, "bytes": PT.bytes, "bool": PT.bool,
    "account": PT.account, "asset": PT.uint64, "application": PT.uint64,
    "biguint": PT.biguint,
    # Puya's value IR can represent AVM-polymorphic values exactly. Keep a
    # residual recovery unknown as `any` for decompilation and analyses instead
    # of asserting uint64; only MIR/codegen lacks this representation.
    "?": PT.any,
}

# Const-push pseudo-ops that survive the lift only when their immediate was a
# deploy-time template variable (`pushint TMPL_X`). Puya models these as
# TemplateVar -- a non-foldable constant, so the optimiser can't fold them away.
_PUSH_U64 = {"pushint", "intc", "intc_0", "intc_1", "intc_2", "intc_3"}
_PUSH_BYTES = {"pushbytes", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3"}



def _make_const(operand: str, is_u64: bool):
    """A recovered operand string -> a Puya constant / template var, or None."""
    operand = operand.strip()
    if is_template_variable(operand):
        return M.TemplateVar(source_location=None, name=operand,
                             ir_type=PT.uint64 if is_u64 else PT.bytes)
    if is_u64:
        try:
            return M.UInt64Constant(source_location=None, value=int(operand, 0))
        except ValueError:
            return None
    try:
        return _bytes_const(operand)
    except ValueError:      # malformed byte literal -> degrade this one const,
        return None         # symmetric with the u64 path (don't fail the lift)


#: ``intc_N`` / ``bytec_N`` -> the const-block index N they load.
_INDEXED = {f"{p}_{i}": i for p in ("intc", "bytec") for i in range(4)}


def _sl(line: int) -> SourceLocation:
    return SourceLocation(file=None, line=line or 1)


def _line_of(bb) -> int:
    c = bb.comment or ""
    return int(c[1:]) if c.startswith("L") and c[1:].isdigit() else 1


def _is_template_push(immediates) -> bool:
    """No immediate at all, or ONLY deployment template variables — both spellings
    must reach the TemplateVar path (a template's value is unknown until deployment,
    and falling through to ``AVMOp("pushint")`` raises)."""
    operands = []
    for imm in immediates:
        tok = str(imm).strip()
        if tok.startswith("//"):
            break            # the rest of the line is an inline comment
        operands.append(tok)
    if not operands:
        return True
    return all(is_template_variable(t) for t in operands)


class _Translator:
    def __init__(self, src_map: dict | None = None, *, unknown_type=PT.any):
        self.regs: dict = {}      # id(pre-IR Register) -> M.Register
        self.blocks: dict = {}    # pre-IR block id -> M.BasicBlock
        self.subs: dict = {}      # pre-IR Subroutine.id -> M.Subroutine
        self.src: dict = src_map or {}
        self._block_cache: dict = {}   # (kind, line) -> recovered const block
        self.unknown_type = unknown_type

    def ty(self, s):
        return self.unknown_type if s == "?" else _IRT.get(s, self.unknown_type)

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
            # An unknown has no type of its own; honour the one stamped on it
            # (`?` remains Puya `any` outside the codegen-only path). Hardcoding
            # uint64 here made
            # `let pc%N: bytes = undefined` -- a divergent join's missing-arm
            # cell whose phi settled to bytes -- fail Puya's assignment check.
            return M.Undefined(source_location=None, ir_type=self.ty(v.ir_type))
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
        if len(parts) != 2:
            return []
        return _tokenize_operands(
            parts[1],
            fold_byte_keywords=parts[0] in {
                "byte", "pushbytes", "pushbytess", "bytecblock"
            },
        )

    def _const_block(self, kind: str, line: int) -> list:
        """The ``intcblock`` / ``bytecblock`` operand list in scope at ``line``, read
        from source because the parser truncates these blocks (dropping ``TMPL_*`` /
        encoded entries), leaving a ``bytec N`` into a dropped slot unresolvable."""
        key = (kind, line)
        if key in self._block_cache:
            return self._block_cache[key]
        op = kind + "block"
        best: list = []
        for idx, text in enumerate(self._src_lines(), start=1):
            t = text.strip()
            if t.startswith(op + " ") and (not line or idx <= line):
                best = _tokenize_operands(
                    t[len(op):], fold_byte_keywords=(kind == "bytec"))
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
            # A const-load by index whose const-block slot the parser dropped:
            # recover from source.
            idx = None
            if s.op in ("bytec", "intc") and len(s.immediates) == 1 and not s.args:
                idx = int(self._imm(s.immediates[0]))
            elif s.op in _INDEXED and not s.args:
                idx = _INDEXED[s.op]
            if idx is not None:
                v = self._block_value(s.op, idx, s.line)
                if v is not None:
                    return v
            # A const-push whose inline operand the parser dropped: recover the
            # literal, else treat it as a template var.
            if (s.op in _PUSH_U64 or s.op in _PUSH_BYTES) and not s.args \
                    and _is_template_push(s.immediates):
                is_u64 = s.op in _PUSH_U64
                ops = self._operands_at(s.line)
                if ops and not is_template_variable(ops[0]):
                    v = _make_const(ops[0], is_u64)
                    if v is not None:
                        return v
                name = ops[0] if ops else _tmpl_name(self.src, s.line)
                return M.TemplateVar(source_location=None, name=name,
                                     ir_type=PT.uint64 if is_u64 else PT.bytes)
            kw = {} if result_types is None else {"types": result_types}
            return M.Intrinsic(
                source_location=_sl(s.line), op=AVMOp(s.op),
                immediates=[self._imm(i) for i in s.immediates],
                args=[self.val(a) for a in reversed(s.args)],   # top-first -> AVM order
                **kw)
        if isinstance(s, pre_ir.Undefined) and result_types and len(result_types) == 1:
            # A bare undefined ASSIGNED to a register takes the register's type:
            # post-recovery the target is the single source of truth, and an
            # unknown adopting it asserts no value. Substitution passes can put
            # an Undefined in source position after the stamped materialisation,
            # so this must not rely on the Undefined's own ir_type alone.
            return M.Undefined(source_location=None, ir_type=result_types[0])
        if isinstance(s, pre_ir.InvokeSubroutine):
            # Subroutine args are positional (args[i] -> param i), NOT AVM-order
            # like Intrinsic args -- Puya builds them `for param in parameters`.
            return M.InvokeSubroutine(
                source_location=_sl(getattr(getattr(s, "origin", None),
                                            "location", None).line
                                    if getattr(getattr(s, "origin", None),
                                               "location", None) is not None else 0),
                target=self.subs[s.target],
                args=[self.val(a) for a in s.args])
        if isinstance(s, pre_ir.ValueTuple):
            return M.ValueTuple(source_location=None,
                                values=[self.val(v) for v in s.values])
        return self.val(s)

    def op(self, o):
        if isinstance(o, pre_ir.Assignment):
            # Multi-const push whose inline operands the parser dropped: Puya has no
            # such op, so split into one `let target_i = <const_i>` per value, with
            # the top-first targets reversed back to source (push) order.
            src = o.source
            if isinstance(src, pre_ir.Intrinsic) and src.op in ("pushbytess", "pushints") \
                    and not src.args:
                ops = self._operands_at(src.line)
                tgts = [self.reg(t) for t in o.targets][::-1]
                is_u64 = src.op == "pushints"
                if ops and len(ops) == len(tgts):
                    out = []
                    for tgt, operand in zip(tgts, ops):
                        out.append(M.Assignment(source_location=_sl(src.line), targets=[tgt],
                                                source=_make_const(operand, is_u64)))
                    return out
            targets = [self.reg(t) for t in o.targets]
            # Our outputs are top-first; Puya intrinsics return bottom-first
            # (AVM order), so a multi-output intrinsic's targets/types reverse.
            if isinstance(o.source, pre_ir.Intrinsic) and len(targets) > 1:
                targets = targets[::-1]
            return M.Assignment(
                source_location=(
                    _sl(o.source.line) if isinstance(o.source, pre_ir.Intrinsic)
                    else _sl(getattr(getattr(o.source, "origin", None),
                                     "location", None).line)
                    if isinstance(o.source, pre_ir.InvokeSubroutine)
                    and getattr(getattr(o.source, "origin", None),
                                "location", None) is not None
                    else None),
                targets=targets,
                source=self.vp(o.source, [t.ir_type for t in targets]))
        if isinstance(o, pre_ir.IntrinsicOp):
            if isinstance(o.intrinsic, pre_ir.Intrinsic) and o.intrinsic.op in (
                    "pop", "popn", "pushbytess", "pushints"):
                # pop/popn discard; a 0-output pushbytess/pushints is a phantom push
                # whose values, if used, are recovered elsewhere (match keys).
                return None
            return self.vp(o.intrinsic)          # side-effecting intrinsic = an Op
        if isinstance(o, pre_ir.Assert):
            return M.Assert(source_location=_sl(o.line), condition=self.val(o.condition),
                            message=o.message or "assert", explicit=True)
        raise TypeError(f"op: {type(o).__name__}")

    def _u64_cond(self, v):
        """Coerce a branch selector to uint64 (a bytes *constant* there is a
        reconstruction artifact for an undefined value)."""
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
            # Test the AVM TYPE FAMILY, not the exact ir_type: type recovery refines
            # uint64 registers to bool / asset / application, which an exact
            # `== PT.uint64` misclassifies as bytes-keyed -- `_bytes_const("5")`
            # then raises and fails the lift.
            _vt = getattr(val, "ir_type", None)
            is_u64 = (getattr(_vt, "avm_type", None) == PT.uint64.avm_type)
            cases = {}
            for lbl, blk in t.cases:
                if is_u64:                       # uint64-keyed match (e.g. OnCompletion)
                    key = M.UInt64Constant(source_location=None, value=int(str(lbl), 0))
                else:
                    key = _bytes_const(str(lbl))
                # AVM ``match`` checks cases in source order. Duplicate keys
                # therefore select the FIRST label; assigning into the dict
                # unconditionally kept the last and silently rerouted the arm.
                cases.setdefault(key, B[blk])
            return M.Switch(source_location=None, value=val,
                            cases=cases, default=B[t.default])
        if isinstance(t, pre_ir.SubroutineReturn):
            return M.SubroutineReturn(source_location=None,
                                      result=[self.val(v) for v in t.result])
        if isinstance(t, pre_ir.ProgramExit):
            r = self.val(t.result)
            # A constant-0 exit is an unconditional reject. Emit it as a
            # non-explicit Fail (same on-chain outcome): Puya's own `exit 0` -> `err`
            # rewrite marks the check EXPLICIT, and the later fold into the
            # surrounding assert then trips its "explicit check removed" invariant.
            if isinstance(r, M.UInt64Constant) and r.value == 0:
                return M.Fail(source_location=None, error_message="reject", explicit=False)
            return M.ProgramExit(source_location=None, result=r)
        if isinstance(t, pre_ir.Fail):
            # NOT explicit: a reconstructed reject/err path is control flow, not a
            # user-written check, and Puya legitimately folds `goto cond ? body : err`
            # into `assert cond` -- which trips its "explicit check removed"
            # invariant if the Err is explicit. `Assert` above stays explicit, so a
            # genuinely-dropped assert still surfaces.
            return M.Fail(source_location=None,
                          error_message=t.error_message or "err", explicit=False)
        raise TypeError(f"ctrl: {type(t).__name__}")

    def phi(self, p):
        # Puya wants one arg per PREDECESSOR, ours has one per EDGE: a block reached
        # by >1 edge (two switch cases -> same target) appears once in the CFG
        # predecessor set, so dedup by `through` (duplicate edges carry one value).
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


_term_targets = pre_ir.succ_ids          # kept: an established import for callers


def _duplicate_shared_epilogues(lifted):
    """Compatibility wrapper; pre-IR construction now performs this repair."""
    return transforms.duplicate_pure_shared_sinks(lifted)


@contextlib.contextmanager
def _puya_error_capture(stage: str, diagnostics: list | None = None):
    """Surface the errors Puya REPORTS but does not raise.

    Puya's own validators (intrinsic arg types / arg counts / immediates —
    ``puya/ir/models.py``) call ``logger.error`` and RETURN, so a type-invalid
    program flows straight through ``to_puya``/``optimize`` as an apparent
    success. Installing ``puya.log.logging_context()`` is the only way to see
    them. On exit: append one line per error/critical to ``diagnostics`` (when
    given) and emit a single summary warning, so a type-invalid lift is never a
    silent green."""
    from puya import log as puya_log
    with puya_log.logging_context() as ctx:
        yield
    if ctx.num_errors:
        msgs = [f"{lg.level}: {lg.message}"
                + (f" @ {lg.file}:{lg.line}" if lg.file is not None else "")
                for lg in ctx.logs if lg.level >= puya_log.LogLevel.error]
        if diagnostics is not None:
            diagnostics.extend(msgs)
        logger.warning(
            "puya reported %d error(s) during %s — the IR is type-invalid where "
            "flagged (puya logs these, it does not raise): %s",
            ctx.num_errors, stage,
            "; ".join(msgs[:5]) + (" …" if len(msgs) > 5 else ""))


def _lower_with_unknown_type(prog, diagnostics, unknown_type):
    """Shared guarded lower; ``unknown_type`` is explicit at the boundary."""
    from ..diagnostics.errors import LiftError
    try:
        with _puya_error_capture("lower", diagnostics):
            return _to_puya_impl(prog, unknown_type=unknown_type)
    except LiftError:
        raise
    except Exception as e:
        raise LiftError(f"{type(e).__name__}: {e}", stage="lower") from e


def to_puya(prog, *, diagnostics: list | None = None):
    """SSAProgram -> (main, subroutines) as real ``puya.ir.models`` objects, with any
    lowering failure surfaced as a typed ``LiftError`` (stage ``"lower"``). Errors
    puya merely LOGS during model validation are appended to ``diagnostics`` (when
    given) — see :func:`_puya_error_capture`."""
    return _lower_with_unknown_type(prog, diagnostics, PT.any)


def _to_puya_for_codegen(prog, *, diagnostics: list | None = None):
    """Lower for Puya MIR, which cannot represent ``AVMType.any`` registers.

    The placeholder is isolated here: detector-facing :func:`to_puya` always
    keeps residual values as ``PT.any``. Selecting uint64 changes no AVM
    instruction for a value that survived recovery (all family-demanding uses
    have already typed it), but it is a codegen accommodation, never evidence.
    """
    return _lower_with_unknown_type(prog, diagnostics, PT.uint64)


def _to_puya_impl(prog, *, unknown_type=PT.any):
    main, subs, _lifter, _t = _to_puya_full(prog, unknown_type=unknown_type)
    return main, subs


def _to_puya_full(prog, *, unknown_type=PT.any):
    """The full lower, additionally returning the ``lifter`` (SSAVar -> pre_ir
    Register) and ``t`` translator (id(pre_ir Register) -> M.Register) so a caller
    can bridge an SSA value to its lowered puya register."""
    # Pre-lift scratch simplification: forward compile-time-constant scratch loads to
    # their literal. HAZARD: this only rewires the LOAD's consumers and KEEPS the
    # store -- scratch is not a sound local, since a `gload i N` in a SIBLING program
    # can read a slot this one never reads. (Puya's own slot_elimination is omitted
    # for the same reason.)
    try:
        prog.propagate_constants()
        prog.propagate_scratch_constants()
    except Exception as e:
        # These must not fail on valid input, so a raise points at a bug, not a
        # coverage limit: degrade (partial annotations still leave valid IR) but
        # make it VISIBLE, not a silent DEBUG line.
        logger.warning("pre-lift scratch const-propagation FAILED (%s: %s) — "
                       "lifting un-simplified; likely a bug", type(e).__name__, e)
    # Via the lifter directly (not `lift()`), to keep its SSAVar->Register map for
    # the byte-length bridge below.
    lifter = _Lifter(prog)
    lifted = lifter.build()
    # Our reconstruction can emit self-referential phis (`r = phi(r)`), which Puya's
    # copy_propagation asserts on -- collapse them before lowering.
    from .transforms import simplify_trivial_phis
    simplify_trivial_phis(lifted)
    _duplicate_shared_epilogues(lifted)
    t = _Translator(_load_src(prog), unknown_type=unknown_type)
    groups = [lifted.main, *lifted.subroutines]

    # Pass 1: shells, so control ops and InvokeSubroutine can reference real
    # block / subroutine objects.
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
    # AFTER the lift, so byte-length propagation can't perturb the lift's own
    # coarse typing.
    try:
        prog.propagate_byte_lengths()
        bytelen = _byte_length_map(lifter, t)
    except Exception as e:
        # A failure on valid input is a bug — degrade but surface it.
        logger.warning("byte-length sized-bytes bridge FAILED (%s: %s) — "
                       "lengths not bridged; likely a bug", type(e).__name__, e)
        bytelen = {}
    _recover_ir_types(main, subs, byte_lengths=bytelen)
    _recover_encoded_types(main, subs)
    return main, subs, lifter, t


def recovered_min_lengths(prog) -> dict:
    """``{ssa_key: (min_bytes, confident)}`` — a LOWER bound on the byte length of
    every SSA value the SPECULATIVE ARC-4 recovery gives an encoded type (a
    fixed-size type contributes ``num_bytes``, a dynamic one ``2``, its
    length/offset head), keyed by the SSA value's stable ``_key()``.

    HAZARD: an ASSUMPTION about well-formed ABI input, NOT a proof — the consumer
    must report any bound it enables as a distinct *speculative* verdict.
    Lifts ``prog`` itself (the lift restores its input CFG on exit, so sharing it
    with SSA-level analyses is safe). ``{}`` if the contract doesn't lower; never
    raises."""
    try:
        main, subs, lifter, t = _to_puya_full(prog)
        guesses, confident = guess_encoded_types_scored(main, subs)
    except Exception as e:
        logger.debug("recovered_min_lengths: lower/recover skipped: %s", e)
        return {}
    reg_src = getattr(lifter, "register_sources", {})
    reg_objects = getattr(lifter, "register_objects", {})
    out: dict = {}
    for rid, ssa_values in reg_src.items():
        pre = reg_objects.get(rid)
        m = t.regs.get(rid) if pre is not None else None
        if m is None:
            continue
        g = guesses.get(id(m))
        if g is None:
            continue
        nb = getattr(g, "num_bytes", None)
        nb = 2 if nb is None else nb            # dynamic ⇒ >= 2-byte head
        for ssa_val in ssa_values:
            key = getattr(ssa_val, "_key", None)
            if key is None:
                continue
            k = key()
            prev = out.get(k)
            if prev is None or nb < prev[0]:    # disagreement: keep the SMALLER bound
                out[k] = (nb, bool(confident.get(id(m))))
    return out


def _byte_length_map(lifter, t) -> dict:
    """``{id(M.Register): exact_byte_length}`` for every SSA value the byte-length
    pass gave an *exact* length; a register fed by values of disagreeing lengths is
    dropped (ambiguous -> stays plain ``bytes``)."""
    out: dict = {}
    conflict: set = set()
    sources = getattr(lifter, "register_sources", {})
    for rid, ssa_values in sources.items():
        # An exact register length is valid only when EVERY SSA value aliased to
        # it proves the same length.  Ignoring an unknown alias would turn one
        # path's fact into a whole-phi fact.
        lengths = []
        for o in ssa_values:
            ty = getattr(o, "type", None)
            bl = getattr(ty, "byte_length", None) if ty is not None else None
            if bl is None or getattr(ty, "kind", None) != "bytes":
                lengths = []
                break
            lengths.append(bl)
        if not lengths or len(set(lengths)) != 1:
            continue
        bl = lengths[0]
        m = t.regs.get(rid)
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


# Refined IR types restored from Puya's langspec when the recovery flattened them
# to the coarse AVM divide: bool <- uint64; biguint / account / SizedBytesType
# bytes[N] <- bytes.
# HAZARD: this must stay a PURE ANNOTATION -- each refined type is INTERCHANGEABLE
# with its AVM base (same `avm_type`, no reinterpret cast in Puya's IR), so the
# lowered TEAL is byte-identical. A refinement must NEVER cross the AVM divide;
# the `rt.avm_type == cur.avm_type` guard below is what keeps it semantics-free.
_REFINED_IR_TYPES = frozenset({PT.bool, PT.biguint, PT.account})

# The coarse base types the recovery leaves; only these get refined (never an
# already-specific type, and never `any`, which is strictly less specific).
_COARSE_BASE = frozenset({PT.uint64, PT.bytes})


def _is_refinable(rt) -> bool:
    """A langspec return type worth restoring: an interchangeable refined primitive,
    or any (bytes-backed) fixed-width ``SizedBytesType``."""
    from puya.ir.types_ import SizedBytesType
    return rt in _REFINED_IR_TYPES or isinstance(rt, SizedBytesType)


def _langspec_returns(intrinsic: "M.Intrinsic"):
    """An Intrinsic's authoritative return IRTypes from Puya's own ``AVMOpData``
    signature — BOTTOM-FIRST, matching Puya's target order — resolving a field-keyed
    dynamic op by its immediate; ``None`` if it has no static signature."""
    # PUBLIC accessor: it resolves a field-keyed dynamic op by its own
    # immediate, which is exactly what this used to hand-roll off the private
    # `_variants`. It RAISES on an immediate it does not know and indexes the
    # immediates positionally, so anything it cannot resolve degrades to None —
    # the same answer the hand-rolled version gave.
    try:
        return intrinsic.op.get_variant(intrinsic.immediates).signature.returns
    except Exception:
        return None


def _address_operand_identities(main, subs) -> set:
    """The identities of every value FED to an operand the AVM REQUIRES to be a
    32-byte address: an account-typed ``itxn_field``, or ``args[0]`` of a
    local-state / account-parameter op.

    HAZARD: take only ``bytes``-form operands — these ops also accept a ``uint64``
    account INDEX (0=sender, i=Accounts[i-1]), which is NOT an address. Identities
    must stay scoped by owning subroutine (``id(s)``): names like ``l%3`` / ``p%0``
    are unique only WITHIN a sub, so a global set retypes unrelated registers."""
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
                    out.add((id(s), r.name, r.version))
    return out


def _recover_ir_types(main, subs, allow=_is_refinable, byte_lengths=None) -> int:
    """Refine each intrinsic result register from the coarse AVM type the recovery
    left to the finer IR type Puya's langspec declares (or, via ``byte_lengths``,
    to a ``SizedBytesType`` the byte-length pass proved), returning the count.

    HAZARD: a refinement is only sound while it shares the current type's
    ``avm_type`` — it must never cross the AVM divide, and the intrinsic's ``types``
    tuple must be rebuilt to match the refined targets."""
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
                # Refine a target the langspec left as plain `bytes` when the
                # byte-length pass knows its exact length.
                for tgt in o.targets:
                    if tgt.ir_type is PT.bytes and id(tgt) in byte_lengths:
                        _compat.set_ir_type(tgt, SizedBytesType(byte_lengths[id(tgt)]))
                        changed = True
                        n += 1
                if changed:
                    _compat.set_intrinsic_types(
                        o.source, (t.ir_type for t in o.targets))

    # USAGE-BACKWARD account recovery: the langspec pass above types addresses
    # FORWARD from producer ops, this one from CONSUMPTION -- a value fed to an
    # AVM-forced address operand IS a 32-byte account. Same avm_type (bytes), so
    # still a pure annotation.
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
                                and (id(s), tgt.name, tgt.version) in addr_ids:
                            _compat.set_ir_type(tgt, PT.account)
                            n += 1
                            hit = True
                    if hit:
                        _compat.set_intrinsic_types(
                            o.source, (t.ir_type for t in o.targets))
    return n




def _opt_passes():
    """Puya optimiser passes that need no compile context AND are pure cleanups (they
    remove dead/duplicate work without altering the lowered TEAL), in roughly Puya's
    own pipeline order.

    HAZARD: keep this list codegen-neutral — the simplifications that CHANGE the
    lowered TEAL belong in :func:`_aggressive_passes`, and slot_elimination must
    stay out entirely (scratch is gload-readable from a sibling program, so it is
    not a sound local). Inlining / box / itxn-field passes need a real context or
    the Slot abstraction we don't emit."""
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
    """Extra Puya passes that genuinely SIMPLIFY the lowered TEAL: intrinsic folding
    plus ARC4 encode∘decode round-trip elimination.

    HAZARD: these CHANGE codegen, so they are opt-in and gated BEHAVIOURALLY (the
    lift behaves identically), never by byte-identity like the default passes."""
    import types

    from puya.ir.optimize.assignments import encode_decode_pair_elimination
    from puya.ir.optimize.intrinsic_simplification import intrinsic_simplifier
    # intrinsic_simplifier reads only `expand_all_bytes` off its context, and
    # encode_decode_pair_elimination ignores its own -- so a shim suffices.
    shim = types.SimpleNamespace(expand_all_bytes=False)
    return [lambda _ctx, s: intrinsic_simplifier(shim, s),
            encode_decode_pair_elimination]


_BYTES_IRT = frozenset({PT.bytes, PT.account})


def _puya_zero(ir_type):
    if ir_type is PT.any:
        return M.Undefined(source_location=None, ir_type=PT.any)
    if ir_type in _BYTES_IRT:
        return M.BytesConstant(source_location=None, value=b"",
                               encoding=AVMBytesEncoding.utf8)
    # A bytes-backed type that is NOT plain bytes/account (an ARC4 `EncodedType`):
    # emit a bytes zero of the type's fixed width and type the constant AS the
    # target, else the assignment fails Puya's exact type check
    # (`source=(uint64) target=(Encoded(...))`).
    if getattr(ir_type, "avm_type", None) == AVMType.bytes:
        nb = getattr(ir_type, "num_bytes", None)
        n = nb if isinstance(nb, int) else 0
        return M.BytesConstant(source_location=None, value=b"\x00" * n,
                               encoding=AVMBytesEncoding.base16, ir_type=ir_type)
    return M.UInt64Constant(source_location=None, value=0)


def _define_named_orphan(subs, name: str, version: int) -> bool:
    """Define a register the optimiser rejected as undefined (a value the
    reconstruction lost to a frame / dynamic-scratch gap) as a typed zero at its
    subroutine's entry.

    HAZARD: keep this PRECISE — only the exact register Puya names. Blanket
    orphan-defaulting corrupts real contracts, and a program that optimises cleanly
    must never reach here."""
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


def _coerce_slice_operands(subs) -> None:
    """extract3/substring3 take (bytes, uint64, uint64). The undefined-register typed-zero fallback
    can leave a uint64 start/len operand as an empty BytesConstant (the register's reconstructed type
    was bytes) -> a type-invalid slice length. Coerce it to a uint64 (empty -> 0), mirroring
    _u64_cond: the operand position IS uint64, so a bytes there is a reconstruction artifact."""
    import attrs
    for sub in subs:
        for bb in getattr(sub, "body", []):
            for o in bb.ops:
                if not (isinstance(o, M.Assignment) and isinstance(o.source, M.Intrinsic)):
                    continue
                src = o.source
                if src.op not in (AVMOp.extract3, AVMOp.substring3) or len(src.args) != 3:
                    continue
                new_args, changed = list(src.args), False
                for i in (1, 2):
                    a = new_args[i]
                    if isinstance(a, M.BytesConstant):
                        new_args[i] = M.UInt64Constant(
                            source_location=None,
                            value=int.from_bytes(a.value[-8:], "big") if a.value else 0)
                        changed = True
                if changed:
                    o.source = attrs.evolve(src, args=new_args)


def optimize(subs, *, max_rounds: int = 100, aggressive: bool = False,
             diagnostics: list | None = None) -> int:
    """Run Puya's context-free optimiser passes over ``subs`` to a fixpoint (mutating
    them in place, returning the rounds taken), where ``aggressive`` additionally
    enables the CODEGEN-CHANGING simplifications the faithful default leaves off.
    Errors puya merely LOGS while rebuilding ops are appended to ``diagnostics``
    (when given) — see :func:`_puya_error_capture`."""
    from ..diagnostics.errors import LiftError
    try:
        with _puya_error_capture("optimize", diagnostics):
            rounds = _optimize_impl(subs, max_rounds=max_rounds, aggressive=aggressive)
            _coerce_slice_operands(subs)   # repair a typed-zero fallback that left a slice len as bytes
        return rounds
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
    if log.getEffectiveLevel() < logging.WARNING:   # only ever RAISE the threshold —
        log.setLevel(logging.WARNING)               # never re-enable chatter a caller silenced
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
    """Render an SSAProgram as real Puya IR text with Puya's own emitter, optionally
    running the optimiser passes first."""
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
