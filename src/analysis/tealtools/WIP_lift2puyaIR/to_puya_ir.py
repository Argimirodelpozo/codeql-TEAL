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

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.ir.types_ import AVMBytesEncoding, PrimitiveIRType as PT
from puya.parse import SourceLocation

from . import pre_ir
from .lift import _Lifter, lift
from .teal_const import _const_bytes, _load_src, _tmpl_name
from ..ast.literals import tokenize_operands as _tokenize_operands

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
    raw, enc = _const_bytes(operand)
    return M.BytesConstant(source_location=None, value=raw, encoding=enc)


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
            raw, enc = _const_bytes(v.value or "0x")
            return M.BytesConstant(source_location=None, value=raw, encoding=enc)
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
                    raw, enc = _const_bytes(str(lbl))
                    key = M.BytesConstant(source_location=None, value=raw, encoding=enc)
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


def to_puya(prog):
    """SSAProgram -> (main, subroutines) as real puya.ir.models objects."""
    # Build via the lifter directly (not `lift()`) so we keep its SSAVar->Register
    # map for the byte-length sized-bytes bridge below.
    lifter = _Lifter(prog)
    lifted = lifter.build()
    # Collapse trivial / self-referential phis (`r = phi(r)`) before lowering:
    # Puya's own copy_propagation asserts on these (it can't represent a
    # register replaced by itself), but our reconstruction can emit them.
    from .transforms import simplify_trivial_phis
    simplify_trivial_phis(lifted)
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
    except Exception:
        bytelen = {}
    _recover_ir_types(main, subs, byte_lengths=bytelen)
    _recover_encoded_types(main, subs)
    return main, subs


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
    v = getattr(intrinsic.op, "_variants", None)
    if isinstance(v, Variant):
        return v.signature.returns
    if isinstance(v, DynamicVariants):
        imms = intrinsic.immediates
        if imms and v.immediate_index < len(imms):
            var = v.variant_map.get(str(imms[v.immediate_index]))
            if var is not None:
                return var.signature.returns
    return None


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
                            object.__setattr__(tgt, "ir_type", rt)
                            changed = True
                            n += 1
                # Byte-length sized-bytes: refine a target the langspec left as
                # plain `bytes` when its exact length is known.
                for tgt in o.targets:
                    if tgt.ir_type is PT.bytes and id(tgt) in byte_lengths:
                        object.__setattr__(
                            tgt, "ir_type", SizedBytesType(byte_lengths[id(tgt)]))
                        changed = True
                        n += 1
                if changed:
                    try:
                        object.__setattr__(
                            o.source, "types", tuple(t.ir_type for t in o.targets))
                    except Exception:
                        pass
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


def _guess_encoding_for(intrinsic: "M.Intrinsic", reg_def: dict):
    """The ARC4 / ABI ``EncodedType`` a producing op's result is *most likely* but
    NOT provably encoded as, or ``None`` -- the **SPECULATIVE** tier, kept
    deliberately separate from :func:`_confident_encoding_for`.

    These are the idioms whose byte layout is *not* self-evidently one ABI type and
    so require either a proof we don't always have or a confidence judgement, e.g.:
      - ``concat(<2-byte value>, data)`` -> ``arc4.String`` / dynamic ``Array`` only
        when the 2-byte prefix can be shown to equal ``len(data)`` (a uint16 length
        header) -- otherwise the prefix could be an unrelated uint16 field;
      - a head/tail buffer with a uint16 offset table -> a *dynamic* ``arc4.Tuple``;
      - ``bytes[N]`` reinterpreted as ``arc4.StaticArray<Byte, N>`` / ``arc4.Address``
        (a 32-byte value), which the bytes alone don't disambiguate from a hash.

    Currently EMPTY -- this is the scaffold. Anything added here is best-effort: it
    is collected into a SIDE-CHANNEL by :func:`_guess_encoded_types` and never
    written to a register's ``ir_type``, so a wrong guess can neither change codegen
    nor weaken the confident, TEAL-neutral IR. (Consumers that tolerate imprecision
    -- e.g. structure-aware fuzzing -- read the side-channel; a verifier would treat
    a guess as a proposed-and-discharged obligation.)"""
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
        ``substring3(X, off_p, off_q)`` slice, taken from ``dynamic_guesses`` (a
        nested String / DynamicArray) or defaulted to dynamic bytes;
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
    out: dict = {}
    for base, sl in slots.items():
        if not any(k == "dyn" for (k, _, _) in sl.values()) or len(sl) < 2:
            continue                                 # a struct: >=1 dynamic field, >=2 fields
        fields = []
        expected = 0
        consistent = True
        for pos in sorted(sl):
            kind, size, info = sl[pos]
            if pos > expected:                       # unread head bytes -> byte blob
                fields.append(ArrayEncoding(
                    element=UIntEncoding(8), size=pos - expected, length_header=False))
            elif pos < expected:                     # overlapping reads -> inconsistent
                consistent = False
                break
            if kind == "static":
                fields.append(info)
            else:                                    # dynamic field
                fld = field_of.get(info)
                enc = (dynamic_guesses[id(fld)].encoding
                       if fld is not None and id(fld) in dynamic_guesses else None)
                fields.append(enc if enc is not None else dyn_byte)
            expected = pos + size
        if consistent and fields:
            out[base] = EncodedType(TupleEncoding(fields))
    return out


def _guess_encoded_types(main, subs) -> dict:
    """SPECULATIVE encoded-type recovery, returned as a SIDE-CHANNEL
    ``{id(M.Register): EncodedType}`` map -- it does NOT mutate any ``ir_type``, so
    it is fully decoupled from the confident, proven-neutral IR and cannot affect
    lowering. Not wired into :func:`to_puya`'s default path; a consumer that wants
    best-effort ABI structure calls it explicitly.

    Sources of guesses (more-specific guesses win over coarser ones in the merge):
      - values DECODED as length-prefixed dynamic arrays/strings (incl. method args),
        via :func:`_guess_decoded_dynamic` (coarsest);
      - dynamic STRUCTS / tuples reconstructed from their offset-table decode, via
        :func:`_guess_struct_encodings` (overrides the array guess for that value);
      - bytes CONSTANTS that are self-describing uint16-length-prefixed sequences,
        via :func:`_guess_const_encoding` -> ``arc4.String``;
      - intrinsic results, via :func:`_guess_encoding_for` (currently none)."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o
    guesses: dict = _guess_decoded_dynamic(main, subs)
    guesses.update(_guess_struct_encodings(main, subs, guesses))
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not isinstance(o, M.Assignment):
                    continue
                src = o.source
                if isinstance(src, M.Intrinsic):
                    et = _guess_encoding_for(src, reg_def)
                elif isinstance(src, M.BytesConstant):
                    et = _guess_const_encoding(src.value)
                else:
                    et = None
                if et is None:
                    continue
                for tgt in o.targets:
                    if tgt.ir_type.avm_type == et.avm_type:
                        guesses[id(tgt)] = et   # producer-side wins over decode-side
    return guesses


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
                            object.__setattr__(tgt, "ir_type", et)
                            touched = changed = True
                            n += 1
                    if touched:
                        try:
                            object.__setattr__(
                                o.source, "types",
                                tuple(t.ir_type for t in o.targets))
                        except Exception:
                            pass
    return n


def _opt_passes():
    """Puya optimiser passes that take no (or an unused) compile context, so they
    run directly on our translated subroutines -- order roughly follows Puya's own
    pipeline. (slot_elimination/intrinsic_simplifier need a real context and act on
    Puya's Slot abstraction / high-level ops we don't emit, so they're omitted.)"""
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


_BYTES_IRT = frozenset({PT.bytes, PT.account})


def _puya_zero(ir_type):
    if ir_type in _BYTES_IRT:
        return M.BytesConstant(source_location=None, value=b"",
                               encoding=AVMBytesEncoding.utf8)
    return M.UInt64Constant(source_location=None, value=0)


def _define_named_orphan(subs, name: str, version: int) -> bool:
    """Define a register the optimiser rejected as undefined (a value the
    reconstruction lost to a frame / dynamic-scratch gap) as a typed zero at its
    subroutine's entry. Precise: only the exact register Puya names is touched,
    so a contract that optimises cleanly never reaches this."""
    from puya.ir.models import _get_used_registers
    for sub in subs:
        if not sub.body:
            continue
        match = next((r for r in _get_used_registers(sub.body)
                      if r.name == name and r.version == version), None)
        if match is not None:
            sub.body[0].ops.insert(0, M.Assignment(
                source_location=None, targets=[match], source=_puya_zero(match.ir_type)))
            return True
    return False


def optimize(subs, *, max_rounds: int = 100) -> int:
    """Run Puya's context-free optimiser passes over ``subs`` to a fixpoint.
    Mutates the subroutines in place; returns the number of rounds taken. Puya's
    pass logging is silenced for the duration. If a pass rejects a register the
    reconstruction left undefined, define it (typed zero) and retry -- bounded,
    and only ever engaged by a contract that fails to optimise."""
    import logging
    import re
    from puya.errors import InternalError
    passes = _opt_passes()
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
                m = re.search(r"not defined: ([^#\s]+)#(\d+)", str(e))
                if not (m and _define_named_orphan(subs, m.group(1), int(m.group(2)))):
                    raise
        return max_rounds
    finally:
        log.setLevel(prev)


def render(prog, *, optimize_ir: bool = False) -> str:
    """Render an SSAProgram as real Puya IR text, using Puya's own emitter. With
    ``optimize_ir`` set, Puya's optimiser passes run on the IR first."""
    from puya.ir.to_text_visitor import TextEmitter, _render_body

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
