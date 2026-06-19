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
from .lift import lift
from .teal_const import (
    _const_bytes, _load_src, _tmpl_name, _tokenize_operands,
)

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
# deploy-time template variable (`pushint TMPL_X`) -- the extractor strips the
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
        extractor truncates these blocks (drops ``TMPL_*`` / encoded entries),
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
        whose const-block slot the extractor dropped, from the source block."""
        kind = "intc" if op_name.startswith("intc") else "bytec"
        entries = self._const_block(kind, line)
        if 0 <= idx < len(entries):
            return _make_const(entries[idx], is_u64=(kind == "intc"))
        return None

    def vp(self, s, result_types=None):
        if isinstance(s, pre_ir.Intrinsic):
            # const-load by index (intc_N / bytec_N / `intc N` / `bytec N`)
            # whose const-block slot the extractor dropped -> recover from source.
            idx = None
            if s.op in ("bytec", "intc") and len(s.immediates) == 1 and not s.args:
                idx = int(self._imm(s.immediates[0]))
            elif s.op in _INDEXED and not s.args:
                idx = _INDEXED[s.op]
            if idx is not None:
                v = self._block_value(s.op, idx, s.line)
                if v is not None:
                    return v
            # const-push whose inline operand the extractor dropped (e.g.
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
            # the extractor dropped: Puya has no such op, so split into one
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
                # push (operands dropped by the extractor) whose values, if used,
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
    lifted = lift(prog)
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
    return main, [t.subs[s.id] for s in lifted.subroutines]


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


def _define_orphans_from_error(subs, err_str: str) -> bool:
    """Define every ``name#version`` register an SSA/optimiser/backend error names
    as undefined. Handles both Puya phrasings -- the singular ``Undefined
    register: x#1`` and the plural ``... used but never defined: l%2#0, l%3#0``
    (raised by ``Subroutine._check_blocks`` at ``validate_with_ssa``). Returns
    True if it defined at least one (so the caller can retry); a register the
    error names but that isn't actually a bad read is left untouched."""
    import re
    # ONLY the undefined-register phrasings -- never e.g. "assigned multiple times"
    # (a different SSA violation; defining the named register there would add yet
    # another assignment and spin the retry forever).
    if not re.search(r"[Uu]ndefined register|not defined|never defined", err_str):
        return False
    defined = False
    for name, ver in re.findall(r"([A-Za-z_][\w%]*)#(\d+)", err_str):
        if _define_named_orphan(subs, name, int(ver)):
            defined = True
    return defined


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
