"""Translate our (mirror) ``ir.Program`` into the *real* ``puya.ir.models`` and
render / optimise it with Puya's own machinery.

Our :mod:`lift` builds a typed, well-formed Puya-shaped IR against a local
mirror of ``puya/ir/models.py``. This walks that mirror and rebuilds it with the
genuine Puya classes, so we can reuse Puya's text renderer (``to_text_visitor``)
and -- via :func:`optimize` -- its real optimiser passes: constant propagation,
copy propagation, control-op simplification, block merging, CSE, and dead-code
elimination (see :func:`_opt_passes`). The IR satisfies Puya's own validators
(``BasicBlock``/``Subroutine`` ``_check_*``), so the passes run unmodified.

Constraints Puya enforces that the translation respects: intrinsic args in AVM
order (our top-first inputs reversed), multi-result intrinsic outputs reversed to
bottom-first, every used register defined (by object identity), block predecessor
lists wired, real ``IRType`` / ``AVMOp`` values, ``SourceLocation`` on each block,
and the typed information our lift adds that decompiled TEAL lacks -- polymorphic
op result types (``load`` / ``app_global_get``), and deploy-time ``TemplateVar``s
recovered from source where the extractor dropped the immediate.
"""
from __future__ import annotations

import os
import zipfile

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.ir.types_ import AVMBytesEncoding, PrimitiveIRType as PT
from puya.parse import SourceLocation

from . import ir
from .lift import lift

_IRT = {
    "uint64": PT.uint64, "bytes": PT.bytes, "bool": PT.bool,
    "account": PT.account, "asset": PT.uint64, "application": PT.uint64,
    "?": PT.uint64,
}

# Const-push pseudo-ops that survive the lift only when their immediate was a
# deploy-time template variable (`pushint TMPL_X`) -- the extractor strips the
# operand, leaving an arg-less, immediate-less push. Puya models these as
# TemplateVar (a non-foldable constant), so the optimiser won't fold them away.
_PUSH_U64 = {"pushint", "intc", "intc_0", "intc_1", "intc_2", "intc_3"}
_PUSH_BYTES = {"pushbytes", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3"}

_SRC_CACHE: dict = {}


def _load_src(db_path: str) -> dict:
    """Map ``basename -> source lines`` from the DB's ``src.zip`` (cached)."""
    if db_path in _SRC_CACHE:
        return _SRC_CACHE[db_path]
    m: dict = {}
    try:
        with zipfile.ZipFile(os.path.join(db_path, "src.zip")) as z:
            for n in z.namelist():
                if n.endswith(".teal"):
                    m[os.path.basename(n)] = z.read(n).decode(
                        "utf-8", "replace").splitlines()
    except (OSError, zipfile.BadZipFile, KeyError):
        pass
    _SRC_CACHE[db_path] = m
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


def _const_bytes(v: str):
    """Parse a TEAL byte literal -> (raw bytes, AVM encoding). Accepts the
    `0x..` / `"str"` / `b64 ..` / `base64(..)` / `b32 ..` / `base32(..)` forms."""
    import base64
    v = v.strip()
    if v.startswith("0x"):
        return bytes.fromhex(v[2:]), AVMBytesEncoding.base16
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _teal_str_bytes(v[1:-1]), AVMBytesEncoding.utf8
    if v.startswith(("b64 ", "base64 ")):
        return base64.b64decode(v.split(None, 1)[1]), AVMBytesEncoding.base64
    if v.startswith("base64(") and v.endswith(")"):
        return base64.b64decode(v[7:-1]), AVMBytesEncoding.base64
    if v.startswith(("b32 ", "base32 ")):
        return base64.b32decode(v.split(None, 1)[1]), AVMBytesEncoding.base32
    if v.startswith("base32(") and v.endswith(")"):
        return base64.b32decode(v[7:-1]), AVMBytesEncoding.base32
    try:
        return bytes.fromhex(v), AVMBytesEncoding.base16
    except ValueError:
        return v.encode("utf-8"), AVMBytesEncoding.utf8


def _sl(line: int) -> SourceLocation:
    return SourceLocation(file=None, line=line or 1)


def _line_of(bb) -> int:
    c = bb.comment or ""
    return int(c[1:]) if c.startswith("L") and c[1:].isdigit() else 1


class _Translator:
    def __init__(self, src_map: dict | None = None):
        self.regs: dict = {}      # id(mirror Register) -> M.Register
        self.blocks: dict = {}    # mirror block id -> M.BasicBlock
        self.subs: dict = {}      # mirror Subroutine.id -> M.Subroutine
        self.src: dict = src_map or {}

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
        if isinstance(v, ir.Register):
            return self.reg(v)
        if isinstance(v, ir.UInt64Constant):
            return M.UInt64Constant(source_location=None, value=v.value)
        if isinstance(v, ir.BytesConstant):
            raw, enc = _const_bytes(v.value or "0x")
            return M.BytesConstant(source_location=None, value=raw, encoding=enc)
        if isinstance(v, ir.Undefined):
            return M.Undefined(source_location=None, ir_type=PT.uint64)
        raise TypeError(f"val: {type(v).__name__}")

    @staticmethod
    def _imm(i):
        s = str(i)
        return int(s) if s.lstrip("-").isdigit() else s

    def vp(self, s, result_types=None):
        if isinstance(s, ir.Intrinsic):
            if (s.op in _PUSH_U64 or s.op in _PUSH_BYTES) and not s.args \
                    and not s.immediates:
                ty = PT.uint64 if s.op in _PUSH_U64 else PT.bytes
                return M.TemplateVar(source_location=None,
                                     name=_tmpl_name(self.src, s.line), ir_type=ty)
            kw = {} if result_types is None else {"types": result_types}
            return M.Intrinsic(
                source_location=None, op=AVMOp(s.op),
                immediates=[self._imm(i) for i in s.immediates],
                args=[self.val(a) for a in reversed(s.args)], **kw)
        if isinstance(s, ir.InvokeSubroutine):
            # Subroutine args are positional (args[i] -> param i), NOT AVM-order
            # like Intrinsic args -- Puya builds them `for param in parameters`.
            return M.InvokeSubroutine(
                source_location=None, target=self.subs[s.target],
                args=[self.val(a) for a in s.args])
        if isinstance(s, ir.ValueTuple):
            return M.ValueTuple(source_location=None,
                                values=[self.val(v) for v in s.values])
        return self.val(s)

    def op(self, o):
        if isinstance(o, ir.Assignment):
            targets = [self.reg(t) for t in o.targets]
            # Our outputs are top-first; Puya intrinsics return bottom-first
            # (AVM order), so a multi-output intrinsic's targets/types reverse.
            if isinstance(o.source, ir.Intrinsic) and len(targets) > 1:
                targets = targets[::-1]
            return M.Assignment(
                source_location=None, targets=targets,
                source=self.vp(o.source, [t.ir_type for t in targets]))
        if isinstance(o, ir.IntrinsicOp):
            if isinstance(o.intrinsic, ir.Intrinsic) and o.intrinsic.op in ("pop", "popn"):
                return None                      # pop/popn = discard; unused value, no-op in SSA
            return self.vp(o.intrinsic)          # side-effecting intrinsic = an Op
        if isinstance(o, ir.Assert):
            return M.Assert(source_location=None, condition=self.val(o.condition),
                            message=o.message or "assert", explicit=True)
        raise TypeError(f"op: {type(o).__name__}")

    def ctrl(self, t):
        B = self.blocks
        if isinstance(t, ir.Goto):
            return M.Goto(source_location=None, target=B[t.target])
        if isinstance(t, ir.ConditionalBranch):
            return M.ConditionalBranch(
                source_location=None, condition=self.val(t.condition),
                non_zero=B[t.non_zero], zero=B[t.zero])
        if isinstance(t, ir.GotoNth):
            return M.GotoNth(source_location=None, value=self.val(t.value),
                             blocks=[B[b] for b in t.blocks], default=B[t.default])
        if isinstance(t, ir.Switch):
            cases = {}
            for lbl, blk in t.cases:
                raw, enc = _const_bytes(str(lbl))
                key = M.BytesConstant(source_location=None, value=raw, encoding=enc)
                cases[key] = B[blk]
            return M.Switch(source_location=None, value=self.val(t.value),
                            cases=cases, default=B[t.default])
        if isinstance(t, ir.SubroutineReturn):
            return M.SubroutineReturn(source_location=None,
                                      result=[self.val(v) for v in t.result])
        if isinstance(t, ir.ProgramExit):
            return M.ProgramExit(source_location=None, result=self.val(t.result))
        if isinstance(t, ir.Fail):
            return M.Fail(source_location=None,
                          error_message=t.error_message or "err", explicit=True)
        raise TypeError(f"ctrl: {type(t).__name__}")

    def phi(self, p):
        return M.Phi(register=self.reg(p.register),
                     args=[M.PhiArgument(value=self.reg(a.value),
                                         through=self.blocks[a.through])
                           for a in p.args if isinstance(a.value, ir.Register)])

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
    if isinstance(term, ir.Goto):
        return [term.target]
    if isinstance(term, ir.ConditionalBranch):
        return [term.non_zero, term.zero]
    if isinstance(term, ir.GotoNth):
        return [*term.blocks, term.default]
    if isinstance(term, ir.Switch):
        return [b for _, b in term.cases] + [term.default]
    return []


def to_puya(prog):
    """SSAProgram -> (main, subroutines) as real puya.ir.models objects."""
    mirror = lift(prog)
    t = _Translator(_load_src(getattr(prog, "db_path", "")))
    groups = [mirror.main, *mirror.subroutines]

    # Pass 1: shells (empty body validates trivially), so control ops and
    # InvokeSubroutine can reference real block / subroutine objects.
    for s in groups:
        for bb in s.body:
            t.blocks[bb.id] = M.BasicBlock(source_location=_sl(_line_of(bb)),
                                           id=bb.id, ops=[], terminator=None)
    for s in mirror.subroutines:
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
            mb.ops = [m for m in (t.op(o) for o in bb.ops) if m is not None]
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

    main = M.Subroutine(id=mirror.main.id, short_name="main", source_location=None,
                        parameters=[], returns=[], body=main_body, inline=None)
    return main, [t.subs[s.id] for s in mirror.subroutines]


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


def optimize(subs, *, max_rounds: int = 100) -> int:
    """Run Puya's context-free optimiser passes over ``subs`` to a fixpoint.
    Mutates the subroutines in place; returns the number of rounds taken. Puya's
    pass logging is silenced for the duration."""
    import logging
    passes = _opt_passes()
    log = logging.getLogger("puya")
    prev = log.level
    log.setLevel(logging.WARNING)
    try:
        for rnd in range(1, max_rounds + 1):
            if not any(pz(None, s) for s in subs for pz in passes):
                return rnd
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
