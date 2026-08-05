"""Pre-IR — the Puya-shaped *working* model the lift builds, mirroring
``puya/ir/models.py`` and lowered to it by :mod:`to_puya_ir`. A type is one
``ir_type`` kind string (uint64/bytes/bool/account/asset/application/?).

HAZARD: it stays SEPARATE and MUTABLE because the lift recovers types by a fixpoint
(registers born ``?``, refined in place) — something Puya's ``@attrs.frozen``
``Register``, with no unknown ``IRType``, cannot express.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

# --------------------------------------------------------------------------
# Values — single value providers (Puya: Value < ValueProvider)
# --------------------------------------------------------------------------


@dataclass
class Register:
    """Puya ``Register``: an SSA value, ``name#version`` of type ``ir_type``.

    HAZARD: mutable and never hashed — passes refine ``ir_type`` in place, so every
    consumer must key a register by ``id()``, not by value."""
    name: str
    version: int
    ir_type: str

    @property
    def local_id(self) -> str:
        return f"{self.name}#{self.version}"

    def __str__(self) -> str:
        return self.local_id


@dataclass(frozen=True)
class UInt64Constant:
    value: int
    ir_type: str = "uint64"

    def __str__(self) -> str:
        return f"{self.value}u"


@dataclass(frozen=True)
class BytesConstant:
    value: str  # "0x..." hex, verbatim (no source strings to recover)
    ir_type: str = "bytes"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Undefined:
    ir_type: str = "?"

    def __str__(self) -> str:
        return "undefined"


Value = Union[Register, UInt64Constant, BytesConstant, Undefined]

# --------------------------------------------------------------------------
# ValueProviders — produce value(s); used as the source of an Assignment
# --------------------------------------------------------------------------


@dataclass
class Intrinsic:
    """Puya ``Intrinsic``: an AVM op applied to ``args`` with ``immediates``."""
    op: str
    immediates: list  # list[str | int]
    args: list  # list[Value]
    line: int = 0  # source line of the originating TEAL op (0 = unknown)

    def __str__(self) -> str:
        toks = [self.op, *(str(i) for i in self.immediates),
                *(str(a) for a in self.args)]
        return "(" + " ".join(t for t in toks if t != "") + ")"


@dataclass
class InvokeSubroutine:
    target: str  # subroutine id
    args: list  # list[Value]

    def __str__(self) -> str:
        a = " ".join(str(x) for x in self.args)
        return f"({self.target}{(' ' + a) if a else ''})"


@dataclass
class ValueTuple:
    values: list  # list[Value]

    def __str__(self) -> str:
        return "(" + ", ".join(str(v) for v in self.values) + ")"


ValueProvider = Union[Value, Intrinsic, InvokeSubroutine, ValueTuple]

# --------------------------------------------------------------------------
# Ops — block-body statements (non-control, non-phi)
# --------------------------------------------------------------------------


@dataclass
class Assignment:
    """Puya ``Assignment``: ``let <targets> = <source>``."""
    targets: list  # list[Register]
    source: object  # ValueProvider
    comment: Optional[str] = None  # trailing annotation, e.g. value ranges

    def render(self) -> str:
        lhs = ", ".join(f"{t.local_id}: {t.ir_type}" for t in self.targets)
        out = f"let {lhs} = {self.source}"
        return f"{out}  // {self.comment}" if self.comment else out


@dataclass
class Assert:
    condition: object  # Value
    message: Optional[str] = None

    def render(self) -> str:
        m = f"  // {self.message}" if self.message else ""
        return f"(assert {self.condition}){m}"


@dataclass
class IntrinsicOp:
    """A side-effecting intrinsic used as a statement (no SSA results)."""
    intrinsic: Intrinsic

    def render(self) -> str:
        return str(self.intrinsic)


Op = Union[Assignment, Assert, IntrinsicOp]

# --------------------------------------------------------------------------
# Phi
# --------------------------------------------------------------------------


@dataclass
class PhiArgument:
    value: object  # Register | Value
    through: int   # predecessor block id

    def __str__(self) -> str:
        return f"{self.value} <- block@{self.through}"


@dataclass
class Phi:
    register: Register
    args: list  # list[PhiArgument]
    comment: Optional[str] = None  # trailing annotation, e.g. value range

    def render(self) -> str:
        a = ", ".join(str(x) for x in self.args)
        out = f"let {self.register.local_id}: {self.register.ir_type} = φ({a})"
        return f"{out}  // {self.comment}" if self.comment else out


# --------------------------------------------------------------------------
# ControlOps — block terminators
# --------------------------------------------------------------------------


@dataclass
class Goto:
    target: int  # block id

    def render(self) -> str:
        return f"goto block@{self.target}"


@dataclass
class ConditionalBranch:
    condition: object  # Value
    non_zero: int      # block id taken when condition != 0
    zero: int          # block id taken when condition == 0

    def render(self) -> str:
        return f"goto {self.condition} ? block@{self.non_zero} : block@{self.zero}"


@dataclass
class GotoNth:
    value: object
    blocks: list  # list[int]
    default: int

    def render(self) -> str:
        bs = ", ".join(f"block@{b}" for b in self.blocks)
        return f"goto_nth {self.value} [{bs}] else block@{self.default}"


@dataclass
class Switch:
    value: object
    cases: list  # list[(case_label:str, block_id:int)]
    default: int

    def render(self) -> str:
        cs = ", ".join(f"{lbl} => block@{b}" for lbl, b in self.cases)
        return f"switch {self.value} {{{cs}, * => block@{self.default}}}"


@dataclass
class SubroutineReturn:
    result: list  # list[Value]

    def render(self) -> str:
        r = " ".join(str(x) for x in self.result)
        return f"return {r}".rstrip()


@dataclass
class ProgramExit:
    result: object  # Value (uint64)

    def render(self) -> str:
        return f"exit {self.result}"


@dataclass
class Fail:
    error_message: Optional[str] = None

    def render(self) -> str:
        return "fail" + (f"  // {self.error_message}" if self.error_message else "")


ControlOp = Union[Goto, ConditionalBranch, GotoNth, Switch,
                  SubroutineReturn, ProgramExit, Fail]

# --------------------------------------------------------------------------
# Structural
# --------------------------------------------------------------------------


@dataclass
class BasicBlock:
    id: int
    phis: list = field(default_factory=list)   # list[Phi]
    ops: list = field(default_factory=list)    # list[Op]
    terminator: object = None                  # ControlOp | None
    comment: Optional[str] = None

    def render(self, indent: str = "    ") -> str:
        head = f"{indent}block@{self.id}:"
        if self.comment:
            head += f" // {self.comment}"
        out = [head]
        for p in self.phis:
            out.append(f"{indent}    {p.render()}")
        for o in self.ops:
            out.append(f"{indent}    {o.render()}")
        if self.terminator is not None:
            out.append(f"{indent}    {self.terminator.render()}")
        return "\n".join(out)


@dataclass
class Parameter:
    register: Register

    def __str__(self) -> str:
        return f"{self.register.local_id}: {self.register.ir_type}"


@dataclass
class Subroutine:
    id: str
    parameters: list           # list[Parameter]
    returns: list              # list[str] (ir_type kinds)
    body: list                 # list[BasicBlock]
    is_main: bool = False

    def render(self) -> str:
        if self.is_main:
            head = f"main {self.id}:"
        else:
            params = ", ".join(str(p) for p in self.parameters)
            rets = ", ".join(self.returns) or "void"
            head = f"subroutine {self.id}({params}) -> {rets}:"
        return head + "\n" + "\n\n".join(b.render() for b in self.body)


@dataclass
class Program:
    main: Subroutine
    subroutines: list = field(default_factory=list)  # list[Subroutine]
    #: How often each guarded pass FIRED building this program (pass name ->
    #: count). Every entry is a pass that refuses silently when its guards
    #: fail: refusal is safe by design (each falls back to a total, honest
    #: representation) which is exactly why a rotted guard is invisible —
    #: nothing raises, nothing changes shape, the fallback just takes over.
    #: `tests/test_pass_firing_ratchet.py` pins these so that stays loud.
    pass_stats: dict = field(default_factory=dict)

    def render(self) -> str:
        return "\n\n".join(s.render() for s in (self.main, *self.subroutines))


# --------------------------------------------------------------------------
# Traversal & structural access — the ONE place that knows where a node's Values
# and SUCCESSORS live, so passes never re-spell the Op/ControlOp dispatch and miss
# an operand position or an edge. ``operands`` / ``succ_ids`` read,
# ``map_operands`` / ``map_succ_ids`` rewrite in place.
# --------------------------------------------------------------------------


def succ_ids(term) -> list:
    """Successor block ids of a terminator, in edge order (no edges -> ``[]``).

    Lives here for the same reason ``operands`` does: a terminator kind added to
    only some of the spellings silently loses an edge, and this was previously
    spelled four times across two modules."""
    if isinstance(term, Goto):
        return [term.target]
    if isinstance(term, ConditionalBranch):
        return [term.non_zero, term.zero]
    if isinstance(term, GotoNth):
        return [*term.blocks, term.default]
    if isinstance(term, Switch):
        return [b for _, b in term.cases] + [term.default]
    return []


def map_succ_ids(term, fn) -> None:
    """Rewrite every successor block id of ``term`` in place through ``fn``."""
    if isinstance(term, Goto):
        term.target = fn(term.target)
    elif isinstance(term, ConditionalBranch):
        term.non_zero = fn(term.non_zero)
        term.zero = fn(term.zero)
    elif isinstance(term, GotoNth):
        term.blocks = [fn(b) for b in term.blocks]
        term.default = fn(term.default)
    elif isinstance(term, Switch):
        term.cases = [(k, fn(b)) for k, b in term.cases]
        term.default = fn(term.default)


def blocks(prog_or_subs):
    """Every :class:`BasicBlock` of a :class:`Program` (main first) or of an iterable
    of :class:`Subroutine`, in order."""
    subs = ((prog_or_subs.main, *prog_or_subs.subroutines)
            if isinstance(prog_or_subs, Program) else prog_or_subs)
    for s in subs:
        yield from s.body


def _vp_values(vp):
    """The Value list inside a ValueProvider (or the bare Value itself)."""
    if isinstance(vp, (Intrinsic, InvokeSubroutine)):
        return vp.args
    if isinstance(vp, ValueTuple):
        return vp.values
    return (vp,)                              # a copy's bare source / a constant


def operands(node):
    """Yield each leaf :data:`Value` operand of an Op / ControlOp / Phi, descending
    into ``Intrinsic`` / ``InvokeSubroutine`` args and ``ValueTuple`` values."""
    if isinstance(node, Phi):
        for a in node.args:
            yield a.value
    elif isinstance(node, Assignment):
        yield from _vp_values(node.source)
    elif isinstance(node, IntrinsicOp):
        yield from _vp_values(node.intrinsic)
    elif isinstance(node, (Assert, ConditionalBranch)):
        yield node.condition
    elif isinstance(node, (Switch, GotoNth)):
        yield node.value
    elif isinstance(node, SubroutineReturn):
        yield from node.result
    elif isinstance(node, ProgramExit):
        yield node.result


def _map_vp(vp, fn, copy_source):
    if isinstance(vp, (Intrinsic, InvokeSubroutine)):
        vp.args = [fn(a) for a in vp.args]
        return vp
    if isinstance(vp, ValueTuple):
        vp.values = [fn(v) for v in vp.values]
        return vp
    return fn(vp) if copy_source else vp     # bare register/const copy source


def map_operands(node, fn, *, copy_source: bool = True) -> None:
    """Rewrite each Value operand of ``node`` through ``fn`` in place — the write twin
    of :func:`operands`; no-op for operand-less nodes / None.

    HAZARD: ``copy_source`` governs a bare copy source (an Assignment whose source is
    a plain Value): ``True`` rewrites it, reaching every reference; ``False`` leaves
    it, as trivial-phi collapse needs, or it forwards a copy into a removed register."""
    if isinstance(node, Phi):
        for a in node.args:
            a.value = fn(a.value)
    elif isinstance(node, Assignment):
        node.source = _map_vp(node.source, fn, copy_source)
    elif isinstance(node, IntrinsicOp):
        _map_vp(node.intrinsic, fn, copy_source)
    elif isinstance(node, Assert):
        node.condition = fn(node.condition)
    elif isinstance(node, ConditionalBranch):
        node.condition = fn(node.condition)
    elif isinstance(node, (Switch, GotoNth)):
        node.value = fn(node.value)
    elif isinstance(node, SubroutineReturn):
        node.result = [fn(r) for r in node.result]
    elif isinstance(node, ProgramExit):
        node.result = fn(node.result)
