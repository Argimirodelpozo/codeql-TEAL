"""Pre-IR — the Puya-shaped *working* model the lift builds, lowered to real
``puya.ir.models`` by :mod:`to_puya_ir`.

A *separate*, mutable model is needed because the lift recovers types by a
fixpoint (registers born ``?``, refined in place), while Puya's ``Register`` is
``@attrs.frozen`` with no unknown ``IRType``. Types here are one ``ir_type`` kind
string (uint64/bytes/bool/account/asset/application/?); the class/field structure
otherwise matches ``puya/ir/models.py`` (Value, ValueProvider, Op, Phi, ControlOp,
structural). Nodes self-render the ``.ssa.slot.ir`` shape via ``render()``.
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

    Mutable (and never hashed) so a later pass can refine ``ir_type`` — e.g.
    unifying a phi's type from its arguments."""
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

    def render(self) -> str:
        return "\n\n".join(s.render() for s in (self.main, *self.subroutines))


# --------------------------------------------------------------------------
# Traversal & operand access — the one place that knows a program's blocks and
# where each node's Values live, so passes don't re-spell the iteration / the
# Op/ControlOp dispatch. ``operands`` reads, ``map_operands`` rewrites in place.
# --------------------------------------------------------------------------


def blocks(prog_or_subs):
    """Every :class:`BasicBlock` of a :class:`Program` (main first) or of an
    iterable of :class:`Subroutine`, in order."""
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
    """Yield each :data:`Value` operand of an Op / ControlOp / Phi — the leaf
    values, descending into ``Intrinsic``/``InvokeSubroutine`` args and
    ``ValueTuple`` values. Nothing for operand-less nodes (Goto, Fail, None)."""
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
    """Rewrite each Value operand of ``node`` through ``fn`` in place — the write
    twin of :func:`operands`; no-op for operand-less nodes / None.

    ``copy_source`` governs a bare copy source (an Assignment whose source is a
    plain Value): ``True`` rewrites it (substitution touches every reference),
    ``False`` leaves it (trivial-phi collapse must not forward a copy into a
    removed register)."""
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
