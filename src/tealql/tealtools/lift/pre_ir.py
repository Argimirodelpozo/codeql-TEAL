"""Pre-IR — the Puya-shaped *working* model the lift builds, mirroring
``puya/ir/models.py`` and lowered to it by :mod:`to_puya_ir`. A type is one
``ir_type`` kind string (uint64/bytes/bool/account/asset/application/?).

The working model stays mutable because the lift recovers types by a fixpoint
(registers born ``?``, refined in place) — something Puya's ``@attrs.frozen``
``Register``, with no unknown ``IRType``, cannot express. Cached analysis
instances are sealed by ``freeze`` after construction.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Optional, Union
from types import MappingProxyType

class _Freezable:
    """Mutable during construction, sealed when published to cached analyses."""
    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise TypeError("cached analysis IR is read-only")
        object.__setattr__(self, name, value)


def freeze(value, seen=None):
    """Seal owned IR recursively; non-owning SSA provenance is never traversed."""
    seen = set() if seen is None else seen
    if isinstance(value, list):
        return tuple(freeze(v, seen) for v in value)
    if isinstance(value, dict):
        return MappingProxyType({k: freeze(v, seen) for k, v in value.items()})
    if isinstance(value, _Freezable) and id(value) not in seen:
        seen.add(id(value))
        for member in fields(value):
            if member.name != "origin":
                object.__setattr__(value, member.name, freeze(getattr(value, member.name), seen))
        object.__setattr__(value, "_frozen", True)
    return value


# --------------------------------------------------------------------------
# Values — single value providers (Puya: Value < ValueProvider)
# --------------------------------------------------------------------------


@dataclass
class Register(_Freezable):
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
    """Analysis TOP: a value reconstruction could not prove.

    Security analyses must treat it as potentially attacker-controlled. Only
    the Puya/backend boundary may choose a typed placeholder so diagnostic or
    recompilation output can be produced; that placeholder is never fed back
    into analysis.
    """

    ir_type: str = "?"

    def __str__(self) -> str:
        return "undefined"


Value = Union[Register, UInt64Constant, BytesConstant, Undefined]

# --------------------------------------------------------------------------
# ValueProviders — produce value(s); used as the source of an Assignment
# --------------------------------------------------------------------------


@dataclass
class Intrinsic(_Freezable):
    """Puya ``Intrinsic``: an AVM op applied to ``args`` with ``immediates``."""
    op: str
    immediates: list  # list[str | int]
    args: list  # list[Value]
    line: int = 0  # source line of the originating TEAL op (0 = unknown)
    # Exact public SSA Assignment that emitted this node. Reporting still uses
    # ``line``; structural/differential consumers use identity.
    origin: object = field(default=None, repr=False, compare=False)

    def __deepcopy__(self, memo):
        """Clone working IR while retaining the non-owning SSA origin.

        Return specialization deep-copies whole subroutines. Following
        ``origin`` from there would copy the public SSA def/use/CFG graph and
        recurse through its cycles; the origin is immutable provenance for the
        IR node, not part of the working graph being cloned.
        """
        from copy import deepcopy

        clone = type(self)(
            self.op,
            deepcopy(self.immediates, memo),
            deepcopy(self.args, memo),
            self.line,
            self.origin,
        )
        memo[id(self)] = clone
        return clone

    def __str__(self) -> str:
        toks = [self.op, *(str(i) for i in self.immediates),
                *(str(a) for a in self.args)]
        return "(" + " ".join(t for t in toks if t != "") + ")"


@dataclass
class InvokeSubroutine(_Freezable):
    target: str  # subroutine id
    args: list  # list[Value]
    origin: object = field(default=None, repr=False, compare=False)

    def __deepcopy__(self, memo):
        """Clone the call and its values, but share its SSA provenance."""
        from copy import deepcopy

        clone = type(self)(
            self.target,
            deepcopy(self.args, memo),
            self.origin,
        )
        memo[id(self)] = clone
        return clone

    def __str__(self) -> str:
        a = " ".join(str(x) for x in self.args)
        return f"({self.target}{(' ' + a) if a else ''})"


@dataclass
class ValueTuple(_Freezable):
    values: list  # list[Value]

    def __str__(self) -> str:
        return "(" + ", ".join(str(v) for v in self.values) + ")"


ValueProvider = Union[Value, Intrinsic, InvokeSubroutine, ValueTuple]

# --------------------------------------------------------------------------
# Ops — block-body statements (non-control, non-phi)
# --------------------------------------------------------------------------


@dataclass
class Assignment(_Freezable):
    """Puya ``Assignment``: ``let <targets> = <source>``."""
    targets: list  # list[Register]
    source: object  # ValueProvider
    comment: Optional[str] = None  # trailing annotation, e.g. value ranges

    def render(self) -> str:
        lhs = ", ".join(f"{t.local_id}: {t.ir_type}" for t in self.targets)
        out = f"let {lhs} = {self.source}"
        return f"{out}  // {self.comment}" if self.comment else out


@dataclass
class Assert(_Freezable):
    condition: object  # Value
    message: Optional[str] = None
    line: int = 0      # source line of the originating TEAL assert (0 = unknown)

    def render(self) -> str:
        m = f"  // {self.message}" if self.message else ""
        return f"(assert {self.condition}){m}"


@dataclass
class IntrinsicOp(_Freezable):
    """A side-effecting intrinsic used as a statement (no SSA results)."""
    intrinsic: Intrinsic

    def render(self) -> str:
        return str(self.intrinsic)


Op = Union[Assignment, Assert, IntrinsicOp]

# --------------------------------------------------------------------------
# Phi
# --------------------------------------------------------------------------


@dataclass
class PhiArgument(_Freezable):
    value: object  # Register | Value
    through: int   # predecessor block id

    def __str__(self) -> str:
        return f"{self.value} <- block@{self.through}"


@dataclass
class Phi(_Freezable):
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
class Goto(_Freezable):
    target: int  # block id

    def render(self) -> str:
        return f"goto block@{self.target}"


@dataclass
class ConditionalBranch(_Freezable):
    condition: object  # Value
    non_zero: int      # block id taken when condition != 0
    zero: int          # block id taken when condition == 0

    def render(self) -> str:
        return f"goto {self.condition} ? block@{self.non_zero} : block@{self.zero}"


@dataclass
class GotoNth(_Freezable):
    value: object
    blocks: list  # list[int]
    default: int

    def render(self) -> str:
        bs = ", ".join(f"block@{b}" for b in self.blocks)
        return f"goto_nth {self.value} [{bs}] else block@{self.default}"


@dataclass
class Switch(_Freezable):
    value: object
    cases: list  # list[(case_label:str, block_id:int)]
    default: int

    def render(self) -> str:
        cs = ", ".join(f"{lbl} => block@{b}" for lbl, b in self.cases)
        return f"switch {self.value} {{{cs}, * => block@{self.default}}}"


@dataclass
class SubroutineReturn(_Freezable):
    result: list  # list[Value]

    def render(self) -> str:
        r = " ".join(str(x) for x in self.result)
        return f"return {r}".rstrip()


@dataclass
class ProgramExit(_Freezable):
    result: object  # Value (uint64)

    def render(self) -> str:
        return f"exit {self.result}"


@dataclass
class Fail(_Freezable):
    error_message: Optional[str] = None

    def render(self) -> str:
        return "fail" + (f"  // {self.error_message}" if self.error_message else "")


ControlOp = Union[Goto, ConditionalBranch, GotoNth, Switch,
                  SubroutineReturn, ProgramExit, Fail]

# --------------------------------------------------------------------------
# Structural
# --------------------------------------------------------------------------


@dataclass
class BasicBlock(_Freezable):
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
class Parameter(_Freezable):
    register: Register

    def __str__(self) -> str:
        return f"{self.register.local_id}: {self.register.ir_type}"


@dataclass
class Subroutine(_Freezable):
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
class Program(_Freezable):
    main: Subroutine
    subroutines: list = field(default_factory=list)  # list[Subroutine]
    #: How often each guarded pass FIRED building this program (pass name ->
    #: count). Every entry is a pass that refuses silently when its guards
    #: fail: refusal is safe by design (each falls back to a total, honest
    #: representation) which is exactly why a rotted guard is invisible —
    #: nothing raises, nothing changes shape, the fallback just takes over.
    #: `tests/test_pass_firing_ratchet.py` pins these so that stays loud.
    pass_stats: dict = field(default_factory=dict)
    #: ``id(cloned register) -> original Register`` for representation-level
    #: clones (currently return-type-specialized subroutines).  Analyses bridge
    #: SSA annotations through this without conflating the clone's SSA identity
    #: with its independently-defined IR register.
    register_origins: dict = field(default_factory=dict, repr=False)

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
        # AVM ``match`` cases are ordered: when a key is repeated, only its
        # first arm is reachable.  Keeping the shadowed target here creates a
        # predecessor that the lowered Puya switch does not actually have.
        seen = set()
        reachable = []
        for key, target in term.cases:
            if key not in seen:
                seen.add(key)
                reachable.append(target)
        return [*reachable, term.default]
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


def registers(prog_or_subs):
    """Every distinct :class:`Register` appearing in the IR, definitions first.

    Identity, not ``local_id``, is authoritative in the mutable pre-IR.  This
    traversal is the shared bridge for analyses that must include parameters,
    synthesized registers, and representation-level clones rather than only
    ``_Lifter.regs``' direct SSA products.
    """
    subs = ((prog_or_subs.main, *prog_or_subs.subroutines)
            if isinstance(prog_or_subs, Program) else prog_or_subs)
    seen: set[int] = set()

    def emit(r):
        if isinstance(r, Register) and id(r) not in seen:
            seen.add(id(r))
            return r
        return None

    for s in subs:
        for p in s.parameters:
            if (r := emit(p.register)) is not None:
                yield r
        for bb in s.body:
            for ph in bb.phis:
                if (r := emit(ph.register)) is not None:
                    yield r
            for op in bb.ops:
                for target in getattr(op, "targets", ()) or ():
                    if (r := emit(target)) is not None:
                        yield r
            for node in (*bb.phis, *bb.ops, bb.terminator):
                for value in operands(node):
                    if (r := emit(value)) is not None:
                        yield r


def structural_errors(prog: Program) -> list[str]:
    """Return violations of the post-transform pre-IR contract.

    This is intentionally independent of Puya.  Detector-facing analyses run on
    pre-IR without lowering, and Puya's validator compares register values in a
    way that can accept two distinct pre-IR objects sharing one ``local_id``.
    Missing definitions would therefore otherwise become silent clean values.
    """
    errors: list[str] = []
    groups = [prog.main, *prog.subroutines]
    sub_ids = [s.id for s in groups]
    if len(sub_ids) != len(set(sub_ids)):
        errors.append("duplicate subroutine id")

    block_owner: dict[int, object] = {}
    block_by_id: dict[int, BasicBlock] = {}
    for sub in groups:
        if not sub.body:
            errors.append(f"{sub.id}: empty body")
        for bb in sub.body:
            if bb.id in block_by_id:
                errors.append(f"block@{bb.id}: duplicate global block id")
            else:
                block_by_id[bb.id] = bb
                block_owner[bb.id] = sub

    predecessors: dict[int, set[int]] = {bid: set() for bid in block_by_id}
    for sub in groups:
        for bb in sub.body:
            if bb.terminator is None:
                errors.append(f"{sub.id}: block@{bb.id} has no terminator")
            for target in succ_ids(bb.terminator):
                owner = block_owner.get(target)
                if owner is None:
                    errors.append(f"{sub.id}: block@{bb.id} targets missing block@{target}")
                    continue
                predecessors[target].add(bb.id)
                if owner is not sub:
                    errors.append(
                        f"{sub.id}: block@{bb.id} crosses into {owner.id}:block@{target}"
                    )

    target_subs = {s.id for s in prog.subroutines}
    for sub in groups:
        definitions: dict[int, str] = {}
        local_ids: dict[str, int] = {}

        def define(reg: Register, where: str) -> None:
            old = definitions.get(id(reg))
            if old is not None:
                errors.append(f"{sub.id}: {reg.local_id} defined at {old} and {where}")
                return
            definitions[id(reg)] = where
            other = local_ids.get(reg.local_id)
            if other is not None and other != id(reg):
                errors.append(
                    f"{sub.id}: distinct registers share local id {reg.local_id}"
                )
            local_ids[reg.local_id] = id(reg)

        for p in sub.parameters:
            define(p.register, "parameter")
        for bb in sub.body:
            for ph in bb.phis:
                define(ph.register, f"block@{bb.id} phi")
            for op in bb.ops:
                for target in getattr(op, "targets", ()) or ():
                    define(target, f"block@{bb.id} assignment")

        for bb in sub.body:
            expected_preds = predecessors.get(bb.id, set())
            for ph in bb.phis:
                through = [a.through for a in ph.args]
                if len(through) != len(set(through)):
                    errors.append(f"{sub.id}: block@{bb.id} phi has duplicate predecessor arms")
                if set(through) != expected_preds:
                    errors.append(
                        f"{sub.id}: block@{bb.id} phi arms {sorted(set(through))} "
                        f"!= predecessors {sorted(expected_preds)}"
                    )
                if any(not isinstance(a.value, Register) for a in ph.args):
                    errors.append(f"{sub.id}: block@{bb.id} phi has non-register arm")
            for node in (*bb.phis, *bb.ops, bb.terminator):
                for value in operands(node):
                    if isinstance(value, Register) and id(value) not in definitions:
                        errors.append(
                            f"{sub.id}: block@{bb.id} uses undefined {value.local_id}"
                        )
                vp = (node.source if isinstance(node, Assignment)
                      else node.intrinsic if isinstance(node, IntrinsicOp) else None)
                if (isinstance(vp, InvokeSubroutine)
                        and vp.target not in target_subs):
                    errors.append(
                        f"{sub.id}: block@{bb.id} invokes missing subroutine {vp.target}"
                    )
            if isinstance(bb.terminator, SubroutineReturn) \
                    and len(bb.terminator.result) != len(sub.returns):
                errors.append(
                    f"{sub.id}: block@{bb.id} returns {len(bb.terminator.result)} "
                    f"value(s), signature declares {len(sub.returns)}"
                )
    return errors


def assert_well_formed(prog: Program) -> None:
    """Raise :class:`ValueError` when :func:`structural_errors` is non-empty."""
    errors = structural_errors(prog)
    if errors:
        shown = "; ".join(errors[:8]) + (" …" if len(errors) > 8 else "")
        raise ValueError(f"malformed pre-IR ({len(errors)} error(s)): {shown}")


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
