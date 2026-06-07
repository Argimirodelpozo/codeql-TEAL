"""Forward user-input taint over the lifted IR (see :mod:`lift`).

Marks every IR register whose value derives from USER-CONTROLLED input -- what an
attacker chooses when invoking the contract -- and with which source(s):

  * ``ApplicationArgs`` -- ``txn``/``txna``/``txnas``/``gtxn*``/``gtxns*``
    ``ApplicationArgs`` (the call's app-call arguments, incl. another group txn's)
  * ``LogicSigArgs``    -- ``arg`` / ``args`` / ``arg_0``..``arg_3`` (lsig args)
  * ``ItxnLastLog``     -- ``itxn``/``gitxn`` ``LastLog`` (the output of a contract
    this app itself called -- attacker-influenceable through that callee)

This is an IR-LAYER analysis -- the sources are ordinary opcodes the lift keeps and
value flow is explicit (Assignment / Phi / Intrinsic args) -- but it consumes ONE
low-layer fact carried up through the lifter: the scratch reaching-def
(``load_stores``), so a ``load N`` is tainted exactly by the ``store N`` values that
reach it, not by every store to the slot (which on a reused slot would over-taint
into uselessness). Subroutine results are tainted if any call arg is (conservative;
a param->return summary would sharpen it). Forward monotonic fixpoint.

``user_input_taint(lifter) -> {id(Register): frozenset[str sources]}``.
"""
from __future__ import annotations

from collections import defaultdict

from ..ssa import Phi, SSAVar
from . import pre_ir

_TXN_FAM = frozenset({"txn", "txna", "txnas", "gtxn", "gtxna", "gtxnas",
                      "gtxns", "gtxnsa", "gtxnsas"})
_ITXN_FAM = frozenset({"itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas"})
_ARG_FAM = frozenset({"arg", "args", "arg_0", "arg_1", "arg_2", "arg_3"})


def source_label(intr) -> str | None:
    """The user-input source kind an intrinsic reads, or ``None``."""
    if not isinstance(intr, pre_ir.Intrinsic):
        return None
    imm = " ".join(str(i) for i in (intr.immediates or []))
    if intr.op in _ARG_FAM:
        return "LogicSigArgs"
    if intr.op in _TXN_FAM and "ApplicationArgs" in imm:
        return "ApplicationArgs"
    if intr.op in _ITXN_FAM and "LastLog" in imm:
        return "ItxnLastLog"
    return None


def _intr(o):
    if isinstance(o, pre_ir.IntrinsicOp) and isinstance(o.intrinsic, pre_ir.Intrinsic):
        return o.intrinsic
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic):
        return o.source
    return None


def _invoke(o):
    if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.InvokeSubroutine):
        return o.source
    if isinstance(o, pre_ir.IntrinsicOp) and isinstance(o.intrinsic, pre_ir.InvokeSubroutine):
        return o.intrinsic
    return None


def user_input_taint(lifter) -> dict:
    """Forward taint from the user-input sources to a fixpoint over ``lifter``'s
    lifted IR. Returns ``{id(Register): frozenset(sources)}`` for tainted registers."""
    # register -> its SSA var, to consult the scratch reaching-def on a `load`.
    ssa_of = {id(r): sv for sv, r in lifter.regs.items()}
    taint: dict = defaultdict(set)

    def reg_t(v):
        return taint.get(id(v), set()) if isinstance(v, pre_ir.Register) else set()

    changed = True
    while changed:
        changed = False
        for b in pre_ir.blocks(lifter.subs):
            for ph in b.phis:                       # phi: union of its args
                new = set()
                for a in ph.args:
                    new |= reg_t(a.value)
                if new - taint[id(ph.register)]:
                    taint[id(ph.register)] |= new
                    changed = True
            for o in b.ops:
                ins = set()
                src = _intr(o)
                if src is not None:
                    lbl = source_label(src)
                    if lbl:
                        ins.add(lbl)                # seed
                    for a in src.args:
                        ins |= reg_t(a)
                    if src.op in ("load", "loads"):  # scratch: reaching-def precise
                        out = o.targets[0] if getattr(o, "targets", None) else None
                        lv = ssa_of.get(id(out)) if out is not None else None
                        for sv in (lifter.load_stores.get(lv, ()) if lv is not None else ()):
                            if isinstance(sv, (SSAVar, Phi)):
                                ins |= reg_t(lifter.reg(sv))
                if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Register):
                    ins |= reg_t(o.source)          # copy
                inv = _invoke(o)
                if inv is not None:
                    for a in inv.args:              # conservative: result <- any arg
                        ins |= reg_t(a)
                    callee = lifter.name2sub.get(inv.target)
                    if callee is not None:          # interprocedural: arg -> callee param
                        for i, p in enumerate(callee.parameters):
                            if i < len(inv.args):
                                pt = reg_t(inv.args[i])
                                if pt - taint[id(p.register)]:
                                    taint[id(p.register)] |= pt
                                    changed = True
                for t in getattr(o, "targets", ()) or ():
                    if ins - taint[id(t)]:
                        taint[id(t)] |= ins
                        changed = True
    return {k: frozenset(v) for k, v in taint.items() if v}


# Sensitive sinks: where a user-controlled value reaching them is worth flagging --
# persistent-state writes, inner-transaction fields (who gets paid / how much),
# emitted logs, and asserted conditions (user-controlled control flow).
_SINKS = frozenset({
    "app_global_put", "app_global_del", "app_local_put", "app_local_del",
    "box_put", "box_del", "box_create", "box_replace", "log", "itxn_field",
})


def tainted_sinks(lifter, taint=None) -> list:
    """User-input -> sensitive-sink flows over the lifted IR: a list of
    ``(sources, sink_op, immediates)`` for every sink whose operands include a
    tainted value. The security payoff of :func:`user_input_taint` -- e.g. a
    user-controlled value reaching an inner-txn ``Amount`` or an ``app_global_put``.
    Pass a precomputed ``taint`` map or one is built."""
    if taint is None:
        taint = user_input_taint(lifter)
    out = []
    for b in pre_ir.blocks(lifter.subs):
        for o in b.ops:
            s = _intr(o)
            if s is not None and s.op in _SINKS:
                args, op, imm = s.args, s.op, s.immediates
            elif isinstance(o, pre_ir.Assert):
                args, op, imm = [o.condition], "assert", None
            else:
                continue
            hit = set()
            for a in args:
                if isinstance(a, pre_ir.Register):
                    hit |= taint.get(id(a), set())
            if hit:
                out.append((frozenset(hit), op, imm))
    return out
