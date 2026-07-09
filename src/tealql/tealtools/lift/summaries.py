"""PROTOTYPE: bottom-up interprocedural procedure summaries over the lifted IR.

A *summary* is a per-subroutine function from input facts to output facts,
computed ONCE bottom-up over the call graph and applied at every call site
instead of re-analysing the callee. This module demonstrates the technique on two
fact lattices sharing ONE marker-based fixpoint (mutual recursion converges — a
callee's summary is consulted as it is built):

  * TAINT TRANSFER (distributive → IFDS-exact): ``passthrough`` = the param
    indices whose value reaches a returned value, and ``internal_sources`` = the
    source labels a returned value carries independent of the caller's args. A
    call's result is then tainted by ``internal_sources`` plus the arg sources at
    the passthrough indices — never "the result is tainted if ANY arg is". (This
    reproduces the taint half of :func:`taint._return_summary`, extracted here as
    a reusable, testable abstraction — see ``tests/test_summaries.py`` for the
    equivalence check on real contracts.)

  * GUARD / VALIDATION (the fact taint summaries do NOT yet carry, and the one
    that retires the documented context-insensitive-``callsub`` false positives):
    ``checked_params`` = the param indices the subroutine ASSERTS unconditionally.
    A caller passing an argument to a checked param may treat that argument as
    validated by the callee — so a user value the callee asserts ``== Sender``
    stops surfacing as attacker-controlled across the call.

Prototype scope / soundness: ``checked_params`` currently recognises asserts in
the subroutine's ENTRY block (which always execute) — sound but conservative
(a dominating assert after a branch is missed; the sound upgrade is a
must-reach/post-dominance analysis over the block CFG, exactly like the
enforcement-seeded every-path check in ``security/_field_protection``). ``passthrough``
propagates through every op (matching the existing conservative taint summary).
Read-only; computes over an already-built ``_Lifter``.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import pre_ir
from .taint import _intr, _invoke, source_label


@dataclass(frozen=True)
class SubSummary:
    """The recovered summary of one subroutine."""
    passthrough: frozenset       # param indices whose value reaches a return
    internal_sources: frozenset  # source labels a return carries independent of args
    checked_params: frozenset    # param indices asserted unconditionally (entry block)

    def result_sources(self, arg_sources: list) -> set:
        """Taint sources of a CALL's result, given each argument's source set."""
        out = set(self.internal_sources)
        for i in self.passthrough:
            if i < len(arg_sources):
                out |= arg_sources[i]
        return out

    def arg_validated(self, arg_index: int) -> bool:
        """Whether an argument passed at ``arg_index`` is validated by the callee."""
        return arg_index in self.checked_params


def compute_summaries(lifter) -> dict:
    """Bottom-up ``{sub.id: SubSummary}`` over ``lifter``'s subroutines. One
    monotone marker fixpoint: each param register is seeded with a namespaced
    marker ``("p", sub.id, i)``; source reads seed their label; a nested call
    resolves through the callee's summary-so-far (so mutual recursion converges).
    """
    subs = [s for s in lifter.subs if not s.is_main]
    taint: dict = defaultdict(set)
    for s in subs:
        for i, p in enumerate(s.parameters):
            taint[id(p.register)].add(("p", s.id, i))
    # mutable accumulators: [internal_sources, passthrough, checked]
    acc: dict = {s.id: [set(), set(), set()] for s in subs}

    def reg_t(v):
        return taint.get(id(v), set()) if isinstance(v, pre_ir.Register) else set()

    changed = True
    while changed:
        changed = False
        for s in subs:
            for b in s.body:
                for ph in b.phis:
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
                            ins.add(lbl)
                        for a in src.args:
                            ins |= reg_t(a)
                    if isinstance(o, pre_ir.Assignment) \
                            and isinstance(o.source, pre_ir.Register):
                        ins |= reg_t(o.source)          # copy
                    inv = _invoke(o)
                    if inv is not None:
                        callee = lifter.name2sub.get(inv.target)
                        if callee is not None:
                            csrcs, cparams, _ = acc[callee.id]
                            ins |= csrcs
                            for i in cparams:
                                if i < len(inv.args):
                                    ins |= reg_t(inv.args[i])
                    for t in getattr(o, "targets", ()) or ():
                        if ins - taint[id(t)]:
                            taint[id(t)] |= ins
                            changed = True

            srcs, params, checked = acc[s.id]
            # taint transfer: markers reaching a returned value
            for b in s.body:
                if isinstance(b.terminator, pre_ir.SubroutineReturn):
                    for rv in b.terminator.result:
                        for m in reg_t(rv):
                            if isinstance(m, tuple) and m[1] == s.id:
                                if m[2] not in params:
                                    params.add(m[2])
                                    changed = True
                            elif not isinstance(m, tuple) and m not in srcs:
                                srcs.add(m)
                                changed = True
            # guard: params asserted unconditionally (entry-block asserts always run)
            entry = s.body[0] if s.body else None
            if entry is not None:
                for o in entry.ops:
                    if isinstance(o, pre_ir.Assert):
                        for m in reg_t(o.condition):
                            if isinstance(m, tuple) and m[1] == s.id \
                                    and m[2] not in checked:
                                checked.add(m[2])
                                changed = True

    return {
        sid: SubSummary(frozenset(v[1]), frozenset(v[0]), frozenset(v[2]))
        for sid, v in acc.items()
    }
