"""PROTOTYPE: bottom-up interprocedural procedure summaries over the lifted IR.

A summary is computed ONCE per subroutine over the call graph and applied at every
call site instead of re-analysing the callee. ``passthrough`` + ``internal_sources``
give a precise taint transfer — never "the result is tainted if ANY arg is" — and
``checked_params`` records params the callee asserts, so a value validated inside a
callee stops surfacing as attacker-controlled at the caller. Read-only; computes over
an already-built ``_Lifter``.

HAZARD: both facts are conservative in the SAFE direction and must stay that way.
``checked_params`` counts only ENTRY-block asserts, so it UNDER-approximates
validation (a dominating assert after a branch is missed → false positives, never a
missed vulnerability); the sound upgrade is must-reach/post-dominance over the block
CFG. ``passthrough`` propagates through every op, OVER-approximating taint.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import pre_ir
from .taint import source_label, transfer_fixpoint


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
    """Bottom-up ``{sub.id: SubSummary}`` over ``lifter``'s subroutines.

    HAZARD: one monotone fixpoint over per-sub-namespaced markers ``("p", sub.id, i)``
    — de-namespacing them aliases params across subs, and a nested call MUST resolve
    through the callee's summary-so-far or mutual recursion never converges.
    """
    subs = [s for s in lifter.subs if not s.is_main]
    taint: dict = defaultdict(set)
    for s in subs:
        for i, p in enumerate(s.parameters):
            taint[id(p.register)].add(("p", s.id, i))
    # mutable accumulators: [internal_sources, passthrough, checked]
    acc: dict = {s.id: [set(), set(), set()] for s in subs}

    def _inv(o, inv, reg_t):
        ins: set = set()
        callee = lifter.name2sub.get(inv.target)
        if callee is not None:
            csrcs, cparams, _ = acc[callee.id]
            ins |= csrcs
            for i in cparams:
                if i < len(inv.args):
                    ins |= reg_t(inv.args[i])
        return ins, False

    def _refine(reg_t) -> bool:
        changed = False
        for s in subs:
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
        return changed

    transfer_fixpoint(lifter, taint, seed_label=source_label, invoke_ins=_inv,
                      per_round=_refine, subs=subs)

    return {
        sid: SubSummary(frozenset(v[1]), frozenset(v[0]), frozenset(v[2]))
        for sid, v in acc.items()
    }
