"""Execution-budget assumptions.

Budget is not a property of an opcode stream alone.  Applications and logic
signatures use different meters, and an application may receive pooled credit
from group and inner application calls.  Analyses therefore take an explicit
context instead of guessing a precise mode from the opcodes they happen to see.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import TYPE_CHECKING, Optional

from ..language.avm import APP_ONLY_OPS

if TYPE_CHECKING:  # pragma: no cover
    from ..ssa import SSAProgram


APP_CALL_OPCODE_BUDGET = 700
MAX_GROUP_APP_CALLS = 16
MAX_INNER_APP_CALLS = 256
LOGICSIG_MAX_COST = 20_000
MAX_GROUP_LOGICSIGS = 16
MAX_STACK_DEPTH = 1000

# A whole application group can acquire this much credit in the most permissive
# execution admitted by the model.  It is deliberately an upper ceiling: loop
# iteration upper bounds become unsound if they assume less credit than an
# execution may actually acquire.
MAX_POOLED_OPCODE_BUDGET = APP_CALL_OPCODE_BUDGET * (
    MAX_GROUP_APP_CALLS + MAX_INNER_APP_CALLS
)

# LogicSig cost is pooled across the atomic group: the total cost may reach
# LogicSigMaxCost times the group size.  A smaller number is not a ceiling on
# one member because other members may leave their share unused.
MAX_POOLED_LOGICSIG_COST = LOGICSIG_MAX_COST * MAX_GROUP_LOGICSIGS


class ProgramMode(str, Enum):
    APPLICATION = "app"
    CLEAR_STATE = "clear-state"
    LOGIC_SIGNATURE = "logicsig"
    UNKNOWN = "unknown"


def infer_program_mode(prog: "SSAProgram") -> ProgramMode:
    """Return the mode proved by opcode legality, otherwise ``UNKNOWN``.

    Seeing an application-only opcode proves application mode.  Not seeing one
    proves nothing: an application is allowed to contain only shared opcodes.
    """
    stream = (
        a
        for bb in prog.blocks.values()
        for a in (bb.stack_assignments or tuple(bb.assignments))
    )
    if any(a.op in APP_ONLY_OPS for a in stream):
        return ProgramMode.APPLICATION
    return ProgramMode.UNKNOWN


def infer_avm_version(prog: "SSAProgram") -> Optional[int]:
    """Highest ``#pragma version`` in the immutable source snapshot.

    A readable source with NO pragma assembles as version 1 (the assembler's
    default), so it reports 1 — v1's distinct opcode costs (hashes) apply.
    ``None`` only when no source text could be read at all."""
    versions: list[int] = []
    saw_source = False
    sources = getattr(prog, "sources", None)
    for unit in getattr(sources, "files", ()):
        try:
            text = unit.text()
        except Exception:
            continue
        saw_source = True
        versions.extend(
            int(match.group(1))
            for match in re.finditer(r"(?m)^\s*#pragma\s+version\s+(\d+)\b", text)
        )
    if versions:
        return max(versions)
    return 1 if saw_source else None


@dataclass(frozen=True)
class BudgetContext:
    """Assumptions under which a budget query is evaluated.

    ``initial_credit`` is the greatest credit the execution may obtain under
    the supplied group assumptions.  A caller with group-shape information can
    provide a smaller value; the conservative constructor never invents that
    information.
    """

    mode: ProgramMode
    avm_version: Optional[int]
    initial_credit: int
    app_calls: Optional[int] = None
    inner_app_calls: Optional[int] = None
    provenance: str = "explicit"

    def __post_init__(self) -> None:
        if self.initial_credit < 0:
            raise ValueError("initial_credit must be non-negative")
        if self.app_calls is not None and not 1 <= self.app_calls <= MAX_GROUP_APP_CALLS:
            raise ValueError("app_calls is outside the AVM group limit")
        if self.inner_app_calls is not None and not 0 <= self.inner_app_calls <= MAX_INNER_APP_CALLS:
            raise ValueError("inner_app_calls is outside the modeled limit")

    @classmethod
    def application(
        cls,
        *,
        avm_version: Optional[int] = None,
        app_calls: int = MAX_GROUP_APP_CALLS,
        inner_app_calls: int = MAX_INNER_APP_CALLS,
    ) -> "BudgetContext":
        if not 1 <= app_calls <= MAX_GROUP_APP_CALLS:
            raise ValueError("app_calls is outside the AVM group limit")
        if not 0 <= inner_app_calls <= MAX_INNER_APP_CALLS:
            raise ValueError("inner_app_calls is outside the modeled limit")
        # Opcode-cost pooling is a PROTOCOL property (go-algorand
        # ``EnableAppCostPooling`` in ``NewAppEvalParams``; inner application
        # calls add to the SAME shared pool in ``NewInnerEvalParams``), not a
        # property of the program's own version: a v4 or v5 program grouped
        # with other application calls — or with a v6 sibling issuing inner
        # calls, the OpUp shape — runs under the whole pool, so ``initial_credit``
        # (the greatest credit an execution may obtain) must include it.
        # Versions 1-3 differ for a different reason: ``check()`` enforces the
        # 700-unit cost STATICALLY over the entire program and no backward
        # branch exists, so every path costs at most 700 and pooling is moot.
        if avm_version is not None and avm_version < 4:
            app_calls, inner_app_calls = 1, 0
        return cls(
            ProgramMode.APPLICATION,
            avm_version,
            APP_CALL_OPCODE_BUDGET * (app_calls + inner_app_calls),
            app_calls=app_calls,
            inner_app_calls=inner_app_calls,
            provenance="application group shape",
        )

    @classmethod
    def clear_state(
        cls, *, avm_version: Optional[int] = None
    ) -> "BudgetContext":
        """The non-pooled per-program ClearState execution limit."""
        return cls(
            ProgramMode.CLEAR_STATE,
            avm_version,
            APP_CALL_OPCODE_BUDGET,
            app_calls=1,
            inner_app_calls=0,
            provenance="clear-state execution limit",
        )

    @classmethod
    def logic_signature(
        cls, *, avm_version: Optional[int] = None
    ) -> "BudgetContext":
        # The group-wide total is pooled even though it is independent of the
        # application opcode pool.
        return cls(
            ProgramMode.LOGIC_SIGNATURE,
            avm_version,
            MAX_POOLED_LOGICSIG_COST,
            provenance="logic-signature group ceiling",
        )

    @classmethod
    def conservative(
        cls, prog: "SSAProgram", *, avm_version: Optional[int] = None
    ) -> "BudgetContext":
        if avm_version is None:
            avm_version = infer_avm_version(prog)
        mode = infer_program_mode(prog)
        if mode is ProgramMode.APPLICATION:
            return cls.application(avm_version=avm_version)
        # With no mode proof, use the larger possible allowance.  This is loose
        # but preserves upper-bound soundness for applications made solely from
        # shared opcodes.
        app_credit = cls.application(avm_version=avm_version).initial_credit
        return cls(
            ProgramMode.UNKNOWN,
            avm_version,
            max(app_credit, MAX_POOLED_LOGICSIG_COST),
            provenance="mode unknown; maximum admissible allowance",
        )

    @classmethod
    def tightened_application(
        cls, prog: "SSAProgram", *, avm_version: Optional[int] = None
    ) -> "BudgetContext":
        """Return the application-group ceiling without local-only guesses.

        A contract's ``assert(Global.GroupSize == N)`` is intentionally *not*
        used here.  It constrains approving executions, but a loop before that
        guard may run under a larger attacker-supplied group and eventually
        reject.  Applying the approval-path fact globally would under-bound
        exactly the exhaustion executions this analysis is meant to model.

        Absence of ``itxn_submit`` in this program is not useful either: opcode
        credit is shared group-wide, and a sibling application can add inner
        application calls (the standard OpUp shape).  Only an explicit whole-
        group model may safely tighten either count.
        """
        if avm_version is None:
            avm_version = infer_avm_version(prog)
        result = cls.application(avm_version=avm_version)
        return cls(
            result.mode,
            result.avm_version,
            result.initial_credit,
            result.app_calls,
            result.inner_app_calls,
            provenance="protocol application-group ceiling",
        )


def context_for(
    prog: "SSAProgram",
    context: Optional[BudgetContext] = None,
    *,
    budget: Optional[int] = None,
) -> BudgetContext:
    """Normalize the context accepted by public budget queries."""
    if context is not None and budget is not None:
        raise ValueError("pass context or budget, not both")
    if context is not None:
        return context
    base = BudgetContext.conservative(prog)
    if budget is None:
        return base
    return BudgetContext(
        base.mode,
        base.avm_version,
        budget,
        provenance="explicit credit with inferred mode",
    )
