"""Budget subcommands: loop cost / iteration bounds."""
from __future__ import annotations


from tealql.tealtools.diagnostics.errors import TealQLError

from ._common import (
    _load_programs,
)


def _cmd_loops(args) -> int:
    """Loop cost / iteration-bound table."""
    from tealql.tealtools.budget import (
        BudgetContext,
        ProgramMode,
        analyze_loops,
        infer_avm_version,
        infer_program_mode,
        render,
        to_dot,
    )
    # Flag validation runs ONCE, before any (possibly expensive) SSA build —
    # a bad flag on a directory target used to surface only after the first
    # program was fully constructed.
    if args.avm_version is not None and args.avm_version < 1:
        raise TealQLError("--avm-version must be positive")
    if args.budget is not None and args.budget < 0:
        raise TealQLError("--budget must be non-negative")
    if args.app_calls is not None and not 1 <= args.app_calls <= 16:
        raise TealQLError("--app-calls must be between 1 and 16")
    if args.inner_app_calls is not None and not 0 <= args.inner_app_calls <= 256:
        raise TealQLError("--inner-app-calls must be between 0 and 256")
    rc = 0
    for prog, _file_filter in _load_programs(args):
        name = getattr(prog, "source_path", None)
        name = name.name if name else "<program>"
        version = (
            infer_avm_version(prog)
            if args.avm_version is None
            else args.avm_version
        )
        if version is not None and version < 1:
            raise TealQLError("--avm-version must be positive")
        if args.budget_mode == "auto":
            if args.app_calls is not None or args.inner_app_calls is not None:
                raise TealQLError(
                    "--app-calls/--inner-app-calls require --budget-mode app"
                )
            if infer_program_mode(prog) is ProgramMode.APPLICATION:
                context = BudgetContext.tightened_application(
                    prog, avm_version=version
                )
            else:
                context = BudgetContext.conservative(prog, avm_version=version)
        elif args.budget_mode == "app":
            context = BudgetContext.application(
                avm_version=version,
                app_calls=16 if args.app_calls is None else args.app_calls,
                inner_app_calls=(
                    256 if args.inner_app_calls is None else args.inner_app_calls
                ),
            )
        elif args.budget_mode == "clear-state":
            if args.app_calls is not None or args.inner_app_calls is not None:
                raise TealQLError(
                    "clear-state does not accept pooled application-call counts"
                )
            context = BudgetContext.clear_state(avm_version=version)
        else:
            if args.app_calls is not None or args.inner_app_calls is not None:
                raise TealQLError(
                    "logic signatures do not accept application-call counts"
                )
            context = BudgetContext.logic_signature(avm_version=version)
        if args.budget is not None:
            context = BudgetContext(
                context.mode,
                context.avm_version,
                args.budget,
                context.app_calls,
                context.inner_app_calls,
                provenance="explicit CLI credit",
            )
        loops = analyze_loops(prog, context=context)
        if args.json_out:
            import json
            print(json.dumps({
                "file": name,
                "context": {
                    "mode": context.mode.value,
                    "avm_version": context.avm_version,
                    "initial_credit": context.initial_credit,
                    "app_calls": context.app_calls,
                    "inner_app_calls": context.inner_app_calls,
                    "provenance": context.provenance,
                },
                "loops": [{
                    "header_line": b.first_line,
                    "kind": b.kind,
                    "entries": [entry.first_line for entry in b.entries],
                    "blocks": len(b.body),
                    "min_iteration_cost": b.min_iteration_cost,
                    "iteration_cost_exact": b.iteration_cost.exact,
                    "stack_growth": b.stack_growth,
                    "prefix_cost": b.prefix_cost,
                    "available_budget": b.available_budget,
                    "budget_bound": b.budget_bound,
                    "stack_bound": b.stack_bound,
                    "max_iterations": b.max_iterations,
                    "bound": b.bound_reason,
                    "degradations": list(b.degradations),
                } for b in loops],
            }, indent=1))
        elif getattr(args, "dot", False):
            print(to_dot(prog, context=context))
        else:
            print(f"== {name}")
            print(render(prog, context=context))
    return rc


def register(sub, add) -> None:
    loops_p = add("loops", "loop cost + iteration bounds (budget / stack ceilings)",
        _cmd_loops)
    loops_p.add_argument(
        "--dot", action="store_true",
        help="emit Graphviz DOT: each loop boxed with its bound, and the blocks "
             "whose budget is spent before it can start")
    loops_p.add_argument(
        "--budget-mode", choices=["auto", "app", "clear-state", "logicsig"],
        default="auto",
        help="metering context (default: infer app when provable, otherwise use "
             "the greatest admissible allowance)")
    loops_p.add_argument(
        "--avm-version", type=int, default=None,
        help="override #pragma version for pooling rules")
    loops_p.add_argument(
        "--budget", type=int, default=None,
        help="explicit available opcode credit")
    loops_p.add_argument(
        "--app-calls", type=int, default=None,
        help="outer application calls contributing pooled credit (app mode)")
    loops_p.add_argument(
        "--inner-app-calls", type=int, default=None,
        help="inner application calls contributing pooled credit (app mode)")
