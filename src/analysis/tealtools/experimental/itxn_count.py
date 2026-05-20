"""Per-line inner-transaction submission count.

For every source line, the largest number of inner txns that could
have been submitted by the AVM **before** this line executes, on
any path. The hard cap is :data:`MAX_INNER_TXNS` (256); paths that
would exceed it halt at the submit op.

Same fold framework as :mod:`stack_depth`, just with submit ops
incrementing the counter and ``itxn_submit`` / ``itxn_next`` capping
out at 256. Loops that submit each iter are bounded by the cap.
"""
from __future__ import annotations

from .tree_fold import TreeFold
from ..cost_analysis import MAX_INNER_TXNS


class ItxnCountFold(TreeFold[int]):
    """State = inner-txn count so far on the path. Records max per line."""

    def __init__(self, prog):
        super().__init__(prog)
        self.per_line_max: dict[tuple[str, int], int] = {}

    def initial(self) -> int:
        return 0

    def merge(self, states: list[int]) -> int:
        return max(states) if states else 0

    def visit_op(self, a, state: int, bb=None) -> int:
        new_count = state
        if a.op in ("itxn_submit", "itxn_next"):
            if state >= MAX_INNER_TXNS:
                # AVM halts at the 257th submission — line not reached.
                return state
            new_count = state + 1
        elif a.op == "callsub":
            # Charge the callee's submit count from the precomputed
            # subroutine summary if we have one.
            if bb is not None and bb.successors:
                callee = bb.successors[0]
                summary = self.subroutine_summaries.get(callee)
                if summary is not None:
                    _, sub_submits = summary
                    new_count = min(MAX_INNER_TXNS, state + sub_submits)
        key = (a.location.file, a.location.line)
        prev = self.per_line_max.get(key)
        if prev is None or new_count > prev:
            self.per_line_max[key] = new_count
        return new_count

    def visit_loop(self, region, state: int) -> int:
        """A loop with submits in its body iterates up to (256 - state)
        / submits_per_iter times — folds the body once at the start
        and once at the iter-cap state to record per-line cums on
        both the first and the cap-reaching iteration."""
        from ..cost_analysis import _body_summary
        _, submits_per_iter = _body_summary(region.body)
        if submits_per_iter == 0:
            return self.visit(region.body, state)
        room = MAX_INNER_TXNS - state
        max_iters = max(0, room // submits_per_iter)
        if max_iters == 0:
            return self.visit(region.body, state)
        # Fold once from entry — gives first-iter cums.
        first = self.visit(region.body, state)
        # Fold once from the last-full-iter entry — gives cap-iter cums.
        last_entry = state + (max_iters - 1) * submits_per_iter
        last = self.visit(region.body, last_entry)
        return max(first, last, state + max_iters * submits_per_iter)


def analyze(prog) -> dict[tuple[str, int], int]:
    """Per-line max inner-txn count on any path reaching that line."""
    fold = ItxnCountFold(prog)
    fold.run()
    return dict(fold.per_line_max)


# ---------------------------------------------------------------------------
# Path-list variant — every distinct itxn count observable per line.
# ---------------------------------------------------------------------------


MAX_COUNTS_PER_LINE = 1024


class ItxnCountPathsFold(TreeFold[frozenset]):
    """State = frozenset of possible inner-txn counts so far."""

    def __init__(self, prog):
        super().__init__(prog)
        self.per_line: dict[tuple[str, int], set[int]] = {}

    def initial(self) -> frozenset:
        return frozenset({0})

    def merge(self, states: list[frozenset]) -> frozenset:
        merged: set[int] = set()
        for s in states:
            merged |= s
            if len(merged) > MAX_COUNTS_PER_LINE:
                lo = min(merged)
                hi = max(merged)
                step = max(1, (hi - lo) // (MAX_COUNTS_PER_LINE - 2))
                merged = set(range(lo, hi, step)) | {hi}
        return frozenset(merged)

    def visit_op(self, a, state: frozenset, bb=None) -> frozenset:
        key = (a.location.file, a.location.line)
        line_set = self.per_line.setdefault(key, set())
        out_state: set[int] = set()
        for c in state:
            if a.op in ("itxn_submit", "itxn_next"):
                if c >= MAX_INNER_TXNS:
                    # AVM halts at the 257th — line never reached past it.
                    continue
                new_c = c + 1
            elif a.op == "callsub":
                # Charge callee summary submits — same as the max-fold.
                if bb is not None and bb.successors:
                    callee = bb.successors[0]
                    summary = self.subroutine_summaries.get(callee)
                    if summary is not None:
                        _, sub_subs = summary
                        new_c = min(MAX_INNER_TXNS, c + sub_subs)
                    else:
                        new_c = c
                else:
                    new_c = c
            else:
                new_c = c
            if len(line_set) < MAX_COUNTS_PER_LINE:
                line_set.add(new_c)
            out_state.add(new_c)
        return frozenset(out_state)

    def visit_loop(self, region, state: frozenset) -> frozenset:
        """Loop-aware: a loop emitting submits each iter produces
        a range of itxn counts at body lines (one per iter). Expand
        explicitly up to the 256-cap, then exit with the cap set."""
        from ..cost_analysis import _body_summary
        _, submits_per_iter = _body_summary(region.body)
        if submits_per_iter == 0:
            return self.visit(region.body, state)
        # Build all per-iter entry states: for each starting count,
        # add 0..max_iters * submits_per_iter, capped at MAX_INNER_TXNS.
        per_iter_entries: set[int] = set()
        for c in state:
            cur = c
            steps = 0
            max_iters = (MAX_INNER_TXNS - c) // submits_per_iter
            for k in range(max_iters + 1):
                per_iter_entries.add(min(MAX_INNER_TXNS, c + k * submits_per_iter))
                if len(per_iter_entries) >= MAX_COUNTS_PER_LINE:
                    break
            if len(per_iter_entries) >= MAX_COUNTS_PER_LINE:
                break
        return self.visit(region.body, frozenset(per_iter_entries))


def analyze_paths(prog) -> dict[tuple[str, int], list[int]]:
    """Per-line sorted list of distinct itxn counts on any path
    reaching the line. Capped at :data:`MAX_COUNTS_PER_LINE`."""
    fold = ItxnCountPathsFold(prog)
    fold.run()
    return {key: sorted(counts) for key, counts in fold.per_line.items()}
