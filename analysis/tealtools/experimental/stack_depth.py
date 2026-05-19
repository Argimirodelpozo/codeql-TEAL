"""Per-line AVM stack-depth analysis built on
:class:`tealtools.experimental.tree_fold.TreeFold`.

TEAL's stack has a 1000-slot limit; pushing past it halts the
program. This analysis folds the per-region net stack effect and
records the max stack depth observable at every source line — same
shape as cost analysis, different ledger.

The op→effect table is **partial** — common ops only. Unknown ops
default to net 0 (a reasonable assumption for the bulk of TEAL ops
that consume their args and push one result, but conservatively
the analysis under-reports for ops with large net effect that
aren't in the table). Extend :data:`OP_STACK_DELTA` as needed.
"""
from __future__ import annotations

from .tree_fold import TreeFold

# AVM stack-effect table — net (pushes - pops). Partial; extend as
# more contracts surface ops with non-trivial effects.
OP_STACK_DELTA: dict[str, int] = {
    # Pushes (1 result, 0 args).
    "pushint": +1, "pushbytes": +1, "intc": +1, "intc_0": +1, "intc_1": +1,
    "intc_2": +1, "intc_3": +1, "bytec": +1, "bytec_0": +1, "bytec_1": +1,
    "bytec_2": +1, "bytec_3": +1, "addr": +1, "byte": +1, "int": +1,
    "txn": +1, "global": +1, "load": +1, "loads": 0,
    "txna": +1, "gtxn": +1, "gtxna": +1, "gtxnas": 0, "gtxns": 0,
    "gload": +1, "gloads": 0, "gaid": +1, "gaids": 0,
    "frame_dig": +1, "proto": 0,
    "app_global_get": 0, "app_local_get": 0,  # pop key, push value
    "app_global_get_ex": +1, "app_local_get_ex": +1,  # 2 results
    "app_params_get": +1, "acct_params_get": +1, "asset_params_get": +1,
    "asset_holding_get": +1, "box_get": +1, "box_len": +1, "box_extract": -2,
    "balance": 0, "min_balance": 0,
    # Pops.
    "pop": -1, "store": -1, "stores": -2, "frame_bury": -1,
    "log": -1, "return": -1, "assert": -1, "err": 0,
    "bnz": -1, "bz": -1, "b": 0,
    "app_global_put": -2, "app_local_put": -3,
    "app_global_del": -1, "app_local_del": -2,
    "box_put": -2, "box_create": -1, "box_del": -1, "box_replace": -3,
    "box_resize": -2, "box_splice": -4,
    "itxn_begin": 0, "itxn_field": -1, "itxn_submit": 0, "itxn_next": 0,
    "itxn": +1, "itxna": +1, "itxnas": 0,
    "gitxn": +1, "gitxna": +1, "gitxnas": 0,
    "callsub": 0, "retsub": 0,  # callsub may have proto args; modeled separately.
    "dup": +1, "dup2": +2, "dupn": 0, "swap": 0, "select": -2, "cover": 0,
    "uncover": 0, "bury": -1,
    # Arithmetic / comparison: 2→1.
    "+": -1, "-": -1, "*": -1, "/": -1, "%": -1, "exp": -1, "expw": 0,
    "addw": 0, "mulw": 0, "divw": -2, "divmodw": -2,
    "==": -1, "!=": -1, "<": -1, ">": -1, "<=": -1, ">=": -1,
    "&&": -1, "||": -1, "!": 0, "~": 0,
    "&": -1, "|": -1, "^": -1, "shl": -1, "shr": -1,
    "concat": -1, "len": 0, "btoi": 0, "itob": 0,
    "getbyte": -1, "setbyte": -2, "extract3": -2, "extract": 0,
    "substring": 0, "substring3": -2, "replace3": -2,
    "sha256": 0, "sha512_256": 0, "sha3_256": 0, "keccak256": 0,
    "ed25519verify": -2, "ed25519verify_bare": -2,
    "ecdsa_verify": -4, "ecdsa_pk_decompress": +1, "ecdsa_pk_recover": +2,
    "vrf_verify": +1, "ec_add": -1, "ec_scalar_mul": -1,
    "ec_pairing_check": -1, "ec_subgroup_check": 0, "ec_map_to": 0,
    # match / switch consume N + selector items off the stack but only
    # branch — modelled as -1 net (pop the selector, others used for branch target).
    "match": -1, "switch": -1,
}

# TEAL's hard stack depth limit. Pushing past it halts execution.
STACK_LIMIT = 1000


def op_stack_delta(op: str) -> int:
    """Net stack effect (pushes - pops) for ``op``. Defaults to 0 for
    unknown ops (conservative under-report — better than over-report
    of stack depth)."""
    return OP_STACK_DELTA.get(op, 0)


class StackDepthFold(TreeFold[int]):
    """State = current stack depth. Records max depth at every line."""

    def __init__(self, prog):
        super().__init__(prog)
        self.per_line_max: dict[tuple[str, int], int] = {}
        self.per_line_min: dict[tuple[str, int], int] = {}

    def initial(self) -> int:
        return 0

    def merge(self, states: list[int]) -> int:
        return max(states) if states else 0

    def visit_op(self, a, state: int, bb=None) -> int:
        delta = op_stack_delta(a.op)
        new_depth = state + delta
        # Stack can't go below 0 — under-reports occur if op table is
        # wrong, but we clamp defensively.
        if new_depth < 0:
            new_depth = 0
        key = (a.location.file, a.location.line)
        prev_max = self.per_line_max.get(key)
        if prev_max is None or new_depth > prev_max:
            self.per_line_max[key] = new_depth
        prev_min = self.per_line_min.get(key)
        if prev_min is None or new_depth < prev_min:
            self.per_line_min[key] = new_depth
        # AVM halts past the limit — don't propagate further depth.
        if new_depth > STACK_LIMIT:
            return STACK_LIMIT
        return new_depth


def analyze(prog) -> dict[tuple[str, int], dict]:
    """Run the fold and return per-line ``{"min", "max"}`` stack-depth
    bounds. ``max`` exceeds :data:`STACK_LIMIT` only when an unknown
    op pushes a lot — those are flagged separately."""
    fold = StackDepthFold(prog)
    fold.run()
    out: dict[tuple[str, int], dict] = {}
    for key, mx in fold.per_line_max.items():
        out[key] = {
            "max": mx,
            "min": fold.per_line_min.get(key, 0),
            "exceeds_limit": mx > STACK_LIMIT,
        }
    return out


# ---------------------------------------------------------------------------
# Path-list variant — every distinct stack depth that can be observed
# at each line, sorted ascending. Mirrors ``per_line_cost_paths``.
# ---------------------------------------------------------------------------


MAX_DEPTHS_PER_LINE = 1024


class StackDepthPathsFold(TreeFold[frozenset]):
    """State = frozenset of possible stack depths at this point.
    Records the union of depths observed at each line."""

    def __init__(self, prog):
        super().__init__(prog)
        self.per_line: dict[tuple[str, int], set[int]] = {}

    def initial(self) -> frozenset:
        return frozenset({0})

    def merge(self, states: list[frozenset]) -> frozenset:
        merged: set[int] = set()
        for s in states:
            merged |= s
            if len(merged) > MAX_DEPTHS_PER_LINE:
                # Cap: keep the smallest and largest extremes.
                lo = min(merged)
                hi = max(merged)
                step = max(1, (hi - lo) // (MAX_DEPTHS_PER_LINE - 2))
                merged = set(range(lo, hi, step)) | {hi}
        return frozenset(merged)

    def visit_op(self, a, state: frozenset, bb=None) -> frozenset:
        delta = op_stack_delta(a.op)
        out_state: set[int] = set()
        key = (a.location.file, a.location.line)
        line_set = self.per_line.setdefault(key, set())
        for d in state:
            new_d = d + delta
            if new_d < 0:
                new_d = 0
            if new_d > STACK_LIMIT:
                # AVM halts past the limit — record the violation and
                # don't propagate further depth from this state.
                if len(line_set) < MAX_DEPTHS_PER_LINE:
                    line_set.add(STACK_LIMIT + 1)
                continue
            if len(line_set) < MAX_DEPTHS_PER_LINE:
                line_set.add(new_d)
            out_state.add(new_d)
        return frozenset(out_state)


def analyze_paths(prog) -> dict[tuple[str, int], list[int]]:
    """Per-line sorted list of every distinct stack depth observable
    on any path reaching the line. Capped at
    :data:`MAX_DEPTHS_PER_LINE` per line."""
    fold = StackDepthPathsFold(prog)
    fold.run()
    return {key: sorted(depths) for key, depths in fold.per_line.items()}
