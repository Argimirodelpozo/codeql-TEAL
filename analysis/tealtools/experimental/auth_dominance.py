"""Region-aware "auth check dominates sensitive op" detector.

Two variants:

- :func:`detect` (V1) — purely structural. For each sensitive op,
  walks up the control-tree ancestors and flags it if no enclosing
  ``If`` / ``IfElse`` / ``Switch`` / ``Guard`` has an ``assert``
  in its cond region. Fast, lots of false positives.

- :func:`detect_with_predicates` (V2) — combines the structural
  walk with :mod:`tealtools.path_predicates`. For each sensitive
  op's BB, asks "does the path predicate at this BB constrain any
  *auth-relevant* SSA value?" — i.e. is the predicate's value a
  function of ``txn Sender`` / ``txn Caller`` /
  ``global CreatorAddress`` / a global-state read? If yes, the
  op is considered guarded *by some authorization check*.

Limitations:

- "Sensitive op" hard-coded via :data:`SENSITIVE_OPS`; extend.
- "Auth-relevant value" hard-coded via :data:`_AUTH_DEFS`; extend.
- Subroutine bodies are folded as their own units; an op inside a
  subroutine called by always-guarded callers is still flagged. A
  proper interprocedural pass would propagate caller predicates
  into callees — left for later.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..control_tree import (
    BlockR, SequenceR, IfR, IfElseR, SwitchR, GuardR, LoopR,
    ImproperR, ProgramR, SubroutineR, Region, build_control_tree,
)
from ..path_predicates import PathPredicateAnalysis, BranchCondition
from ..ssa import BasicBlock, Assignment, SSAProgram, SSAVar, Phi, Const


# State-mutating ops + outbound transactions — anything an attacker
# would target via an unguarded code path.
SENSITIVE_OPS: frozenset[str] = frozenset({
    "app_global_put", "app_global_del",
    "app_local_put", "app_local_del",
    "box_put", "box_create", "box_del", "box_replace",
    "box_resize", "box_splice",
    "itxn_submit",
})

# Ops that bail out / halt — their presence in a cond region's
# leading block is taken as evidence of a runtime check (assert,
# panic, return false).
GUARD_OPS: frozenset[str] = frozenset({"assert", "err", "return"})


@dataclass
class UnguardedFinding:
    op: Assignment
    region_path: list[Region] = field(default_factory=list)

    def pretty(self) -> str:
        loc = self.op.location
        chain = " → ".join(r.kind for r in self.region_path) or "(top-level)"
        return f"{loc.file}:L{loc.line} {self.op.op}: no guard ancestor [{chain}]"


def _cond_contains_guard(cond: Region) -> bool:
    """``True`` if any block in ``cond`` runs an op from
    :data:`GUARD_OPS`. Walking the region's basic blocks is enough
    — guards in TEAL are line-local."""
    for bb in cond.basic_blocks():
        for a in bb.assignments:
            if a.op in GUARD_OPS:
                return True
    return False


def _walk(
    region: Region,
    ancestors: list[Region],
    findings: list[UnguardedFinding],
) -> None:
    """Recurse the tree; flag sensitive ops whose ancestor chain
    has no guarding region."""
    if isinstance(region, BlockR):
        for a in region.bb.assignments:
            if a.op not in SENSITIVE_OPS:
                continue
            if any(_is_guard_ancestor(anc) for anc in ancestors):
                continue
            findings.append(
                UnguardedFinding(op=a, region_path=list(ancestors))
            )
        return
    # Non-leaf: push ourselves onto the ancestor chain and recurse.
    ancestors.append(region)
    if isinstance(region, IfR):
        _walk(region.cond, ancestors, findings)
        _walk(region.then_branch, ancestors, findings)
    elif isinstance(region, IfElseR):
        _walk(region.cond, ancestors, findings)
        _walk(region.then_branch, ancestors, findings)
        _walk(region.else_branch, ancestors, findings)
    elif isinstance(region, GuardR):
        _walk(region.cond, ancestors, findings)
        _walk(region.exit_arm, ancestors, findings)
    elif isinstance(region, SwitchR):
        _walk(region.cond, ancestors, findings)
        for case in region.cases:
            _walk(case, ancestors, findings)
    elif isinstance(region, (SequenceR, ImproperR)):
        for child in region.children():
            _walk(child, ancestors, findings)
    elif isinstance(region, LoopR):
        _walk(region.body, ancestors, findings)
    elif isinstance(region, ProgramR):
        for child in region.children():
            _walk(child, ancestors, findings)
    elif isinstance(region, SubroutineR):
        _walk(region.body, ancestors, findings)
    ancestors.pop()


def _is_guard_ancestor(region: Region) -> bool:
    """A region counts as "guarding" sensitive ops nested under it
    if its conditional-branch cond contains a guard op."""
    if isinstance(region, (IfR, IfElseR, GuardR, SwitchR)):
        return _cond_contains_guard(region.cond)
    return False


def detect(prog: SSAProgram) -> list[UnguardedFinding]:
    """Returns sensitive ops in ``prog`` that have no guarding
    ancestor region in the control tree."""
    tree = build_control_tree(prog)
    findings: list[UnguardedFinding] = []
    _walk(tree, [], findings)
    return findings


def render(prog: SSAProgram) -> str:
    findings = detect(prog)
    if not findings:
        return "(no unguarded sensitive ops)"
    return "\n".join(f.pretty() for f in findings)


# ---------------------------------------------------------------------------
# V2 — path-predicate-aware
# ---------------------------------------------------------------------------


# SSA op + immediate-substring combos that constitute an
# authorization-relevant value source. A predicate that constrains
# a value transitively derived from any of these is treated as an
# auth check. Extend as new patterns surface.
_AUTH_DEFS: list[tuple[str, str]] = [
    # (op, immediate substring). Empty substring matches any immediates.
    ("txn", "Sender"),
    ("txn", "Caller"),
    ("txn", "ApplicationID"),
    ("gtxn", "Sender"),
    ("gtxn", "Caller"),
    ("gtxna", "Sender"),
    ("gtxns", "Sender"),
    ("gtxnas", "Sender"),
    ("global", "CreatorAddress"),
    ("global", "CallerApplicationAddress"),
    # State reads are heuristically auth-relevant — most contracts
    # store an admin / owner / manager in global state and compare
    # against the caller.
    ("app_global_get", ""),
    ("app_global_get_ex", ""),
    ("app_local_get", ""),
    ("app_local_get_ex", ""),
    # Box-state reads can carry per-account access lists too.
    ("box_get", ""),
]


def _op_is_auth_def(op: str, immediates: str) -> bool:
    for want_op, want_im in _AUTH_DEFS:
        if op != want_op:
            continue
        if not want_im or want_im in immediates:
            return True
    return False


def _value_depends_on_auth(value, visited: set[int] | None = None) -> bool:
    """Walk back through SSA def-use chain from ``value``; return
    True if any transitive defining op is in :data:`_AUTH_DEFS`."""
    if visited is None:
        visited = set()
    if value is None:
        return False
    vid = id(value)
    if vid in visited:
        return False
    visited.add(vid)
    if isinstance(value, Const):
        return False
    if isinstance(value, Phi):
        for arg in getattr(value, "args", ()) or ():
            if _value_depends_on_auth(arg, visited):
                return True
        return False
    if isinstance(value, SSAVar):
        defn = value.defined_by
        if defn is None:
            return False
        if _op_is_auth_def(defn.op, getattr(defn, "immediates", "") or ""):
            return True
        for inp in defn.inputs:
            if _value_depends_on_auth(inp, visited):
                return True
    return False


def _predicate_is_auth(cond: BranchCondition) -> bool:
    return _value_depends_on_auth(cond.value)


def _bb_of(op_line_key: tuple[str, int], prog: SSAProgram) -> BasicBlock | None:
    """Look up the BB containing the assignment at ``(file, line)``."""
    for bb in prog.blocks.values():
        for a in bb.assignments:
            if (a.location.file, a.location.line) == op_line_key:
                return bb
    return None


def detect_with_predicates(prog: SSAProgram) -> list[UnguardedFinding]:
    """Stricter variant: an op is *guarded* iff some path predicate
    at its BB constrains an auth-relevant SSA value (sender, app
    creator, global/local state read, ...). Returns the remaining
    unguarded ops — should be a much smaller set than :func:`detect`."""
    pp = PathPredicateAnalysis(prog)
    findings: list[UnguardedFinding] = []
    for bb in prog.blocks.values():
        for a in bb.assignments:
            if a.op not in SENSITIVE_OPS:
                continue
            preds = pp.predicates_at(a.location.file, a.location.line)
            if any(_predicate_is_auth(p) for p in preds):
                continue
            findings.append(UnguardedFinding(op=a, region_path=[]))
    return findings


def render_with_predicates(prog: SSAProgram) -> str:
    findings = detect_with_predicates(prog)
    if not findings:
        return "(no unguarded sensitive ops — every one is auth-predicate-covered)"
    out = [f"{len(findings)} unguarded sensitive ops (path-predicate-aware):"]
    for f in findings:
        loc = f.op.location
        out.append(f"  {loc.file}:L{loc.line}  {f.op.op}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# V3 — interprocedural (caller predicates propagate into callees)
# ---------------------------------------------------------------------------


def _build_caller_predicates(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    subs: dict,
) -> dict:
    """For each subroutine entry BB, compute the **intersection** of
    the path predicates at every site that calls it — these are the
    predicates a caller has *guaranteed* by every call path.

    Iterated to fixed point over the call graph so that nested calls
    inherit the predicates their callers asserted. The intersection
    is the standard "must hold on *every* call site" semantics — a
    sensitive op in S is guarded iff S has an auth predicate either
    locally or asserted by *all* of its callers."""
    # callee_entry → list of caller BBs (the callsub-ending BBs).
    callers: dict = {entry_bb: [] for entry_bb in subs}
    for bb in prog.blocks.values():
        if not bb.assignments:
            continue
        if bb.assignments[-1].op != "callsub":
            continue
        if not bb.successors:
            continue
        callee = bb.successors[0]
        if callee in callers:
            callers[callee].append(bb)

    # bb → entry_bb of the sub it belongs to (or None for main).
    bb_to_sub: dict = {}
    for entry_bb, body_region in subs.items():
        for sub_bb in body_region.basic_blocks():
            bb_to_sub[sub_bb] = entry_bb

    # Iterate to fixed point: caller_preds[S] starts ∅; each round,
    # recompute as intersection over callers of (pp.predicates_at(C)
    # ∪ caller_preds[sub_containing(C)]). Bounded by max call depth.
    caller_preds: dict = {entry: frozenset() for entry in subs}
    for _ in range(min(len(subs) + 1, 64)):
        changed = False
        for entry_bb, caller_bbs in callers.items():
            if not caller_bbs:
                continue
            per_site = []
            for c in caller_bbs:
                loc = c.assignments[-1].location
                site_preds = pp.predicates_at(loc.file, loc.line)
                # If the caller itself sits inside a subroutine, add
                # that sub's caller_preds — those hold at this site too.
                outer = bb_to_sub.get(c)
                if outer is not None:
                    site_preds = site_preds | caller_preds.get(
                        outer, frozenset()
                    )
                per_site.append(site_preds)
            common = (
                set.intersection(*[set(p) for p in per_site])
                if per_site else set()
            )
            new = frozenset(common)
            if new != caller_preds[entry_bb]:
                caller_preds[entry_bb] = new
                changed = True
        if not changed:
            break
    return {"caller_preds": caller_preds, "bb_to_sub": bb_to_sub}


def detect_with_predicates_interprocedural(prog: SSAProgram) -> list[UnguardedFinding]:
    """V3: combines in-BB path predicates with caller-context
    predicates propagated through the subroutine call graph.

    A sensitive op inside subroutine ``S`` is guarded iff either
    its in-BB path predicate has an auth-relevant value, *or* every
    caller of ``S`` (transitively) had one at the call site. This
    captures the common idiom of asserting admin status in the
    top-level method router and then doing state mutations from
    deeper subroutines without re-checking.
    """
    pp = PathPredicateAnalysis(prog)
    tree = build_control_tree(prog)
    subs = tree.subroutines if isinstance(tree, ProgramR) else {}
    ctx = _build_caller_predicates(prog, pp, subs)
    caller_preds: dict = ctx["caller_preds"]
    bb_to_sub: dict = ctx["bb_to_sub"]

    findings: list[UnguardedFinding] = []
    for bb in prog.blocks.values():
        for a in bb.assignments:
            if a.op not in SENSITIVE_OPS:
                continue
            own = pp.predicates_at(a.location.file, a.location.line)
            cp = caller_preds.get(bb_to_sub.get(bb), frozenset())
            combined = own | cp
            if any(_predicate_is_auth(p) for p in combined):
                continue
            findings.append(UnguardedFinding(op=a, region_path=[]))
    return findings


def render_with_predicates_interprocedural(prog: SSAProgram) -> str:
    findings = detect_with_predicates_interprocedural(prog)
    if not findings:
        return (
            "(no unguarded sensitive ops — every one is "
            "auth-predicate-covered, in-context or via callers)"
        )
    out = [
        f"{len(findings)} unguarded sensitive ops "
        f"(path-predicate-aware, interprocedural):"
    ]
    for f in findings:
        loc = f.op.location
        out.append(f"  {loc.file}:L{loc.line}  {f.op.op}")
    return "\n".join(out)
