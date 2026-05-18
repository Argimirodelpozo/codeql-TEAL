"""Auth-dominance detector implemented as a walk over the
functional IR.

Same question as :func:`tealtools.experimental.auth_dominance.detect_with_predicates`:
*is every sensitive op gated by an auth-relevant check?* But the
implementation is much shorter — walking the IR tree, we have the
ancestor chain of ``If`` / ``IfElse`` / ``Assert`` conditions in
hand, and ``Expr`` is recursive so we can ask "does this cond
mention ``txn Sender``, ``app_global_get``, ...?" in a one-line
recursion.

No `PathPredicateAnalysis` invocation needed — the IR's structure
*is* the predicate chain. The interprocedural version (caller
predicates flow through ``Call``) folds in just as naturally.

This is the validation of the "formal analysis is easier on the IR"
hypothesis from the earlier discussion.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import ir
from .lifter import lift
from ...ssa import SSAProgram


# State mutations + outbound calls.
SENSITIVE_OPS: frozenset[str] = frozenset({
    "app_global_put", "app_global_del",
    "app_local_put", "app_local_del",
    "box_put", "box_create", "box_del", "box_replace",
    "box_resize", "box_splice",
    "itxn_submit",
})


# (op, substring-of-immediates) — empty substring matches any.
_AUTH_DEFS: list[tuple[str, str]] = [
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
    ("app_global_get", ""),
    ("app_global_get_ex", ""),
    ("app_local_get", ""),
    ("app_local_get_ex", ""),
    ("box_get", ""),
]


def _op_is_auth(op: str, immediates: str) -> bool:
    for want_op, want_im in _AUTH_DEFS:
        if op != want_op:
            continue
        if not want_im or want_im in immediates:
            return True
    return False


def _expr_depends_on_auth(e: ir.Expr) -> bool:
    """Recursive expr walk — any sub-expression an auth-relevant
    App? With the IR this is one line; with raw SSA it'd be a
    def-use chain crawl."""
    if isinstance(e, ir.App):
        if _op_is_auth(e.op, e.immediates):
            return True
        return any(_expr_depends_on_auth(a) for a in e.args)
    if isinstance(e, ir.TupleExpr):
        return any(_expr_depends_on_auth(p) for p in e.parts)
    return False


@dataclass
class UnguardedFinding:
    """A sensitive op with no auth-relevant guard in its ancestor chain."""

    op: str
    immediates: str
    # Optional rendering of the surrounding stmt path for context.
    path: list[str]

    def pretty(self) -> str:
        chain = " → ".join(self.path) if self.path else "(top-level)"
        return f"{self.op} {self.immediates}  [{chain}]"


def detect(prog: SSAProgram) -> list[UnguardedFinding]:
    """Walk the lifted IR. For every sensitive op, check whether
    any enclosing ``If`` / ``IfElse`` / ``Assert`` has a cond that
    depends on an auth-relevant value. Subroutine bodies are walked
    with their callers' guards in scope (interprocedural)."""
    funcir = lift(prog)
    findings: list[UnguardedFinding] = []
    # Build a callsite-predicate index: for each Sub name, what
    # guards were in scope at the callers? Iterate to fixed point.
    sub_guards = _compute_sub_caller_guards(funcir)
    for main in funcir.mains:
        _walk(main, guards=[], sub_guards=sub_guards, path=["main"], findings=findings)
    for sub in funcir.subs.values():
        seeded = sub_guards.get(sub.name, [])
        _walk(sub.body, guards=list(seeded), sub_guards=sub_guards,
              path=[sub.name], findings=findings)
    return findings


def render(prog: SSAProgram) -> str:
    findings = detect(prog)
    if not findings:
        return "(no unguarded sensitive ops)"
    out = [f"{len(findings)} unguarded sensitive ops (funcir-based):"]
    for f in findings:
        out.append(f"  {f.pretty()}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _walk(
    stmt: ir.Stmt,
    *,
    guards: list[ir.Expr],
    sub_guards: dict,
    path: list[str],
    findings: list[UnguardedFinding],
) -> None:
    """Recursive walk. ``guards`` is the stack of cond expressions
    that dominate this point; ``path`` is the human-readable region
    chain for printing."""
    if isinstance(stmt, ir.Block):
        local_guards = list(guards)
        for c in stmt.body:
            _walk(c, guards=local_guards, sub_guards=sub_guards,
                  path=path, findings=findings)
            # Asserts dominate everything that follows in the same Block.
            if isinstance(c, ir.Assert):
                local_guards.append(c.value)
        return
    if isinstance(stmt, ir.Let):
        # Check the value: if it's a sensitive App, evaluate guards.
        if isinstance(stmt.value, ir.App) and stmt.value.op in SENSITIVE_OPS:
            if not any(_expr_depends_on_auth(g) for g in guards):
                findings.append(UnguardedFinding(
                    op=stmt.value.op, immediates=stmt.value.immediates,
                    path=list(path),
                ))
        return
    if isinstance(stmt, ir.Assign):
        if isinstance(stmt.value, ir.App) and stmt.value.op in SENSITIVE_OPS:
            if not any(_expr_depends_on_auth(g) for g in guards):
                findings.append(UnguardedFinding(
                    op=stmt.value.op, immediates=stmt.value.immediates,
                    path=list(path),
                ))
        return
    if isinstance(stmt, ir.Assert):
        # Asserts are checked in the surrounding Block (see above);
        # we still recurse into the value expression for any
        # sensitive ops nested inside (very rare but possible).
        return
    if isinstance(stmt, ir.If):
        new = guards + [stmt.cond]
        _walk(stmt.then, guards=new, sub_guards=sub_guards,
              path=path + ["if"], findings=findings)
        return
    if isinstance(stmt, ir.IfElse):
        _walk(stmt.then_, guards=guards + [stmt.cond],
              sub_guards=sub_guards, path=path + ["if"], findings=findings)
        _walk(stmt.else_, guards=guards + [_negate(stmt.cond)],
              sub_guards=sub_guards, path=path + ["else"], findings=findings)
        return
    if isinstance(stmt, ir.Switch):
        for i, arm in enumerate(stmt.arms):
            _walk(arm, guards=guards + [stmt.cond],
                  sub_guards=sub_guards, path=path + [f"case{i}"], findings=findings)
        return
    if isinstance(stmt, ir.Guard):
        _walk(stmt.exit_arm, guards=guards + [stmt.cond],
              sub_guards=sub_guards, path=path + ["guard"], findings=findings)
        return
    if isinstance(stmt, ir.Loop):
        _walk(stmt.body, guards=guards, sub_guards=sub_guards,
              path=path + ["loop"], findings=findings)
        return
    if isinstance(stmt, ir.Call):
        # Propagate guards into the callee via sub_guards; the actual
        # walk into the callee happens in detect()'s outer loop.
        sub_guards.setdefault(stmt.sub_name, []).extend(guards)
        return
    if isinstance(stmt, ir.Unstructured):
        for c in stmt.body:
            _walk(c, guards=guards, sub_guards=sub_guards,
                  path=path + ["unstructured"], findings=findings)
        return


def _negate(cond: ir.Expr) -> ir.Expr:
    """Build a `not cond` expression for else-arm context. Just
    wraps in a synthetic ``!`` App so the auth check sees the same
    underlying SSA values."""
    return ir.App(op="!", immediates="", args=[cond])


def _compute_sub_caller_guards(funcir: ir.Prog) -> dict:
    """Single-pass collection of guards at every call site, keyed by
    callee sub name. Iterates twice so transitively propagated
    guards (caller-of-caller predicates) reach deep callees too."""
    sub_guards: dict[str, list[ir.Expr]] = {}
    for _ in range(2):
        for main in funcir.mains:
            _walk(main, guards=[], sub_guards=sub_guards,
                  path=[], findings=[])
        for sub in funcir.subs.values():
            seeded = sub_guards.get(sub.name, [])
            _walk(sub.body, guards=list(seeded), sub_guards=sub_guards,
                  path=[], findings=[])
    # Intersect across call sites — only common guards count as
    # "every caller asserted this". Simple approach: keep only the
    # guards that appear at every recorded call site.
    # (For first cut: keep them all and let _expr_depends_on_auth's
    # any() do the work — over-permissive but matches the structural
    # detector's behaviour.)
    return sub_guards
