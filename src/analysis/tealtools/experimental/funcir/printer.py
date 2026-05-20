"""Pretty-printer for the functional IR.

Produces Python-ish pseudocode — easy to skim, not meant to be
machine-parseable. ``pretty(prog)`` returns a string; pass an
:class:`Expr`, :class:`Stmt`, or :class:`Prog`.
"""
from __future__ import annotations

from typing import Union

from . import ir


def pretty(node, *, indent: int = 0) -> str:
    if isinstance(node, ir.Prog):
        return _pretty_prog(node)
    if isinstance(node, ir.Sub):
        return _pretty_sub(node, indent)
    if isinstance(node, ir.Stmt):
        return _pretty_stmt(node, indent)
    if isinstance(node, ir.Expr):
        return _pretty_expr(node)
    return repr(node)


# ---------------------------------------------------------------------------


def _pretty_prog(p: ir.Prog) -> str:
    out: list[str] = []
    for name, sub in sorted(p.subs.items()):
        out.append(_pretty_sub(sub, 0))
        out.append("")
    for i, main in enumerate(p.mains):
        if len(p.mains) > 1:
            out.append(f"# --- main {i} ---")
        out.append(_pretty_stmt(main, 0))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _pretty_sub(s: ir.Sub, indent: int) -> str:
    pad = "  " * indent
    params = ", ".join(s.params)
    head = f"{pad}sub {s.name}({params}):"
    body = _pretty_stmt(s.body, indent + 1)
    return f"{head}\n{body}"


def _pretty_stmt(s: ir.Stmt, indent: int) -> str:
    pad = "  " * indent
    if isinstance(s, ir.Block):
        # Filter empty sub-Blocks (lifter leaves them as placeholders
        # for dropped mat-phi copies; they shouldn't print as ``pass``
        # inside a non-empty parent).
        filtered = [c for c in s.body if not (isinstance(c, ir.Block) and not c.body)]
        if not filtered:
            return f"{pad}pass"
        return "\n".join(_pretty_stmt(c, indent) for c in filtered)
    if isinstance(s, ir.Let):
        rhs = _pretty_expr(s.value)
        if not s.targets:
            return f"{pad}{rhs}"
        return f"{pad}{', '.join(s.targets)} = {rhs}"
    if isinstance(s, ir.Assign):
        return f"{pad}{s.target} := {_pretty_expr(s.value)}"
    if isinstance(s, ir.If):
        cond_s = _pretty_expr(s.cond)
        if s.negated:
            cond_s = f"not {cond_s}"
        head = f"{pad}if {cond_s}:"
        body = _pretty_stmt(s.then, indent + 1)
        return f"{head}\n{body}"
    if isinstance(s, ir.IfElse):
        cond_s = _pretty_expr(s.cond)
        if s.negated:
            cond_s = f"not {cond_s}"
        head = f"{pad}if {cond_s}:"
        body = _pretty_stmt(s.then_, indent + 1)
        tail_head = f"{pad}else:"
        tail = _pretty_stmt(s.else_, indent + 1)
        return f"{head}\n{body}\n{tail_head}\n{tail}"
    if isinstance(s, ir.Switch):
        out = [f"{pad}switch {_pretty_expr(s.cond)}:"]
        for i, arm in enumerate(s.arms):
            lbl = f" → {s.labels[i]}" if i < len(s.labels) else ""
            out.append(f"{pad}  case {i}{lbl}:")
            out.append(_pretty_stmt(arm, indent + 2))
        return "\n".join(out)
    if isinstance(s, ir.Guard):
        cond_s = _pretty_expr(s.cond)
        if s.negated:
            cond_s = f"not {cond_s}"
        head = f"{pad}guard {cond_s}:"
        body = _pretty_stmt(s.exit_arm, indent + 1)
        return f"{head}\n{body}"
    if isinstance(s, ir.Loop):
        head = f"{pad}loop:"
        body = _pretty_stmt(s.body, indent + 1)
        return f"{head}\n{body}"
    if isinstance(s, ir.Break):
        return f"{pad}break"
    if isinstance(s, ir.Call):
        args = ", ".join(_pretty_expr(a) for a in s.args)
        targets = ", ".join(s.results)
        if targets:
            return f"{pad}{targets} = call {s.sub_name}({args})"
        return f"{pad}call {s.sub_name}({args})"
    if isinstance(s, ir.Return):
        val = "" if s.value is None else f" {_pretty_expr(s.value)}"
        return f"{pad}{s.kind}{val}"
    if isinstance(s, ir.Halt):
        return f"{pad}halt  # err"
    if isinstance(s, ir.Assert):
        return f"{pad}assert {_pretty_expr(s.value)}"
    if isinstance(s, ir.Label):
        return f"{pad}{s.name}:"
    if isinstance(s, ir.Goto):
        return f"{pad}goto {s.target}"
    if isinstance(s, ir.IfGoto):
        cond_s = _pretty_expr(s.cond)
        if s.negated:
            cond_s = f"not {cond_s}"
        return f"{pad}if {cond_s}: goto {s.target}"
    if isinstance(s, ir.Unstructured):
        head = f"{pad}# unstructured: {s.label}"
        if not s.body:
            return f"{head}\n{pad}  pass"
        # Render the body inline at the same indent so Label entries
        # line up like source-code labels.
        body = "\n".join(_pretty_stmt(c, indent) for c in s.body)
        return f"{head}\n{body}"
    return f"{pad}<unknown {type(s).__name__}>"


def _pretty_expr(e: ir.Expr) -> str:
    if isinstance(e, ir.Lit):
        if e.kind == "bytes" and isinstance(e.value, bytes):
            return f"0x{e.value.hex()}"
        if e.kind == "int":
            return str(e.value)
        return str(e.value)
    if isinstance(e, ir.Ref):
        prefix = "*" if e.is_mut else ""
        return f"{prefix}{e.name}"
    if isinstance(e, ir.App):
        # SSA copy op (=) introduced by materialize_phis — render as
        # bare reference for readability.
        if e.op == "=" and len(e.args) == 1:
            return _pretty_expr(e.args[0])
        # ``frame_dig N`` with no propagated inputs is a parameter
        # or local-frame-slot read. Render semantically — ``arg0`` for
        # the first param (frame[-N]), ``local0`` etc. for locals.
        if e.op == "frame_dig" and not e.args:
            try:
                n = int(e.immediates.strip())
            except (ValueError, AttributeError):
                n = None
            if n is not None:
                return f"arg{-n - 1}" if n < 0 else f"local{n}"
        # ``frame_bury N (value)`` is a write to a local frame slot.
        if e.op == "frame_bury" and len(e.args) == 1:
            try:
                n = int(e.immediates.strip())
            except (ValueError, AttributeError):
                n = None
            if n is not None and n >= 0:
                return f"local{n} := {_pretty_expr(e.args[0])}"
        # Single ``intc_*`` / ``bytec_*`` op — short alias for the
        # constant-table push (``intc 0`` etc.). Bare op name is
        # already the short form.
        args = ", ".join(_pretty_expr(a) for a in e.args)
        imm = f" {e.immediates}" if e.immediates else ""
        # Render binary arithmetic infix for readability.
        if e.op in ("+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||") and len(e.args) == 2:
            return f"({_pretty_expr(e.args[0])} {e.op} {_pretty_expr(e.args[1])})"
        if not e.args:
            return f"{e.op}{imm}" if imm else e.op
        return f"{e.op}{imm}({args})"
    if isinstance(e, ir.TupleExpr):
        return "(" + ", ".join(_pretty_expr(p) for p in e.parts) + ")"
    return f"<unknown_expr {type(e).__name__}>"
