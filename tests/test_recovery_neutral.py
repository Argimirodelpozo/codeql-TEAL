"""Permanent gate: TYPE RECOVERY IS ANNOTATION-ONLY (checked at the IR level).

Both recovery passes — the langspec scalar pass (``_recover_ir_types``) and the
ARC4/ABI encoded-type pass (``_recover_encoded_types``) — must ONLY refine a
register's ``ir_type``. They must never change the IR's STRUCTURE (ops, args,
control flow) and never change a register's ``avm_type`` (the coarse
bytes-vs-uint64 lattice codegen keys on).

Checked directly on the Puya IR, by SNAPSHOTTING THE SAME OBJECT GRAPH
immediately before and after recovery runs (the two passes are wrapped in
place). Two things this is deliberately NOT:

  * NOT a recompile-to-TEAL diff. That is the wrong oracle: it runs the IR
    through Puya's whole backend, where a *correctly* recovered type unlocks
    optimisations (aggressive ARC4 encode/decode elimination, dead-encode
    removal). Recovery-on vs -off TEAL genuinely differs on ~8 corpus
    contracts — all behaviour-preserving, none a recovery fault.
  * NOT a build-twice (recovery-off vs -on) comparison. Two separate ``to_puya``
    builds renumber temp registers slightly differently; that is construction
    noise, not recovery. Snapshotting one in-place build sidesteps it entirely
    — register identities are stable across the before/after, so any diff is
    genuinely recovery's doing.

The 5 real contracts (incl. the big xgov / folks programs) are the default;
``LIFT_SEMANTICS_CORPUS=1`` adds the 248-case corpus (the full sweep is ~8s —
254 contracts proven annotation-only). puya-gated. One build per contract, no
backend.

Perf note (learned the hard way): the structural signature MUST render every
container — including ``dict`` fields like ``Switch.cases`` — through
:func:`_sig`, never fall back to ``repr()``. A ``repr()`` of a case dict
expands the nested case blocks in full (multi-megabyte signatures → CPU
meltdown) AND embeds their registers' ``ir_type`` (leaking a legitimate
refinement as a bogus structural diff). Both were the same missing ``dict``
branch.
"""
from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path

import pytest

pytest.importorskip("puya")

# Puya's lower/build path emits THOUSANDS of DEBUG structlog lines per contract.
# A ``redirect_stdout``/``stderr`` only moves the Python stream; pytest still
# captures at the fd level, so across the 248-case corpus the buffered log
# explodes (13s of real work stretched past a 150s wall). Silence emission at
# the source — the logger — so there is nothing to capture. This is the fix
# that makes the corpus sweep actually runnable.
logging.getLogger("puya").setLevel(logging.CRITICAL)

import puya.ir.models as M                              # noqa: E402
from puya.ir.types_ import IRType                       # noqa: E402

from tealql.tealtools.lift import to_puya_ir            # noqa: E402
from tealql.tealtools.ssa import SSAProgram             # noqa: E402

_ROOT = Path(__file__).resolve().parent
_REAL_CONTRACT_DIR = _ROOT / "contracts"
_CORPUS_DIR = _ROOT / "experimental_IR_lift" / "puya"

# The type/annotation dimension (allowed to change) plus cyclic/cosmetic
# fields; everything else is structure and must be identical.
_SKIP = {"ir_type", "_types", "source_location", "comment", "label",
         "error_message", "_predecessors"}


def _sig(node) -> str:
    """Type-free structural signature. Block/subroutine REFERENCES render by id
    (cycle-safe); block contents are expanded only by :func:`_prog_sig`."""
    if isinstance(node, M.Register):
        return f"r:{node.name}#{node.version}"
    if isinstance(node, M.BasicBlock):
        return f"blk#{node.id}"
    if isinstance(node, M.Subroutine):
        return f"sub#{node.id}"
    if isinstance(node, IRType):
        return ""
    if isinstance(node, (list, tuple)):
        return "[" + ",".join(_sig(x) for x in node) + "]"
    if isinstance(node, dict):
        # e.g. Switch.cases (BytesConstant -> BasicBlock). MUST render keys +
        # values via _sig, not repr(dict): repr expands the case BasicBlocks in
        # full (megabyte-scale on nested switches) AND embeds their registers'
        # ir_type, which would leak a type refinement as a bogus structural
        # diff. Same object graph before/after, so insertion order is stable.
        return "{" + ",".join(f"{_sig(k)}:{_sig(v)}" for k, v in node.items()) + "}"
    aa = getattr(node, "__attrs_attrs__", None)
    if aa is None:
        return repr(node)
    parts = [f"{f.name}={_sig(getattr(node, f.name))}"
             for f in aa if f.name not in _SKIP]
    return f"{type(node).__name__}({','.join(parts)})"


def _prog_sig(main, subs) -> str:
    lines = []
    for s in sorted((main, *subs), key=lambda x: x.id):
        lines.append(f"SUB {s.id} params={_sig(s.parameters)} "
                     f"returns={_sig(list(s.returns))}")
        for bb in s.body:
            lines.append(f" BLK {bb.id} phis={_sig(bb.phis)}")
            for o in bb.ops:
                lines.append("  OP " + _sig(o))
            lines.append("  TERM " + _sig(bb.terminator))
    return "\n".join(lines)


def _reg_map(main, subs, key):
    """(name, version) -> {key(register)} over every register in the IR."""
    out: dict = {}
    seen: set = set()

    def walk(n):
        if isinstance(n, M.Register):
            out.setdefault((n.name, n.version), set()).add(key(n))
            return
        if isinstance(n, (M.BasicBlock, M.Subroutine)):
            if id(n) in seen:
                return
            seen.add(id(n))
        if isinstance(n, dict):                 # Switch.cases: walk keys + values
            for k, v in n.items():
                walk(k)
                walk(v)
            return
        aa = getattr(n, "__attrs_attrs__", None)
        if aa:
            for f in aa:
                if f.name in ("source_location", "_predecessors"):
                    continue
                v = getattr(n, f.name)
                for x in (v if isinstance(v, (list, tuple)) else [v]):
                    walk(x)

    for s in (main, *subs):
        walk(s)
    return out


def _snapshot_recovery(source):
    """Build ``source`` to IR and capture, on the SAME object graph, the
    structural signature + avm map + ir_type map immediately BEFORE recovery
    and immediately AFTER (both passes wrapped in place). Returns
    ``(before, after)`` dicts."""
    snaps: dict = {}
    _RI = to_puya_ir._recover_ir_types
    _RE = to_puya_ir._recover_encoded_types

    def cap(main, subs):
        return {
            "struct": _prog_sig(main, subs),
            "avm": _reg_map(main, subs, lambda r: r.ir_type.avm_type),
            "ir": _reg_map(main, subs, lambda r: str(r.ir_type)),
        }

    def wrap_ri(main, subs, **kw):
        snaps["before"] = cap(main, subs)
        return _RI(main, subs, **kw)

    def wrap_re(main, subs, **kw):
        r = _RE(main, subs, **kw)
        snaps["after"] = cap(main, subs)
        return r

    # Force the puya logger quiet HERE, inside the test body: pytest's logging
    # plugin can reset levels per-test, and puya FORMATS thousands of DEBUG
    # lines per build even when they'd be discarded — that formatting (not
    # capture) is what stretched 7s of real work past a 150s wall. The redirect
    # is a cheap belt-and-suspenders for any non-logger stdout puya emits.
    logging.getLogger("puya").setLevel(logging.CRITICAL)
    to_puya_ir._recover_ir_types = wrap_ri
    to_puya_ir._recover_encoded_types = wrap_re
    try:
        with open(os.devnull, "w") as dn, \
                contextlib.redirect_stdout(dn), contextlib.redirect_stderr(dn):
            to_puya_ir.to_puya(SSAProgram(source))
    finally:
        to_puya_ir._recover_ir_types = _RI
        to_puya_ir._recover_encoded_types = _RE
    assert "before" in snaps and "after" in snaps, "recovery passes did not run"
    return snaps["before"], snaps["after"]


def _has_source(d: Path) -> bool:
    return bool(list(d.glob("*.teal"))) or (d / "src.zip").exists()


def _contracts():
    names = ("xgov", "folks-consensus-v2", "folks-consensus-v3",
             "folks-xgov-registry", "repro")
    out = [(n, _REAL_CONTRACT_DIR / n) for n in names
           if _has_source(_REAL_CONTRACT_DIR / n)]
    if os.environ.get("LIFT_SEMANTICS_CORPUS") and _CORPUS_DIR.exists():
        out += [(p.name, p / "src") for p in sorted(_CORPUS_DIR.iterdir())
                if _has_source(p / "src")]
    return out


_NO_FIXTURES = [pytest.param(None, None, id="no-fixtures",
                             marks=pytest.mark.skip(reason="no lift fixtures present"))]
_PARAMS = [pytest.param(n, str(d), id=n) for n, d in _contracts()] or _NO_FIXTURES


@pytest.mark.parametrize("name,source", _PARAMS)
def test_recovery_is_annotation_only(name, source):
    if source is None:
        pytest.skip("no fixtures")
    before, after = _snapshot_recovery(source)

    # 1. Structure (ops / args / control flow) unchanged by recovery.
    assert before["struct"] == after["struct"], (
        f"{name}: type recovery changed the IR STRUCTURE, not just types.\n" +
        _first_diff(before["struct"], after["struct"])
    )
    # 2. No register's avm_type moved (that IS what codegen keys on).
    moved = {k: (before["avm"][k], after["avm"][k])
             for k in before["avm"] if before["avm"][k] != after["avm"].get(k)}
    assert not moved, (
        f"{name}: recovery changed a register's avm_type: "
        f"{list(moved.items())[:5]}"
    )


def _first_diff(a: str, b: str) -> str:
    import difflib
    return "\n".join(
        l for l in difflib.unified_diff(a.splitlines(), b.splitlines(),
                                        "before", "after", lineterm="")
        if l[:1] in "+-@"
    )[:800]


def test_gate_is_not_vacuous():
    """A contract that DOES refine types must show refinement, else the
    neutrality assertions prove nothing. fixed_bytes_ops refines ~10 register
    ir_types (all within the same avm_type)."""
    d = _CORPUS_DIR / "fixed_bytes_ops_FixedBytesOps" / "src"
    if not (d.exists() and _has_source(d)):
        pytest.skip("fixed_bytes_ops corpus fixture not present")
    before, after = _snapshot_recovery(str(d))
    refined = sum(1 for k in before["ir"]
                  if before["ir"][k] != after["ir"].get(k))
    assert refined > 0, "expected fixed_bytes_ops to refine some ir_types"
