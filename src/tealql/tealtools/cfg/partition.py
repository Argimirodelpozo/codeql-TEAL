"""Trace partitioning of path predicates by ABI method and/or OnCompletion.

:class:`.path_predicates.PathPredicateAnalysis` intersects predicates over
EVERY incoming path at a join, so on a router-shaped program (ARC-4 ``match``
on the selector, ``switch`` on OnCompletion, Puya's shared
``bury 1; b main_after_if_else@N; … return`` exit) every arm's facts vanish at
the shared exit. Here the state of a block is a map ``partition → predicates``
and joins happen only WITHIN a partition::

    preds[bb][q] = ⋂ { preds[p][k] ∪ edge(p, bb)  |  p ∈ preds(bb),
                                                    refine(k, p→bb) = q }

A partition's key is FIXED at a dispatch edge — the outgoing edge of a two-way
or multi-way branch whose edge predicates pin ``txna ApplicationArgs 0`` to a
constant selector (``match`` arm, ``== sel; bnz``) or ``txn OnCompletion`` to a
constant (``switch`` arm, Puya's ``(!ApplicationID)*6 + OnCompletion`` key,
``== K; bnz``, ``bz`` on OnCompletion). Once a field is set along a path it
never changes (keys only refine None → value), so a partition is a property of
the PATH, which is what makes per-partition intersection sound.

HAZARD: ``assert`` edges never refine a key — an assert has one successor, it
does not partition flow, and treating it as dispatch would label paths without
splitting them.

Budget: when more than ``budget`` partitions are live at one block, that block
is COLLAPSED permanently to one partition (the meet over all its incoming
contributions, key :data:`COLLAPSED`), recorded in :attr:`collapsed_blocks`;
everything downstream of it inherits the collapsed key. With no dispatch edge
anywhere, the only partition is :data:`ROOT` and its predicates equal the
unpartitioned analysis block for block.

Edge transfer, ``callsub``/``retsub`` call-stable carrying, entry and per-BB
seeds are the unpartitioned analysis's own (its ``edge_predicates`` and
:func:`.path_predicates.call_stable_predicates`), never re-derived here.
"""
from __future__ import annotations

import heapq
import re
from dataclasses import dataclass
from typing import Optional

from .dominance import program_entries
from .exits import is_approval_exit
from .path_predicates import (
    BranchCondition,
    PathPredicateAnalysis,
    call_stable_predicates,
)
from .subroutines import call_executed_blocks, is_retsub_block
from ..language.avm import COND_BRANCH_OPS, MULTIWAY_BRANCH_OPS
from ..ssa import BasicBlock, SSAProgram, const_int

_KEYS = ("method", "oncompletion", "both")

#: OnCompletion action names, by value, for rendering.
_OC_NAMES = ("NoOp", "OptIn", "CloseOut", "ClearState", "UpdateApplication",
             "DeleteApplication")


@dataclass(frozen=True)
class Partition:
    """A path class. ``method`` = the dispatched selector (``0x`` hex, lower
    case) or ``None`` when no selector dispatch was taken on the path;
    ``oncompletion`` likewise. ``collapsed`` marks the budget-overflow class,
    which carries no key at all."""

    method: Optional[str] = None
    oncompletion: Optional[int] = None
    collapsed: bool = False

    def sort_key(self):
        return (self.collapsed, self.method or "", -1 if self.oncompletion is None
                else self.oncompletion)

    def label(self, names: Optional[dict] = None) -> str:
        if self.collapsed:
            return "<collapsed>"
        parts = []
        if self.method is not None:
            name = (names or {}).get(self.method)
            parts.append(f"method={name or self.method}")
        if self.oncompletion is not None:
            oc = self.oncompletion
            parts.append("oc=" + (_OC_NAMES[oc] if 0 <= oc < len(_OC_NAMES) else str(oc)))
        return ", ".join(parts) or "<undispatched>"

    def compatible_prefix_of(self, other: "Partition") -> bool:
        """``self`` could be ``other`` before some refinements (each field is
        unset or equal); a collapsed class is compatible with everything."""
        if self.collapsed or other.collapsed:
            return True
        return ((self.method is None or self.method == other.method)
                and (self.oncompletion is None
                     or self.oncompletion == other.oncompletion))


#: The partition of every path before any dispatch edge.
ROOT = Partition()
#: The single partition of a budget-collapsed block (and its downstream).
COLLAPSED = Partition(collapsed=True)


def _field_read(value, field: str, index: Optional[str] = None) -> bool:
    d = getattr(value, "defined_by", None)
    if d is None or d.op not in ("txn", "txna"):
        return False
    imm = d.immediates.split()
    if index is None:
        return imm == [field]
    return imm == [field, index]


def _selector_hex(const) -> Optional[str]:
    if getattr(const, "kind", None) != "bytes":
        return None
    v = str(getattr(const, "value", ""))
    if v.lower().startswith("0x") and len(v) == 10:
        return v.lower()
    return None


_COMMENT_SIG_RE = re.compile(r'(0x[0-9A-Fa-f]{8})\b.*?//\s*"([^"]+\([^"]*\)[^"]*)"')


def method_names_for(prog: SSAProgram, method_table: Optional[dict] = None) -> dict:
    """``{selector_hex: AbiMethod}`` from the program's high-level ABI info:
    ``method "sig"`` (source or pseudo-op-patch comments), an ARC-56
    ``method_table``, and PyTeal's ``pushbytes 0x… // "sig"`` comments ONLY when
    the signature hashes to that exact selector. Never a reverse lookup."""
    from ..metadata.abi import extract_method_table, method_selector, parse_signature
    table: dict = {}
    try:
        files = prog.sources.files
    except Exception:
        files = ()
    for unit in files:
        try:
            text = unit.text()
        except Exception:
            continue
        for k, m in extract_method_table(text).items():
            table.setdefault(k.lower(), m)
        for sel, sig in _COMMENT_SIG_RE.findall(text):
            sel = sel.lower()
            if sel in table:
                continue
            try:
                if "0x" + method_selector(sig).hex() != sel:
                    continue
            except Exception:
                continue
            m = parse_signature(sig)
            if m is not None:
                table[sel] = m
    for k, m in (method_table or {}).items():
        table.setdefault(str(k).lower(), m)
    return table


class PartitionedPredicates:
    """Path predicates per ``(block, partition)``; see the module docstring."""

    def __init__(
        self,
        prog: SSAProgram,
        *,
        key: str = "method",
        budget: int = 64,
        base: Optional[PathPredicateAnalysis] = None,
        method_table: Optional[dict] = None,
    ):
        if key not in _KEYS:
            raise ValueError(f"partition key must be one of {_KEYS}, got {key!r}")
        if budget < 1:
            raise ValueError("partition budget must be >= 1")
        self.prog = prog
        self.key = key
        self.budget = budget
        self.base = base if base is not None else PathPredicateAnalysis(prog)
        self._method_table = method_table
        self.collapsed_blocks: set[BasicBlock] = set()
        self.state: dict[BasicBlock, dict[Partition, frozenset[BranchCondition]]] = {}
        self._edge_cache: dict = {}
        self._compute()

    # -- public ---------------------------------------------------------

    @property
    def method_names(self) -> dict:
        """``{selector_hex: AbiMethod}`` (lazy; see :func:`method_names_for`)."""
        names = getattr(self, "_names", None)
        if names is None:
            try:
                names = method_names_for(self.prog, self._method_table)
            except Exception:
                names = {}
            self._names = names
        return names

    def partitions_at(self, bb: BasicBlock) -> list[Partition]:
        """Live partitions reaching ``bb`` (``[]`` = unreachable), sorted."""
        return sorted(self.state.get(bb, {}), key=Partition.sort_key)

    def predicates_at(self, bb: BasicBlock, partition: Partition) -> frozenset[BranchCondition]:
        """Predicates holding on every path of ``partition`` reaching ``bb``."""
        return self.state.get(bb, {}).get(partition, frozenset())

    def merged_at(self, bb: BasicBlock) -> frozenset[BranchCondition]:
        """Meet over all partitions at ``bb`` (⊇ the unpartitioned result)."""
        parts = self.state.get(bb)
        if not parts:
            return frozenset()
        out = None
        for preds in parts.values():
            out = preds if out is None else out & preds
        return out or frozenset()

    def exits_by_partition(self) -> dict[Partition, dict[BasicBlock, frozenset[BranchCondition]]]:
        """Approving exits (:func:`.exits.is_approval_exit`) reached by each
        partition, with that partition's predicates there."""
        out: dict[Partition, dict] = {}
        for bb in sorted(self.prog.blocks.values(), key=lambda b: (b.file, b.first_line)):
            if not is_approval_exit(bb):
                continue
            for p, preds in self.state.get(bb, {}).items():
                out.setdefault(p, {})[bb] = preds
        return dict(sorted(out.items(), key=lambda kv: kv[0].sort_key()))

    def methods_at(self, bb: BasicBlock) -> Optional[frozenset]:
        """The selector keys of the partitions reaching ``bb`` (``None`` entries
        for undispatched paths); ``None`` when the answer is unknown (collapsed
        block, or key mode without methods)."""
        if self.key == "oncompletion":
            return None
        parts = self.state.get(bb, {})
        if any(p.collapsed for p in parts):
            return None
        return frozenset(p.method for p in parts)

    def method_at(self, file: str, line: Optional[int]):
        """The :class:`.metadata.abi.AbiMethod` owning ``(file, line)`` by
        partition: exactly ONE method partition (and no undispatched or
        collapsed path) reaches its block and its selector has a known
        signature; else ``None``."""
        if line is None:
            return None
        bb = self.prog.block_containing(file, line)
        if bb is None:
            return None
        methods = self.methods_at(bb)
        if not methods or len(methods) != 1:
            return None
        (sel,) = methods
        if sel is None:
            return None
        return self.method_names.get(sel)

    def render(self, *, file: Optional[str] = None) -> str:
        names = {k: m.name for k, m in self.method_names.items()}
        out = [f"partition key={self.key} budget={self.budget} "
               f"collapsed_blocks={len(self.collapsed_blocks)}"]
        for bb in self._blocks(file):
            mark = "  [collapsed]" if bb in self.collapsed_blocks else ""
            parts = self.partitions_at(bb)
            out.append(f"BB L{bb.first_line:>3}-L{bb.last_line:<3}{mark}"
                       + ("" if parts else "  (unreachable)"))
            for p in parts:
                out.append(f"    [{p.label(names)}]  {_fmt(self.predicates_at(bb, p))}")
        exits = self.exits_by_partition()
        if exits:
            out.append("approving exits by partition:")
            for p, blocks in exits.items():
                where = ", ".join(f"L{b.first_line}" for b in blocks)
                out.append(f"    [{p.label(names)}]  {where}")
        return "\n".join(out)

    def to_dict(self, *, file: Optional[str] = None) -> dict:
        names = {k: m.name for k, m in self.method_names.items()}
        blocks = []
        for bb in self._blocks(file):
            blocks.append({
                "file": bb.file,
                "first_line": bb.first_line,
                "last_line": bb.last_line,
                "collapsed": bb in self.collapsed_blocks,
                "partitions": [
                    {**_part_dict(p, names),
                     "predicates": [repr(c) for c in _sorted(self.predicates_at(bb, p))]}
                    for p in self.partitions_at(bb)
                ],
            })
        exits = [
            {**_part_dict(p, names),
             "exits": [{"file": b.file, "first_line": b.first_line,
                        "predicates": [repr(c) for c in _sorted(preds)]}
                       for b, preds in by_bb.items()]}
            for p, by_bb in self.exits_by_partition().items()
        ]
        return {
            "key": self.key,
            "budget": self.budget,
            "collapsed_blocks": [
                {"file": b.file, "first_line": b.first_line}
                for b in sorted(self.collapsed_blocks, key=lambda b: (b.file, b.first_line))
            ],
            "methods": names,
            "blocks": blocks,
            "exits_by_partition": exits,
        }

    def annotations(self) -> dict:
        """``{block: ["[partition] predicates", ...]}`` for a CFG overlay."""
        names = {k: m.name for k, m in self.method_names.items()}
        return {
            bb: [f"[{p.label(names)}] {_fmt(self.predicates_at(bb, p))}"
                 for p in self.partitions_at(bb)]
            for bb in self.prog.blocks.values() if bb in self.state
        }

    # -- internals ------------------------------------------------------

    def _blocks(self, file):
        return [bb for bb in sorted(self.prog.blocks.values(),
                                    key=lambda b: (b.file, b.first_line))
                if file is None or bb.file == file]

    def _edge(self, pred: BasicBlock, succ: BasicBlock):
        """``(edge predicates, refine)`` for ``pred → succ``; ``refine`` maps a
        partition to its successor partition (identity off dispatch edges)."""
        k = (id(pred), id(succ))
        hit = self._edge_cache.get(k)
        if hit is not None and hit[0] is pred and hit[1] is succ:
            return hit[2], hit[3]
        edge = self.base.edge_predicates(pred, succ)
        method = oc = None
        last = pred.assignments[-1] if pred.assignments else None
        if last is not None and (last.op in COND_BRANCH_OPS
                                 or last.op in MULTIWAY_BRANCH_OPS):
            method, oc = self._dispatch_keys(edge)
        if self.key == "method":
            oc = None
        elif self.key == "oncompletion":
            method = None
        self._edge_cache[k] = (pred, succ, edge, (method, oc))
        return edge, (method, oc)

    @staticmethod
    def _dispatch_keys(edge) -> tuple:
        method = oc = None
        for c in edge:
            if c.kind == "eq" and c.args:
                if _field_read(c.value, "ApplicationArgs", "0"):
                    sel = _selector_hex(c.args[0])
                    if sel is not None:
                        method = sel
                elif _field_read(c.value, "OnCompletion"):
                    k = const_int(c.args[0])
                    if k is not None:
                        oc = k
            elif c.kind == "zero" and _field_read(c.value, "OnCompletion"):
                oc = 0
        return method, oc

    @staticmethod
    def _refine(p: Partition, keys: tuple) -> Partition:
        if p.collapsed:
            return p
        method, oc = keys
        if (method is None or p.method is not None) and (oc is None or p.oncompletion is not None):
            return p
        return Partition(p.method if p.method is not None else method,
                         p.oncompletion if p.oncompletion is not None else oc)

    def _compute(self) -> None:
        prog, base = self.prog, self.base
        caller_of, return_target_of = base._callsub_return_maps()
        executed_during = call_executed_blocks(prog)
        memos: dict = {}
        refine_memo: dict = {}
        # (call site, partition) -> (call site, its predicates, stable subset):
        # recomputed only when that partition's predicates object changes.
        stable_memo: dict = {}
        entries = set(program_entries(prog.blocks.values()))
        state = self.state
        for bb in prog.blocks.values():
            if not bb.predecessors or bb in entries:
                state[bb] = {ROOT: base.entry_seeds | base.bb_seeds.get(bb, frozenset())}

        def refines_during(caller) -> bool:
            """Whether the call at ``caller`` may execute a dispatch edge (so a
            path's key may be refined inside it); unknown closure ⇒ True."""
            hit = refine_memo.get(caller)
            if hit is None:
                blocks = executed_during.get(caller)
                hit = blocks is None or any(
                    self._edge(b, s)[1] != (None, None)
                    for b in blocks for s in b.successors)
                refine_memo[caller] = hit
            return hit

        def via_caller(bb, p):
            """``(feasible, carried)`` for partition ``p`` crossing a ``retsub``
            edge into return target ``bb``. A real such path passed the call
            site with key ``p`` — or a prefix of it, when the call may refine —
            so a partition the call site never held is an artefact of the
            context-insensitive return edge and is DROPPED; the surviving call
            site partitions' call-stable facts are carried (unpartitioned
            semantics: :meth:`PathPredicateAnalysis._carried_across_return`)."""
            caller = caller_of.get(bb)
            if caller is None:
                return True, None
            cparts = state.get(caller)
            if not cparts:
                return False, None  # call site not reached (yet): re-queued on change
            if p in cparts:
                sources = [p]
            elif refines_during(caller) or p.collapsed:
                sources = [cp for cp in cparts if cp.compatible_prefix_of(p)]
            else:
                sources = [cp for cp in cparts if cp.collapsed]
            if not sources:
                return False, None
            out = None
            for cp in sources:
                preds = cparts[cp]
                hit = stable_memo.get((id(caller), cp))
                if hit is not None and hit[0] is caller and hit[1] is preds:
                    stable = hit[2]
                else:
                    stable = call_stable_predicates(
                        preds, executed=executed_during.get(caller),
                        memo=memos.setdefault(caller, {}))
                    stable_memo[(id(caller), cp)] = (caller, preds, stable)
                out = stable if out is None else (out & stable)
            return True, out

        # Reverse-postorder priority worklist: the fixpoint is order-independent,
        # the iteration count is not (LIFO re-walks long chains per partition).
        order = _rpo_index(prog, entries)
        queued = set(prog.blocks.values())
        worklist = [(order[b], i, b) for i, b in enumerate(prog.blocks.values())]
        heapq.heapify(worklist)
        tick = len(worklist)

        def push(b):
            nonlocal tick
            if b not in queued:
                queued.add(b)
                tick += 1
                heapq.heappush(worklist, (order[b], tick, b))

        while worklist:
            bb = heapq.heappop(worklist)[2]
            queued.discard(bb)
            contrib: dict[Partition, set] = {}
            if bb in entries:
                contrib[ROOT] = set(base.entry_seeds)
            for pred in bb.predecessors:
                pparts = state.get(pred)
                if not pparts:
                    continue  # TOP: not reached yet
                edge, keys = self._edge(pred, bb)
                retsub = is_retsub_block(pred)
                for p, preds in pparts.items():
                    q = self._refine(p, keys)
                    c = set(preds) | edge
                    if retsub:
                        feasible, extra = via_caller(bb, p)
                        if not feasible:
                            continue
                        if extra:
                            c |= extra
                    cur = contrib.get(q)
                    contrib[q] = c if cur is None else (cur & c)
            if not contrib:
                continue
            if bb not in self.collapsed_blocks and len(contrib) > self.budget:
                self.collapsed_blocks.add(bb)
            if bb in self.collapsed_blocks:
                merged = None
                for c in contrib.values():
                    merged = c if merged is None else (merged & c)
                contrib = {COLLAPSED: merged}
            seed = base.bb_seeds.get(bb)
            new = {p: frozenset(c | seed) if seed else frozenset(c)
                   for p, c in contrib.items()}
            if state.get(bb) != new:
                state[bb] = new
                for succ in bb.successors:
                    push(succ)
                rt = return_target_of.get(bb)
                if rt is not None:
                    push(rt)


def _rpo_index(prog, entries) -> dict:
    """Reverse-postorder index per block from the program entries (and every
    no-predecessor block); blocks never visited sort last."""
    seen: set = set()
    post: list = []
    roots = sorted(set(entries) | {b for b in prog.blocks.values() if not b.predecessors},
                   key=lambda b: (b.file, b.first_line))
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        stack = [(root, iter(root.successors))]
        while stack:
            node, it = stack[-1]
            nxt = next((s for s in it if s not in seen), None)
            if nxt is None:
                post.append(node)
                stack.pop()
            else:
                seen.add(nxt)
                stack.append((nxt, iter(nxt.successors)))
    n = len(post)
    index = {b: n - i for i, b in enumerate(post)}
    for b in prog.blocks.values():
        index.setdefault(b, n + 1)
    return index


def _sorted(preds):
    return sorted(preds, key=lambda c: (c.kind, repr(c.value)))


def _fmt(preds) -> str:
    return ", ".join(repr(c) for c in _sorted(preds)) if preds else "(none)"


def _part_dict(p: Partition, names: dict) -> dict:
    return {
        "partition": p.label(names),
        "method": None if p.method is None else names.get(p.method, p.method),
        "selector": p.method,
        "oncompletion": p.oncompletion,
        "collapsed": p.collapsed,
    }


__all__ = [
    "COLLAPSED",
    "Partition",
    "PartitionedPredicates",
    "ROOT",
    "method_names_for",
]
