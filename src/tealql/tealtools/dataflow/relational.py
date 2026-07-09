"""A relational (zone / difference-bound) abstract domain for byte-access
bounds — proving ``offset + width <= len(buffer)`` when neither side is a
compile-time constant.

The non-relational domains bound each quantity *separately*: intervals give
``offset ∈ [.,.]`` and ``width ∈ [.,.]``, ``byte_length_prop`` gives ``len(buf)``
— but none RELATES them, and ABI-decode safety is exactly a relation. This
domain tracks difference constraints ``a - b <= c`` (a Difference-Bound Matrix,
the *zone* domain) between length-relevant terms:

  * ``Len(buf)`` — a symbolic atom for each buffer's byte length,
  * integer SSA vars — offsets, widths, and the results of ``len`` /
    ``extract_uint*`` / ``btoi`` / integer arithmetic,
  * a shared origin ``0`` — every constant ``n`` folds in as ``0 + n``.

``offset + width <= len(buffer)`` is not itself a difference constraint (three
variables), but it BECOMES one the moment either operand is constant — which is
the overwhelming majority of real accesses:

  * constant width ``w``  ⇒  ``offset - Len(buf) <= -w``   (``extract`` imm,
    ``getbyte`` w=1, ``extract_uint*`` w∈{2,4,8}),
  * constant offset ``k`` ⇒  ``width  - Len(buf) <= -k``   (the ``extract3 X 0
    (len X)`` whole-buffer idiom: ``k=0``, and ``width == Len(X)`` from ``len``).

Facts come from three places, each with the right soundness:

  * STRUCTURAL (global — an SSA def dominates all its uses): ``L = len X`` gives
    ``L == Len(X)``; ``s = a + k`` / ``s = a - k`` (one operand constant) give
    ``s - a == ±k``; every uint64 term is ``>= 0``; a constant literal buffer
    gives an EXACT ``Len == n`` (both bounds — enabling proven-OOB), a tracked
    ``byte_length`` gives only a sound LOWER bound ``Len >= n`` (it can
    under-count, the safe direction for an in-bounds proof).
  * ASSERT-DERIVED (flow-sensitive — applied only where the assert DOMINATES the
    query): ``assert(A <= B)`` ⇒ ``A - B <= 0``; ``assert(len X >= 32)`` seeds a
    length floor; ``assert(off + 2 <= len X)`` seeds the length-prefix
    well-formedness relation the decode turns on. Dominance is approximated by
    reachability exactly as in :mod:`..passes.range_assert` (over-approx ⇒ a
    constraint is at worst skipped, never applied unsoundly).

The DBM is closed (Floyd–Warshall) so chained facts compose transitively, and
consistency-checked (a negative self-cycle ⇒ the site is unreachable ⇒ no
claim). Read-only; used by :mod:`.bounds`.
"""
from __future__ import annotations

from ..ssa import SSAProgram, SSAVar
from ..ssa.operands import const_int, const_byte_length
from ..avm import U64_CMP_OPS

# The DBM origin (the constant 0); constants fold in as ``ORIGIN + n``.
ORIGIN = "@0"

_SWAP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _iatom(v: SSAVar):
    return ("v", id(v))


def _latom(buf):
    return ("L", id(buf))


def _term(operand):
    """``(atom, offset)`` such that ``value(operand) == value(atom) + offset``,
    or ``None`` when the operand isn't a length-relevant term (a phi, a bytes
    value). A constant ``n`` is ``(ORIGIN, n)``; an SSA var is ``(v, 0)``."""
    n = const_int(operand)
    if n is not None:
        return (ORIGIN, n)
    if isinstance(operand, SSAVar):
        return (_iatom(operand), 0)
    return None


class DBM:
    """A difference-bound matrix. ``m[(a, b)] = c`` encodes ``a - b <= c``; a
    missing entry is ``+∞``. Small and sparse — atoms are only the
    length-relevant terms."""

    __slots__ = ("m",)

    def __init__(self, m=None):
        self.m = dict(m) if m else {}

    def add(self, a, b, c: int) -> None:
        """Tighten with ``a - b <= c``."""
        if a == b:
            if c < self.m.get((a, a), 0):
                self.m[(a, a)] = c        # negative self-loop ⇒ inconsistent
            return
        cur = self.m.get((a, b))
        if cur is None or c < cur:
            self.m[(a, b)] = c

    def copy(self) -> "DBM":
        return DBM(self.m)

    def _atoms(self) -> set:
        s = {ORIGIN}
        for a, b in self.m:
            s.add(a)
            s.add(b)
        return s

    def close(self) -> None:
        """All-pairs shortest paths (Floyd–Warshall) + nonnegativity. After
        this, ``entails`` reads off the tightest derivable bound."""
        atoms = self._atoms()
        # Every non-origin term is a uint64 quantity or a length: ``>= 0``.
        for a in atoms:
            if a != ORIGIN:
                self.add(ORIGIN, a, 0)
        m = self.m
        for k in atoms:
            for i in atoms:
                ik = m.get((i, k))
                if ik is None:
                    continue
                for j in atoms:
                    kj = m.get((k, j))
                    if kj is None:
                        continue
                    nv = ik + kj
                    cur = m.get((i, j))
                    if cur is None or nv < cur:
                        m[(i, j)] = nv

    def consistent(self) -> bool:
        return all(self.m.get((a, a), 0) >= 0 for a in self._atoms())

    def entails(self, a, b, c: int) -> bool:
        """Is ``a - b <= c`` provable? (Assumes :meth:`close` has run.)"""
        if a == b:
            return c >= 0
        v = self.m.get((a, b))
        return v is not None and v <= c


# ─── flow-insensitive dominance (mirrors passes.range_assert) ────────────────

def _all_blocks(prog: SSAProgram) -> set:
    seed = set()
    for a in prog.assignments:
        if a.basic_block is not None:
            seed.add(a.basic_block)
    for ph in prog.phis.values():
        bb = getattr(ph, "basic_block", None)
        if bb is not None:
            seed.add(bb)
    allb, stack = set(seed), list(seed)
    while stack:
        b = stack.pop()
        for nb in (*b.predecessors, *b.successors):
            if nb not in allb:
                allb.add(nb)
                stack.append(nb)
    return allb


def _reachable_avoiding(entries: list, avoid) -> set:
    seen = {e for e in entries if e is not avoid}
    stack = list(seen)
    while stack:
        b = stack.pop()
        for s in b.successors:
            if s is avoid or s in seen:
                continue
            seen.add(s)
            stack.append(s)
    return seen


class LengthRelations:
    """Builds the structural DBM once, then answers a bounds query at any
    access site with the assert facts that dominate *that* site folded in."""

    def __init__(self, prog: SSAProgram):
        self._entries = [b for b in _all_blocks(prog) if not b.predecessors]
        self._base = DBM()
        self._seed_structural(prog)
        # (assert-assignment, [(a, b, c), ...]) for every decodable assert.
        self._asserts = self._collect_asserts(prog)
        self._reach_cache: dict = {}   # assert-block -> reachable-without-it
        self._dbm_cache: dict = {}     # frozenset(assert idx) -> closed DBM

    # -- structural (global) facts ------------------------------------------
    def _seed_structural(self, prog: SSAProgram) -> None:
        base = self._base
        for a in prog.assignments:
            op, ins, outs = a.op, a.inputs, a.outputs
            if op == "len" and len(ins) == 1 and outs:
                # L == Len(buf)
                lv, la = _iatom(outs[0]), _latom(ins[0])
                base.add(lv, la, 0)
                base.add(la, lv, 0)
            elif op == "+" and len(ins) == 2 and outs:
                # s = a + b, one operand constant k ⇒ s == other + k
                self._affine(base, outs[0], ins[0], ins[1], sign=+1)
            elif op == "-" and len(ins) == 2 and outs:
                # top-first: s = inputs[1] - inputs[0]; subtrahend inputs[0]
                s, sub, minu = outs[0], ins[0], ins[1]
                k = const_int(sub)
                if k is not None and isinstance(minu, SSAVar):
                    sv, mv = _iatom(s), _iatom(minu)
                    base.add(sv, mv, -k)   # s - minu <= -k
                    base.add(mv, sv, k)    # minu - s <= k

    @staticmethod
    def _affine(base: DBM, s, x, y, *, sign: int) -> None:
        """``s = x + y`` with one of ``x``/``y`` a constant ⇒ ``s == var + k``."""
        kx, ky = const_int(x), const_int(y)
        if kx is not None and isinstance(y, SSAVar):
            var, k = y, kx
        elif ky is not None and isinstance(x, SSAVar):
            var, k = x, ky
        else:
            return
        sv, vv = _iatom(s), _iatom(var)
        base.add(sv, vv, k)    # s - var <= k
        base.add(vv, sv, -k)   # var - s <= -k

    def seed_buffer(self, buf) -> None:
        """Register a buffer's length bound: an EXACT ``Len == n`` for a literal
        (enables proven-OOB), else a sound LOWER bound ``Len >= n`` from a tracked
        ``byte_length`` (which can under-count — the safe direction)."""
        la = _latom(buf)
        n = const_byte_length(buf)
        if n is not None:
            self._base.add(la, ORIGIN, n)     # Len <= n
            self._base.add(ORIGIN, la, -n)    # Len >= n
            return
        if isinstance(buf, SSAVar) and buf.type is not None \
                and buf.type.byte_length is not None:
            self._base.add(ORIGIN, la, -buf.type.byte_length)   # Len >= n only

    # -- assert (flow-sensitive) facts --------------------------------------
    def _collect_asserts(self, prog: SSAProgram):
        out = []
        for a in prog.assignments:
            if a.op != "assert" or not a.inputs:
                continue
            edges = self._decode(a.inputs[0])
            if edges:
                out.append((a, edges))
        return out

    def _decode(self, cond):
        """Difference edges proven by ``assert(cond)`` continuing past."""
        d = getattr(cond, "defined_by", None)
        if d is not None and d.op in U64_CMP_OPS and len(d.inputs) == 2:
            lhs, rhs = d.inputs[1], d.inputs[0]      # top-first: in1 op in0
            return self._cmp_edges(lhs, d.op, rhs)
        if isinstance(cond, SSAVar):                 # truthiness: cond >= 1
            return [(ORIGIN, _iatom(cond), -1)]
        return []

    def _cmp_edges(self, lhs, rel, rhs):
        lt, rt = _term(lhs), _term(rhs)
        if lt is None or rt is None:
            return []
        (la, lo), (ra, ro) = lt, rt
        # value(lhs) = la + lo, value(rhs) = ra + ro
        edges = []
        if rel in ("<", "<="):                       # lhs <= rhs (- 1 if strict)
            edges.append((la, ra, ro - lo - (1 if rel == "<" else 0)))
        elif rel in (">", ">="):                     # rhs <= lhs
            edges.append((ra, la, lo - ro - (1 if rel == ">" else 0)))
        elif rel == "==":
            edges.append((la, ra, ro - lo))
            edges.append((ra, la, lo - ro))
        return edges

    def _dominating_assert_ids(self, block, line: int) -> frozenset:
        ids = []
        for i, (a, _edges) in enumerate(self._asserts):
            ab = a.basic_block
            if ab is None:
                continue
            if ab is block:
                if line > a.location.line:
                    ids.append(i)
                continue
            reach = self._reach_cache.get(ab)
            if reach is None:
                reach = self._reach_cache[ab] = _reachable_avoiding(self._entries, ab)
            if block not in reach:
                ids.append(i)
        return frozenset(ids)

    def _dbm_for(self, ids: frozenset) -> DBM:
        dbm = self._dbm_cache.get(ids)
        if dbm is None:
            dbm = self._base.copy()
            for i in ids:
                for a, b, c in self._asserts[i][1]:
                    dbm.add(a, b, c)
            dbm.close()
            self._dbm_cache[ids] = dbm
        return dbm

    # -- query --------------------------------------------------------------
    def verdict(self, buf, base_operand, extra_c, site_block, site_line):
        """``(in_bounds, proven_oob)`` for an access reading up to byte
        ``value(base_operand) + extra_c`` of ``buf`` (``base_operand is None`` ⇒
        the bound is the constant ``extra_c``). ``extra_c is None`` ⇒ unbounded
        (neither)."""
        if extra_c is None:
            return (False, False)
        la = _latom(buf)  # buffers must be pre-seeded via seed_buffer (see bounds.py)
        if base_operand is None:
            base_atom, thresh = ORIGIN, extra_c
        else:
            t = _term(base_operand)
            if t is None:
                return (False, False)
            base_atom, off = t
            thresh = extra_c + off
        dbm = self._dbm_for(self._dominating_assert_ids(site_block, site_line))
        if not dbm.consistent():
            return (False, False)                # unreachable ⇒ no claim
        in_bounds = dbm.entails(base_atom, la, -thresh)      # base + thresh <= Len
        proven_oob = (not in_bounds
                      and dbm.entails(la, base_atom, thresh - 1))  # Len < base + thresh
        return (in_bounds, proven_oob)
