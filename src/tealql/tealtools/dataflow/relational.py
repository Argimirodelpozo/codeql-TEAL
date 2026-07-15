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
from ..ssa.operands import binary_operands, const_int, const_byte_length
from ..cfg.dominance import AssertDominance
from ..avm import U64_CMP_OPS

# The DBM origin (the constant 0); constants fold in as ``ORIGIN + n``.
ORIGIN = "@0"

_SWAP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _iatom(v: SSAVar):
    return ("v", id(v))


def _latom(buf):
    return ("L", id(buf))


def _int_or_none(imm, i):
    try:
        return int(imm[i])
    except (IndexError, ValueError):
        return None


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
    """A system of difference constraints ``a - b <= c`` as a weighted graph
    (edge ``a -> b`` with weight ``c``). Entailment of ``a - b <= c`` is exactly
    "shortest path ``a -> b`` has weight ``<= c``". We answer queries by
    ON-DEMAND single-source shortest path (Bellman–Ford) from the query's source
    atom, scoped to the nodes reachable from it — NOT all-pairs closure, which
    is O(n³) and blew up once slice-lengths and interval bridges made ``n``
    program-wide. Nonnegativity (``ORIGIN -> v`` weight 0 for every ``v``) is
    applied lazily during the reachable-set walk."""

    __slots__ = ("adj",)

    def __init__(self, adj=None):
        # adj[a] = {b: c}  (tightest c for each edge a -> b)
        self.adj = {a: dict(d) for a, d in adj.items()} if adj else {}

    def add(self, a, b, c: int) -> None:
        d = self.adj.setdefault(a, {})
        if b not in d or c < d[b]:
            d[b] = c

    def copy(self) -> "DBM":
        return DBM(self.adj)

    def _node_count(self) -> int:
        s = {ORIGIN}
        for a, d in self.adj.items():
            s.add(a)
            s.update(d)
        return len(s)

    def shortest(self, src) -> "tuple[dict, bool]":
        """``(dist, ok)`` — shortest path weight from ``src`` to every reachable
        atom; ``ok`` is False if a negative cycle is reachable (infeasible ⇒ the
        program point is unreachable, no claim). SPFA (queue-based Bellman–Ford):
        only nodes whose distance improved are re-examined, near-linear on these
        sparse constraint graphs — the all-pairs closure it replaces was O(n³)
        and blew up once ``n`` spanned the whole program. (Uint64 nonnegativity
        is NOT a graph edge — it would make ORIGIN a hub connected to every atom;
        it is applied at the OOB query endpoint instead, the only place it pays.)"""
        from collections import deque
        limit = self._node_count()
        dist = {src: 0}
        inq = {src}
        relaxed: dict = {}
        q = deque([src])
        while q:
            u = q.popleft()
            inq.discard(u)
            du = dist[u]
            for v, w in self.adj.get(u, {}).items():
                nv = du + w
                if v not in dist or nv < dist[v]:
                    dist[v] = nv
                    if v not in inq:
                        inq.add(v)
                        q.append(v)
                        relaxed[v] = relaxed.get(v, 0) + 1
                        if relaxed[v] > limit:
                            return dist, False    # negative cycle reachable
        return dist, True


class LengthRelations:
    """Builds the structural DBM once, then answers a bounds query at any
    access site with the assert facts that dominate *that* site folded in."""

    def __init__(self, prog: SSAProgram):
        self._dom = AssertDominance(prog)
        self._base = DBM()
        self._seed_structural(prog)
        # (assert-assignment, [(a, b, c), ...]) for every decodable assert.
        self._asserts = self._collect_asserts(prog)
        self._dbm_cache: dict = {}     # frozenset(assert idx) -> constraint graph
        self._sssp_cache: dict = {}    # (assert-set, source atom) -> (dist, ok)

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
            elif outs:
                self._seed_slice_len(a, op, ins, outs[0])

    def _eq(self, a_atom, a_off: int, b_atom, b_off: int) -> None:
        """Assert ``value(a) == value(b)`` where ``value(x) == x_atom + x_off``."""
        # a_atom + a_off == b_atom + b_off  ⇒  a_atom - b_atom == b_off - a_off
        self._base.add(a_atom, b_atom, b_off - a_off)
        self._base.add(b_atom, a_atom, a_off - b_off)

    def _seed_slice_len(self, a, op, ins, out) -> None:
        """A slice op PRODUCES a bytes value whose length is determined by the
        slice — the biggest sound source of buffer lengths (``Y = extract3 X A
        B`` ⇒ ``Len(Y) == B``, exact even when ``B`` is a runtime variable, which
        is why ``byte_length_prop`` — a forward CONSTANT length — misses it)."""
        lo = _latom(out)
        if op == "extract3" and len(ins) == 3:            # Len(Y) == count(ins[0])
            t = _term(ins[0])
            if t is not None:
                self._eq(lo, 0, *t)
                self.seed_range(ins[0])
        elif op == "substring3" and len(ins) == 3:        # Len(Y) == end - start
            end, start = _term(ins[0]), const_int(ins[1])
            if end is not None and start is not None:      # start const: end - k
                self._eq(lo, 0, end[0], end[1] - start)
                self.seed_range(ins[0])
        elif op == "extract" and len(ins) == 1:           # extract A B (imm)
            imm = (a.immediates or "").split()
            A, B = _int_or_none(imm, 0), _int_or_none(imm, 1)
            if A is None:
                return
            if B == 0:                                     # to end: Len(Y)==Len(X)-A
                self._eq(lo, 0, _latom(ins[0]), -A)
            elif B is not None:                            # Len(Y) == B
                self._eq(lo, 0, ORIGIN, B)
        elif op == "substring" and len(ins) == 1:         # substring A B (imm)
            imm = (a.immediates or "").split()
            A, B = _int_or_none(imm, 0), _int_or_none(imm, 1)
            if A is not None and B is not None:            # Len(Y) == B - A
                self._eq(lo, 0, ORIGIN, B - A)

    def seed_length_lb(self, buf, n: int) -> None:
        """Seed a LOWER bound ``Len(buf) >= n`` (never an upper bound), so it can
        only ever help an in-bounds proof and can NEVER create a false proven-OOB.
        Used for SPECULATIVE ARC-4 lengths (an assumption about well-formed input);
        the sound seeds live in :meth:`seed_buffer`."""
        self._base.add(ORIGIN, _latom(buf), -n)      # Len >= n

    def seed_range(self, var) -> None:
        """Bridge an SSA var's non-relational :class:`IntRange` INTO the zone
        domain (``lo <= var <= hi``), so a relation like ``Len(Y) == count`` can
        borrow the count's interval to prove a fixed-width read in-bounds."""
        if not isinstance(var, SSAVar) or var.range is None:
            return
        a = _iatom(var)
        self._base.add(a, ORIGIN, var.range.hi)      # var <= hi
        self._base.add(ORIGIN, a, -var.range.lo)     # var >= lo

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
            lhs, rhs = binary_operands(d)
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
        ids = [
            i for i, (a, _edges) in enumerate(self._asserts)
            if a.basic_block is not None
            and self._dom.dominates(a.basic_block, block, a.location.line, line)
        ]
        return frozenset(ids)

    def _graph_for(self, ids: frozenset) -> DBM:
        """Structural base + the dominating asserts' edges (un-closed), cached
        by the assert-id set."""
        g = self._dbm_cache.get(ids)
        if g is None:
            g = self._base.copy()
            for i in ids:
                for a, b, c in self._asserts[i][1]:
                    g.add(a, b, c)
            self._dbm_cache[ids] = g
        return g

    def _sssp(self, g: DBM, ids: frozenset, src):
        key = (ids, src)
        r = self._sssp_cache.get(key)
        if r is None:
            r = self._sssp_cache[key] = g.shortest(src)
        return r

    def _entails(self, g, ids, a, b, c: int) -> bool:
        """Is ``a - b <= c`` provable and consistent?"""
        if a == b:
            return c >= 0
        dist, ok = self._sssp(g, ids, a)
        if not ok:
            return False
        v = dist.get(b)
        return v is not None and v <= c

    def _prove_len_ge(self, buf, na, no: int, g, ids, depth: int = 0) -> bool:
        """Prove ``len(buf) >= value(na) + no`` (the need ``na + no``). Tries the
        seeded ``Len(buf)`` facts, then UNFOLDS a slice definition — a sub-slice's
        length is a symbolic expression of its parent's offsets, which substitutes
        the 3-variable ``offset+width <= len`` back into a 2-variable difference
        query (and recurses through nested slices)."""
        # (1) direct: len(buf) >= na+no  ⇔  na - Len(buf) <= -no
        if self._entails(g, ids, na, _latom(buf), -no):
            return True
        if depth > 4 or not isinstance(buf, SSAVar):
            return False
        d = getattr(buf, "defined_by", None)
        if d is None:
            return False
        op, ins = d.op, d.inputs
        if op == "extract3" and len(ins) == 3:            # len == count(ins[0])
            t = _term(ins[0])
            return t is not None and self._entails(g, ids, na, t[0], t[1] - no)
        if op == "substring3" and len(ins) == 3:          # len == end(0) - start(1)
            if na != ORIGIN:                               # 3-var: only const-hi
                return False
            end, start = _term(ins[0]), _term(ins[1])      # no <= end - start
            return (end is not None and start is not None
                    and self._entails(g, ids, start[0], end[0],
                                      end[1] - start[1] - no))
        if op == "extract" and len(ins) == 1:             # extract A B (imm)
            imm = (d.immediates or "").split()
            A, B = _int_or_none(imm, 0), _int_or_none(imm, 1)
            if A is None:
                return False
            if B == 0:                                     # to end: len==len(X)-A
                return self._prove_len_ge(ins[0], na, no + A, g, ids, depth + 1)
            if B is not None:                              # len == B
                return self._entails(g, ids, na, ORIGIN, B - no)
        if op == "substring" and len(ins) == 1:           # substring A B (imm)
            imm = (d.immediates or "").split()
            A, B = _int_or_none(imm, 0), _int_or_none(imm, 1)
            if A is not None and B is not None:            # len == B - A
                return self._entails(g, ids, na, ORIGIN, (B - A) - no)
        return False

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
        ids = self._dominating_assert_ids(site_block, site_line)
        g = self._graph_for(ids)
        # in-bounds: base + thresh <= len(buf) (unfolding slice definitions).
        if self._prove_len_ge(buf, base_atom, thresh, g, ids):
            return (True, False)
        # proven-OOB: Len < base + thresh. Directly via shortest(Len -> base)
        # <= thresh-1, OR via base >= 0 (uint64) and Len <= shortest(Len ->
        # ORIGIN): then Len - base <= Len <= that bound.
        dist2, ok2 = self._sssp(g, ids, la)
        if not ok2:
            return (False, False)
        db = dist2.get(base_atom)
        do = dist2.get(ORIGIN)
        proven_oob = ((db is not None and db <= thresh - 1)
                      or (do is not None and do <= thresh - 1))
        return (False, proven_oob)
