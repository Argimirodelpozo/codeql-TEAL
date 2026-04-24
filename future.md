# Future work

Design notes for features that have been sketched but not yet implemented.

## Integer range analysis (extends `tryAsInt` narrowing)

Today's `ConstantPropagation::tryAsInt` narrows an integer SSAVar to a single
compile-time value when a dominating guard pins a field read to a literal
(e.g. `txn Fee == 1000; assert` narrows every downstream `txn Fee` to
`1000`). The v1 covers pointwise equality only. A natural generalisation is
to track a constraint set — disjoint intervals plus explicit holes — per
`(SSAVar, BasicBlock)` pair. Pointwise narrowing becomes the degenerate
case where a range is `[K, K]` and there are no holes.

### Core abstraction

```ql
/**
 * Holds if at `bb`, `v`'s runtime value is in the closed interval `[lo, hi]`.
 * Unknown vars default to `[0, 2^64 - 1]` (TEAL's native u64 domain). A
 * contradictory var (range clipped to empty) means `bb` is unreachable on
 * that path and callers should prune.
 */
predicate intRangeAt(SSAVar v, BasicBlock bb, int lo, int hi)

/** Holds if at `bb`, `v` is known *not* to equal `k`. */
predicate intHoleAt(SSAVar v, BasicBlock bb, int k)
```

A disjunctive range set is represented by multiple `intRangeAt` tuples for
the same `(v, bb)` — no extra data structure. Holes live in a sibling
relation to avoid an `N+1`-tuple explosion when `N` `!=` constraints
accumulate.

`tryAsInt(v) = K` becomes: there exists `intRangeAt(v, bb, lo, hi)` with
`lo = hi = K` and no `intHoleAt(v, bb, K)`.

### Guard facts, generalised

Each TEAL comparison yields facts on both the true and false branches of
its dominating `bnz` / `bz` / `assert`:

| Guard (true) | Effect on `x` |
|---|---|
| `x == K` | range clipped to `[K, K]` |
| `x != K` | `intHoleAt(x, bb, K)` |
| `x < K`  | range upper-clipped to `K - 1` |
| `x <= K` | range upper-clipped to `K` |
| `x > K`  | range lower-clipped to `K + 1` |
| `x >= K` | range lower-clipped to `K` |
| `a && b` | intersect facts from both operands |
| `a \|\| b` | union facts (weaker — one tuple per operand, not intersection) |

False-branch facts are the dual (operator flipped).

### Main costs to manage

1. **Interval explosion from holes.** `x != K1 and x != K2 and x != K3`
   represented as explicit disjoint intervals yields `N + 1` tuples per
   `N` holes. The separate hole relation avoids this.
2. **Recursion + widening.** Refinement traverses CFG → guards → more
   refinement. Needs a widening operator (collapse to `[0, 2^64 - 1]`
   after N iterations, or cap the interval count per var). CodeQL's
   monotone recursion handles simple lattice fixpoints, but unbounded
   intervals blow up fast.
3. **Multiple reaching definitions.** At a join BB, `intRangeAt` on a
   phi var must UNION incoming ranges. Cheap but easy to forget — missing
   it is unsound.
4. **Symbolic bounds.** Clipping `x < K` where `K` is another SSAVar (not
   a literal) means range-of-`x` depends transitively on range-of-`K`,
   and the system becomes a simultaneous constraint solve. For v1, only
   accept guards where the non-`x` side is resolvable via `tryAsInt` —
   same constraint today's pointwise narrowing has.

### Recommended first increment

- **Skip holes entirely for v1.** Intervals only. Covers `x <= K`, `x >= K`,
  `x == K` cleanly; `!=` is dropped.
- **Add `intRangeAt(v, bb, lo, hi)` as a NEW predicate**, don't fold into
  `tryAsInt` immediately. Callers opt in.
- **Only refine at guard BBs.** Initial range at the field-read BB is
  `[0, 2^64 - 1]`; dominated guards progressively clip it. No full-CFG
  dataflow fixpoint yet.
- **Retrofit `tryAsInt`** so the field-read narrowing case becomes
  `intRangeAt(v, bb, K, K) ⇒ K`. Existing narrowing tests pass unchanged.
- **Second pass:** add holes (for `!=` and false-branch `==`).
- **Third pass:** widening / normalisation and UNION at phi joins.

Estimated scope: v1 intervals-only is ~a day, holes adds half a day, the
widening/fixpoint machinery is a real engineering push if industrial
precision is required.
