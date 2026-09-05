Numeric facts and supported fragments
=====================================

`program.facts(FactDomain.RANGES)` exposes three complementary queries:

```python
facts.range_at(value, use)       # inclusive bounds at this instruction
facts.congruence(value)          # inductive modulus/residue, independent of use
facts.call_result(call, slot=0)  # numeric result of one explicit callsub site
```

These queries preserve canonical SSA. Arithmetic bounds describe values on
successful executions; they do not establish reachability, termination, available
resources, or absence of arithmetic failure.

Intervals and induction
-----------------------

Range queries combine definition-site arithmetic, must-predicates at the queried
use, and transitive difference constraints over integer-typed operands. For
example, `Fee < LastValid` and `LastValid < 100` establish `Fee <= 98` after
both checks. Guarded facts do not narrow another branch or a use before the
guard. A traversal cut is context-dependent and its result is not cached for
another root.

Congruence equations grow from bottom to a post-fixpoint. Phi joins include all
arms; resets weaken the modulus. Unsupported values and unseeded cycles become
unknown. Addition, subtraction, multiplication, constant division/remainder,
shifts and bitwise low-bit facts participate. Left shifts account for uint64
wrapping. Intersecting the resulting residue with an interval improves endpoints:
a counter starting at zero, stepping by four and exiting at `counter >= 10`
has exit value 12. This is an inductive counter fact, not a trip-count prediction.

The rounding obligation now recognizes divisible expressions even when their
value varies, such as `4*x / 4` on successful uint64 arithmetic. Units and the
intended conservation equation still require application policy.

Queries are bounded: 128 dependency nodes, 4,096 congruence worklist steps,
24 relational atoms, and 64 affine expansion visits. No partial congruence
iterate is published after exhaustion. Nonlinear relations, general relational
loop invariants, arbitrary scratch aliases and recursive numeric summaries
remain outside the proved fragments.

Numeric call summaries
----------------------

`call_result` symbolically executes the stack and frame of a straight-line
`proto` routine, including nested summarized calls, frame replacement, stack
shuffles and the supported integer arithmetic. Results contain `bounds`,
`congruence`, `complete`, and `reason`. Return slots are indexed in bottom-first
ABI order. Separate invocations retain separate actual arguments and the
caller's bounds at the call instruction.

The query refuses branches, recursive calls, unsupported effects, caller
residual accesses, incomplete program representations, ambiguous return layouts,
and exhausted expression/operation budgets. An assertion is consumed without
claiming it succeeds. A successful numeric summary is not an effect summary or
a proof that the callee can finish.

Call identity must be explicit. Canonical callee SSA values can represent several
invocations, including values saved before a later call. `range_at` therefore
does not substitute the most recent call's arguments into such a shared value.
Doing so could incorrectly narrow an earlier result saved in scratch.

Validation
----------

Independent integer oracles cover arithmetic, modular residues, uint64 edges,
wrapping shifts, loop strides and resets. Regression tests cover transitive and
difference relations, query order, separate and nested calls, multiple returns,
frame replacement, stale revisions, and bounded refusal. The integration run
passed 228 checks; core-only validation passed 97. The 231-program offline
default finding comparison completed with no changed cells or crashes.
