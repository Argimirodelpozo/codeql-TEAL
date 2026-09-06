# Remaining stack gaps

The remaining corpus operand gaps are resolved. All 231 distinct programs have
zero missing ordinary operands and zero unresolved declared call results across
97,077 consuming instructions. All 10 shared blocks have complete routine
execution records. The physical overlaps remain visible; `shared_unresolved`
separately counts missing context records or explicit stack operands.

## Implemented changes

Six missing `concat` operands came from withdrawing caller residuals when nested
helpers had height-conflicting joins. A lower-bound fixed point now establishes
that those helpers cannot rewrite the caller's cells. Joins use the minimum
depth, and fixed-arity calls transfer their argument/result counts. Exact frame
coordinates retain their existing poison and frame-slot proofs. A minimum never
stands in for an exact coordinate.

Seven missing `store` operands followed a legacy helper that returns only zero
on failure, and a value plus a nonzero flag on success. The interpreter now
retains each physical return stack until the caller's immediate assertion or
conditional branch checks the flag. Each surviving path keeps its actual depth
and the correctly aligned caller residual. Unknown flags remain possible on
both outcomes; collapsed branch arms cannot narrow the stack.

The simulator now follows each routine's execution body through shared tails.
Return stacks remain separate by routine, while the canonical public opcode
operands join values from every executing context. This retains source-position
identity and prevents one owner's operands from standing in for all callers.
The construction-SSA visualization also exposes the separate context operands.
The four shared effect blocks and six shared control blocks in the census are
all represented, including shared inner-transaction tails.

## Bounds and limits

Minimum-depth propagation has a 100,000-operation bound. Descending cycles and
unresolved call effects cannot publish a partial fixed point. An ambiguous
legacy return count stays unsafe even when the callee's local writes preserve
its own caller cells: unlike `proto`, a legacy `retsub` does not enforce a fixed
result count. A regression covers one shared return site reached at two depths,
where assuming the larger count would silently change the caller's value.

Return refinement requires one local predecessor and an immediate flag guard,
with at most 32 return alternatives and 4,096 retained stack cells. Pending
recursive returns, intervening instructions, other predecessors and unsupported
flags retain the conservative result. Zero surviving alternatives do not become
a fabricated value or a proof of reachability.

Execution-context enumeration has a 100,000-block-visit bound; exhaustion is
reported in analysis health. Shared frame reads without a context-specific frame
proof remain unknown. Public SSA joins can lose correlations across invocations;
this is not arbitrary context-sensitive equivalence or whole-program security.

## Reviewed detector change

Compared with `8ac2014c`, exactly one default detector cell changes across the
231-program offline corpus. `partial-tainted-fund-flow` no longer reports lines
175 and 181 (`Receiver` and `AssetReceiver`) in `app_1050027991.teal`, content hash
`0b35caf4425ed5f1`. Its totals change from 57 to 55 findings in 19 to 18 programs;
there are no detector crashes.

At line 162, the accepted helper return now supplies the operand of `store 71`.
The previous missing operand produced unconstrained byte uncertainty at the two
later recipient reads. Recovering that value lets the existing authority
analysis follow its provenance. These are conditional finding removals: the
report explicitly retains initialization and revision-preservation premises for
global authority keys `SL` and `BY`. Amount and close/rekey findings are unchanged.
This does not establish that the contract is safe for arbitrary historical state.

The before/after inspection used an isolated copy of `8ac2014c` and the current
source. It checked raw and retained findings, byte coverage, unknown IR taint and
reported authority premises. The exact reviewed digest is committed alongside
the per-program representation census; no finding locations were dropped from
the comparison.

## Validation

Independent list/integer controls cover caller residual alignment, both branch
polarities, non-Boolean nonzero flags, unknown flags, other predecessors,
collapsed arms, growing/shrinking loops, shared returns, shared effect operands
and bounded refusal. The private interpreter independently checks eight flag
and minimum-depth cases, including rejection, and a shared inner-payment tail.
All nine new runtime controls passed.

The frozen external evaluation evidence is preserved. Its six programs now
also report `shared_unresolved: 0`; tests assert that new field separately and
compare every historical result unchanged. The first combined private run found
this schema difference in all six examples; its other 51 checks passed.

| Final gate | Result |
| --- | --- |
| Full suite with backend/corpus and branch coverage | Running. |
| Complete core-only suite without Puya | Running. |
| Combined private-node, assembler and external gate after schema adaptation | 57 passed in 204.13 seconds. The disposable private node was stopped and removed afterward. |
| Fresh non-editable wheel | Passed in a new core-only environment: CLI, policy/resource/box/revision APIs, catalog views, guarded return shapes and separate shared return stacks. Puya is absent. |
| Corpus representation and default detector review | 231 programs complete; zero representation gaps; one classified detector cell changes; zero crashes. |
| Static checks | Ruff and diff whitespace checks pass. |

The source SHA-256 used for final validation is
`2d104e4e25cc2f9552dc7d19e359eef6196a0d7419b90c30e40c9b4f8be84b7a`,
hashing each sorted `src/**/*.py` path, NUL, contents, NUL in sequence.
Local evidence is in `/tmp/tealql-remaining-full.log`,
`/tmp/tealql-remaining-core.log`, `/tmp/tealql-remaining-coverage.json`,
`/tmp/tealql-remaining-private-final.log`, and
`/tmp/tealql-remaining-review.log`.

The verified wheel is `/tmp/tealql-remaining-dist/tealql-0.1.0-py3-none-any.whl`,
SHA-256 `c0c6eb2bd166e633049f2d9b8b4503da59e96065fe56e5c68cd3fba9a8daf2df`.
Its isolated smoke-test log is `/tmp/tealql-remaining-wheel.log`.
