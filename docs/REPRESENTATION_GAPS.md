Representation census follow-up
==============================

The 231-program census now has **0 unresolved declared return slots**, **0
missing operands**, and **0 unresolved shared execution blocks**. Ten physical
blocks are shared by routines; all have complete execution records. The census
examines 97,077 ordinary consuming instructions. Parsing still covers 857 distinct
programs without excluded spans. This is a representation census, not a measure
of vulnerabilities or behavioral equivalence.

All seven return-slot entries were resolved:

| Programs | Historical call lines | Cause and correction |
| --- | --- | --- |
| `app_1850858495`, `app_1850904282` | 356/408, 357/409 | Four callees terminate the whole program with `return`; no `retsub` can deliver a result. The diagnostic now distinguishes this from a missing result. |
| `app_3350348253` | 3938 | A recursive return shares its continuation with a direct branch. A distinct return merge now retains the recursive arm. |
| `app_2450526014` | 1929 | A multi-return call shares its continuation with a direct branch; omitting its value left only the branch's constant. Both call returns and the direct branch now participate. |
| `app_3550180073` | 1569 | The same call/branch join issue with three return sites. |

The canonical phi factory already allocates distinct identities for a return
merge and a block-entry merge. Allowing that existing mechanism at a caller-owned
branch target restores the missing values. A new independent value regression
requires all concrete alternatives `{1, 2, 7}` to remain represented, with no
constant answer; recursive and legacy-call controls cover the adjacent cases.

The formerly remaining entries retain their exact source locations in
`tests/representation_gaps.json` and checked by `test_representation_gaps.py`:

| Historical entries | Classification | Implemented correction |
| --- | --- | --- |
| 6 missing `concat` operands, across 3 programs | Caller residual withdrawn after nested calls | A minimum-depth fixed point proves that the nested helpers never rewrite the caller's residual. The ABI log prefix stays named even when extra locals make exact frame heights ambiguous. |
| 7 missing `store` operands, across 4 programs | Legacy helper returns different stack depths | Each return keeps its physical stack until the immediate `assert` or branch checks its flag. The accepted path recovers the returned value and the caller's correctly aligned residual. |
| 4 shared blocks, across 2 programs | Shared inner-transaction effect tails | The simulator runs every routine's execution body, retains separate return stacks and joins public operands across all contexts. Independent tests cover different incoming values, and the private interpreter verifies a shared inner-payment tail. |
| 6 shared blocks, across 4 programs | Shared control flow without an incoming stack operand | Each routine now has an execution record for the shared control block. Physical overlap remains visible and is counted separately from unresolved contexts. |

The site-level tests require zero missing operands, complete records for every
shared context, and the corrected operation at each historical line. Corpus
ceilings independently prevent an improvement from hiding a new failing site.

These results do not establish arbitrary context-sensitive equivalence.
Public SSA joins context values and can lose correlations. Shared frame reads
without a context-specific frame proof remain unknown. Return-shape refinement
requires an immediate flag guard, at most 32 return alternatives and 4,096
retained cells; unknown flags stay in both outcomes. Minimum-depth and execution
walks each have a 100,000-step/visit bound. Ambiguous legacy return counts do not
become fixed-arity summaries. Details and validation are in
[STACK_COMPLETION.md](STACK_COMPLETION.md).
