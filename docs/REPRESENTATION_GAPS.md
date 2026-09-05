Representation census follow-up
==============================

The 231-program census now has **0 unresolved declared return slots**, **13
missing operands**, and **10 blocks shared by routine contexts** (97,077
ordinary consuming instructions examined). Parsing still covers 857 distinct
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

The remaining entries are classified at exact source locations in
`tests/representation_gaps.json` and checked by `test_representation_gaps.py`:

| Entries | Classification | Current limit |
| --- | --- | --- |
| 6 missing `concat` operands, across 3 programs | Caller residual withdrawn after nested calls | These callees are conservatively classified as possibly changing caller stack cells. Their bodies contain nested calls; the exact residual-effect summary currently supports call-free trees. The ABI log prefix beneath the arguments remains unnamed. |
| 7 missing `store` operands, across 4 programs | Legacy helper returns different stack depths | The helper's failure return has one cell; successful returns have two. A following `assert` or rejecting branch filters the flag, but SSA does not couple that flag with the returned stack depth. |
| 4 shared blocks, across 2 programs | Shared inner-transaction effect tails | These blocks consume incoming operands and execute in multiple routine contexts. A single SSA ownership context cannot establish a separate operand set for every entry. The lifted representation's duplication must be validated independently. |
| 6 shared blocks, across 4 programs | Shared control flow without an incoming stack operand | Four bare `retsub` blocks, another shared `retsub`, and a constant whole-program return. These are legitimate ownership overlaps; this metric alone does not establish a lost data operand. |

The site-level tests verify the missing-operation sets, the preceding divergent
callee or unsupported residual summary, and whether each shared block consumes
incoming stack data. An improvement requires updating its classification;
unchanged totals cannot silently substitute a different failing site.
