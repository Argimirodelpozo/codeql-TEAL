# Implemented SAST inference fragments

The experimental obligations now infer temporal, group, resource and execution
facts from source. They remain conditional proofs with explicit environmental
premises. A complete result describes the supported analysis scope; it does not
establish reachability, application acceptance or whole-contract security.
The default detector set remains unchanged. The opt-in command and Python APIs
are documented in [OBLIGATIONS.md](OBLIGATIONS.md).

| Direction | Inferred evidence | Boundary of the proof |
| --- | --- | --- |
| Authority | Shared writer provenance, exact sender identity, and an acyclic storage-read window with no possibly aliasing writer before guarded use. | Historical initialization and revision preservation remain premises. Dynamic keys, stale reads, unresolved aliases and calls refuse the temporal storage proof. Even a potentially harmless intervening same-key write is conservatively unknown. |
| Shared boxes | Constant inner application calls, permission-bearing accesses, family marks and their propagation through matched returns. | Closed app IDs/creators/flags and owner reference mappings are environmental facts. Conditional paths, recursion, missing targets, permission mutation and inner lifecycle transitions are incomplete. Permission does not imply box availability or successful execution. |
| Relational groups | A fixed 2–16-member group ending in the current NoOp call, preceded entirely by caller-to-app payments with all relevant parties and close/rekey fields guarded. Proven singleton dynamic indices normalize to the same group-field identities. | These are funding relationships; intended amounts, fees and application-specific roles require additional obligations. Solver limits may refuse larger groups despite their protocol validity. |
| Crypto and replay | Accepted verification over exact ordered fixed-width fields; a signed consumed-key encoding; zero check before consumption; and an all-writers monotone marker invariant before the selected use. | Every dynamic key leaf must be signed, and read/write keys must be the exact same value, not merely have the same flattened hash fields. Resets/deletions, calls, cycles and variable-width encodings refuse. Key persistence, cryptographic strength, domain adequacy and key authority remain explicit premises. |
| Lifecycle | Creator-authorized paired writes to exact proposal/timestamp keys, using the current timestamp, plus fresh reads and actual upgrade/proposal/delay guards. | The pair must occur once per writer block and cannot be modified between read and upgrade. Initial pair consistency, future revision preservation, clear-program binding and proposal-specific validity remain separate. |
| Rounding and conservation | Congruence-based exact division and linear equality between inferred incoming funding amounts and a single-block inner payment group's actual amounts. | This concerns gross ALGO transfers on successful operations. It does not infer beneficiary authorization, fees paid elsewhere, units of arbitrary state, economic value or absence of arithmetic failure. |
| Resources and retry | Conservative opcode, stack, log, box I/O, allocation, inner-count, fee and balance bounds; validation of a supplied retry credit witness against unchanged initial box state. | Only a straight-line outer approval, own boxes and constant inner payments to the existing caller or app are modeled. Availability of extra credit and application acceptance are separate. |
| Revision compatibility | Canonical ordered implementation events, preserving effects and possible traps while normalizing stack copies and safe literal arithmetic. | Existing-app NoOp equivalence requires identical inputs/state, the same version and sufficient resources. External calls, program metadata/hash dependencies and control-flow choices refuse. Migration and structural ABI/storage contracts are separate. |

## Shared machinery and bounds

The new consumers use immutable constants/ranges, exact source identities,
`PathPredicateAnalysis`, `AssertDominance`, central state effect roles and the
existing inner transaction report. The temporal checks share a bounded flow
window. Box traces, resource analysis and revision comparison share
`analysis.execution_trace`, which follows canonical physical instructions and
requires one entry and an explicit exit. It refuses conditional branches,
subroutines, cycles and missing operands instead of silently skipping them.

Arithmetic normalization memoizes expression DAGs. Its default limits are
256 arithmetic nodes, depth 64 and 4,096-bit coefficients. This prevents repeated
doubling or squaring from expanding shared expressions exponentially.
`LinearEqualities` uses rational elimination as an overapproximation of integer
solutions, with at most 64 atoms, 256 premise rows and 512-bit coefficients.
Detected contradictions or exhaustion cannot produce a proof. Unsupported
premises may be omitted as a sound subset; no integer feasibility witness is
claimed. The existing difference solver remains the guard-bound engine.

Temporal analyses admit at most 4,096 assignments. Fixed-width encoding walks
visit at most 128 nodes; obligation expressions admit 128 nodes and depth 64.
Resource and revision traces default to 1,024 instructions. Resource byte-length
queries memoize values with a 128-node, depth-32 budget. The box call walk shares
a 4,096-instruction budget across the closed graph and permits at most eight
inner call levels. Unsupported or exhausted traces cannot publish partial
resource totals as complete proofs.

## Resource accounting

The resource environment describes the invocation's remaining pooled credits
and initial own-box inventory. The app and outer sender must already exist and
meet their initial minimum balances. Missing credit yields `UNKNOWN`; an invalid
inventory or unsupported effect makes every computed requirement unknown.
The analysis admits fixed-cost scalar instructions, own `box_create`, `box_put`,
`box_get`, `box_len`, `box_del`, `box_resize`, logs and constant inner payments.
Inner payments require explicit zero fees, default app sender, no close/rekey
fields and a receiver known to be the app or the existing outer sender.
External apps, foreign boxes and mutable application parameters refuse.

Allocation uses 2,500 microAlgos per box plus 400 per key/value byte. The balance
bound preserves the largest cumulative allocation/debit requirement even when
a later delete releases minimum balance. Self-payments are still charged as
debits, which can overestimate requirements. Each access charges its full
maximum old/new box extent, and the bound also covers the initial referenced
box sizes. This conservatively covers read/write accounting rather than trying
to reproduce the evaluator's dirty-box optimizations. An insufficient upper
bound yields `UNKNOWN`, not a claim that the invocation must fail.

The protocol also bounds stack depth at 1,000, logs at 32 calls/1,024 total bytes,
and pooled inner transactions at 256. Each zero-fee inner payment needs 1,000
microAlgos of remaining fee credit and one remaining inner-transaction credit.
The supplied `inner_transaction_credit` is capped at 256 and defaults to zero;
earlier group members may already have consumed part of the pool.
Opcode cost comes from the pinned spec with
an allowance for the assembler's two possible constant-table initializers.
Box I/O credit is supplied directly: this API does not assume a universal
per-reference byte credit across protocol revisions. These rules are checked
against the pinned [consensus parameters](https://github.com/algorand/go-algorand/blob/da5946a14568c0cbaa2c9daf4241882de12f3c16/config/consensus.go),
[evaluator](https://github.com/algorand/go-algorand/blob/da5946a14568c0cbaa2c9daf4241882de12f3c16/data/transactions/logic/eval.go)
and [box implementation](https://github.com/algorand/go-algorand/blob/da5946a14568c0cbaa2c9daf4241882de12f3c16/data/transactions/logic/box.go).

## Revision observations and independent controls

The revision comparator interns symbolic values directly, without relying on
hash collision assumptions for equality. It retains state reads/writes, log
order, scratch stores and every operation that might trap, including operations
whose results are discarded. Fully constant failed executions commit no logs.
Constant tables must execute before their references; possible stack overflow
is retained. A differing symbolic event trace is unknown, not automatically a
behavioral counterexample.

`ed25519verify` includes the executing program hash in its signed message, as
shown by the pinned [verification implementation](https://github.com/algorand/go-algorand/blob/da5946a14568c0cbaa2c9daf4241882de12f3c16/data/transactions/logic/crypto.go#L217).
Matching explicit operands therefore cannot establish equivalence across
revisions. This opcode is refused by the comparator. Bare verification has no
such implicit program dependency and remains an ordinary preserved event.

Tests remove individual guards, introduce stale writes, reset replay markers,
break proposal pairs and alter actual payment amounts. Independent finite
integer and invocation-sequence oracles check the arithmetic and monotone-key
claims. Box tests distinguish marks inherited across same-creator returns from
foreign returns, plus missing/recursive/depth-limited targets. Resource tests
cover allocation peaks and a value logged after its original box is resized.
Revision tests compare concrete integer outcomes, retained traps, state/log/
scratch differences and shared expression DAGs.

The private interpreter also checks constant execution agreement/difference,
assembler-generated opcode cost, and the 64/65-byte numeric-comparison boundary.
This last control found a shared constant-folder bug: numeric byte comparisons
must reject integer operands and encoded byte arrays longer than 64 bytes,
including leading zeros. These are benign local simulations and do not submit
transactions. Passing finite controls does not enlarge the documented fragments.
