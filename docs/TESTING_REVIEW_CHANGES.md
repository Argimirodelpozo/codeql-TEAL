# Test boundaries and evaluation

The corpus completion manifest contains 857 distinct parser inputs and 231
distinct representation inputs. Every input has a named pytest case. Unexpected
load failures fail the case; regeneration rejects parse diagnostics and failed
construction. Per-program ceilings prevent an improvement elsewhere from hiding
a regression. The follow-up representation census is 0 unresolved return slots, 13 missing
operands, 10 shared execution blocks, and 97,077 examined operations. These are
measured limits, not claims that the representation is complete.

The recompilation sample is also parametrized by program. No aggregate loop can
turn compilation failures into skips or hide them behind one timeout. Shared
content enumeration uses SHA-256, independent of Python's randomized hash seed.

`corpus_families.json` adds AVM version, call/frame/scratch/router dimensions and
218 syntax families. Literal values and label names are normalized while branch
target structure is retained. Whole families are assigned to development or a
reserved partition (42 programs currently reserved). This is a reproducible
split for future work, **not an independent holdout**: the existing corpus has
already influenced development. Accuracy claims require separately reviewed,
unseen families. The current curated benchmark and mutation gates retain their
original scope.

`EXTERNAL_EVALUATION.md` records a separately acquired six-family evaluation,
including pinned provenance, the first attempt's adapter failure, the corrected
result, and its limits. Those inputs are now regression fixtures, not a reusable
claim of unseen evaluation.

Interval kernel properties use independent Python mathematical semantics for
successful uint64 operations. CFG tests cover guards, joins, loop backedges,
calls, opposite-branch controls, and bounded query work. Router tests enumerate
all twelve creation/completion combinations and reject a different multiplier.
Snapshot tests protect cached pre-IR and summary reuse. Core-only CI installs
without the optional compiler; a subprocess test also blocks compiler imports.
Mixed construction/compiler regressions run core assertions independently of
the compiler variant. Declared ABI length assumptions also work in core-only
installations, while compiler type recovery remains optional.

Performance controls test work and retained state directly: guard queries reuse
only frozen definitions, distinguish subjects and return contexts, and bound
memo size. Frame-source filtering terminates on cyclic phis without expanding
unrelated upstream assignments or dropping dependencies across rule barriers.

## Execution oracle

`tests.behavioral_lift.observations` keeps outcome, completion count, and effect
availability separate. Zero completed cases, execution errors, absent required
observations, or no successful comparison produce `INCONCLUSIVE`. The legacy
dryrun adapter compares logs and global/local deltas. It pins the requested
round, timestamp, and protocol, and reports missing box/inner/scratch effects.

go-algorand 5.0 removed dryrun from its [API routes](https://github.com/algorand/go-algorand/tree/da5946a14568c0cbaa2c9daf4241882de12f3c16/daemon/algod/api/server/v2/generated).
The current localnet fixture instead uses
read-only simulation against the same ledger round for both programs. It compares
ordered logs, global/local deltas, recursive inner-transaction fields, box changes,
and final exported scratch when the trace exposes them. Foreign-box owner
identity and application-parameter changes remain unobserved and therefore
inconclusive. One atomic group establishes an app, its funded account, and state
before subsequent calls. Both variants use identical inputs apart from initial
approval code; repeated calls have distinct matching transaction notes. Group
hashes and the initial approval bytes are excluded from effect comparison,
while other transaction fields and installed update code remain observable.
The current backend emits at least AVM 10.

The scheduled/manual workflow pins the official go-algorand 5.0 image by digest,
uses a disposable private network bound to localhost, and installs the locked
`behavioral` SDK extra. Its 16 runtime tests cover creation, global state across
calls, box write/read/delete, inner payments, group fields, exported scratch,
opt-in/close-out/clear/update/delete transitions, and numeric loops/calls. Expected
logs independently check concrete values, including stride 12, multiple returns,
frame replacement, and wide-arithmetic caller residuals. Deliberately changed
state must diverge. The fixtures never submit a transaction.
The workflow also runs nine assembler differential checks; the combined 25-test
command passed locally. The external evaluation adds six original/lifted
assembly checks. This does not establish equivalence for arbitrary initial
ledger state, unsupported effects, or unexecuted input paths.

```sh
uv sync --locked --extra dev --extra lift --extra behavioral
TEALQL_LOCALNET=1 ALGOD_ADDRESS=http://127.0.0.1:41980 \
  TEAL_ALGOD_LOCAL=http://127.0.0.1:41980 \
  uv run pytest tests/test_behavioral_localnet.py tests/test_assembler_differential.py -q
```

When the gate is explicitly enabled, unavailable infrastructure is a failure.
Normal hermetic runs skip the runtime tests. The workflow supplies the node setup
and cleanup; existing public networks and accounts are not used.
