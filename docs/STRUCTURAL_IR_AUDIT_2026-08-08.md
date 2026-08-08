# Structural IR audit — 2026-08-08

Scope: the representation spine from parsed graph through public/private SSA,
mutable pre-IR, and Puya IR. This is a follow-up to `AUDIT_2026-08-07.md`; it
concentrates on identity, ownership, metadata, and information preservation at
the arrows between representations rather than detector policy.

## Representation contracts

| Boundary | Contract checked |
|---|---|
| AST/CFG → graph | File-qualified node identity, labelled control edges, basic-block membership, disconnected program isolation, parse diagnostics. |
| graph → preliminary SSA | One assignment per opcode, correct stack arity, const-block literals, off-end exits, branch polarity, unknown-op evidence. |
| preliminary SSA → `PySSA` → public SSA | Replaced blocks/assignments preserve program metadata and literal annotations; definitions, uses, phi arms, and block edges refer to the rebuilt objects. |
| public SSA → pre-IR | Exactly one AVM execution per `Program`; globally unique block ids; one block owner; identity-consistent register defs/uses; complete phi predecessors; resolvable invokes; return arity. |
| transformed pre-IR → analyses | `_Lifter` and `Program` expose the same subroutines; all exact representation clones retain SSA provenance; aliases are many-to-many, not overwritten. |
| pre-IR → Puya IR | Every register and predecessor is defined by identity, refined byte facts hold for every alias, and no structural repair is deferred until after detector-facing analyses. |

The audit used adversarial unit programs, selected real mainnet probes, the
pass-firing ratchet, the 64-contract recompilation gate, and the existing Puya
validator/backend suites. The new `pre_ir.structural_errors()` checker is run at
the end of every lift, before a detector can consume malformed pre-IR.

## Fixed findings

### 1. Private SSA replacement dropped assignment constants

`_apply_pyssa_to()` replaces the preliminary `Assignment` objects. It preserved
the output variable's `const_value`, but discarded `Assignment.const` and the
original `ast_code`. Byte-length and bytemath propagation deliberately read the
assignment field, so a `bytec_0` could lose its exact length and integer range at
this boundary.

The rebuild now snapshots assignments by `(file, line)` and copies both fields.
The regression test proves a four-byte `bytec_0` retains length 4 and the exact
`0xdeadbeef` range after public SSA construction.

### 2. Exported `PySSA.build()` dropped program metadata

Normal construction mutates an existing `SSAProgram`, which happened to retain
`off_end_exits`, `edge_polarity`, and `unknown_ops`. The exported fresh-shell
`PySSA.build(prog)` path did not. A consumer using that API could therefore miss
a real exit or reconstruct a guard with less evidence even though the rendered
assignments looked identical.

Those properties are now explicit boundary snapshots. Parse diagnostics remain
attached through the preserved graph.

### 3. Return specialization cloned parameters and bodies separately

`specialize_polymorphic_returns()` deep-copied the parameter list separately
from the body. A body operand and its declared parameter consequently became two
distinct `Register` objects with the same printed id. Puya compared the printed
identity permissively enough for the program to lower, while identity-keyed
taint treated the body operand as an undefined clean look-alike.

The whole subroutine is now copied once with one memo. The clone's body operands
are the declared parameter objects, and clone-to-origin metadata preserves its
SSA annotations.

### 4. `_Lifter` exposed stale pre-transform subroutine views

Specialization appended clones to `pre_ir.Program.subroutines`, but
`_Lifter.subs` and `_Lifter.name2sub` still described the pre-transform list.
IR analyses iterating the lifter skipped specialized bodies and could not
resolve their invoke targets.

The views are synchronized after all transforms and an invariant test pins
object-for-object agreement.

### 5. The SSA/pre-IR bridge was incorrectly one-to-one

`lifter.regs` is a useful primary map but not a complete provenance relation:
frame parameters and locals live in `frame_map`, multiple SSA values can alias
one pre-IR register, and structural transforms create independent register
objects. Code that inverted `regs` silently kept only one alias.

The lifter now publishes:

- `register_objects`: every surviving pre-IR register by object identity;
- `register_sources`: every SSA source for each register, as a many-to-many
  relation;
- `Program.register_origins`: the origin of exact structural clones.

Scratch taint, byte taint, partial fund-flow, recovered lengths, and Puya byte
refinement now consume that relation. Exact byte lengths are emitted only when
every aliased SSA source proves the same value.

### 6. Multi-file SSA was silently lifted as one executable

A directory-backed `SSAProgram` is a collection of disconnected AVM programs.
Pre-IR has exactly one `main`, yet the old lift combined all directory blocks
under one synthetic main; line-only indexes also allowed equal line numbers in
different files to collide. The optional detector `file` argument was ignored.

`SSAProgram.source_files` and `SSAProgram.for_file()` now make the boundary
explicit. Direct lifting refuses a collection; `build_lifter(prog, file=...)`,
`ir_lifter`, and precise `TaintQuery` project and cache one independent program
per file. A single-file program retains its existing object and cache behavior.

### 7. A graph-ownership repair happened only during Puya lowering

Compiler-generated TEAL can share a pure reject sink between main and a
subroutine. `to_puya_ir` duplicated that sink just before creating Puya blocks,
so recompilation worked, but detector-facing pre-IR still contained a
cross-owner edge. The new structural checker found this on
`app_1850601905.teal`.

Pure shared-sink duplication now runs in `transforms.py` before validation and
analysis. The lowering helper remains as an idempotent compatibility wrapper.
Value-carrying cross-owner sinks are not guessed: they require real value/phi
splitting and fail the structural boundary instead.

### 8. Pre-IR had no independent well-formedness check

Puya validation is too late for IR detectors and does not reliably distinguish
two pre-IR objects with the same printed register id. The new checker verifies:

- unique subroutine and global block ids;
- non-empty routines and present terminators;
- existing, same-owner successor targets;
- exact phi/predecessor coverage with no duplicate arms;
- one definition per register object and no textual look-alike definitions;
- every register use defined in its owning routine;
- invoke targets and subroutine return arity.

Failures surface as `LiftError(stage="build")`, preserving the established
fallback behavior while making the precision loss visible.

### 9. In-memory IR findings could report `<memory>` instead of their file

IR findings now prefer the detector's selected file or the unique
`SSAProgram.source_files` identity before falling back to `source_path`.

### 10. Legacy negative frame reads were not counted as arguments

A pre-`proto` subroutine still has a frame anchored by `callsub`. Operations
such as `frame_dig -1` legally read the caller's stack, but legacy arity
inference counted only pop-induced stack dips. It inferred zero arguments and
the lift emitted an undefined `l%-1` local. The structural validator exposed the
gap in the existing hostile-totality fixture.

The shared SSA/lift arity fixpoint now includes the deepest negative frame slot
in the implicit argument band. Both stack simulation and pre-IR consequently
wire the read to the same declared parameter.

## Recommended next work

These are proposals, not changes in this branch, ordered by soundness leverage.

1. **Make program collections a different type.** `SSAProgramSet` (or equivalent)
   should own directory inputs and yield one `SSAProgram` per file. That removes
   the need for every single-entry consumer to remember the projection rule.
2. **Make provenance first-class in pre-IR.** Put stable origin ids on values,
   blocks, and invokes instead of maintaining side maps on `_Lifter`. This would
   let every transform state whether it preserves, combines, or synthesizes a
   value, and would survive serialization.
3. **Validate each structural transform in debug/tests.** Run a cheaper graph
   contract (ids, targets, phi coverage, ownership) before and after each pass,
   with the full register checker at the pipeline exit. This localizes a broken
   transform instead of reporting only the final malformed program.
4. **Introduce explicit value/type lattices.** Residual `?` currently lowers as
   `uint64`; a dynamically bytes-backed value can therefore be mistyped. Model
   `unknown`, `uint64`, `bytes`, and conflict explicitly, and refuse lowering a
   live unresolved conflict rather than choosing a family.
5. **Replace scratch reconstruction with memory SSA.** Scratch slots, dynamic
   `loads/stores`, and frame locals currently cross several bespoke reaching-def
   bridges. Per-slot memory SSA plus an explicit unknown-slot node would reduce
   duplicated logic across constant, boolean-taint, byte-taint, and lift passes.
6. **Ratchet graph and SSA invariants over the full probe corpus.** Persist only
   compact counts/hashes: programs, entries, exits, block/edge/phi counts,
   undefined uses, and transform firings. This catches structural drift without
   committing enormous rendered snapshots.
7. **Differential-test stack effects against the active AVM spec.** Generate a
   minimal legal use for each opcode/version and compare preliminary arity,
   `stacksim`, and assembler acceptance. A wrong effect corrupts every later SSA
   identity and deserves its own release gate.
8. **Add call-graph SCC summaries.** Current interprocedural passes have separate
   fixed points and recursion guards. One shared SCC ordering for taint, returns,
   and frame effects would reduce both duplicated code and inconsistent recursive
   behavior.
9. **Give mutable programs a revision.** Caches currently key on object identity.
   A monotonically increasing structural revision, included in cached analysis
   keys, would prevent stale dominance/taint/lift results after supported
   mutations.

## Residual risks

- Legal pre-`proto` subroutines are not necessarily functions. The lifter has a
  guarded per-call-site splice for divergent legacy bodies, but shapes outside
  those guards still degrade or refuse rather than claim a false signature.
- Some real-program registers remain type-unknown and Puya lowering still uses
  the documented `uint64` fallback. This is visible in warnings but remains the
  largest structural typing risk.
- Synthesized recovery values that are not exact clones intentionally have no
  SSA origin. Consumers must treat an uncovered value as unknown/tainted; the
  byte-taint adapter does so through `sink_tainted()`.
- `PySSA` remains importable despite being an implementation representation.
  Its metadata contract is now tested, but a narrower public surface would make
  replacement safer.

## Regression coverage added

`tests/test_structural_ir_boundaries.py` pins constant and metadata preservation,
clone identity/provenance, lifter/program synchronization, undefined look-alike
rejection, legacy-frame parameter wiring, and multi-file isolation/caching.
Existing byte-taint and lift tests now require frame-parameter coverage and
body/parameter identity in specialized clones. The shared-epilogue and
recompilation gates cover the ownership repair.

The frame provenance fix intentionally expands
`ir-partial-tainted-fund-flow` on the distinct mainnet corpus from 11 contracts
/ 22 findings to 15 / 26. The four additions are one `ApplicationArgs[2]` flow
each on `app_2645463331`, `app_3600022590`, `app_2300200702`, and
`app_2694165644`; there are no removals or changes to existing findings. The
committed findings digest records that reviewed behavior change.

## Validation performed

- `ruff check` and `compileall` pass.
- The post-update non-slow suite passes: 3,218 passed, 10 skipped, 9 deselected.
- A full run reached 3,226 passed / 10 skipped with one findings-ratchet failure;
  the failure was exactly the four reviewed additions above. A detector-only
  recomputation over all 231 distinct programs confirmed no removals or changed
  existing counts before the digest was updated.
- The 64-contract recompile gate passes, including the real shared-sink contract
  that the new ownership validator initially exposed.
- Focused graph/SSA invariants pass (1,843 tests), as do the frame-resolution,
  pass-firing, Puya compatibility, shared-epilogue, and structural-boundary
  suites.
