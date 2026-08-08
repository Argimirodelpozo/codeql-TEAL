# The pipeline: what a TEAL file becomes, stage by stage

Every arrow is a distinct representation with its own owner module. Stages 1–4
are the *extractor floor*, 5–7 the *analysis substrate* detectors read, 8–10 the
*lift* proper.

```
bytes → AstNode list → CFG tuples → nx graph → SSAProgram → (PySSA)
      → annotated SSA → pre-IR → puya.ir.models → TEAL
```

## 1. Raw bytes — `graph.py`

`_load_source_bytes()` accepts a `.teal` file, a directory of them, or an
in-memory `{name: text}` mapping (no filesystem). `_normalize_pseudo_ops()`
rewrites `byte` / `method` / `addr` pseudo-ops line-by-line first, so the
grammar only ever sees canonical forms.

## 2. `list[AstNode]` — `ast/parse.py:parse_nodes()`

A tree-sitter C grammar produces a CST that is consumed immediately and thrown
away. What survives is one typed node per opcode line — `BnzOpcode`,
`IntegerAddOpcode`, … resolved through the mnemonic registry in `ast/ast.py` —
plus `Label` nodes and a single `Source` container spanning the whole file.

- **Identity is `(file, start_line)`.** One instruction per line is
  architectural, not stylistic: SSAVar identity, the scratch/cost indexes and
  every finding are keyed by it. `int 1; int 2` on one line collapses and is
  reported as a `ParseDiagnostic`.
- `Source` is the one node that is *not* a line, so it opts out of location
  identity (`AstNode.location_identity = False`); otherwise it compares equal to
  whatever sits on line 1 and displaces it from the graph.
- Anything the grammar dropped surfaces as `ParseDiagnostic`, never silently.

## 3. CFG facts — `cfg/build.py`

Converts AstNodes into an internal `_Node` view (`_children()`), then
`_program_cfg()` computes candidate edges plus a reachability fixpoint that
gates each `retsub`'s return edges on its `callsub` being live. Output is
`(edges, blocks)` as plain tuples via `build_cfg()`.

This is the floor: it runs *before* any SSA exists and imports nothing else from
the toolkit. Three successor labels exist — `normal`, `true`, `false` — read
only by the DOT renderer and the golden fixtures; guard reasoning re-derives
polarity itself in `path_predicates.py`.

## 4. `nx.MultiDiGraph` — `graph.py:load_graph()`

Nodes are the AstNodes; edges carry `kind="cfg"` and a `successor` label; each
node gets `bb=(file, first_line, last_line)`. Then
`const_values.py:compute_const_values()` attaches `const_outputs` and the
single-output `const_value`.

This is the boundary CodeQL used to own — the `nodes` / `cfgEdges` /
`basicBlocks` relations, now pure Python.

## 5. `SSAProgram` — `ssa/program.py:_build_from_graph()`

The public IR everything downstream reads. Dataclasses live in `ssa/models.py`
(`Assignment`, `SSAVar`, `Phi`, `BasicBlock`, `Const`, `IntRange`, `Location`).

- **Pass 1** — one `Assignment` per opcode, outputs sized by
  `avm.py:op_arity()`. Unknown opcodes are recorded on `prog.unknown_ops` and
  refused under `strict`.
- **Pass 2** — basic-block predecessor/successor wiring.
- **Pass 3** — labels, for rendering only.

## 6. PySSA (private) — `ssa/ssa.py`

Braun on-demand SSA construction over `ssa/stacksim.py` (the only stack
simulator), with `frame_band.py` and `callee_effects.py` handling subroutine
frames. `_apply_pyssa_to()` then rebuilds the public `SSAVar` / `Phi` /
`BasicBlock` objects from the private ones.

> **Gotcha:** that rebuild *replaces every BasicBlock instance*. State attached
> to a block during graph construction is silently discarded — which is why
> off-end exits are recorded on `SSAProgram.off_end_exits`, keyed by bb id. The
> same replacement also has to carry assignment literals and program-level
> branch/unknown-op metadata explicitly; boundary regressions are pinned in
> `tests/test_structural_ir_boundaries.py`.

## 7. Annotated SSA — `passes/orchestrate.py:run_all_passes()`

Layers facts *onto* the same SSA, in an order that is a precondition chain, not
a preference: value flow first (constants, scratch, inputs), then annotations
(ranges, byte lengths, frame resolution, stack shuffles), then structural
cleanup last. Every pass is idempotent — callers re-run the pipeline freely.

Analyses read from here: `dataflow/` (taint, byte-taint, bounds), `cfg/cfg.py`
(dominance, reachability, exits), `structure.py`, `subroutines.py`,
`path_predicates.py`, and the `security/` detectors.

## 8. Pre-IR — `lift/lift.py:_Lifter` + `lift/pre_ir.py`

Puya-shaped but **mutable**, because `lift/type_recovery.py` recovers types by
fixpoint: registers are born `?` and refined in place, which Puya's frozen
`Register` (with no unknown `IRType`) cannot express. This layer stays
puya-free so detectors can use it.

One `pre_ir.Program` represents exactly one AVM execution. A directory-backed
`SSAProgram` is a collection, so callers project it with `prog.for_file(file)`
(the detector caches do this automatically). `_Lifter` exposes the many-to-many
`register_sources` relation rather than asking analyses to invert its historical
primary `regs` map. After all transforms, `pre_ir.assert_well_formed()` checks
block ownership/targets, phi coverage, register identity, invoke targets, and
return arity before any IR detector consumes the result.

## 9. Real Puya IR — `lift/to_puya_ir.py`

Lowers already-validated pre-IR into genuine `puya.ir.models`, then validates
and optimises it with Puya's own passes. Structural repairs that affect detector
semantics (for example duplicating a cross-routine pure reject sink) happen in
pre-IR transforms, not for the first time here. This is the only module on this
path that imports `puya`, hence the lazy export in `lift/__init__.py`.

## 10. Back to TEAL — `lift/backend.py:lift_to_teal()`

Continues through Puya's own backend: split ValueTuples → destructure SSA → MIR
→ TEAL. This is what makes the disassemble → lift → recompile → dryrun
differential possible.

## Side channels

Three optional enrichers read the **raw text**, not the parsed nodes (the parser
strips comments):

| Module | Reads | Gives |
|---|---|---|
| `source_map.py` | `// contract.py:26` comments | TEAL line → source line |
| `abi.py` | `// method "sig"` comments, `method` ops | signatures, per-method line ranges |
| `arc56.py` | ARC-56 JSON app spec | methods, struct types, state/box schema |

All optional: raw or hand-written TEAL yields an empty map and consumers degrade
to TEAL lines only.

---

# Open question 1: are comments a dumb way to get a source map?

**Puya does emit real source maps.** Verified by compiling a sample contract:
`puyapy --output-source-map` produces `C.approval.puya.map`, a standard
JS-style sourcemap:

```json
{"version": 3, "sources": ["../contract.py"], "mappings": ";AAEA;;AAAA;…",
 "op_pc_offset": 0, "pc_events": {…}}
```

So the artifact exists. Three reasons the comment scan is still the right
default, and one place where the map genuinely wins:

1. **It is PC-keyed; we are line-keyed.** Every identity in this codebase is
   `(file, line)` over a TEAL text we often disassembled ourselves, whose line
   numbering has no relation to the compiler's program counters. Using a
   `.puya.map` means first establishing PC ↔ our-line alignment — that is the
   hard part, not the mapping.
2. **It is a build artifact.** The primary use case is pulling bytecode from
   algod and disassembling it. No `.map`, and no comments either.
3. **Where the map exists, the comments exist too** — same build, and they ride
   inside the one file the user already hands us rather than a second file they
   must remember to pass.

**Where the map wins: precision.** `source_map.py` assigns each TEAL line to the
*nearest preceding* `// file.py:N` comment. That smears across ops the compiler
could attribute exactly. If a `.puya.map` is present, ingesting it would be a
real upgrade for the local-build case, with the comment scan as fallback —
additive, not a replacement.

**Correction worth recording:** ARC-56's `sourceInfo` is *not* a source map. It
is error attribution by PC:

```json
{"sourceInfo": [{"pc": [46, 55],
                 "errorMessage": "invalid number of bytes for arc4.uint64"}],
 "pcOffsetMethod": "none"}
```

The related question is already settled the right way: for ABI methods and state
schema we prefer the structured artifact (`arc56.py`) and treat `// method "sig"`
comments as fallback enrichment. We never reverse a selector — it is a hash.

---

# Open question 2: is `kind="cfg"` necessary?

**Measured: no, not today.** Loading 60 real mainnet contracts and collecting
every edge attribute yields exactly one kind:

```
edge kinds present in a loaded graph (60 real contracts): {'cfg'}
```

`load_graph()` has a single `add_edge` call and it always passes `kind="cfg"`.
The other graphs with typed edges are **separate objects**:
`ssa/render.py:data_graph()` builds its own `nx.MultiDiGraph` with
`def` / `use` / `phi_in` edges, and the `dataflow/` taint graphs use a different
attribute entirely (`kinds`, a set). Nothing ever merges them into the loaded
graph.

So all 8 `if data.get("kind") != "cfg": continue` sites are no-ops, and two
comments actively mislead — `_forward_through_empty` warns that "a data edge
would forward to a block control never reaches from here", describing a hazard
that cannot occur in this graph.

It reads as a CodeQL-era vestige, from when one relation table held several edge
kinds. Two defensible options:

- **Remove** the attribute and the filters — simplest, and stops implying a
  distinction that does not exist. Touches 8 sites plus one test.
- **Keep** it as cheap insurance for a future merged graph, but fix the comments
  so they stop describing data edges as a live possibility.

Recommendation: keep the attribute (it is one keyword on one call, and the graph
is a semi-public artifact), drop the misleading comments. Not worth churning 8
call sites for a `dict.get` that costs nothing.
