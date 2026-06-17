# SSA phi-construction perf — plan

> ## ⚠️ MEASURED 2026-06-16 — original trivial-phi hypothesis is WRONG
>
> Profiled `SSAProgram(db)` on the python backend (graph-load is now ~ms, so
> this is pure SSA):
>
> | DB | SSA time | raw phis (post-phase4) | final phis | trivial (≤1 leaf) |
> |----|---------:|-----------------------:|-----------:|------------------:|
> | xgov | **7.3 s** | 77,023 | 12,002 | 191 (0.2%) |
> | folks-v3 | **12.1 s** | 159,818 | 36,114 | 635 (0.4%) |
>
> **Correction (the "99.6% non-trivial" was a measurement bug):** that used
> transitive *leaf* count. Braun's actual trivial test is *distinct-arg*
> count, and by THAT metric **74% (xgov) / 83% (folks-v3) of phis ARE
> trivial** — exactly the single-predecessor copy-phis (71–81% of phis sit on
> single-pred blocks). So trivial-phi elimination very much applies.
>
> ## PROTOTYPED 2026-06-16 — on-demand join-only placement WINS
>
> Two gated prototypes (both keep the lift faithful — Tier-1/2 AND Tier-3
> backend-lowering to real TEAL pass on all 5 real contracts):
>
> - `TEAL_SSA_TRIVIAL_ELIM` — post-hoc trivial-phi removal after phase 6.
>   Correct, kills the 12.4 s collapse, but only **1.2×**: you still pay to
>   *create* all 160k in phase 4 AND to *walk* them in the elim pass.
> - `TEAL_SSA_JOIN_ONLY` (`_phase34_join_only`) — **the winner.** Replaces
>   eager phase 3+4: create a phi ONLY at join blocks (≥2 preds), threading
>   values through single-pred chains (whose entry phase 6 already
>   reconstructs from the pred's exit stack). Never creates the ~75%
>   single-pred copies.
>
>   | | xgov | folks-v3 |
>   |--|--|--|
>   | SSA speedup | **2.5×** | **4.3×** |
>   | final phis | 12k→6k | 36k→**1027** |
>   | Tier-3 lift→TEAL | ✅ | ✅ |
>
>   Mechanism: a value `X` at `from_b`'s exit slot `eslot` flows to each succ
>   at the same top-first entry slot; at a JOIN it's an arg of
>   `phi(s,eslot)` (created on first touch, then propagated by its own
>   survival); through a SINGLE-pred block it threads to `L+eslot-C` carrying
>   the original value — no phi. Seed = each block's surviving locals.
>
> **DONE (promoted to default).** `_phase34_join_only` is now the default phi
> placement; eager is behind `TEAL_SSA_EAGER_PHIS` as an A/B oracle; the
> trivial-elim prototype is retired. Behavioural equivalence to eager verified
> on **35 real mainnet contracts** (live-localnet dryrun, identical
> approve/reject on 678 input×OnComplete combos; the one divergence is a
> pre-existing eager lift gap, not join-only). Only `loop_frame_dig`'s phi-count
> snapshot changed (1000→0). The original write-up below is the background; the
> implemented win is join-only.
>
> **Where the 12.1 s goes** (folks-v3, cProfile ≈2.3× real):
> - `_collapse_phi_args_to_leaves` (ssa.py:687) — **12.4 s / 43%** (SCC
>   condensation over the full ~160k-phi arg-DAG; already micro-optimized)
> - `_phase4_indirect_propagation` — 4.9 s (creates the explosion)
> - `_drop_unconsumed_phis` + `_phase8_live_filter` — ~4 s
>
> **The actual shape of the waste:** phase 3/4 place a phi at *every stack
> slot of every block* (the `[1..STACK_MAX]` indirect space). Of ~160k raw
> phis, only ~36k are *directly* consumed by an op input; the other ~124k are
> **intermediate nodes in the phi-arg DAG** that `_collapse_phi_args_to_leaves`
> needs for connectivity and then discards (after collapse flattens args to
> SSAVar leaves, `_drop_unconsumed_phis`'s transitive walk is a no-op — only
> the 36k directly-consumed survive). They can't be pruned *before* collapse.
>
> **Correct lever = demand/liveness-driven placement.** Only create/propagate
> a phi for slot `k` at block `b` if slot `k` is actually *read* on some
> forward path from `b` (a backward liveness over stack slots, computable from
> the per-block `_consumed`/`_locals` counts already in phase 2 + the CFG).
> That shrinks the 160k toward ~36k **at creation**, cutting phase 4, the 12.4 s
> collapse, AND both liveness passes proportionally — plausibly a 3–4× SSA
> speedup. This is Braun's *on-demand* half (`readVariableRecursive` only fires
> on a real read), NOT the trivial-removal half. Braun is still the right
> framework; just the on-demand reading, not the trivial elimination, is what
> pays here.
>
> **Revised sequencing:**
> 1. Prototype **slot-liveness gating** in phase 3/4 (don't place a phi for a
>    slot no live path reads). Measure raw-phi count + SSA time on xgov/folks-v3.
>    Smaller blast radius than a full Braun rewrite, attacks the root.
> 2. If that lands the win, stop. Else do the full on-demand Braun construction
>    (below), which subsumes it.
> 3. Gate everything on `test_lift_semantics` + the new graph-equivalence /
>    snapshot tests — faithfulness over speed.
>
> The original write-up below is kept for the algorithm mechanics; read
> "trivial-phi" as "unread-slot phi" throughout.

---

# Braun-style SSA construction for PySSA

Plan to replace PySSA's *maximal-SSA-then-prune* phi construction with
on-demand, trivial-phi-eliminating construction (Braun et al. 2013,
"Simple and Efficient Construction of Static Single Assignment Form").

Goal: cut SSA construction time (currently **17–40s**, the dominant cost in
the pipeline) by never creating the ~100k trivial phis that today's eager
placement manufactures and then prunes.

---

## 1. Why the current approach is slow

`ssa.py` (`class PySSA`) builds SSA as **maximal SSA, then prune**:

- **Phase 3 `_phase3_direct_placement`** — for every stack slot that survives
  a block, create a phi at *every* successor. Phis everywhere, eagerly.
- **Phase 4 `_phase4_indirect_propagation`** — worklist that forward-propagates
  each phi to successor phis via `_phi_node_exit_index` (`L + k - C`), to
  fixpoint.
- **Phase 6 `_phase6_sim_blocks`** — per-BB stack sim filling `op.inputs` /
  `exit_stack`; builds `entry_stack` from placed phis.
- **Phase 8 `_phase8_live_filter`** + `_drop_unconsumed_phis` +
  `_collapse_phi_args_to_leaves` — prune phis nobody references.

The killer is phase 4. Its own phase-6 comment names it: *"once a contract
hits the `[1..STACK_MAX]` indirect-phi space (phis number 100k+)."* On a loop
carrying a deep constant stack, a phi is created for slots `1..1000` and
churned around the back-edge.

**Key fact about TEAL:** a loop mutates only the top few stack slots; deep
slots carry the *same value from every predecessor*. So almost all of those
100k phis are **trivial** (a phi whose args are all one value), created only
to be pruned. We pay to build and propagate garbage.

Per-block stack facts we already compute in **phase 2** (`_phase2_arities`)
and will reuse:
- `_consumed[b]` = `C`, args consumed below the block's own stack.
- `_locals[b]`   = `L`, locals left on the stack at block exit.
- `_surv[b]`     = `[(survivor_PyVar, outStackOrder)]`, top-first 1-based.

Slot bookkeeping is **top-first, 1-based**; a phi at entry slot `k` exits at
`L + k - C` (`_phi_node_exit_index`), or is consumed when `k <= C`.

---

## 2. The Braun algorithm, specialized to PySSA

Braun constructs SSA on demand and removes trivial phis *at creation time*:

- Materialize a phi for a slot only when an instruction actually **reads**
  that slot at a join.
- Reading a slot recurses into predecessors. If they all agree → **no phi**,
  use the value directly. A freshly built phi whose args are all identical
  (or self + one other) is **trivial** → removed immediately, its uses
  forwarded to the unique operand (which may cascade-trivialize users).
- Back-edges handled by the "incomplete phi" + recursive trivial-removal
  trick (correct even for irreducible loops).

### Why this codebase is the *easy* case
1. The explosion we fight is exactly the trivial phis Braun never creates.
2. The per-block stack facts Braun needs already exist (phase 2). A read of
   entry slot `k` beyond the block's local defs is precisely the "look up
   predecessors" trigger.
3. **The whole CFG is known up front** (`cfg_build` + `_phase1_instantiate`),
   so every block is **sealed immediately** — we skip all incremental-IR
   bookkeeping (`sealBlock`, pending incomplete phis for not-yet-known preds).
   We are in Braun's filled+sealed special case.
4. It is the same rewrite as the *"CFG + SSA + stacksim in one pass"* idea:
   Braun *is* the fused CFG-walk + stack-sim + phi-construction.

### Specialization details
- **Variables** = stack slots, identified top-first 1-based per block (the
  existing `(bb_key, slot)` phi key space). Scratch slots are separate
  variables keyed by scratch index (today handled via `load_stores` / scratch
  passes — keep that path; Braun applies to the *stack* slot merges that
  cause the explosion).
- **`writeVariable(slot, block, value)`** / **`readVariable(slot, block)`**:
  within a block, the stack sim already knows the current top contents; a read
  of a slot defined in-block returns the local PyVar. A read of a slot that
  predates the block (entry slot `> L_local_defs`) becomes
  **`readVariableRecursive`**.
- **`readVariableRecursive(slot, block)`** (sealed-block path only):
  - 1 predecessor → `readVariable(slot_mapped, pred)` where `slot_mapped`
    is the pred-exit slot that feeds this entry slot (invert `L + k - C`).
  - ≥2 predecessors → create phi `P` at `(block, slot)`, **record it as the
    slot's def before recursing** (breaks cycles), fill
    `P.args = [readVariable(slot_mapped, p) for p in preds]`, then
    `tryRemoveTrivialPhi(P)`.
- **`tryRemoveTrivialPhi(P)`**: if `P.args` (ignoring self-refs) has a single
  distinct value `v`, replace all uses of `P` with `v`, drop `P`, and
  re-run `tryRemoveTrivialPhi` on any phi that used `P` (cascade). This is the
  whole win — the constant-stack-loop chain collapses to `v` and never reaches
  `1..1000`.

### Slot-mapping note (the one fiddly bit)
Today's forward map is `exit_slot = L + entry_k - C` (`_phi_node_exit_index`).
Braun reads *backwards*: given an entry slot `k` of block `b`, which exit slot
of predecessor `p` supplies it? It's the inverse along the edge: the value at
`b`'s entry slot `k` is `p`'s exit-stack slot `k` (entry stacks are aligned
top-first across an edge), i.e. `p.exit_stack[k]`. Validate this inversion
against the current direct/indirect placement on a small loop before scaling.

---

## 3. Two levers, ranked by risk

**Lever A — low-risk, ~80% of the win (do first):**
On-the-fly **trivial-phi collapse inside phase 4**. Before propagating a phi,
if it resolves to a single value, substitute that value instead of the phi.
The constant-stack-loop chain collapses cascade-style and never reaches
`1..1000`. Small, localized; keeps the pipeline and the QL-shaped phi set.
Likely cuts phi count 100k → hundreds. This de-risks Lever B and may suffice.

**Lever B — principled rewrite:**
Replace phases 3+4 (and fold in phase 6's sim) with Braun. Cleaner, gives the
one-pass fusion. **Risk:** Braun yields *minimal* SSA, which may differ from
QL's maximal-then-pruned phi set, so **parity + downstream passes are the
risk**. Mitigant: the existing prune passes already drive toward
referenced-only phis, so the *final* set may already be near-minimal — confirm
end-states match before committing.

---

## 4. Sequencing

1. **Profile first.** Confirm the 17–40s is in phase 4 (phi count), not phase
   6 sim or the QL load. (The phase-6 comment implies phase 4, but measure.)
   The win is "stop creating trivial phis" regardless of lever, so the cheap
   lever validates the diagnosis.
2. **Lever A** (trivial-collapse guard in phase 4). Re-measure phi count + wall
   time on the big DBs (xgov, folks-v3 — the ones that hit the loop space).
3. Decide: if A gets us there, stop. Else **Lever B** (Braun), gated by the
   SSA-shape parity harness (the lift semantics test + any phi-count
   invariants) — must stay green on all 5 real DBs + the puya corpus.

---

## 5. Guardrails

- **Don't put this in `ssa.py` if it can live beside it** — per project
  guidance, new layers go in their own module. Braun construction is core SSA
  though; if it must touch `ssa.py`, keep it as a swappable phase set behind
  `PySSA._construct` so A/B can be compared.
- **Faithfulness > speed.** The lift must stay behaviourally faithful (live
  localnet behavioural test) and IR-optimiser-clean (lift semantics test).
  A faster SSA that changes a single approve/reject is a regression, not a win.
- **Scratch stores are not dead** — Braun touches stack-slot phis only; leave
  the scratch (`gload`-readable cross-group) handling untouched.

---

## References
- M. Braun, S. Buchwald, S. Hack, R. Leißa, C. Mallon, A. Zwinkau,
  "Simple and Efficient Construction of Static Single Assignment Form,"
  CC 2013. (filled+sealed case; `readVariableRecursive`,
  `tryRemoveTrivialPhi`.)
- Cytron et al. 1991 (iterated dominance frontier) — the textbook alternative;
  rejected here because DF computation + per-slot def sites are more work than
  Braun's on-demand scheme for a stack machine with the CFG already in hand.
