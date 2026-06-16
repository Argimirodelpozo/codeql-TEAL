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
