# To-read — static analysis research relevant to this project

A reading list mapped onto what this repo actually does (pure-Python TEAL → SSA →
Puya-IR lift → detectors + cross-contract + behavioural validation). Each entry
notes *why it matters here*. Algorand/TEAL has almost no dedicated academic work,
so nearly everything below is a **transfer** from EVM / Move / general program
analysis — which is also the opportunity.

---

## 0. Read this first — the closest architectural sibling

- **SlithIR / Slither** — Feist, Grieco, Groce, *WETSEB 2019*.
  A custom SSA IR lifted from EVM + a suite of ~90 detectors + printers.
  **Almost exactly our architecture.** Their SSA-IR design and detector catalog
  (and how they structure "find sink → check guard via dataflow") are the most
  directly transferable reference. *Tie-in:* `ssa/`, the `detections/` registry,
  the lift.

---

## 1. Declarative / dataflow foundations — our guard + taint layer

- **Securify** — Tsankov et al., *CCS 2018*.
  Vulnerabilities as **compliance vs violation patterns** over semantic dataflow
  facts (Datalog). A principled model of our "is this sink *guarded*?" question;
  resonates with the CodeQL origins. *Tie-in:* `auth_domination`,
  `tainted-fund-flow`, `path_predicates`.

- **IFDS / IDE** — Reps, Horwitz, Sagiv, *POPL 1995* / Sagiv, Reps, Horwitz,
  *TCS 1996*. "Precise interprocedural dataflow via graph reachability."
  *The* framework for the **taint-layer-split problem** — the principled version
  of the hand-rolled `_return_summary`, and the way to unify the IR-vs-SSA
  interprocedural taint gap. *Tie-in:* `lift/taint.py`,
  `tainted-fund-flow` (param-fed false-negative).

- **Abstract interpretation** — Cousot & Cousot, *POPL 1977*. Foundational;
  the lattice/fixpoint theory under the range / bytemath / taint passes.
  *Tie-in:* `analysis/_range_*`, `analysis/_bigints`.

- **Doop / declarative pointer analysis** — Bravenboer & Smaragdakis,
  *OOPSLA 2009*. Datalog-based, context-sensitive analysis; relevant to the
  QL origins and to any declarative reformulation.

---

## 2. Decompilation — the lift *is* a decompiler

- **Gigahorse** — Grech et al., *ICSE 2019*; and **Elipmoc** — Grech et al.,
  *OOPSLA 2022*. Declarative, **context-sensitive** decompilation of EVM
  bytecode to a structured IR. Our problem in another VM; the context-sensitivity
  is the path from one-hop to **multi-hop xcontract**. *Tie-in:* `lift/`,
  `xcontract`.

- **Retypd** — Noonan, Loginov, Cok, *PLDI 2016*. Constraint-based
  **type inference for decompilation** (sub-typing constraints). The gold-standard
  treatment of what `type_recovery.py` does heuristically — would make AVM-type
  recovery *sound* rather than evidence-tiered. *Tie-in:* `lift/type_recovery.py`.

- **MadMax** — Grech et al., *OOPSLA 2018*. Vulnerability detection (gas /
  overflow) *on top of* a decompiled IR. The model for "detect on the optimised
  IR." *Tie-in:* the IR-layer `fund_flow.py` + the optimised-IR detection idea.

- **"No More Gotos"** — Yakdan et al., *NDSS 2015*. Structural control-flow
  recovery (readable, goto-free output). Relevant if we ever emit
  Algorand-Python-like source for human triage.

---

## 3. Symbolic execution → witness generation (the flagged frontier)

- **teEther** — Krupp & Rossow, *USENIX Security 2018*.
  Symbolic-execution-driven **automatic exploit generation** — produces the
  concrete attack transaction. Exactly "turn a tainted-fund-flow finding into a
  solved exploit input." *Tie-in:* `tainted-fund-flow`, the benchmark.

- **Oyente** — Luu et al., *CCS 2016* (the seminal EVM symbolic executor).
- **Manticore** — Mossberg et al., *ASE 2019* (symbolic exec framework).
- **halmos** + **hevm / Kontrol** — Runtime Verification. Modern, lightweight
  **bounded symbolic execution as a property check** (Foundry-integrated); the
  pragmatic model for "bounded symbolic exec over the SSA."

---

## 4. Measurement — the field's playbook for the benchmark we just built

- **SmartBugs** — Durieux, Ferreira, Abreu, Cruz, *ICSE 2020*.
  A curated, **labeled** vulnerability dataset + a framework that runs *many*
  analyzers and compares them. The direct model for growing `tests/benchmark/`
  and for **differential testing vs Tealer**. *Tie-in:* `tests/test_benchmark.py`.

---

## 5. Formal verification — the long horizon

- **The Move Prover** — Zhong et al., *CAV 2020*. Spec-driven verification via
  Boogie + Z3 for the closest resource-oriented cousin language. The model for
  where `Puya IR → a verification IR` could go. *Tie-in:* the lift as a
  verification frontend.

- **Certora Prover** (industry) and **KEVM** (Hildenbrandt et al., *CSF 2018*) —
  formal EVM semantics + verification, for breadth.

---

## 6. Foundational SSA — what's already under the hood

- **Braun et al.** "Simple and Efficient Construction of SSA", *CC 2013* —
  was the constructor until 2026-08-03. Replaced by a forward per-routine stack
  simulation (`ssa/stacksim.py`), because a stack machine's "variable" is a slot
  whose identity depends on the DEPTH — a forward fact the on-demand backward
  walk had to import from a separate BFS. Braun's cycle handling survives
  though: hand out the phi before recursing, complete it after (`deferred`).
- **Boissinot et al.** "Revisiting Out-of-SSA Translation", *PLDI 2009* —
  the principled basis for out-of-SSA translation. `ssa/block_args.py` was a
  read-only view of it; `lift/to_puya_ir.py` superseded it and it is gone.
- **Cytron et al.** "Efficiently Computing SSA and the Control Dependence Graph",
  *TOPLAS 1991* — the classic dominance-frontier construction.

---

## 7. DeFi / economic security (the value-flow direction)

- **Flash Boys 2.0** — Daian et al., *S&P 2020*. MEV / value-extraction;
  background for modelling whether an attacker can extract net-positive funds.
- **Sailfish** — Bose et al., *S&P 2022*. State-inconsistency (reentrancy-style)
  bug detection via storage-dependency graphs; relevant to the unbuilt
  reentrancy / call-ordering xcontract direction.

---

## 8. LLM-assisted analysis (ride our near-source IR)

- **LLM4Decompile** — Tan et al., 2024. Neural decompilation; we already produce
  a near-source IR, an unusually good substrate.
- **GPTScan** — Sun et al., *ICSE 2024*. LLM + static analysis hybrid for
  smart-contract logic-bug detection; the model for LLM-assisted triage over
  the lifted IR.

---

## Highest-leverage matches to prototype next

1. **IFDS** (#1) → a unified, principled interprocedural taint that closes the
   IR-vs-SSA split (the `param-derived` / param-fed false-negative).
2. **Retypd** (#2) → sound, constraint-based AVM-type recovery.
3. **teEther / halmos** (#3) → a witness generator that turns a fund-flow finding
   into a concrete exploit transaction.
4. **SmartBugs** (#4) → grow the labeled benchmark + differential-test vs Tealer.

> The Algorand-specific gap is the opportunity: a rigorous TEAL decompiler +
> detector suite + behavioural-differential validation has no direct published
> counterpart. Most of the above is a *transfer*, not a reimplementation.
