---
name: tealql-security
description: >-
  Analyze TEAL / Algorand smart contracts for security with the `tealql` toolkit.
  Use when asked to find vulnerabilities, taint flows, dangerous sinks, or attack
  surface in a .teal file (or a PuyaPy/TealScript contract compiled to TEAL) —
  e.g. "what dangerous sinks can this input reach?", "is this fund transfer
  guarded?", "what's the attack surface?", "which attacker inputs reach this
  state write?". Also for structural recovery (ABI methods, storage schema, group
  shape) on compiled Algorand apps.
---

# tealql — TEAL/Algorand security analysis

`tealql` is a pure-Python static-analysis toolkit for Algorand TEAL. It
reconstructs SSA from raw `.teal` (no source needed) and lifts it to a
Puya-shaped IR — the lift itself is dependency-free; only the *typed* audits
(`abi-audit`, `box-audit`, `storage-schema`) need the `puya` package. Invoke the
CLI as `python -m tealql.cli.main <command>` (or `tealql <command>` if
installed). Most commands take a TARGET: a `.teal` file or a directory of them
(one program per directory). Every command accepts `--json`.

**Key mental model.** A contract runs inside an atomic group; an external caller
(the *attacker*) controls this txn's `ApplicationArgs`, all *sibling* group txns
(`gtxn N …`), and the sender. A finding is real only if attacker-controlled data
reaches a **dangerous sink** *without being validated*. Taint reachability tells
you the first half; guard reasoning (the detectors) tells you the second.

## Answering "dangerous sinks for a source" — use `taint-query`

This is the open query layer: taint reachability from attacker inputs to
dangerous sinks, classified by category + severity.

```
# every dangerous sink an attacker input can reach (the attack surface):
tealql taint-query app.teal

# sinks reachable from a specific TEAL line (a source):
tealql taint-query app.teal --from 158

# sinks reachable from a HIGH-LEVEL source line (PuyaPy/TealScript), via the
# compiler's `// contract.py:N` comments in the TEAL:
tealql taint-query app.teal --from-src contract.py:42

# who can steer this sink? (attacker inputs reaching a sink line):
tealql taint-query app.teal --to 904

# inventories:
tealql taint-query app.teal --sinks      # every dangerous sink + severity
tealql taint-query app.teal --sources    # every attacker input
```

Output lines look like:
`[HIGH] app.teal:9  inner-payment-receiver  itxn_field Receiver  <- contract.py:105`
— severity, TEAL location, category, the op, and (when a source map exists) the
high-level line it compiled from.

**Sink categories** (severity): inner-txn `CloseRemainderTo`/`AssetCloseTo`/
`RekeyTo` (critical), `Receiver`/`AssetReceiver`/`ApplicationID`/`XferAsset`/asset-
admin/freeze fields (high), `Amount`/`AssetAmount`/`Fee` (medium); `app_global_put`/
`app_local_put`/box writes — the KEY (high), `box_del` (medium); `log` (low).

**IMPORTANT — over-approximation.** A reachable sink is *not* necessarily
exploitable: the taint may be validated (a receiver pinned to the app, a sender
gate) before reaching it. Plain `taint-query` is a **triage lens**, not a
verdict. Two flags close the gap:

### `--precise` — IR-backed reachability

The default reachability is a coarse SSA def-use graph: fast, but it both
invents phantom def-use edges AND misses flows across subroutine calls.
`--precise` re-runs reachability over the lifted IR (reaching-def / scratch /
interprocedural summaries — the same engine the `ir-*` detectors use), so it is
sharper *and* more complete. No downside beyond lift time (ms → ~300ms on a
large contract); if the contract doesn't lift it silently falls back to coarse.
Still guard-blind.

### `--verify` — one-shot guard-aware verdict

For every attacker-reachable sink, runs the matching guard-aware detector once
and labels the sink:

* **CONFIRMED** — a detector flags it (a likely-real *unguarded* flow);
* **guarded** — a detector that covers this sink category ran and did *not* flag
  it (its sender-auth / receiver-pin / group-index reasoning cleared the reach);
* **unverified** — no detector covers this category yet (reachable, unjudged).

```
# the recommended one-shot for a single contract — sharpest sink set, each with
# a verdict, CONFIRMED first (the two share a single lift):
tealql taint-query app.teal --precise --verify
```

Prefer this over eyeballing `taint-query` output against a separate
`detections` run.

## Verdicts — the fixed detectors

```
tealql detections app.teal --all --mode app   # every detector that applies to an app
tealql detections app.teal --detector ir-tainted-fund-flow
tealql detections --list                      # names of all ~36 detectors
tealql detections-scan ./contracts/ --json    # recursively scan a tree
```

Detectors encode both the sink AND the guard reasoning (sender auth, receiver
pins, group-index pinning, type exclusion), so their findings are verdicts, not
just reachability. Notable ones: `ir-tainted-fund-flow` (attacker input → inner
payment/close/rekey, guard-aware), `unvalidated-group-sibling` (trusts a sibling
transfer's value without pinning its receiver), `rekey-to` / `close-remainder-to`
/ `asset-close-to` (delegated-lsig drain fields), `ir-tainted-state-write`
(attacker picks a state-write key).

**Mode matters.** Several detectors only make sense for a delegated LogicSig
(`applies_to=logicsig`); running them on an app is meaningless noise. Pass
`--mode app` or `--mode logicsig` with `--all` (or a `--config` with globs for
scans) so only applicable detectors run.

Two typed audits complement the detectors when `puya` is installed:

```
tealql abi-audit app.teal   # caller-supplied arc4.Address paid to a fund/asset
                            # sink unguarded (ABI-type-driven)
tealql box-audit app.teal   # address-keyed BoxMap not bound to txn Sender =
                            # cross-user box access
```

## Structural recovery & recon (compiled apps)

```
tealql methods app.teal              # ABI method table (name/args/selector)
tealql methods app.teal --arc56 app.arc56.json   # authoritative, from a spec
tealql arc56 app.arc56.json          # ingest an ARC-56 app spec
tealql storage-schema app.teal       # global/local/box keys + recovered types (needs puya)
tealql group-shape app.teal --per-exit   # the group shape(s) the contract forces
tealql group-layout app.teal         # forced group size + per-position layout
tealql itxn-report app.teal          # every inner transaction the app can send
tealql auth app.teal                 # state-mutating ops + the path predicates
                                     # dominating them (exit 1 if any unguarded)
tealql box-df app.teal --flavour into        # box dataflow; also: out, correlated
tealql dump app.teal                 # every representation (debug)
```

## Cross-contract / group analysis

```
# taint across an atomic group (members IN ORDER; shared scratch + logs):
tealql group-taint m0.teal m1.teal

# follow inner appcalls into callee contracts; registry maps AppID -> .teal,
# or --from-chain fetches deployed callees (transitive, cached):
tealql xcontract app.teal --registry registry.yaml --detections
tealql xcontract app.teal --from-chain --detections
```

## Python API (for deeper / composed analysis)

```python
from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.dataflow.taint_query import TaintQuery

prog = SSAProgram("app.teal")                 # reconstruct SSA from raw TEAL
q = TaintQuery(prog)
for hit in q.sinks_from(op="txna", immediates="ApplicationArgs 1"):
    print(hit.category, hit.severity, hit.location, hit.source)
for hit in q.tainted_sinks(precise=True):     # attack surface (IR-backed)
    ...
q.sources_of(line=904)                        # backward: who reaches this sink

# one-shot: reachable sinks + guard-aware verdict (CONFIRMED / GUARDED / UNVERIFIED):
from tealql.security.sink_verdict import verify_sinks
for v in verify_sinks(prog, precise=True):
    print(v.verdict, v.sink.render(), v.confirmed_by)

# run a specific detector:
from tealql.security import DETECTORS
findings = DETECTORS["ir-tainted-fund-flow"](prog, file="app.teal").detect()
```

Other useful modules: `tealql.tealtools.group_reasoning` (`analyze`,
`analyze_per_exit`, `constraints_at` — what group shape / GroupIndex a contract
forces), `tealql.tealtools.dataflow.bounds` (`check_bounds` — in-bounds proofs for
`extract`/`substring`), `tealql.tealtools.arc56` (`load` an ARC-56 spec),
`tealql.tealtools.source_map` (`source_map_for` — TEAL ↔ high-level lines).

## Workflow for a free-form question

1. **Locate.** If the user names a high-level line, `taint-query --from-src` (or
   `source_map_for` to resolve it to TEAL lines). If a TEAL line, `--from`.
2. **Reach + verify.** `taint-query --precise --verify` gives the sharpest
   reachable-sink set, each with a CONFIRMED / guarded / unverified verdict.
   For a *specific* source→sink question use `--from`/`--to` (coarse,
   guard-blind) and then the matching `detections --detector …`.
3. **Read the flagged code** to confirm — reachability over-approximates, and
   detectors can be wrong in both directions.
4. **Report** in the user's terms: use the high-level source line from the sink's
   `source` field when available.
