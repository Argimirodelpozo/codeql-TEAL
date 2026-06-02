# folks-finance test programs

Compiled TEAL for three real Folks Finance contracts, recovered from the old
`folks-finance-db` fixture's `src.zip`. `teal-compiled/` holds six programs —
the approval + clear pair for each of `consensus_v2`, `consensus_v3`, and
`xgov_registry`.

## ⚠️ The `teal-compiled/` sources are PATCHED (extractor workaround)

The prebuilt CodeQL TEAL extractor **silently drops the `int` / `byte` / `method`
assembler pseudo-ops** (it only emits nodes for `pushint` / `pushbytes` /
`intc*` / `bytec*`). The folks contracts were compiled with the pseudo-op forms,
so every constant they push — method selectors, OnCompletion enums, state keys,
the ARC4 return prefix — vanished from the extracted graph, starving the
method-dispatch `==`, `app_global_put`, and a `dupn`. The folks DBs could not be
lifted to a faithful SSA / Puya IR.

As the agreed interim workaround (2026-06-02), the approval `.teal` files were
rewritten in place: each pseudo-op is now its canonical equivalent
(`int NoOp` → `pushint 0`, `byte "k"` → `pushbytes 0x6b`,
`method "sig"` → `pushbytes 0x<sha512_256(sig)[:4]>`) and **tagged inline** with
`// [pseudo-op-patch] was: <original>`, so the rewrite is unmistakable and the
original is recoverable. The rewrite is semantically identical TEAL. Re-run /
regenerate with **`python3 test-projects/folks-finance/patch_pseudo_ops.py`**
(idempotent), then rebuild the DBs (below). The proper fix is rebuilding the
extractor to emit these pseudo-ops; this unblocks folks until then.

## Why these are separate DBs now

The original `tests/dbs/folks-finance-db` was built by extracting the whole
`teal-compiled/` directory at once, so it contained **all six programs in one
CodeQL database**. The analyzer (and the `WIP_lift2puyaIR` lift) is built for a
single program per DB — like every other fixture — so it treated the six as one
mixed program: one `main`, the other five programs' dispatch blocks orphaned
(unreachable from that single `main`), and the detectors analyzing six programs
as one. (The bundle was also a bloated 853 MB for ~460 blocks.)

Each **approval** program is now its own single-program DB (the three clear
programs are 1-block `int 1; return` stubs, omitted):

| DB (under `tests/dbs/`, gitignored) | program | blocks |
|---|---|---|
| `folks-consensus-v2-db`   | `consensus_v2_approval.teal`          |  43 |
| `folks-consensus-v3-db`   | `consensus_v3_approval.teal`          | 401 |
| `folks-xgov-registry-db`  | `xgov_registry_approval_program.teal` |  17 |

## Rebuilding a DB

`tests/dbs/*` are gitignored (large, locally built). Rebuild one program's DB by
pointing `codeql` at a directory containing only that `.teal`:

```sh
mkdir /tmp/one && cp teal-compiled/consensus_v3_approval.teal /tmp/one/
codeql database create tests/dbs/folks-consensus-v3-db \
    --overwrite -l teal -s /tmp/one \
    --search-path="$PWD/.codeql-extractors"
```
