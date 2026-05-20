# Missing RekeyTo Validation

**Severity:** high · **Applies to:** application & logicsig

## What it looks for

A contract with at least one approval exit that doesn't validate `txn RekeyTo` against the zero address. When `RekeyTo` is set to a non-zero address, the AVM permanently rebinds the signing key of the spending account to that address — an attacker can effectively steal an escrow account, a delegated LogicSig, or a stateful contract's controllable address with one well-crafted transaction.

## How it works

**Per-exit path-aware form** — unlike the strict-dominance detections, this one flags *each* unprotected approval exit individually. An approval exit is "protected" when one of the dominating branch predicates (along every CFG path from entry to the exit) constrains `RekeyTo` to zero. A program with three approving paths, two of which check `RekeyTo` and one of which doesn't, produces one finding pointing at the unprotected path.

This shape lets the detector handle realistic dispatch tables that route different OnCompletion values down different branches, with `RekeyTo` checks only in the branches that actually need them.

## Files

- `rekey_to.py` — Python port. Builds `PathPredicateAnalysis(prog)` and checks each approval exit's dominating predicates for a `RekeyTo == 0` (or `== ZeroAddress`) constraint.
- Subdirectories `direct/`, `callsub/`, `proto-sub/`, `scratch-space/`, `partial-branch/`, `false-path-approves/` — fixture taxonomies covering each control-flow shape the path-aware analysis must handle (direct checks, checks behind subroutines, proto-sub args, scratch slots, partial-branch coverage, and cases where the *false* branch of a check is the approving one).
- `gabe_vuln.teal` / `gabe_fixed.teal` — DevRel real-world pair.
