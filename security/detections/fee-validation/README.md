# Missing Fee Validation

**Severity:** high · **Applies to:** logicsig (primarily)

## What it looks for

A LogicSig that doesn't bound `txn Fee`. Without an upper bound on the fee, an attacker can submit transactions signed by the LogicSig with absurdly inflated fees (up to the account balance), draining the spending account through fee extraction rather than the payment amount.

## How it works

**Anywhere-checked form** — the program just has to compare `Fee` against *some* value *somewhere*. Path-aware variants (per-OnCompletion fee bounds) aren't required for the check to pass.

## Files

- `fee_validation.py` — Python port. Walks `prog.assignments` for any comparison opcode whose inputs include a `txn Fee` read.
- `*.teal` — fixtures: `gabe_vuln.teal` / `gabe_fixed.teal` (DevRel real-world pair), `vuln-branch-skip.teal` (per-branch fee check fails the anywhere requirement only if the path is conditionally dead), `vuln-subroutine-dead.teal` (fee check in dead code), `fixed-callsub.teal` (fee check in a live subroutine).
