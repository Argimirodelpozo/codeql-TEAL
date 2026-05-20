# Unsafe LogicSig Argument Usage

**Severity:** high · **Applies to:** logicsig

## What it looks for

A LogicSig that uses `arg N` (or `args`) opcodes as one side of an equality / inequality comparison. LogicSig args come from the calling transaction's `Args` field — i.e., they're attacker-controlled. Comparing an attacker-controlled value to a constant lets the attacker satisfy any equality precondition the LogicSig sets, sidestepping authorisation that depends on the comparison.

The correct pattern uses `txn Sender` (or fields covered by the AVM signature) for auth-relevant comparisons, not args.

## How it works

**Per-opcode finding** — every `arg N` (or `args`) read that flows into a comparison opcode (`==`, `!=`, `<`, `>`, `<=`, `>=`) is reported. The detection is data-flow-based: the arg's SSAVar has to actually be one of the comparison's input operands, not just appear in the same program.

## Files

- `unsafe_lsig_args.py` — Python port. Walks `prog.assignments` for `arg` / `args` ops and traces each output SSAVar's uses to find comparison-op consumers.
- `*.teal` — fixtures: `vuln.teal` / `fixed.teal` (canonical pair), `vuln-callsub.teal` (arg consumed by a comparison inside a subroutine), `vuln-nested-sub.teal` (arg passed through nested subs to the comparison), `vuln-branch-merge.teal` (arg used in a comparison after a CFG join).
