# TEAL static analysis and decompilation review

Reviewed revision `aa2eaa87`. Fix state-backed call target inference and the behavioral test verdict first. The former can direct analysis to the wrong contract. The latter can report success without a single completed comparison.

## 1. Make state-backed call target inference account for aliasing

In [intercontract/analysis.py](../src/tealql/tealtools/intercontract/analysis.py#L217), `_resolve_state_app_id` infers a single application ID when the constant writes it collects agree. For ordinary puts, it skips a write when none of its operands equals the tracked key. That condition also holds when the key is dynamic and the value is an integer. A constant write to a routing key followed by a write through an unknown key can therefore leave the first ID looking certain. The inferred ID feeds both call-site resolution and candidate discovery.

Decode the key and value by opcode and operand position. Distinguish a definite match, a definite mismatch and a possible alias. A possible alias with an incompatible or unknown value should invalidate a singleton target. Apply the same rule to partial writes and deletes, where the current scan can mistake a constant payload for evidence about the key. Keep an unresolved call-site record with its source location so consumers can distinguish incomplete traversal from a program with no app calls.

**Regression check.** Extend [the dynamic application ID tests](../tests/test_xcontract_dynamic_appid.py) with a known routing key plus a second write. A distinct literal key should preserve the inferred ID. An unknown key storing a different ID should leave the target unresolved.

## 2. Prevent empty or incomplete dryruns from certifying a lift

[compare.py](../tests/behavioral_lift/compare.py#L76) records a dryrun exception and continues. Its CLI labels a contract faithful whenever the divergence count is zero. The [corpus sweep](../tests/behavioral_lift/sweep_probes.py#L60) repeats that decision independently. Even when comparisons complete, both drivers derive selector inputs from the lifted program alone. A selector lost during recovery can disappear from the test inputs too.

Share one verdict function and count attempted, completed, errored, jointly approved and divergent cases. Any observed divergence should fail. An all-error run should be inconclusive, and a partly executed matrix should report incomplete coverage. Display reject-only agreement separately. Sample selectors from the original and lifted programs together, recording which were exercised. For successful calls, extend the current approval/log comparison to normalized state deltas where the runner exposes them.

**Regression check.** Stub the dryrun adapter for all-error, partial-error, reject-only and divergent runs. Include a selector present only in the original and a pair of approvals with identical logs but different state writes. These verdict tests can run without algod.

## 3. Preserve keyed dispatch when a match arm is also the default

In [lift/lift.py](../src/tealql/tealtools/lift/lift.py#L1297), `_control_match` identifies the default successor by subtracting all case targets from the successor set. When the block immediately after a multi-target match is also a named arm, that subtraction yields no default. Even with every literal key recovered, the caller then emits a positional branch with an undefined selector. This loses a known selector-to-body mapping in the decompiled IR. The neighboring switch implementation already resolves the fall-through from instruction order.

Share fall-through resolution across these terminators, preserving splice-site target mapping. Keep match arms ordered, including repeated destinations. **Regression check.** Use two nonconsecutive integer keys and two distinguishable result blocks, with the first result block serving as both a case and fall-through. Assert the keyed pre-IR shape and check the two hits plus a miss after lowering. Repeat with byte keys.

## 4. Track taint dependencies per subroutine return position

In [lift/taint.py](../src/tealql/tealtools/lift/taint.py#L245), the summary refinement loops over every returned value and merges all internal sources and parameter dependencies into one pair of sets per subroutine. A helper returning a constant and a caller-derived value consequently loses the distinction between those outputs at the call boundary. Downstream findings can attribute influence to the constant result.

Index the existing summary by return position. Union dependencies across return blocks at the same position, retain the current fixed-point propagation for nested calls, and apply each position's summary to its corresponding call result. **Regression check.** Route each output of a two-result helper to a separately observable use. Only the caller-derived result should inherit its input label. Reverse the return order and add a wrapper call to check positional wiring at both boundaries.

## 5. Make code generation repairs visible to API consumers

The [backend](../src/tealql/tealtools/lift/backend.py#L85) can recover from a missing register definition by inserting a typed zero, logging a warning and returning TEAL. Its MIR retry can search multiple subroutines for the same register name and version. A caller receiving TEAL needs to know whether that value came from the input or was synthesized by the backend.

Propagate a structured repair record through the existing diagnostics argument at both the SSA destruction and MIR retry sites. Include the stage, affected subroutine and register. Add an opt-in strict mode that stops at the first required substitution. **Regression check.** Exercise both repair paths with an orphan fixture, assert the affected registers in permissive diagnostics, and require strict mode to report the same first repair before emitting code. A repair-free fixture should produce identical TEAL in both modes.

## Review scope

This is a source review of call discovery, lifted taint, terminator reconstruction, backend repair and the behavioral comparison drivers. The proposed regression cases are acceptance criteria. No suite or localnet dryrun was executed, and the frequency of these conditions in the contract corpus was not measured.
