/**
 * Constant propagation on top of the TEAL dataflow framework.
 *
 * Exports `tryAsInt`, which resolves an SSA variable to one or more
 * concrete compile-time integer values. Uses `LocalFlow::localFlow` to
 * propagate literal `IntegerConstant`s through every value-preserving
 * transformation the dataflow framework already understands: stack
 * manipulation opcodes, phi nodes, the scratch-slot bridge, the callsub
 * bridge. Arithmetic (`+`, `-`, `*`, `/`, `%`) is handled explicitly.
 *
 * ARCHITECTURAL NOTE. This module cannot live inside `SSA.qll` (as a
 * member predicate on `SSAVar`) because `Dataflow.qll` imports `SSA.qll`,
 * and the reverse import — which we need here, to call `localFlow` —
 * would create a module cycle. Placing this file in `dataflow/` sidesteps
 * the cycle entirely.
 *
 * FIELD-PROPAGATION NOTE. `SSAVar` has a non-unique field
 * `varInternalIndex`, which means CodeQL re-existentially-quantifies it
 * at every predicate boundary — so `v.getInternalOutputIndex()` inside a
 * predicate returns *every* valid index for the underlying AstNode, not
 * the specific one the caller had in hand. To avoid this trap we do all
 * the work in terms of the newtype branch `TSSAVar(idx, node)` directly:
 * `idx` is a plain int, so binding it at the destructure site carries the
 * specific output index through the rest of the predicate body.
 */

private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.ast.IntegerConstants
private import codeql.teal.dataflow.Dataflow

/**
 * Gets a concrete compile-time integer value for the value produced by
 * `def`, if one can be resolved.
 *
 * Multi-valued: if `def` could take several possible constant values (for
 * example a scratch-slot load whose slot is written by several different
 * stores on disjoint branches, or a subroutine return reachable from
 * several internal constants), every reachable value is returned. Callers
 * requiring a unique value should check `count(tryAsIntDef(def)) = 1`.
 *
 * See the field-propagation note at the top of this file for why we
 * destructure via `def = TSSAVar(idx, op)` rather than going through
 * `def.(SSAWriteDef).getVar().getInternalOutputIndex()`.
 */
int tryAsIntDef(Definition def) {
  // Base case: the opcode that produced `def` is a literal integer
  // constant (`int 5`, `intc 0`, `pushint 10`, etc.). `idx` must be 1
  // because integer constants produce exactly one output.
  exists(AstNode op |
    def = TSSAVar(1, op) and
    result = op.(IntegerConstant).getValue()
  )
  or
  // Pass-through case: some literal `IntegerConstant` flows to `def` via
  // strict `localFlow`. Strict flow only traverses identity-preserving
  // steps (stack manip opcodes, phi nodes, the scratch bridge, the
  // callsub bridge), so any constant reached this way genuinely equals
  // `def`'s runtime value. One clause here replaces a per-opcode
  // enumeration of every stack-manipulation instruction.
  exists(IntegerConstant c, Dataflow::Node cNode, Dataflow::Node defNode |
    cNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, c) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::localFlow(cNode, defNode) and
    result = c.getValue()
  )
  or
  // `+` — commutative.
  exists(IntegerAddOpcode op, int v1, int v2 |
    def = TSSAVar(1, op) and
    v1 = tryAsIntDef(op.getStackInputByOrder(1)) and
    v2 = tryAsIntDef(op.getStackInputByOrder(2)) and
    result = v1 + v2
  )
  or
  // `-` — TEAL computes (second-from-top) - (top). Input 1 is the
  // subtrahend (top), input 2 is the minuend. TEAL panics on underflow,
  // so we require `v2 >= v1` to mirror the runtime contract.
  exists(SubOpcode op, int v1, int v2 |
    def = TSSAVar(1, op) and
    v1 = tryAsIntDef(op.getStackInputByOrder(1)) and
    v2 = tryAsIntDef(op.getStackInputByOrder(2)) and
    v2 >= v1 and
    result = v2 - v1
  )
  or
  // `*` — commutative.
  exists(MulOpcode op, int v1, int v2 |
    def = TSSAVar(1, op) and
    v1 = tryAsIntDef(op.getStackInputByOrder(1)) and
    v2 = tryAsIntDef(op.getStackInputByOrder(2)) and
    result = v1 * v2
  )
  or
  // `/` — same operand order as `-`: input 1 is divisor, input 2 is
  // dividend. Zero divisor skipped (TEAL panics).
  exists(DivOpcode op, int v1, int v2 |
    def = TSSAVar(1, op) and
    v1 = tryAsIntDef(op.getStackInputByOrder(1)) and
    v2 = tryAsIntDef(op.getStackInputByOrder(2)) and
    v1 != 0 and
    result = v2 / v1
  )
  or
  // `%` — same operand order as `/`.
  exists(ModOpcode op, int v1, int v2 |
    def = TSSAVar(1, op) and
    v1 = tryAsIntDef(op.getStackInputByOrder(1)) and
    v2 = tryAsIntDef(op.getStackInputByOrder(2)) and
    v1 != 0 and
    result = v2 % v1
  )
}

/**
 * Ergonomic wrapper for callers that already have an `SSAVar` in hand.
 *
 * `v.toDef()` is evaluated in the CALLER'S scope before crossing the
 * `tryAsIntDef` boundary, so the caller's specific `varInternalIndex`
 * binding survives — the field loss only happens when SSAVar itself is
 * the parameter type.
 */
int tryAsInt(SSAVar v) {
  result = tryAsIntDef(v.toDef())
}
