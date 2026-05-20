/**
 * Byte-valued constant propagation, mirroring `ConstantPropagation.qll`
 * for bytes-producing opcodes.
 *
 * Exports `tryAsBytes(SSAVar v)` and `tryAsBytesDef(Definition def)`,
 * which return a compile-time byte-string representation of the value
 * (as the raw token text — `0xdeadbeef`, `"hello"`, etc.) when one can
 * be resolved.
 *
 * Currently supported base cases are exactly the byte-literal opcodes
 * the extractor produces: `pushbytes`, `bytec`, `bytec_0..3` (via
 * `bytecblock`), and the `global ZeroAddress` special-case (a 32-byte
 * all-zero value). `byte 0x..`, `byte "..."`, `addr <addr>`, and
 * `method "sig"` are NOT yet supported — the extractor silently drops
 * these pseudo-opcodes today, so they never appear as AstNodes.
 *
 * Two byte values with the same canonical form (source token text)
 * unify. Mixed encodings of the same bytes (e.g. `0x68656c6c6f` and
 * `"hello"`) do NOT unify in v1 — the caller who wants that should
 * normalize first.
 *
 * FIELD-PROPAGATION NOTE (same as `ConstantPropagation.qll`): we
 * destructure through `def = TSSAVar(idx, node)` to avoid SSAVar's
 * non-unique `varInternalIndex` field being re-existentially-quantified
 * at predicate boundaries.
 */

private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.dataflow.Dataflow
private import codeql.teal.dataflow.ConstantPropagation
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.cfg.Completion::Completion

/**
 * The canonical byte-string for the well-known `global ZeroAddress`
 * constant — 32 zero bytes, rendered as a lowercase hex literal to match
 * how a source-level `pushbytes 0x...` would be stored.
 */
private string zeroAddressHex() {
  result = "0x0000000000000000000000000000000000000000000000000000000000000000"
}

/**
 * Holds if `def`'s runtime value is identity-equivalent to some byte-read
 * opcode with canonical `fieldKey`. Same `LocalFlow`-based identity
 * traversal as `defResolvesToFieldRead` in `ConstantPropagation.qll`;
 * it is re-expressed here for bytes-narrowing so the two modules stay
 * independent of each other's private helpers.
 */
private predicate defResolvesToBytesFieldRead(Definition def, string fieldKey) {
  exists(AstNode op, Dataflow::Node srcNode, Dataflow::Node defNode |
    fieldKey = fieldReadKey(op) and
    srcNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, op) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(srcNode, defNode)
  )
}

/**
 * Holds if, whenever `governingDef` evaluates to true, the field
 * identified by `fieldKey` is guaranteed to equal `value` (as a byte
 * string). Same shape as `guardDefAssertsEquality` in
 * `ConstantPropagation.qll` but with the constant side resolved via
 * `tryAsBytesDef` instead of `tryAsIntDef`.
 */
private predicate guardDefAssertsBytesEquality(
  Definition governingDef, string fieldKey, string value
) {
  exists(EqualsComparisonOpcode eq, Definition fieldSide, Definition constSide |
    governingDef.(SSAWriteDef).getRHS() = eq and
    (
      fieldSide = eq.firstOp() and constSide = eq.secondOp()
      or
      fieldSide = eq.secondOp() and constSide = eq.firstOp()
    ) and
    defResolvesToBytesFieldRead(fieldSide, fieldKey) and
    value = tryAsBytesDef(constSide)
  )
  or
  exists(AndOpcode a |
    governingDef.(SSAWriteDef).getRHS() = a and
    (
      guardDefAssertsBytesEquality(a.getStackInputByOrder(1), fieldKey, value)
      or
      guardDefAssertsBytesEquality(a.getStackInputByOrder(2), fieldKey, value)
    )
  )
}

/**
 * Holds if, on every path reaching `bb`, control has passed through a
 * guard that asserts the byte-valued `fieldKey == value`. Recognises the
 * same three sources as `equalityHoldsAt` in `ConstantPropagation.qll`:
 * preceding assert, bnz, and bz with the "value was nonzero" successor
 * dominating `bb`.
 */
private predicate bytesEqualityHoldsAt(BasicBlock bb, string fieldKey, string value) {
  exists(Definition governingDef |
    guardDefAssertsBytesEquality(governingDef, fieldKey, value)
    |
    exists(AssertOpcode a, BasicBlock assertBB |
      assertBB.getLastNode().getAstNode() = a and
      a.getConsumedValues() = governingDef and
      assertBB.getASuccessor().dominates(bb)
    )
    or
    exists(SimpleConditionalBranches br, BasicBlock brBB |
      brBB.getLastNode().getAstNode() = br and
      br.getConsumedValues() = governingDef and
      brBB.getASuccessor(any(BooleanSuccessor s | s.getValue() = true)).dominates(bb)
    )
  )
}

/**
 * Gets a compile-time byte-string value for the value produced by `def`.
 *
 * Multi-valued: same semantics as `tryAsIntDef`. Caller that wants a
 * unique answer should check `count(tryAsBytesDef(def)) = 1`.
 */
string tryAsBytesDef(Definition def) {
  // Base: literal BytesConstant opcode.
  exists(AstNode op |
    def = TSSAVar(1, op) and
    result = op.(BytesConstant).getValue()
  )
  or
  // Pass-through via LocalFlow.
  exists(BytesConstant c, Dataflow::Node cNode, Dataflow::Node defNode |
    cNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, c) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(cNode, defNode) and
    result = c.getValue()
  )
  or
  // Special case: `global ZeroAddress` has a known value — 32 zero bytes.
  exists(GlobalOpcode g |
    def = TSSAVar(1, g) and
    g.getField() = "ZeroAddress" and
    result = zeroAddressHex()
  )
  or
  // Pass-through of `global ZeroAddress` through LocalFlow.
  exists(GlobalOpcode g, Dataflow::Node cNode, Dataflow::Node defNode |
    g.getField() = "ZeroAddress" and
    cNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, g) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(cNode, defNode) and
    result = zeroAddressHex()
  )
  or
  // Field-read narrowing via dominating bytes-equality guard.
  exists(AstNode op, string fieldKey, Dataflow::Node srcNode, Dataflow::Node defNode |
    fieldKey = fieldReadKey(op) and
    srcNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, op) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(srcNode, defNode) and
    bytesEqualityHoldsAt(op.getBasicBlock(), fieldKey, result)
  )
}

/**
 * Bytes mirror of `tryAsIntPhi`. See that predicate's docstring for
 * the rationale (higher-stratum, soundness via per-arg
 * `strictcount = 1`, coverage trade-off for phi-of-phis chains).
 */
string tryAsBytesPhi(DirectPhi phi) {
  forex(SSAVar arg | arg = phi.getOriginatingInput() |
    strictcount(string s | s = tryAsBytesDef(arg.toDef())) = 1 and
    result = tryAsBytesDef(arg.toDef())
  )
}

/**
 * Ergonomic wrapper for callers that already have an `SSAVar` in hand.
 * Inlined for the same field-propagation reason as `tryAsInt`.
 */
pragma[inline]
string tryAsBytes(SSAVar v) {
  result = tryAsBytesDef(v.toDef())
}
