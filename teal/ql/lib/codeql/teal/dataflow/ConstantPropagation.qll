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
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.cfg.Completion::Completion

/**
 * Canonical string key for an opcode that reads a deterministic field of
 * the current execution context. Two opcodes with the same key are
 * guaranteed to return the same runtime value within a single transaction,
 * so a guard that pins one can narrow the other on dominated BBs.
 *
 * Safe (deterministic, static-index) field-read opcodes enumerated here:
 *   - `txn F`          — current transaction's field
 *   - `txna F i`       — current transaction's array field at static index
 *   - `gtxn t F`       — group transaction at static group index `t`, field
 *   - `global F`       — chain/transaction-level constant
 *
 * Deliberately excluded:
 *
 *   - Dynamic-index variants (`txnas`, `gtxns`, `gtxnsa`, `gtxnas`,
 *     `gtxnsas`, `gitxnas`): the field being read depends on a stack
 *     value, so two opcodes with the same AstNode shape can refer to
 *     different runtime fields. Keying by AstNode identity alone would
 *     be unsound.
 *
 *   - Inner-transaction reads (`itxn`, `itxna`, `gitxn`, `gitxna`): these
 *     reference builder/submitted-inner-txn state that mutates during
 *     program execution (via `itxn_begin` / `itxn_submit`), so two reads
 *     at different program points can legitimately return different
 *     values.
 *
 *   - App state reads (`app_global_get`, `app_local_get`, `app_params_get`,
 *     ...): conditionally deterministic — only safe to narrow between
 *     reads when no intervening `app_*_put` / `app_*_del` writes the
 *     same key. Handling this requires a kill analysis similar to the
 *     scratch-space bridge; out of scope here.
 *
 *   - `balance`, `min_balance`, `asset_holding_get`, etc.: take an
 *     account/asset index off the stack and can be mutated by inner
 *     transactions, so they're not safe to cross-narrow by AST identity.
 *
 * The key is opaque to the rest of the narrowing machinery — extending
 * this predicate with more opcodes (once their accessors are exposed and
 * their determinism justified) is sufficient to pick up additional
 * narrowing without further changes elsewhere.
 */
string fieldReadKey(AstNode op) {
  op instanceof TxnOpcode and
  result = "txn." + op.(TxnOpcode).getField()
  or
  op instanceof TxnaOpcode and
  result = "txna." + op.(TxnaOpcode).getField() + "[" + op.(TxnaOpcode).getIndex() + "]"
  or
  op instanceof GtxnOpcode and
  result = "gtxn[" + op.(GtxnOpcode).getIndex() + "]." + op.(GtxnOpcode).getField()
  or
  op instanceof GtxnaOpcode and
  result =
    "gtxna[" + op.(GtxnaOpcode).getIndex() + "]." + op.(GtxnaOpcode).getField() +
      "[" + op.(GtxnaOpcode).getArrayIndex() + "]"
  or
  op instanceof GlobalOpcode and
  result = "global." + op.(GlobalOpcode).getField()
}

/**
 * Holds if `def`'s runtime value is identity-equivalent to reading a
 * field-read opcode with canonical key `fieldKey`. Uses `LocalFlow` so the
 * identity chain can traverse stack manipulation, phi nodes, the scratch
 * bridge, and the callsub bridge.
 */
private predicate defResolvesToFieldRead(Definition def, string fieldKey) {
  exists(AstNode op, Dataflow::Node srcNode, Dataflow::Node defNode |
    fieldKey = fieldReadKey(op) and
    srcNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, op) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(srcNode, defNode)
  )
}

/**
 * Holds if, whenever the value of `governingDef` evaluates to true, the
 * field identified by `fieldKey` is guaranteed to equal `value`.
 *
 * Leaf case: `governingDef` is produced by an `==` cmp with a field read
 * on one side and a compile-time-constant expression on the other (both
 * operand orderings are handled). The constant side is resolved
 * recursively via `tryAsIntDef`, so nested arithmetic / constants /
 * stack-threaded literals all work.
 *
 * Compositional case: `governingDef` is produced by `&&`; if either
 * operand subtree asserts the equality then the whole AND does too
 * (because both operands must be true when the AND is true).
 *
 * Not handled in v1 (deliberately):
 *   - `||` — at polarity true, one-or-the-other doesn't pin a field.
 *   - `!` — would require tracking polarity=false through the recursion.
 *   - `!=` — yields disequalities, which we're not storing.
 */
private predicate guardDefAssertsEquality(Definition governingDef, string fieldKey, int value) {
  exists(EqualsComparisonOpcode eq, Definition fieldSide, Definition constSide |
    governingDef.(SSAWriteDef).getRHS() = eq and
    (
      fieldSide = eq.firstOp() and constSide = eq.secondOp()
      or
      fieldSide = eq.secondOp() and constSide = eq.firstOp()
    ) and
    defResolvesToFieldRead(fieldSide, fieldKey) and
    value = tryAsIntDef(constSide)
  )
  or
  exists(AndOpcode a |
    governingDef.(SSAWriteDef).getRHS() = a and
    (
      guardDefAssertsEquality(a.getStackInputByOrder(1), fieldKey, value)
      or
      guardDefAssertsEquality(a.getStackInputByOrder(2), fieldKey, value)
    )
  )
}

/**
 * Holds if on every path reaching `bb`, control has passed through a
 * guard that asserts `fieldKey == value`. Three sources are recognised:
 *
 *  1. A preceding `assert(g)` whose BB's successor dominates `bb` (the
 *     assert is a terminator, so its immediate post-successor is the BB
 *     where the asserted condition is known to hold).
 *
 *  2. A preceding `bnz(g)` whose "value was non-zero" successor dominates
 *     `bb` (non-zero = guard evaluated true).
 *
 *  3. A preceding `bz(g)` whose "value was non-zero" successor dominates
 *     `bb` (for bz, non-zero means the branch fell through; the CFG
 *     models the fall-through as a true-valued `BooleanSuccessor`).
 *
 * In all three cases, `g` must itself assert `fieldKey == value` via
 * `guardDefAssertsEquality`.
 */
private predicate equalityHoldsAt(BasicBlock bb, string fieldKey, int value) {
  exists(Definition governingDef |
    guardDefAssertsEquality(governingDef, fieldKey, value)
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
    LocalFlow::valueIdentityFlow(cNode, defNode) and
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
  or
  // Field-read narrowing via a dominating equality guard.
  //
  // `def` is identity-equivalent to some field-read opcode `op` (either
  // `def` is `op`'s own def, or `op`'s value flows to `def` through
  // stack manipulation / phi / scratch / callsub). If there is a guard
  // on any path reaching `op`'s basic block that pins the field to
  // `result`, then at `op` — and therefore at `def` — the value is
  // `result`.
  //
  // Cross-opcode narrowing: the guard's cmp does not need to reference
  // `op` itself. Any other field-read opcode with the same `fieldKey`
  // counts, because field reads are deterministic within a transaction.
  exists(AstNode op, string fieldKey, Dataflow::Node srcNode, Dataflow::Node defNode |
    fieldKey = fieldReadKey(op) and
    srcNode.(Dataflow::SsaDefinitionNode).asDefinition() = TSSAVar(1, op) and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = def and
    LocalFlow::valueIdentityFlow(srcNode, defNode) and
    equalityHoldsAt(op.getBasicBlock(), fieldKey, result)
  )
}

/**
 * Ergonomic wrapper for callers that already have an `SSAVar` in hand.
 *
 * Marked `pragma[inline]` so the wrapper body is splice-evaluated in the
 * caller's scope. This is important because `SSAVar` has a non-unique
 * `varInternalIndex` field that CodeQL re-existentially-quantifies at
 * every predicate boundary — without inlining, `v.toDef()` inside the
 * wrapper would fan out across every valid index for the underlying
 * AstNode, silently making `tryAsInt(v)` return *every* constant that
 * reaches *any* output of the opcode that produced `v`. Inlining forces
 * the `toDef()` call to happen at the callsite, where the query's
 * specific field binding still applies.
 */
pragma[inline]
int tryAsInt(SSAVar v) {
  result = tryAsIntDef(v.toDef())
}
