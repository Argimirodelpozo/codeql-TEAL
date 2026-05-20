/**
 * Per-line stack simulation for TEAL programs.
 *
 * For every AST node `n`, derives the ordered contents of the runtime
 * stack BEFORE and AFTER `n` executes. Slots are typed as `Definition`
 * (`SSAWriteDef` / `DirectPhi` / `IndirectPhi`); slot 1 is the topmost.
 *
 * Built on the existing SSA model (`SSA.qll`) and the per-opcode stack
 * effect predicates on `AstNode` (`getNumberOfConsumedArgs`,
 * `getNumberOfOutputArgs`, `getOutputVar`). No new symbolic identities
 * are introduced — retsub-output SSAVars, frame_dig outputs, and join
 * phis are all reused as-is.
 *
 * The slot-ordering scheme mirrors `getStackInputByOrder` in `AST.qll`:
 *
 *   - Locally-produced SSAVars surviving to `n` get a small score
 *     `(n.line - v.line) * 1000 + outputIndex`. Recent lines rank
 *     above older lines (top of stack); within a line, lower output
 *     index ranks above higher (matches `SSAVar.outStackOrder()`).
 *
 *   - Phis at `n`'s BB get a large score `BASELINE + phi.getOrd()`,
 *     where `BASELINE = 10^8` strictly exceeds any local score.
 *     `phi.getOrd()` returns `getInitialStackIndex()`, where slot 1
 *     is the topmost incoming slot from the predecessor BB.
 *
 *   - DirectPhi and IndirectPhi at the same `(bb, slot)` deliberately
 *     collapse to the same score — they're parallel views of one
 *     stack position, not two.
 *
 * The IN-stack ranking uses the same rank-by-distinct-int trick as
 * `getStackInputByOrder` to keep ord assignment gap-free across
 * collapsed parallel-phi scores. The OUT-stack is computed by
 * transformation: top `numberOfConsumedArgs` slots are dropped,
 * `getOutputVar(1..k)` are pushed.
 */

private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.ast.StackDepth as StackDepth

/**
 * Max possible stack height before `n` executes. Drawn from the cached
 * `nodeStackDepth` predicate in `StackDepth.qll`. Used to clip phantom
 * IndirectPhis that the SSA model emits at slots beyond actual depth
 * (the `phiNodeExitIndex` predicate enumerates `[1..1000]` slots,
 * which leaks at recursive-subroutine entries — see `framedig-tests/06`
 * where the model emits 999 slot-N IndirectPhis at every BB).
 */
private int maxStackDepthAt(AstNode n) {
  result = max(int d | StackDepth::nodeStackDepth(n, d) | d)
}

/**
 * Score for `def` as a slot at the IN-stack of `n`. Smaller score is
 * closer to the top of stack. See file-level doc for the scheme.
 */
private predicate inSlotScore(AstNode n, Definition def, int score) {
  // Local SSAVar: defined in n's BB, before n's line, still alive at n.
  exists(SSAWriteDef wd, AstNode declN, int outIdx |
    def = wd and
    outIdx = wd.getInternalOutputIndex() and
    declN = wd.getRHS() and
    declN.getBasicBlock() = n.getBasicBlock() and
    declN.getLineNumber() < n.getLineNumber() and
    (
      // No local consumer ⇒ survives end-of-BB ⇒ alive at every later
      // line in the BB, including n.
      not exists(declN.getConsumedBy(outIdx))
      or
      // Local consumer at line ≥ n's line ⇒ still on the stack at n's
      // IN (the consumer at line == n's line is `n` itself reading it).
      declN.getConsumedBy(outIdx).getLineNumber() >= n.getLineNumber()
    ) and
    score = (n.getLineNumber() - declN.getLineNumber()) * 1000 + outIdx
  )
  or
  // Phi at n's BB, alive at n. Bounded by actual entry depth so the
  // SSA model's slot-1..1000 IndirectPhi enumeration doesn't leak
  // into the rendered stack at recursive-subroutine entries.
  exists(BasicBlock bb | bb = n.getBasicBlock() |
    (
      def.(DirectPhi).getBasicBlock() = bb and
      def.(DirectPhi).getInitialStackIndex() <= maxStackDepthAt(bb.getFirstNode().getAstNode()) and
      (
        not exists(def.(DirectPhi).getConsumedBy())
        or
        def.(DirectPhi).getConsumedBy().getLineNumber() >= n.getLineNumber()
      )
      or
      def.(IndirectPhi).getBasicBlock() = bb and
      def.(IndirectPhi).getInitialStackIndex() <= maxStackDepthAt(bb.getFirstNode().getAstNode()) and
      (
        not exists(def.(IndirectPhi).getConsumedBy())
        or
        def.(IndirectPhi).getConsumedBy().getLineNumber() >= n.getLineNumber()
      )
    )
  ) and
  score = 100000000 + def.getOrd()
}

/**
 * Holds if `score` is the score of some IN-stack slot at `n`. Defined
 * as a thin existential so the rank in `stackSlotIn` can range over
 * distinct int scores rather than over Definitions (avoids the same
 * rank-tie pitfall documented on `consumedSlotHasScore` in `AST.qll`).
 */
private predicate inSlotHasScore(AstNode n, int score) {
  exists(Definition def | inSlotScore(n, def, score))
}

/**
 * Slot at the IN-stack of `n`, with `slotIdx` = 1 for the topmost.
 *
 * Uses the same two-stage rank as `getStackInputByOrder`:
 *   (1) rank distinct slot scores ascending,
 *   (2) project back to every Definition at the chosen score
 *       (so collapsed DirectPhi+IndirectPhi parallel views both
 *       appear at the same `slotIdx`).
 */
predicate stackSlotIn(AstNode n, int slotIdx, Definition def) {
  exists(int slotScore |
    slotScore = rank[slotIdx](int s | inSlotHasScore(n, s) | s order by s asc) and
    inSlotScore(n, def, slotScore)
  )
}

/**
 * Slot at the OUT-stack of `n`, with `slotIdx` = 1 for the topmost.
 *
 * - Slots `1 .. n.getNumberOfOutputArgs()` are `n`'s own outputs.
 *   By the SSA convention (`SSAVar.outStackOrder()` ranks asc by
 *   `getInternalOutputIndex()` within a line), `getOutputVar(1)` is
 *   the topmost output and `getOutputVar(k)` is the deepest.
 *
 * - Slots beyond `n`'s outputs come from the IN-stack with the top
 *   `numberOfConsumedArgs` slots dropped. The mapping is:
 *     `out[outputs + i] = in[consumed + i]` for i ≥ 1.
 */
predicate stackSlotOut(AstNode n, int slotIdx, Definition def) {
  // From n's outputs.
  exists(SSAVar v |
    slotIdx in [1 .. n.getNumberOfOutputArgs()] and
    v = n.getOutputVar(slotIdx) and
    def = v.toDef()
  )
  or
  // Surviving IN-stack slots, shifted by the net stack delta.
  exists(int inSlotIdx |
    slotIdx > n.getNumberOfOutputArgs() and
    inSlotIdx = slotIdx - n.getNumberOfOutputArgs() + n.getNumberOfConsumedArgs() and
    stackSlotIn(n, inSlotIdx, def)
  )
}

/**
 * Identifier for a `Definition` slot, suitable for human-readable rendering.
 * Uses the existing `toString()` of `SSAWriteDef` / `DirectPhi` /
 * `IndirectPhi`, with a parallel-phi marker `=` when both phi kinds
 * collapse to one slot.
 */
private string slotIdentifier(AstNode n, int slotIdx) {
  exists(Definition def |
    stackSlotIn(n, slotIdx, def) and
    // Pick DirectPhi over IndirectPhi when parallel views collapse.
    not (def instanceof IndirectPhi and exists(Definition d2 |
      stackSlotIn(n, slotIdx, d2) and d2 instanceof DirectPhi))
  |
    result = def.toString()
  )
}

private string slotOutIdentifier(AstNode n, int slotIdx) {
  exists(Definition def |
    stackSlotOut(n, slotIdx, def) and
    not (def instanceof IndirectPhi and exists(Definition d2 |
      stackSlotOut(n, slotIdx, d2) and d2 instanceof DirectPhi))
  |
    result = def.toString()
  )
}

/**
 * Human-readable IN stack of `n`, formatted bottom-first as
 * `[bot, ..., top]`. Empty stacks render as `[]`.
 */
string stackInString(AstNode n) {
  exists(n.getBasicBlock()) and
  result = "[" + concat(int slotIdx, string s |
    s = slotIdentifier(n, slotIdx) |
    s, ", " order by slotIdx desc
  ) + "]"
}

/** Human-readable OUT stack of `n`, formatted bottom-first as `[bot, ..., top]`. */
string stackOutString(AstNode n) {
  exists(n.getBasicBlock()) and
  result = "[" + concat(int slotIdx, string s |
    s = slotOutIdentifier(n, slotIdx) |
    s, ", " order by slotIdx desc
  ) + "]"
}
