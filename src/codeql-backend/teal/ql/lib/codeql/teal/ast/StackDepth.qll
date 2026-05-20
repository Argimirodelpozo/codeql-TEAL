/**
 * Stack depth analysis for TEAL programs.
 *
 * Computes possible stack heights at every opcode by propagating depths
 * forward from program entry (depth=0) through the linear program structure,
 * handling branches explicitly.
 *
 * Detects three classes of violations:
 * - Stack overflow: depth exceeds the AVM limit of 1000
 * - Stack underflow: opcode tries to consume more items than available
 * - Inconsistent depth: different paths to the same node produce different depths
 */

private import codeql.teal.ast.AST

/**
 * Holds if a node ends a straight-line sequence (no fall-through to next line).
 */
private predicate terminatesSequence(AstNode n) {
  n instanceof UnconditionalBranches or
  // assert only exits on failure; on success execution continues to next line
  (n instanceof ContractExitOpcode and not n instanceof AssertOpcode)
}


/**
 * Holds if `depth` is a possible stack height before the node at `lineNum`
 * in program `p` executes. Bounded to [0, 1000] to ensure termination.
 *
 * Propagation rules:
 * 1. Line 0 starts at depth 0
 * 2. Fall-through: if previous line doesn't terminate, depth = prev + prev.delta
 * 3. Branch targets: labels get depth from branching opcodes (after their stack effect)
 * 4. Retsub return: line after callsub gets depth = callsub_depth - proto.input + proto.output
 */
cached
predicate stackHeightAtLine(Program p, int lineNum, int depth) {
  // Base case: first line starts at depth 0
  lineNum = 0 and depth = 0 and exists(p.getChild(0))
  or
  // Fall-through from previous line
  exists(AstNode prev, int prevDepth |
    prev = p.getChild(lineNum - 1) and
    not terminatesSequence(prev) and
    stackHeightAtLine(p, lineNum - 1, prevDepth) and
    depth = prevDepth + prev.getStackDelta() and
    depth >= 0 and depth <= 1000
  )
  or
  // Target of unconditional branch (b) — forward edges only
  exists(BOpcode b, int bDepth |
    b.getProgram() = p and
    b.getTargetLabel() = p.getChild(lineNum) and
    b.getLineNumber() < lineNum and
    stackHeightAtLine(p, b.getLineNumber(), bDepth) and
    depth = bDepth and
    depth >= 0 and depth <= 1000
  )
  or
  // Target of callsub (subroutine entry)
  exists(CallsubOpcode cs, int csDepth |
    cs.getProgram() = p and
    cs.getTargetLabel() = p.getChild(lineNum) and
    stackHeightAtLine(p, cs.getLineNumber(), csDepth) and
    (
      // With proto: normalize entry depth so all callers agree.
      // Subroutine sees proto.inputArgs on its frame regardless of caller.
      exists(ProtoOpcode proto |
        proto = cs.getSubroutine().getAffectingProto() and
        depth = proto.getNumberOfSubroutineInputArgs()
      )
      or
      // Without proto: pass caller's depth through
      not exists(cs.getSubroutine().getAffectingProto()) and
      depth = csDepth
    ) and
    depth >= 0 and depth <= 1000
  )
  or
  // Target of conditional branch (bnz/bz) — forward edges only
  exists(SimpleConditionalBranches cb, int cbDepth |
    cb.getProgram() = p and
    cb.getTargetLabel() = p.getChild(lineNum) and
    cb.getLineNumber() < lineNum and
    stackHeightAtLine(p, cb.getLineNumber(), cbDepth) and
    depth = cbDepth + cb.getStackDelta() and
    depth >= 0 and depth <= 1000
  )
  or
  // Target of switch/match — forward edges only
  exists(MultiTargetConditionalBranch mb, int mbDepth |
    mb.getProgram() = p and
    mb.getTargetLabels() = p.getChild(lineNum) and
    mb.getLineNumber() < lineNum and
    stackHeightAtLine(p, mb.getLineNumber(), mbDepth) and
    depth = mbDepth + mb.getStackDelta() and
    depth >= 0 and depth <= 1000
  )
  or
  // Return from subroutine: the line after a callsub gets depth from retsub
  // With proto: depth = callsub_depth - proto.inputArgs + proto.outputArgs
  // Without proto: depth = callsub_depth (net subroutine effect unknown, treat as 0)
  exists(RetsubOpcode rs, CallsubOpcode cs, int csDepth |
    rs.getProgram() = p and
    rs.predictRetsubReturn() = p.getChild(lineNum) and
    cs.getTargetLabel() = rs.getEntrypoint() and
    cs.getProgram() = p and
    stackHeightAtLine(p, cs.getLineNumber(), csDepth) and
    (
      exists(ProtoOpcode proto |
        proto = rs.getAffectingProto() and
        depth = csDepth - proto.getNumberOfSubroutineInputArgs() + proto.getNumberOfSubroutineOutputArgs()
      )
      or
      not exists(rs.getAffectingProto()) and depth = csDepth
    ) and
    depth >= 0 and depth <= 1000
  )
}

/**
 * Holds if `depth` is a possible stack height before AST node `n` executes.
 * There may be multiple possible depths if different paths reach `n` with
 * different stack states.
 */
predicate nodeStackDepth(AstNode n, int depth) {
  stackHeightAtLine(n.getProgram(), n.getLineNumber(), depth)
}

/**
 * Holds if `minDepth` and `maxDepth` are the minimum and maximum possible
 * stack depths before AST node `n` executes.
 */
predicate nodeStackDepthBefore(AstNode n, int minDepth, int maxDepth) {
  minDepth = min(int d | nodeStackDepth(n, d) | d) and
  maxDepth = max(int d | nodeStackDepth(n, d) | d)
}

/**
 * Holds if `minDepth` and `maxDepth` are the minimum and maximum possible
 * stack depths after AST node `n` executes.
 */
predicate nodeStackDepthAfter(AstNode n, int minDepth, int maxDepth) {
  exists(int beforeMin, int beforeMax, int delta |
    nodeStackDepthBefore(n, beforeMin, beforeMax) and
    delta = n.getStackDelta() and
    minDepth = beforeMin + delta and
    maxDepth = beforeMax + delta
  )
}

/** Holds if node `n` causes a stack overflow (depth exceeds 1000 after execution). */
predicate stackOverflow(AstNode n, int maxDepth) {
  nodeStackDepthAfter(n, _, maxDepth) and
  maxDepth > 1000
}

/** Holds if node `n` causes a stack underflow (tries to consume more items than available). */
predicate stackUnderflow(AstNode n, int minDepth) {
  exists(int consumed |
    nodeStackDepthBefore(n, minDepth, _) and
    consumed = n.getNumberOfConsumedArgs() and
    minDepth < consumed
  )
}

/** Holds if different paths to node `n` produce different stack depths. */
predicate inconsistentStackDepth(AstNode n, int minDepth, int maxDepth) {
  nodeStackDepthBefore(n, minDepth, maxDepth) and
  minDepth != maxDepth
}

/**
 * Holds if `delta` is the effective stack delta of `retsub`, accounting for proto.
 * With proto: delta = -depth + proto.outputArgs (clears subroutine frame, keeps outputs).
 * Without proto: delta = 0.
 */
predicate retsubEffectiveDelta(RetsubOpcode retsub, int delta) {
  exists(ProtoOpcode proto, int depth |
    proto = retsub.getAffectingProto() and
    depth = retsub.getEntrypoint().(Subroutine).getFrameRelativeSubroutineStackHeight(retsub) and
    delta = -depth + proto.getNumberOfSubroutineOutputArgs()
  )
  or
  not exists(retsub.getAffectingProto()) and
  delta = 0
}
