/**
 * @name Phi Edges (relational)
 * @description Edges into and out of SSA phi nodes. Each endpoint carries
 *              full identity (file, line, stackIdx, kind), since phis are
 *              keyed by (bb, stackIdx, kind) and can share (file, line)
 *              with the BB's first opcode — and with each other.
 *
 *              Row: srcFile, srcLine, srcStackIdx, srcKind,
 *                   dstFile, dstLine, dstStackIdx, dstKind, label
 *              where *Kind ∈ {"ast", "DirectPhi", "IndirectPhi"} and
 *              stackIdx = -1 for "ast" endpoints.
 * @id tealql/python-analysis/phi-edges
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

/** Immediate DirectPhi parent of an IndirectPhi (one hop, not the whole chain). */
private DirectPhi directParent(IndirectPhi ip) {
  result.getBasicBlock().getASuccessor() = ip.getBasicBlock() and
  ip.getInitialStackIndex() =
    phiNodeExitIndex(result.getInitialStackIndex(), result.getBasicBlock())
}

/** Immediate IndirectPhi parent of an IndirectPhi (one hop). */
private IndirectPhi indirectParent(IndirectPhi ip) {
  result.getBasicBlock().getASuccessor() = ip.getBasicBlock() and
  ip.getInitialStackIndex() =
    phiNodeExitIndex(result.getInitialStackIndex(), result.getBasicBlock())
}

from
  string srcFile, int srcLine, int srcStackIdx, string srcKind,
  string dstFile, int dstLine, int dstStackIdx, string dstKind,
  string label
where
  // ---- Inputs into a DirectPhi: originating SSAVar's declaration AST node ----
  exists(DirectPhi p, SSAVar v, AstNode decl |
    v = p.getOriginatingInput() and
    decl = v.getDeclarationNode() and
    srcFile = decl.getLocation().getFile().getRelativePath() and
    srcLine = decl.getLocation().getStartLine() and
    srcStackIdx = -1 and
    srcKind = "ast" and
    dstFile = p.getLocation().getFile().getRelativePath() and
    dstLine = p.getLocation().getStartLine() and
    dstStackIdx = p.getInitialStackIndex() and
    dstKind = "DirectPhi" and
    label = "PhiIn"
  )
  or
  // ---- Input into an IndirectPhi from its immediate DirectPhi parent ----
  exists(IndirectPhi ip, DirectPhi dp |
    dp = directParent(ip) and
    srcFile = dp.getLocation().getFile().getRelativePath() and
    srcLine = dp.getLocation().getStartLine() and
    srcStackIdx = dp.getInitialStackIndex() and
    srcKind = "DirectPhi" and
    dstFile = ip.getLocation().getFile().getRelativePath() and
    dstLine = ip.getLocation().getStartLine() and
    dstStackIdx = ip.getInitialStackIndex() and
    dstKind = "IndirectPhi" and
    label = "PhiIn"
  )
  or
  // ---- Input into an IndirectPhi from its immediate IndirectPhi parent ----
  exists(IndirectPhi ip, IndirectPhi parent |
    parent = indirectParent(ip) and
    srcFile = parent.getLocation().getFile().getRelativePath() and
    srcLine = parent.getLocation().getStartLine() and
    srcStackIdx = parent.getInitialStackIndex() and
    srcKind = "IndirectPhi" and
    dstFile = ip.getLocation().getFile().getRelativePath() and
    dstLine = ip.getLocation().getStartLine() and
    dstStackIdx = ip.getInitialStackIndex() and
    dstKind = "IndirectPhi" and
    label = "PhiIn"
  )
  or
  // ---- Output edge: DirectPhi -> consumer AST node ----
  exists(DirectPhi p, AstNode consumer |
    consumer = p.getConsumedBy() and
    srcFile = p.getLocation().getFile().getRelativePath() and
    srcLine = p.getLocation().getStartLine() and
    srcStackIdx = p.getInitialStackIndex() and
    srcKind = "DirectPhi" and
    dstFile = consumer.getLocation().getFile().getRelativePath() and
    dstLine = consumer.getLocation().getStartLine() and
    dstStackIdx = -1 and
    dstKind = "ast" and
    label = "PhiOut"
  )
  or
  // ---- Output edge: IndirectPhi -> consumer AST node ----
  exists(IndirectPhi p, AstNode consumer |
    consumer = p.getConsumedBy() and
    srcFile = p.getLocation().getFile().getRelativePath() and
    srcLine = p.getLocation().getStartLine() and
    srcStackIdx = p.getInitialStackIndex() and
    srcKind = "IndirectPhi" and
    dstFile = consumer.getLocation().getFile().getRelativePath() and
    dstLine = consumer.getLocation().getStartLine() and
    dstStackIdx = -1 and
    dstKind = "ast" and
    label = "PhiOut"
  )
select srcFile, srcLine, srcStackIdx, srcKind,
       dstFile, dstLine, dstStackIdx, dstKind,
       label
