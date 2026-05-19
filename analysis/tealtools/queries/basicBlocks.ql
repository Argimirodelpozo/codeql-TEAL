/**
 * @name Basic Block Membership
 * @description For every AST node that participates in the CFG, the basic
 *              block it belongs to. BB identity is (file, firstLine); we
 *              also emit the BB's last line so consumers can size/label
 *              the collapsed node.
 *
 *              Row: astFile, astLine, bbFirstLine, bbLastLine
 * @id tealql/python-analysis/basic-blocks
 */

import codeql.teal.ast.AST
import codeql.teal.cfg.CFG
import codeql.teal.cfg.CFG::CfgImpl

from AstNode n, BasicBlock bb, AstNode first, AstNode last
where
  bb = n.getBasicBlock() and
  first = bb.getFirstNode().(AstCfgNode).getAstNode() and
  last = bb.getLastNode().(AstCfgNode).getAstNode()
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       first.getLocation().getStartLine(),
       last.getLocation().getStartLine()
