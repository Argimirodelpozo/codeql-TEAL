/**
 * @name CFG Edges (relational)
 * @description Source/destination AST locations for every CFG edge, with successor type.
 * @id tealql/python-analysis/cfg-edges
 */

import codeql.teal.ast.AST
import codeql.teal.cfg.CFG
import codeql.teal.cfg.CFG::CfgImpl
import codeql.teal.cfg.Completion::Completion

from AstCfgNode pred, AstCfgNode succ, SuccessorType t
where succ = pred.getASuccessor(t)
select pred.getLocation().getFile().getRelativePath(),
       pred.getLocation().getStartLine(),
       succ.getLocation().getFile().getRelativePath(),
       succ.getLocation().getStartLine(),
       t.toString()
