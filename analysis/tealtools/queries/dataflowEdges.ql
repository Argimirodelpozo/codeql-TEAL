/**
 * @name Dataflow Edges (relational)
 * @description Source/destination AST locations for every local dataflow step.
 * @id tealql/python-analysis/dataflow-edges
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

from Dataflow::Node src, Dataflow::Node sink, AstNode srcAst, AstNode sinkAst
where
  LocalFlow::localFlowStep(src, sink) and
  srcAst = src.getUnderlyingASTNode() and
  sinkAst = sink.getUnderlyingASTNode()
select srcAst.getLocation().getFile().getRelativePath(),
       srcAst.getLocation().getStartLine(),
       sinkAst.getLocation().getFile().getRelativePath(),
       sinkAst.getLocation().getStartLine()
