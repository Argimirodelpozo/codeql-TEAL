/**
 * CFG / basic-block construction sanity. Selects each BB as
 * (start_line, end_line, num_successors), giving a structural
 * fingerprint that breaks visibly if BB boundaries or edges
 * shift due to a grammar / extractor / CFG change.
 */
import codeql.teal.cfg.BasicBlocks

from BasicBlock bb, int startLine, int endLine, int succCount
where
  startLine = bb.getFirstNode().getLocation().getStartLine() and
  endLine = bb.getLastNode().getLocation().getStartLine() and
  succCount = strictcount(BasicBlock s | s = bb.getASuccessor())
select startLine, endLine, succCount order by startLine, endLine
