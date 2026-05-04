/**
 * @id tealql/debug/stack-input-coverage
 * @kind table
 *
 * Regression probe for the parallel-view rank-gap bug in
 * ``AstNode.getStackInputByOrder`` (see ``teal/ql/lib/codeql/teal/ast/
 * AST.qll``). For every stack-consuming opcode the predicate must
 * resolve a Definition at every ``ord`` in ``[1 .. n.getNumberOfConsumedArgs()]``.
 * Rows = violations. Empty result = invariant holds.
 *
 * The previous implementation ranked over ``Definition`` directly and
 * relied on score ties to express parallel DirectPhi/IndirectPhi views
 * at the same ``(bb, slot)``. CodeQL's competition ranking then pushed
 * deeper slots' phis past the upper bound on ``ord``, leaving them
 * unreachable to every consumer (dataflow, ssaInputs extraction,
 * stack-shuffle propagation in the Python pipeline). The fix ranks
 * over distinct slot scores (an ``int`` domain) and projects back to
 * every Definition at the chosen score; this query exists to catch
 * any regression of that fix.
 */
import codeql.teal.ast.AST

from AstNode op, int ord
where ord in [1 .. op.getNumberOfConsumedArgs()]
  and not exists(op.getStackInputByOrder(ord))
select op.getLocation().getFile().getRelativePath() as file,
       op.getLocation().getStartLine() as line,
       ord, op.toString() as opString
