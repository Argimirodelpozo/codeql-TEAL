/**
 * @name Phi Liveness Enumeration
 * @description Emits every ``DirectPhi`` and ``IndirectPhi`` in the
 *              program, with its kind, stack index, source line, and
 *              direct-consumer line if any. Used by the phi-liveness
 *              qltest suite to verify the ``IndirectPhi`` liveness
 *              filter defined in ``SSA.qll``: dead propagation tails
 *              are pruned, while phis whose consumer is several BB
 *              hops away remain alive.
 *
 *              Row: (file, line, stackIdx, kind, directConsumerLineOr"-").
 * @kind table
 * @id teal/sec-guide/phi-liveness
 * @tags test
 *      ssa
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from
  Definition p, string file, int line, int idx, string kind, string consumer
where
  (p instanceof DirectPhi or p instanceof IndirectPhi) and
  file = p.getLocation().getFile().getBaseName() and
  line = p.getLocation().getStartLine() and
  (
    idx = p.(DirectPhi).getInitialStackIndex() or
    idx = p.(IndirectPhi).getInitialStackIndex()
  ) and
  (if p instanceof DirectPhi then kind = "DirectPhi" else kind = "IndirectPhi") and
  (
    exists(AstNode c |
      (c = p.(DirectPhi).getConsumedBy() or c = p.(IndirectPhi).getConsumedBy()) and
      consumer = "L" + c.getLocation().getStartLine().toString()
    )
    or
    not exists(p.(DirectPhi).getConsumedBy()) and
    not exists(p.(IndirectPhi).getConsumedBy()) and
    consumer = "-"
  )
select file, line, idx, kind, consumer
