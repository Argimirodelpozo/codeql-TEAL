/**
 * @name Must-Be-Constant SSAVars (dataflow-extended)
 * @description Per SSAVar, the literal value the var is provably equal to
 *              under all reachable execution paths. Layered on top of the
 *              ``ConstantPropagation`` / ``BytesPropagation`` libraries.
 *
 *              Soundness comes for free now that the libraries themselves
 *              are sound: ``tryAsInt`` and ``tryAsBytes`` propagate
 *              literals only through ``LocalFlow::valueIdentityFlow``,
 *              which excludes the broad taint pass-through that was
 *              previously letting the lookup KEY of ``app_global_get``
 *              flow through and be reported as the value. Single-valued
 *              ``tryAsInt`` therefore implies "must be K," not "may be K."
 *
 *              Row: astFile, astLine, outIdx, kind, value
 * @id tealql/python-analysis/must-values
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.ConstantPropagation
import codeql.teal.dataflow.BytesPropagation

from int outIdx, AstNode declNode, SSAVar v, string kind, string value
where
  v = MkSSAVar(outIdx, declNode) and
  (
    exists(int k |
      k = tryAsInt(v) and
      strictcount(int m | m = tryAsInt(v)) = 1 and
      kind = "int" and
      value = k.toString())
    or
    exists(string s |
      s = tryAsBytes(v) and
      strictcount(string t | t = tryAsBytes(v)) = 1 and
      kind = "bytes" and
      value = s)
  )
select declNode.getLocation().getFile().getRelativePath(),
       declNode.getLocation().getStartLine(),
       outIdx, kind, value
