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
 *              On top of the lib, we layer multi-arg DirectPhi unification
 *              (``tryAsIntPhi`` / ``tryAsBytesPhi``). The lib can't host
 *              that case directly — its ``forex``/``strictcount`` shape
 *              would create non-monotonic recursion inside ``tryAsIntDef``
 *              — so we apply it at the query stratum: a phi K propagates
 *              to any SSAVar reached from the phi via ``valueIdentityFlow``.
 *
 *              Row: astFile, astLine, outIdx, kind, value
 * @id tealql/python-analysis/must-values
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.ConstantPropagation
import codeql.teal.dataflow.BytesPropagation
import codeql.teal.dataflow.Dataflow

/**
 * Every integer value `v` may take, combining (1) the lib's
 * ``tryAsInt`` (literal/flow/arith/field-narrowing) and (2) multi-arg
 * DirectPhi unification reached through identity-preserving flow.
 *
 * Single-source phis are already covered by ``tryAsInt`` itself via
 * ``valueIdentityFlow``'s ssawrite→phi edge.
 */
private int possibleInt(SSAVar v) {
  result = tryAsInt(v)
  or
  exists(DirectPhi phi, Dataflow::Node phiNode, Dataflow::Node defNode |
    result = tryAsIntPhi(phi) and
    phiNode.(Dataflow::SsaDefinitionNode).asDefinition() = phi and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = v.toDef() and
    LocalFlow::valueIdentityFlow(phiNode, defNode)
  )
}

private string possibleBytes(SSAVar v) {
  result = tryAsBytes(v)
  or
  exists(DirectPhi phi, Dataflow::Node phiNode, Dataflow::Node defNode |
    result = tryAsBytesPhi(phi) and
    phiNode.(Dataflow::SsaDefinitionNode).asDefinition() = phi and
    defNode.(Dataflow::SsaDefinitionNode).asDefinition() = v.toDef() and
    LocalFlow::valueIdentityFlow(phiNode, defNode)
  )
}

from int outIdx, AstNode declNode, SSAVar v, string kind, string value
where
  v = MkSSAVar(outIdx, declNode) and
  (
    exists(int k |
      k = possibleInt(v) and
      strictcount(int m | m = possibleInt(v)) = 1 and
      kind = "int" and
      value = k.toString())
    or
    exists(string s |
      s = possibleBytes(v) and
      strictcount(string t | t = possibleBytes(v)) = 1 and
      kind = "bytes" and
      value = s)
  )
select declNode.getLocation().getFile().getRelativePath(),
       declNode.getLocation().getStartLine(),
       outIdx, kind, value
