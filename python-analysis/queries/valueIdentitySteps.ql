/**
 * @name Value-Identity Flow Steps
 * @description One row per ``valueIdentityFlowStep(src, sink)``: a single
 *              identity-preserving dataflow step where ``src`` and
 *              ``sink`` are guaranteed to hold the same runtime value
 *              (stack pass-through, single-source phi convergence,
 *              indirect-phi forwarding, callsub bridge, scratch bridge).
 *
 *              Each endpoint may be an ``SSAWriteDef`` (rendered as kind
 *              ``"SSAVar"`` with ``idx = internalOutputIndex``) or a
 *              ``DirectPhi`` / ``IndirectPhi`` (rendered with
 *              ``idx = initialStackIndex``). The (file, line, idx, kind)
 *              tuple matches the keys used by ``ssaOutputs.ql`` and
 *              ``phiNodes.ql`` so consumers can dereference them
 *              directly.
 *
 *              We emit STEPS only — not the transitive closure — so the
 *              row count stays linear in the program. Python iterates to
 *              fixed point cheaper than QL would materialize the closure.
 *
 *              Row: srcFile, srcLine, srcIdx, srcKind,
 *                   sinkFile, sinkLine, sinkIdx, sinkKind
 * @id tealql/python-analysis/value-identity-steps
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.Dataflow

private predicate defKey(
  Definition def, string file, int line, int idx, string kind
) {
  exists(SSAWriteDef w |
    def = w and
    file = w.getRHS().getLocation().getFile().getRelativePath() and
    line = w.getRHS().getLocation().getStartLine() and
    idx = w.getInternalOutputIndex() and
    kind = "SSAVar"
  )
  or
  exists(DirectPhi p |
    def = p and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine() and
    idx = p.getInitialStackIndex() and
    kind = "DirectPhi"
  )
  or
  exists(IndirectPhi p |
    def = p and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine() and
    idx = p.getInitialStackIndex() and
    kind = "IndirectPhi"
  )
}

from
  Dataflow::Node src, Dataflow::Node sink,
  Definition srcDef, Definition sinkDef,
  string srcFile, int srcLine, int srcIdx, string srcKind,
  string sinkFile, int sinkLine, int sinkIdx, string sinkKind
where
  LocalFlow::valueIdentityFlowStep(src, sink) and
  srcDef = src.(Dataflow::SsaDefinitionNode).asDefinition() and
  sinkDef = sink.(Dataflow::SsaDefinitionNode).asDefinition() and
  srcDef != sinkDef and
  defKey(srcDef, srcFile, srcLine, srcIdx, srcKind) and
  defKey(sinkDef, sinkFile, sinkLine, sinkIdx, sinkKind) and
  // Skip DirectPhi -> IndirectPhi: the IndirectPhi -> root DirectPhi
  // pointer is already in `phiArgs.ql` and Python's `Phi.args` carries
  // it structurally. Emitting these adds O(chain^2) noise without new
  // information.
  sinkKind != "IndirectPhi"
select srcFile, srcLine, srcIdx, srcKind,
       sinkFile, sinkLine, sinkIdx, sinkKind
