/**
 * @name Coarse / lenient taint-flow edges
 * @description One row per *lenient* flow-step edge.
 *
 *              The lenient predicate is the union of:
 *
 *                - ``LocalFlow::localSsaFlowStep`` (the standard flow:
 *                   SSA def-use, stack shuffles, phi joins, plus
 *                   bridges).
 *                - ``SubroutineFlow::simpleLocalFlowStep`` (cross-
 *                   subroutine flow).
 *                - A generic "every consumed input → every produced
 *                   output" step for opcodes that aren't covered
 *                   above (bytemath, arithmetic, hash, slice, btoi,
 *                   comparison, concat — anything that consumes
 *                   inputs and produces outputs whose value depends
 *                   on them).
 *
 *              Pure literal pushers and context loads (``pushint``,
 *              ``pushbytes``, ``intc_*``, ``bytec_*``, ``txn``,
 *              ``txna``, ``gtxn``, ``global``) are natural stoppers:
 *              they have no inputs, so the generic step never fires
 *              for them.
 *
 *              Each row carries a ``kind`` label so Python refiners
 *              can distinguish:
 *
 *                - ``callsub``  — caller↔callee bridge.
 *                - ``scratch``  — store→load bridge.
 *                - ``identity`` — value-identity preserving step
 *                                 (SSA def-use, shuffle, phi).
 *                - ``subroutine`` — extra step from SubroutineFlow.
 *                - ``broad``    — localFlowStep step that's not
 *                                 identity (taint-shape only).
 *                - ``generic``  — the lenient consumes-produces step.
 *
 *              Row: srcFile, srcLine, srcClass,
 *                   sinkFile, sinkLine, sinkClass,
 *                   kind
 *
 * @id tealql/tealtools/coarse-flow-edges
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.dataflow.Dataflow

/** Lenient flow step: union of standard channels plus the generic
 *  "any consumed input flows to any produced output of the consuming
 *  opcode". */
predicate lenientFlowStep(Dataflow::Node nodeFrom, Dataflow::Node nodeTo) {
    LocalFlow::localSsaFlowStep(nodeFrom, nodeTo)
    or
    LocalFlow::localFlowStep(nodeFrom, nodeTo)
    or
    SubroutineFlow::simpleLocalFlowStep(nodeFrom, nodeTo)
    or
    genericConsumesProducesStep(nodeFrom, nodeTo)
    or
    phiArgFlowStep(nodeFrom, nodeTo)
}

/** Phi-arg edge: every predecessor's incoming def → the phi node.
 *  Bridges cross-BB flows that the per-step predicates miss when
 *  multi-output ops (like ``asset_params_get``) feed a phi at a
 *  successor BB's entry. */
predicate phiArgFlowStep(Dataflow::Node nodeFrom, Dataflow::Node nodeTo) {
    exists(DirectPhi phi, Definition arg |
        arg = phi.getOriginatingInput().toDef() |
        nodeFrom.(Dataflow::SsaDefinitionNode).asDefinition() = arg and
        nodeTo.(Dataflow::SsaDefinitionNode).asDefinition() = phi
    )
    or
    exists(IndirectPhi phi |
        nodeFrom.(Dataflow::SsaDefinitionNode).asDefinition() = phi.getGenerator() and
        nodeTo.(Dataflow::SsaDefinitionNode).asDefinition() = phi
    )
}

/** Generic input→output step for opcodes whose outputs depend on
 *  their inputs but aren't covered by ``defSSAFlowThroughOp`` (which
 *  is restricted to stack-shuffles). Captures bytemath, arithmetic,
 *  hash, slice, comparison, concat, btoi, etc. */
predicate genericConsumesProducesStep(Dataflow::Node nodeFrom, Dataflow::Node nodeTo) {
    exists(Definition defFrom, AstNode op, int outOrd, SSAWriteDef defTo |
        defTo = TSSAVar(outOrd, op) and
        op.getConsumedValues() = defFrom
        |
        nodeFrom.(Dataflow::SsaDefinitionNode).asDefinition() = defFrom and
        nodeTo.(Dataflow::SsaDefinitionNode).asDefinition() = defTo
    )
}

/** Per-channel membership: one row per (src, sink, kind) for each
 *  channel that fires on that edge. Python collapses by (src, sink)
 *  into one edge whose ``kinds: set[str]`` lists every contributor
 *  — no info lost to a priority chain. */
predicate edgeChannel(Dataflow::Node src, Dataflow::Node sink, string kind) {
    LocalFlow::callsubBridge(src, sink) and kind = "callsub"
    or
    LocalFlow::scratchBridge(src, sink) and kind = "scratch"
    or
    LocalFlow::valueIdentityFlowStep(src, sink) and kind = "identity"
    or
    SubroutineFlow::simpleLocalFlowStep(src, sink) and kind = "subroutine"
    or
    LocalFlow::localSsaFlowStep(src, sink) and kind = "ssa-step"
    or
    LocalFlow::localFlowStep(src, sink) and kind = "broad"
    or
    genericConsumesProducesStep(src, sink) and kind = "generic"
    or
    phiArgFlowStep(src, sink) and kind = "phi-arg"
}

/** Best-effort class label for any Node — falls back to a stable
 *  string when the node has no underlying AST (e.g. phis). */
string nodeClass(Dataflow::Node n) {
    result = n.getUnderlyingASTNode().getAPrimaryQlClass()
    or
    not exists(n.getUnderlyingASTNode()) and result = "Phi"
}

/** Location of a node — falls back to the underlying AST when the
 *  Node subclass has no ``getLocation`` override (e.g.
 *  ``NoOutputNode`` for sinks like ``box_put`` / ``assert``). */
string nodeFile(Dataflow::Node n) {
    result = n.getLocation().getFile().getRelativePath()
    or
    not exists(n.getLocation()) and
    result = n.getUnderlyingASTNode().getLocation().getFile().getRelativePath()
}
int nodeLine(Dataflow::Node n) {
    result = n.getLocation().getStartLine()
    or
    not exists(n.getLocation()) and
    result = n.getUnderlyingASTNode().getLocation().getStartLine()
}

from Dataflow::Node src, Dataflow::Node sink, string kind
where edgeChannel(src, sink, kind)
select
  nodeFile(src) as srcFile,
  nodeLine(src) as srcLine,
  nodeClass(src) as srcClass,
  nodeFile(sink) as sinkFile,
  nodeLine(sink) as sinkLine,
  nodeClass(sink) as sinkClass,
  kind
