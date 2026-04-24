/**
 * @name Phi Liveness Invariant
 * @description Emits any ``IndirectPhi`` that is dead — not directly
 *              consumed *and* has no consumed descendant on the
 *              propagation chain. The liveness filter in ``SSA.qll``
 *              is supposed to prune exactly these; if any survive, the
 *              filter has a bug or regression.
 *
 *              This predicate is defined **independently** of the
 *              filter's internal ``phiIsLive`` (which is private), so
 *              a broken filter cannot accidentally pass this test by
 *              sharing the same bug.
 *
 *              Expected output: EMPTY. Any row indicates a filter bug.
 * @kind table
 * @id teal/sec-guide/phi-liveness-invariant
 * @tags test
 *      ssa
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

/**
 * White-box re-implementation of the filter's liveness predicate, on
 * the `IndirectPhi` class (not the raw newtype). Used only for the
 * invariant check.
 *
 * An IndirectPhi is considered "eventually consumed" if either it is
 * directly consumed in its own BB, or it has an IndirectPhi successor
 * that is itself eventually consumed.
 */
predicate eventuallyConsumed(IndirectPhi p) {
  exists(p.getConsumedBy())
  or
  exists(IndirectPhi child |
    child.getBasicBlock() = p.getBasicBlock().getASuccessor() and
    eventuallyConsumed(child))
}

from IndirectPhi p
where not eventuallyConsumed(p)
select p.getLocation().getFile().getBaseName() as file,
       p.getLocation().getStartLine() as line,
       p.getInitialStackIndex() as idx,
       "LEAK: dead IndirectPhi survived the liveness filter" as msg
