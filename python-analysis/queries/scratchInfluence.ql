/**
 * @name Scratch-Slot Store→Load Influence Relation
 * @description For every ``load N`` opcode, emit one row per
 *              ``store N`` that may influence its read. Each row carries:
 *
 *                - the load's identity (loadFile, loadLine), used to
 *                  index its output SSAVar in Python (output is always
 *                  at outIdx = 1 since loads push exactly one value), and
 *                - the consumed SSAVar of the store (storeValueFile,
 *                  storeValueLine, storeValueIdx), which is the value
 *                  actually written to the slot at the store's site.
 *
 *              Python-side scratch propagation iterates the influencing
 *              stores per load and concludes the load is constant iff
 *              every influencing store wrote the same compile-time literal.
 *
 *              Only the immediate forms (``store N`` / ``load N`` with a
 *              compile-time slot index) are covered — the dynamic forms
 *              (``stores`` / ``loads``) are out of scope (they pop the
 *              slot index off the stack).
 *
 *              Row: loadFile, loadLine, storeFile, storeLine,
 *                   storeValueFile, storeValueLine, storeValueIdx
 * @id tealql/python-analysis/scratch-influence
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.ast.opcodes.ScratchSpace

from
  LoadOpcode load, StoreOpcode store, SSAVar storedVar
where
  store = load.getInfluencingStore() and
  storedVar = store.getScratchSpaceStoredVariable()
select load.getLocation().getFile().getRelativePath() as loadFile,
       load.getLocation().getStartLine() as loadLine,
       store.getLocation().getFile().getRelativePath() as storeFile,
       store.getLocation().getStartLine() as storeLine,
       storedVar.getDeclarationNode().getLocation().getFile().getRelativePath() as storeValueFile,
       storedVar.getDeclarationNode().getLocation().getStartLine() as storeValueLine,
       storedVar.getInternalOutputIndex() as storeValueIdx
