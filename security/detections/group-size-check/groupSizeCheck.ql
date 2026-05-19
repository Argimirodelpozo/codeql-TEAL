/**
 * @name Missing GroupSize Validation
 * @description Detects contracts that use gtxn with absolute group indices
 *              without validating global GroupSize. Not validating group size
 *              allows attackers to pad groups with extra application calls,
 *              causing methods to execute multiple times for a single payment.
 *              Also, referencing group indices without verifying group size
 *              allows attacker-controlled incomplete groups to bypass validation.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/group-size-check
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from GtxnOpcode gtxn, Program prog
where
  gtxn.getProgram() = prog and
  not hasGroupSizeCheck()
select gtxn,
  "gtxn access uses an absolute group index without validating global GroupSize — attackers can pad the group with extra transactions."
