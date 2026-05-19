/**
 * @name Missing RekeyTo Validation
 * @description An approval path does not validate the RekeyTo transaction
 *              field against ZeroAddress. Without this check, an attacker can
 *              permanently transfer signing authority to their own address,
 *              compromising the escrow or delegator's account. The alert
 *              points at the specific approval-exit basic block that is not
 *              protected — so a partially-guarded contract produces one
 *              alert per unprotected exit.
 * @kind problem
 * @severity high
 * @id teal/sec-guide/rekey-to
 * @tags security
 *      sec-guide
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA
import codeql.teal.cfg.BasicBlocks
import SecGuideCommon

from BasicBlock exit
where
  exit = approvalExit() and
  not approvalExitProtectedForField(exit, "RekeyTo")
select exit.getLastNode(),
  "Approval exit at line " + exit.getLastNode().getLocation().getStartLine().toString() +
  " is reachable without a RekeyTo check — an attacker can rekey the account."
