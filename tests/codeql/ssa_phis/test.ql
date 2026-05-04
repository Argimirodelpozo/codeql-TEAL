/**
 * Asserts SSA emits at least one phi for the value that joins from
 * two arms of the bnz. Reports the count; non-zero is the success
 * signal, zero would indicate a regression.
 */
import codeql.teal.SSA.SSA

from int directCount, int indirectCount
where
  directCount = count(DirectPhi p) and
  indirectCount = count(IndirectPhi p)
select directCount, indirectCount
