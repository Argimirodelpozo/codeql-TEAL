/**
 * Regression test: `InnerTransactionField.getItxnField()` returns both
 * scalar field names (`TypeEnum`, `ApplicationID`) AND array field
 * names (`ApplicationArgs`). The qll relation reads both
 * `getTxnField()` and `getTxnArrayField()` from the parser; if either
 * arm is dropped, this test fails.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.InnerTransactions

from InnerTransactionField field
select field.getLocation().getStartLine() as line, field.getItxnField() as fieldName
order by line
