/**
 * Suppression Logic for TEAL CodeQL Checks
 *
 * Archaeology Results:
 * ==================
 * Internal Class: Comment
 * Source: Teal::Comment (TreeSitter.qll, line 176)
 * Location Mapping: Verified across voting_approval.teal (12 comments discovered, all correctly mapped to line numbers)
 *
 * This module provides suppression predicates that check for the "codeql-skip"
 * directive in TEAL comments to selectively suppress security findings.
 */

import codeql.teal.ast.AST
import codeql.teal.dataflow.Dataflow

/**
 * Predicate: isSuppressed
 * 
 * Holds if a dataflow node should be suppressed based on a comment containing
 * "codeql-skip" on the same line OR the previous line as the node's underlying AST element.
 *
 * Usage in security checks:
 * ```
 * from SomeDataFlowNode n
 * where not isSuppressed(n) and someSecurityCondition(n)
 * select n, "Security issue..."
 * ```
 *
 * @param n The dataflow node to check for suppression
 */
predicate isSuppressed(Dataflow::Node n) {
  exists(Comment c |
    // Comment is on the same line OR one line BEFORE the node's underlying AST node
    (c.getLocation().getStartLine() = n.getUnderlyingASTNode().getLocation().getStartLine() or
     c.getLocation().getStartLine() = n.getUnderlyingASTNode().getLocation().getStartLine() - 1) and
    // The comment contains the codeql-skip directive
    c.getText().matches("%codeql-skip%")
  )
}

/**
 * Predicate: isAstNodeSuppressed
 * 
 * Holds if an AST node should be suppressed based on a comment containing
 * "codeql-skip" on the same line OR the previous line.
 *
 * Usage:
 * ```
 * from Opcode op
 * where not isAstNodeSuppressed(op) and someSecurityCondition(op)
 * select op, "Security issue..."
 * ```
 *
 * @param node The AST node to check for suppression
 */
predicate isAstNodeSuppressed(AstNode node) {
  exists(Comment c |
    (c.getLocation().getStartLine() = node.getLocation().getStartLine() or
     c.getLocation().getStartLine() = node.getLocation().getStartLine() - 1) and
    c.getText().matches("%codeql-skip%")
  )
}

/**
 * Predicate: isLineSuppressed
 * 
 * Holds if a specific line in a file has a suppression comment on that line 
 * or on the previous line.
 *
 * @param file The file to check
 * @param line The line number to check
 */
predicate isLineSuppressed(File file, int line) {
  exists(Comment c |
    c.getLocation().getFile() = file and
    (c.getLocation().getStartLine() = line or
     c.getLocation().getStartLine() = line - 1) and
    c.getText().matches("%codeql-skip%")
  )
}

/**
 * Predicate: getSuppressedReason
 * 
 * Extracts the suppression reason from a comment on the same line or previous line.
 * Format: `// codeql-skip: <reason>`
 *
 * Example:
 * ```
 * txn OnCompletion  // codeql-skip: Deferred to post-check subroutine
 * ```
 * Or on the previous line:
 * ```
 * // codeql-skip: Deferred to post-check subroutine
 * txn OnCompletion
 * ```
 *
 * @param node The AST node to check
 * @param reason The suppression reason extracted from the comment (may be empty)
 */
predicate getSuppressedReason(AstNode node, string reason) {
  exists(Comment c, string text, int skipIndex |
    (c.getLocation().getStartLine() = node.getLocation().getStartLine() or
     c.getLocation().getStartLine() = node.getLocation().getStartLine() - 1) and
    text = c.getText() and
    text.matches("%codeql-skip:%") and
    skipIndex = text.indexOf("codeql-skip:") and
    reason = text.substring(skipIndex + 12, text.length()).trim()
  )
}
