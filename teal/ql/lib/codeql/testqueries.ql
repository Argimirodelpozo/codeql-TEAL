// To create db, from root folder do:
// codeql database create --overwrite --search-path codeql/teal/extractor-pack -l teal test-projects/db1 -s test-projects/

private import codeql.teal.ast.internal.TreeSitter
private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.cfg.CFG::CfgImpl
private import codeql.teal.ast.InnerTransactions
// private import codeql.teal.ast.IntegerConstants


//given an err statement, trace the values that make it happen



// from Definition def
// select def, getGenerator(def)

// from AstNode n
// select n, n.getConsumedVars()

from BasicBlock b
where exists(AstNode a, AstNode n | b.getANode().getAstNode() = a and b.getANode().getAstNode() = n and a!= n
and a.getCodeblockStart() = a and n.getCodeblockStart() = n)
// where b.getFirstNode().getAstNode() instanceof TOpcode_app_local_get and b.length() = 11
// and b.getANode() = n
select b, b.getANode(), b.length()
// n.getAPredecessor(), n, n.getASuccessor(), b.getScope()




//TODO: fix bug of the ONE basic block thats too long (retsub wont cut it)
// from BasicBlock bb
// select bb.getFirstNode(), bb.getLastNode()




// Is there global storage?

// Is global storage gated by app creation?

// Is there local storage?

// If there is, give me dominator blocks of their writes

// Are there any itxns to contracts?

// What is the highest number of application arguments used?