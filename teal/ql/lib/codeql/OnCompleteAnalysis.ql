// To create db, from root folder do:
// codeql database create --overwrite --search-path codeql/teal/extractor-pack -l teal test-projects/db1 -s test-projects/

private import codeql.teal.ast.internal.TreeSitter
private import codeql.teal.ast.AST
private import codeql.teal.SSA.SSA
private import codeql.teal.cfg.BasicBlocks
private import codeql.teal.cfg.CFG::CfgImpl


//given an err statement, trace the values that make it happen



// from Definition def
// select def, getGenerator(def)

// from AstNode n
// select n, n.getConsumedVars()

from BasicBlock b
select b




//TODO: fix bug of the ONE basic block thats too long (retsub wont cut it)
// from BasicBlock bb
// select bb.getFirstNode(), bb.getLastNode()




// Is there global storage?

// Is global storage gated by app creation?

// Is there local storage?

// If there is, give me dominator blocks of their writes

// Are there any itxns to contracts?

// What is the highest number of application arguments used?