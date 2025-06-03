private import codeql.teal.ast.AST
private import codeql.controlflow.Cfg as CfgShared
private import codeql.Locations
private import codeql.teal.ast.internal.TreeSitter
private import codeql.teal.cfg.Completion::Completion

module CfgScope {
  abstract class CfgScope extends AstNode { }

  class ProgramScope extends CfgScope, Program { 
    
    // override string toString(){
    //   result = "ProgramScope"
    // }
  }

  // class CodeblockScope extends CfgScope, Codeblock { 
    
  //   // override string toString(){
  //   //   result = "CodeblockScope"
  //   // }
  // }
}

private module Implementation implements CfgShared::InputSig<Location> {
  import codeql.teal.ast.AST
  import codeql.teal.cfg.Completion::Completion
  import CfgScope

  predicate completionIsNormal(Completion c) { c instanceof NormalCompletion }

  // Not using CFG splitting, so the following are just dummy types.
  // private newtype TUnit = Unit()

  // class SplitKindBase = TUnit;

  // class Split extends TUnit {
  //   abstract string toString();
  // }

  predicate completionIsSimple(Completion c) { c instanceof SimpleCompletion }

  predicate completionIsValidFor(Completion c, AstNode e) { c.isValidFor(e) }

  CfgScope getCfgScope(AstNode e) {
    result = e.getProgram()
    // if e instanceof Program or e instanceof Codeblock then result = e.getProgram()
    // else 
    // result = e.getCodeblockStart().(Codeblock)
  }

  int maxSplits() { result = 0 }

  predicate scopeFirst(CfgScope scope, AstNode e) {
    first(scope.(Program), e)
    // or
    // not scope instanceof Program and
    // first(scope.(Codeblock), e)
  }

  predicate scopeLast(CfgScope scope, AstNode e, Completion c) {
    last(scope.(Program), e, c)
    // or
    // not scope instanceof Program and
    // last(scope.(Codeblock), e, c)
  }

  predicate successorTypeIsSimple(SuccessorType t) { t instanceof NormalSuccessor }

  predicate successorTypeIsCondition(SuccessorType t) { t instanceof BooleanSuccessor }

  SuccessorType getAMatchingSuccessorType(Completion c) { result = c.getAMatchingSuccessorType() }

  predicate isAbnormalExitType(SuccessorType t) { none() }

    /**
   * Gets an `id` of `node`. This is used to order the predecessors of a join
   * basic block.
   */
  int idOfAstNode(AstNode node){result = node.getLineNumber()}

  /**
   * Gets an `id` of `scope`. This is used to order the predecessors of a join
   * basic block.
   */
  int idOfCfgScope(CfgScope scope){result = scope.getCodeblockStart().getLineNumber()}
}

module CfgImpl = CfgShared::Make<Location, Implementation>;

private import CfgImpl
private import Completion
private import CfgScope
// private import codeql.teal.cfg.BasicBlocks


// /**
//  * A control flow node.
//  *
//  * A control flow node is a node in the control flow graph (CFG). There is a
//  * many-to-one relationship between CFG nodes and AST nodes.
//  *
//  * Only nodes that can be reached from an entry point are included in the CFG.
//  */
// class CfgNode extends CfgImpl::Node {
//   /** Gets the name of the primary QL class for this node. */
//   string getAPrimaryQlClass() { none() }

//   /** Gets the file of this control flow node. */
//   final File getFile() { result = this.getLocation().getFile() }

//   /** Gets a successor node of a given type, if any. */
//   final CfgNode getASuccessor(SuccessorType t) { result = super.getASuccessor(t) }

//   /** Gets an immediate successor, if any. */
//   final CfgNode getASuccessor() { result = this.getASuccessor(_) }

//   /** Gets an immediate predecessor node of a given flow type, if any. */
//   final CfgNode getAPredecessor(SuccessorType t) { result.getASuccessor(t) = this }

//   /** Gets an immediate predecessor, if any. */
//   final CfgNode getAPredecessor() { result = this.getAPredecessor(_) }

//   /** Gets the basic block that this control flow node belongs to. */
//   BasicBlock getBasicBlock() { result.getANode() = this }
// }








private class ProgramTree extends ControlFlowTree instanceof Program {
    override predicate propagatesAbnormal(AstNode child) { none() }

    override predicate first(AstNode first) { first(this.(Program).getChild(0).(CodeblockTree), first) }

    override predicate succ(AstNode pred, AstNode succ, Completion c) {
      succ.getProgram() = this and pred.getProgram() = this and
      (
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof BzOpcode and
      first(pred.(BzOpcode).getNextNode(c.(ConditionalJumpCompletion).getValue()).(Codeblock), succ)
      or
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof BnzOpcode and
      first(pred.(BnzOpcode).getNextNode(c.(ConditionalJumpCompletion).getValue()).(Codeblock), succ)
      or
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof BOpcode and
      c instanceof UnconditionalJumpCompletion and
      first(pred.(BOpcode).getTargetLabel().(Codeblock), succ)
      or
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof CallsubOpcode and
      c instanceof UnconditionalJumpCompletion and
      first(pred.(CallsubOpcode).getTargetLabel().(CodeblockTree), succ)
      or
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof RetsubOpcode and
      c instanceof RetsubCompletion and
      first(pred.(RetsubOpcode).predictRetsubReturn().(CodeblockTree), succ)

        or
        last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
        pred.getNextLine() instanceof Label and 
        // not (pred instanceof UnconditionalBranches 
        //   or pred instanceof SimpleConditionalBranches or pred instanceof ContractExitOpcode or
        //   pred instanceof MultiTargetConditionalBranch) 
          // and
        c instanceof SimpleCompletion and
        first(pred.getNextLine().(Codeblock), succ)
        or
        last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
        pred instanceof AssertOpcode and
        c.(AssertCompletion).getValue() = true and
        first(pred.getNextLine().(Codeblock), succ)
        or
        last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
        pred instanceof ReturnOpcode and c instanceof ReturnCompletion and succ = this.(Program)
        or
        last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
        pred instanceof ErrOpcode and c instanceof ErrCompletion and succ = this.(Program)
        or
        last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
        pred instanceof AssertOpcode and c.(AssertCompletion).getValue() = false and succ = this.(Program)

      //TODO: test
      or
      last(pred.getCodeblockStart().(CodeblockTree), pred, c) and
      pred instanceof MultiTargetConditionalBranch and
      c instanceof UnconditionalJumpCompletion and
      first(pred.(MultiTargetConditionalBranch).getTargetLabels(), succ)
      )
  }

  override predicate last(AstNode last, Completion c) {
    last.getProgram() = this and(
      last = this and c instanceof SimpleCompletion
      // or
      // c instanceof SimpleCompletion and
      // last instanceof Label and not exists(last.(Label).getNextLine())
    )
  }
}

private class CodeblockTree extends ControlFlowTree instanceof Codeblock{

  override predicate propagatesAbnormal(AstNode child) { none() }

  override predicate first(AstNode first) { first = this.getCodeblockStart() }

  override predicate succ(AstNode pred, AstNode succ, Completion c) {
    pred.isInSameCodeblock(this) and succ.isInSameCodeblock(this)
    and succ = pred.getNextLine() and c instanceof SimpleCompletion
  }

  override predicate last(AstNode last, Completion c) {
    last.endsACodeblock() and last.isInSameCodeblock(this)
    and (
      last instanceof ReturnOpcode and c instanceof ReturnCompletion
      or last instanceof ErrOpcode and c instanceof ErrCompletion
      or last instanceof AssertOpcode and c instanceof AssertCompletion
      or last instanceof BOpcode and c instanceof UnconditionalJumpCompletion
      or last instanceof CallsubOpcode and c instanceof UnconditionalJumpCompletion

      or last instanceof RetsubOpcode and c instanceof RetsubCompletion
      or last instanceof SimpleConditionalBranches and c instanceof ConditionalJumpCompletion
      or last.getNextLine() instanceof Label and not
        (last instanceof ContractExitOpcode or last instanceof UnconditionalBranches or
        last instanceof SimpleConditionalBranches or last instanceof MultiTargetConditionalBranch) 
        and c instanceof SimpleCompletion
    )
    // or last.isInSameCodeblock(this) and last.getNextLine() instanceof RetsubOpcode and c instanceof NormalCompletion
  }
}

private class OpcodeTree extends LeafTree instanceof AstNode {
  OpcodeTree(){
    not this instanceof Program
    and not this instanceof Codeblock
  }
}

// private class LabelTree extends LeafTree instanceof Label {}

// private class FunctionCallExpressionTree extends StandardPostOrderTree instanceof FunctionCallExpression
// {
//   override ControlFlowTree getChildNode(int i) { result = super.getArgument(i) }
// }

// private class BinaryOpExpressionTree extends StandardPostOrderTree instanceof BinaryOpExpression {
//   override ControlFlowTree getChildNode(int i) {
//     result = super.getLhs() and i = 0
//     or
//     result = super.getRhs() and i = 1
//   }
// }

// private class ConditionalExpressionTree extends PostOrderTree instanceof ConditionalExpression {
//   override predicate propagatesAbnormal(AstNode child) { none() }

//   override predicate first(AstNode first) { first(super.getCondition(), first) }

//   override predicate succ(AstNode pred, AstNode succ, Completion c) {
//     last(super.getCondition(), pred, c) and
//     (
//       first(super.getThen(), succ) and c.(BooleanCompletion).getValue() = true
//       or
//       first(super.getElse(), succ) and c.(BooleanCompletion).getValue() = false
//     )
//     or
//     last(super.getThen(), pred, c) and
//     succ = this and
//     c instanceof SimpleCompletion
//     or
//     last(super.getElse(), pred, c) and
//     succ = this and
//     c instanceof SimpleCompletion
//   }
// }

// /**
//  * From https://llvm.org/docs/tutorial/MyFirstLanguageFrontend/LangImpl05.html#code-generation-for-the-for-loop in the LLVM tutorial it appears that
//  * for loop conditions are checked at the end of the body, not the start. So for loops are roughly translated as follows:
//  * ```
//  * for VAR = INIT, CONDITION, STEP in
//  *   BODY
//  * ```
//  * -->
//  * ```
//  * VAR = INIT
//  * do {
//  *   BODY
//  *   VAR = VAR + STEP
//  * } while (CONDITION)
//  * ```
//  */
// private class ForExpressionTree extends PostOrderTree instanceof ForExpression {
//   override predicate propagatesAbnormal(AstNode child) { none() }

//   override predicate first(AstNode first) { first(super.getInitializer(), first) }

//   override predicate succ(AstNode pred, AstNode succ, Completion c) {
//     last(super.getInitializer(), pred, c) and
//     first(super.getBody(), succ) and
//     c instanceof SimpleCompletion
//     or
//     last(super.getCondition(), pred, c) and
//     (
//       first(super.getBody(), succ) and c.(BooleanCompletion).getValue() = true
//       or
//       succ = this and c.(BooleanCompletion).getValue() = false
//     )
//     or
//     last(super.getBody(), pred, c) and
//     first(super.getStep(), succ) and
//     c instanceof SimpleCompletion
//     or
//     last(super.getStep(), pred, c) and
//     first(super.getCondition(), succ) and
//     c instanceof SimpleCompletion
//   }
// }

// private class InitializerTree extends StandardPostOrderTree instanceof Initializer {
//   override ControlFlowTree getChildNode(int i) { result = super.getExpression() and i = 0 }
// }

// private class NumberTree extends LeafTree instanceof Number { }

// private class ParenExpressionTree extends StandardPostOrderTree instanceof ParenExpression {
//   override ControlFlowTree getChildNode(int i) { result = super.getExpression() and i = 0 }
// }

// private class UnaryOpExpressionTree extends StandardPostOrderTree instanceof UnaryOpExpression {
//   override ControlFlowTree getChildNode(int i) { result = super.getOperand() and i = 0 }
// }

// private class VarInExpressionTree extends StandardPostOrderTree instanceof VarInExpression {
//   override ControlFlowTree getChildNode(int i) {
//     result = super.getInitializer(i)
//     or
//     result = super.getBody() and i = count(super.getInitializer(_))
//   }
// }

// private class VariableExpressionTree extends LeafTree instanceof VariableExpression { }