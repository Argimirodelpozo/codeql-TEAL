private import codeql.teal.ast.AST


module Completion {
    private newtype TCompletion =
      TSimpleCompletion() or
      TConditionalJumpCompletion(boolean b){ b in [false, true] } or
      TUnconditionalJumpCompletion() or
      TErrCompletion() or
      TAssertCompletion(boolean b){ b in [false, true] } or
      TReturnCompletion() or
      TRetsubCompletion()
      // TRetsubCompletion(CallsubOpcode callingNode)
  
    abstract class Completion extends TCompletion {
      abstract string toString();
  
      predicate isValidForSpecific(AstNode e) { none() }
  
      predicate isValidFor(AstNode e) { this.isValidForSpecific(e) }
  
      abstract SuccessorType getAMatchingSuccessorType();
    }
  
    abstract class NormalCompletion extends Completion { }
  
    class SimpleCompletion extends NormalCompletion, TSimpleCompletion {
      override string toString() { result = "SimpleCompletion" }
  
      override predicate isValidFor(AstNode e) { not any(Completion c).isValidForSpecific(e) }
  
      override NormalSuccessor getAMatchingSuccessorType() { any() }
    }
  
    class ConditionalJumpCompletion extends NormalCompletion, TConditionalJumpCompletion {
      boolean value;
  
      ConditionalJumpCompletion() { this = TConditionalJumpCompletion(value) }
  
      override string toString() { result = "ConditionalJumpCompletion(" + value + ")" }
  
      override predicate isValidForSpecific(AstNode e) {e instanceof SimpleConditionalBranches}
  
      override BooleanSuccessor getAMatchingSuccessorType() { result.getValue() = value }
  
      final boolean getValue() { result = value }
    }
  
    class ReturnCompletion extends Completion, TReturnCompletion {
      override string toString() { result = "ReturnCompletion" }
  
      override predicate isValidForSpecific(AstNode e) { e instanceof ReturnOpcode }
  
      override NormalSuccessor getAMatchingSuccessorType() { none() }
    }
  
    class UnconditionalJumpCompletion extends Completion, TUnconditionalJumpCompletion {
      override string toString() { result = "UnconditionalJumpCompletion" }
  
      override predicate isValidForSpecific(AstNode e) { e instanceof BOpcode or e instanceof CallsubOpcode}
  
      override NormalSuccessor getAMatchingSuccessorType() { any() }
    }
  
    class RetsubCompletion extends Completion, TRetsubCompletion {
      override string toString() { result = "RetsubCompletion" }

      // CallsubOpcode getOriginalCallsub(){
      //   this = TRetsubCompletion(result)
      // }
  
      override predicate isValidForSpecific(AstNode e) { e instanceof RetsubOpcode 
        // and 
        // e.(RetsubOpcode).getEntrypoint() = this.getOriginalCallsub().getTargetLabel()
      }
  
      override RetsubSuccessor getAMatchingSuccessorType() { any() }
    }
  
    class ErrCompletion extends Completion, TErrCompletion {
      override string toString() { result = "ErrCompletion" }
  
      override predicate isValidForSpecific(AstNode e) { e instanceof ErrOpcode }
  
      override NormalSuccessor getAMatchingSuccessorType() { none() }
    }
  
    class AssertCompletion extends Completion, TAssertCompletion {
      boolean value;
      AssertCompletion() { this = TAssertCompletion(value) }
  
      override string toString() { result = "AssertCompletion" }
  
      override predicate isValidForSpecific(AstNode e) { e instanceof AssertOpcode }
  
      override BooleanSuccessor getAMatchingSuccessorType() { if value = true then result.getValue() = true else none() }
  
      final boolean getValue() { result = value }
    }
  
    cached
    private newtype TSuccessorType =
      TNormalSuccessor() or
      TBooleanSuccessor(boolean b) { b in [false, true] } or
      TRetsubSuccessor(CallsubOpcode n)
      // or
      // TReturnSuccessor()
  
    class SuccessorType extends TSuccessorType {
      string toString() { none() }
    }
  
    class NormalSuccessor extends SuccessorType, TNormalSuccessor {
      override string toString() { result = "NormalSuccessor" }
    }
  
    class BooleanSuccessor extends SuccessorType, TBooleanSuccessor {
      boolean value;
  
      BooleanSuccessor() { this = TBooleanSuccessor(value) }
  
      override string toString() { result = "BooleanSuccessor(" + value.toString() + ")" }
  
      boolean getValue() { result = value }
    }

    class RetsubSuccessor extends SuccessorType, TRetsubSuccessor {
      override string toString() {result = "retsub"}
    // class ReturnSuccessor extends SuccessorType, TReturnSuccessor {
    //   override string toString() { result = "return" }
    }
  }