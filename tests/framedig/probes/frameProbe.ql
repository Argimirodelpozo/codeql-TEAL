/**
 * @id tealql/debug/frame-probe
 * @kind table
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.StackManipulation
import codeql.teal.SSA.SSA

class Frame extends AstNode {
  Frame() { this instanceof FrameDigOpcode or this instanceof FrameBuryOpcode }

  string kind() {
    if this instanceof FrameDigOpcode then result = "dig" else result = "bury"
  }

  Subroutine getSub() {
    result = this.(FrameDigOpcode).getSubroutine()
    or
    result = this.(FrameBuryOpcode).getSubroutine()
  }

  int getConsumed() {
    result = this.(FrameDigOpcode).getNumberOfConsumedArgs()
    or
    result = this.(FrameBuryOpcode).getNumberOfConsumedArgs()
  }

  int getOutputs() {
    result = this.(FrameDigOpcode).getNumberOfOutputArgs()
    or
    result = this.(FrameBuryOpcode).getNumberOfOutputArgs()
  }

  int getImm() {
    result = this.(FrameDigOpcode).getImmediate()
    or
    result = this.(FrameBuryOpcode).getImmediate()
  }
}

from Frame f, string kind, int line, int imm, int subLine, int consumed, int outputs, int ssaVarCount
where
  kind = f.kind() and
  line = f.getLocation().getStartLine() and
  imm = f.getImm() and
  (
    if exists(f.getSub())
    then subLine = f.getSub().getLocation().getStartLine()
    else subLine = -1
  ) and
  (
    if exists(int k | k = f.getConsumed()) then consumed = f.getConsumed() else consumed = -1
  ) and
  (
    if exists(int k | k = f.getOutputs()) then outputs = f.getOutputs() else outputs = -1
  ) and
  ssaVarCount = count(SSAVar v | v.getDeclarationNode() = f)
select line, kind, imm, subLine, consumed, outputs, ssaVarCount
