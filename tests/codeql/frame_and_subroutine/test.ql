/**
 * Subroutine + frame opcodes: assert FrameDigOpcode.getImmediate()
 * preserves sign, ProtoOpcode exposes input/output counts, and
 * CallsubOpcode resolves to the target label by name.
 *
 * Frame-related extractor regressions are silent and catastrophic
 * — every detector that walks subroutine call graphs would
 * misbehave. This locks the public surface.
 */
import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.StackManipulation
import codeql.teal.ast.opcodes.ControlFlow

from int line, string opName, string detail
where
  exists(FrameDigOpcode f |
    line = f.getLocation().getStartLine() and
    opName = "frame_dig" and
    detail = f.getImmediate().toString()
  )
  or
  exists(FrameBuryOpcode f |
    line = f.getLocation().getStartLine() and
    opName = "frame_bury" and
    detail = f.getImmediate().toString()
  )
  or
  exists(ProtoOpcode p |
    line = p.getLocation().getStartLine() and
    opName = "proto" and
    detail =
      p.getNumberOfSubroutineInputArgs().toString()
      + " in / "
      + p.getNumberOfSubroutineOutputArgs().toString()
      + " out"
  )
  or
  exists(CallsubOpcode c |
    line = c.getLocation().getStartLine() and
    opName = "callsub" and
    detail = c.getTargetLabel().getName()
  )
select line, opName, detail order by line
