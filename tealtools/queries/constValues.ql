/**
 * @name Resolved Constant Values per SSAVar Output
 * @description For every constant-pushing opcode, emit one row per
 *              output index with the resolved literal value:
 *
 *                - ``IntegerConstant`` (``intc_*``/``intc``/``int``/``pushint``):
 *                  one output, ``outIdx = 1``.
 *                - ``BytesConstant`` (``bytec_*``/``bytec``/``pushbytes``):
 *                  one output, ``outIdx = 1``.
 *                - ``PushintsOpcode``: one row per pushed literal,
 *                  ``outIdx = 1..N``.
 *                - ``PushbytessOpcode``: one row per pushed literal,
 *                  ``outIdx = 1..N`` (limited by tree-sitter packing —
 *                  the grammar may report N=1 for multi-value pushbytess).
 *
 *              This query reports ONLY direct literal sources — sound for
 *              "must-be" semantics. Dataflow-aware widening is handled by
 *              ``mustValues.ql``, which propagates literals through
 *              must-equal pass-throughs / arithmetic / phis.
 *
 *              Row: astFile, astLine, outIdx, kind, value
 *              where kind ∈ {"int", "bytes"}.
 * @id tealql/python-analysis/const-values
 */

import codeql.teal.ast.AST
import codeql.teal.ast.opcodes.Constants

from AstNode n, int outIdx, string kind, string value
where
  exists(IntegerConstant ic |
    ic = n and outIdx = 1 and kind = "int" and value = ic.getValue().toString()
  )
  or
  exists(BytesConstant bc |
    bc = n and outIdx = 1 and kind = "bytes" and value = bc.getValue()
  )
  or
  exists(PushintsOpcode op, int i |
    op = n and i in [0 .. op.getNumberOfOutputArgs() - 1] and
    outIdx = i + 1 and kind = "int" and value = op.getValue(i).toString()
  )
  or
  exists(PushbytessOpcode op, int i |
    op = n and i in [0 .. op.getNumberOfOutputArgs() - 1] and
    outIdx = i + 1 and kind = "bytes" and value = op.getValue(i)
  )
select n.getLocation().getFile().getRelativePath(),
       n.getLocation().getStartLine(),
       outIdx, kind, value
