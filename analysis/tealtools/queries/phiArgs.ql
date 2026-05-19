/**
 * @name Phi Arguments
 * @description Per phi, one row per "argument" used to expand its label:
 *
 *              - DirectPhi: one row per ``getOriginatingInput()`` SSAVar.
 *                argKind = "SSAVar"; argIdx = internalOutputIndex.
 *              - IndirectPhi: exactly one row pointing at its root
 *                DirectPhi (via ``getGenerator()``). argKind = "DirectPhi";
 *                argIdx = initialStackIndex.
 *
 *              Consumers can render DirectPhi as ``phi(V#1@L10, V#1@L20)``
 *              and IndirectPhi as ``phi(phi(V#1@L10, V#1@L20))`` by
 *              recursively looking up the referenced arg.
 *
 *              Row: phiFile, phiLine, phiStackIdx, phiKind,
 *                   argFile, argLine, argIdx, argKind
 * @id tealql/python-analysis/phi-args
 */

import codeql.teal.ast.AST
import codeql.teal.SSA.SSA

from
  string phiFile, int phiLine, int phiStackIdx, string phiKind,
  string argFile, int argLine, int argIdx, string argKind
where
  // DirectPhi: one row per originating SSAVar.
  exists(DirectPhi p, SSAVar v |
    v = p.getOriginatingInput() and
    phiFile = p.getLocation().getFile().getRelativePath() and
    phiLine = p.getLocation().getStartLine() and
    phiStackIdx = p.getInitialStackIndex() and
    phiKind = "DirectPhi" and
    argFile = v.getLocation().getFile().getRelativePath() and
    argLine = v.getLocation().getStartLine() and
    argIdx = v.getInternalOutputIndex() and
    argKind = "SSAVar"
  )
  or
  // IndirectPhi: point at the root DirectPhi (getGenerator walks the chain).
  exists(IndirectPhi ip, DirectPhi root |
    root = ip.getGenerator() and
    phiFile = ip.getLocation().getFile().getRelativePath() and
    phiLine = ip.getLocation().getStartLine() and
    phiStackIdx = ip.getInitialStackIndex() and
    phiKind = "IndirectPhi" and
    argFile = root.getLocation().getFile().getRelativePath() and
    argLine = root.getLocation().getStartLine() and
    argIdx = root.getInitialStackIndex() and
    argKind = "DirectPhi"
  )
select phiFile, phiLine, phiStackIdx, phiKind,
       argFile, argLine, argIdx, argKind
