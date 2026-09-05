"""Isolate protocol opcodes newer than the pinned tree-sitter grammar.

Only signatures and immediate forms present in the pinned specification are
accepted. Replaced lines retain byte offsets so native grammar diagnostics and
source locations remain accurate. Existing grammar recovery stays separate.
"""
from ..diagnostics.errors import ParseDiagnostic
from ..language.spec import PUYA_57_UNSUPPORTED, opcode_spec
from .ast import ZeroArgumentOpcode, Location


def protocol_nodes(source: bytes, file: str):
    if not any(token in source for token in (b"app_box_", b"poseidon2", b"app_params_set")):
        return source, [], []
    masked, nodes, diagnostics = [], [], []
    version = 1
    for row, raw in enumerate(source.splitlines(keepends=True), 1):
        code = raw.split(b'//', 1)[0].strip()
        words = code.decode('utf-8', 'replace').split()
        if words[:2] == ['#pragma', 'version'] and len(words) == 3 and words[2].isdigit():
            version = int(words[2])
        if not words or words[0] not in PUYA_57_UNSUPPORTED:
            masked.append(raw)
            continue
        spec = opcode_spec(words[0], version)
        valid = spec is not None and len(words) - 1 == len(spec.immediates)
        if valid and spec.fields:
            valid = words[1] in spec.fields and spec.fields[words[1]][1] <= version
        if valid:
            column = len(raw) - len(raw.lstrip())
            nodes.append(ZeroArgumentOpcode(Location(file, row, column, row, column + len(code)),
                                 code.decode('utf-8', 'replace')))
        else:
            diagnostics.append(ParseDiagnostic(file=file, start_line=row, end_line=row,
                snippet=f'unsupported version or invalid immediate: {code.decode("utf-8", "replace")}'))
        masked.append(bytes(c if c in (10, 13) else 32 for c in raw))
    return b''.join(masked), nodes, diagnostics
