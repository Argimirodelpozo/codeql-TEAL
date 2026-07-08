"""Box STORAGE-SCHEMA recovery: reconstruct ``Box`` / ``BoxMap`` declarations
from the box opcodes in the lifted Puya IR.

Algorand box storage is a flat ``bytes -> bytes`` key space, but Puya's source
abstractions leave a recoverable fingerprint:

* a **Box** (a single named box) compiles to box ops keyed by a CONSTANT byte
  string -- the box name;
* a **BoxMap[K, V]** compiles to box ops keyed by ``concat(key_prefix, encode(k))``
  -- a constant prefix followed by the encoded map key. The prefix is the
  ``BoxMap``'s name; the tail is one encoded ``K``.

So the schema is: group box ops by their key shape, name each group (the constant
/ the prefix), and recover the KEY type (the non-prefix tail) and VALUE type by
running the same ABI type recovery
(:func:`tealql.tealtools.lift.to_puya_ir.guess_encoded_types_scored`) over the box
key tail and the box value operand/result. Value operands by op: ``box_put`` arg1,
``box_replace`` arg2, ``box_splice`` arg3; value RESULTS: ``box_get`` /
``box_extract`` target0. The key is always arg0.

Keys reached as a subroutine PARAMETER (the ``BoxMap`` abstraction commonly passes
the built key into a helper) are reported as one ``dynamic`` group per program --
the concrete name lives at the caller (interprocedural; a documented limit).

Side-channel / read-only: never mutates the IR.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BoxSchema:
    kind: str                      # "Box" | "BoxMap" | "dynamic"
    name: "bytes | None"           # Box: the key; BoxMap: the prefix; dynamic: None
    key_type: "str | None" = None  # BoxMap: recovered encoded-key type
    value_type: "str | None" = None
    value_confident: bool = False
    ops: set = field(default_factory=set)

    def render(self) -> str:
        who = (repr(self.name.decode("latin-1")) if self.name is not None
               else "<dynamic key>")
        val = self.value_type or "bytes (opaque)"
        conf = "" if self.value_confident or self.value_type is None \
            else " (speculative)"
        if self.kind == "BoxMap":
            return (f"BoxMap prefix={who} key={self.key_type or '?'} "
                    f"value={val}{conf}  [{','.join(sorted(self.ops))}]")
        if self.kind == "Box":
            return f"Box {who} value={val}{conf}  [{','.join(sorted(self.ops))}]"
        return f"<box via passed-in key> value={val}{conf}  [{','.join(sorted(self.ops))}]"


# value-operand argument index by op (the key is always arg0); ops absent here
# carry their value as a RESULT target instead (box_get / box_extract).
_VALUE_ARG = {"box_put": 1, "box_replace": 2, "box_splice": 3}
_VALUE_RESULT = {"box_get", "box_extract"}


def recover_box_schema(main, subs, guesses=None, confident=None) -> list:
    """Reconstruct the ``Box`` / ``BoxMap`` schema of a lifted program as a list
    of :class:`BoxSchema` (one per distinct box name / prefix, plus at most one
    ``dynamic`` group). ``guesses`` / ``confident`` may be supplied to reuse an
    existing :func:`guess_encoded_types_scored` run; otherwise it is computed."""
    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp

    from . import to_puya_ir
    if guesses is None:
        guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)
    confident = confident or {}

    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[(t.name, t.version)] = o.source

    def resolve(val):
        """Follow register copies to the underlying source (intrinsic / const /
        param); returns the source object (or the value itself)."""
        seen = set()
        cur = val
        while isinstance(cur, M.Register):
            k = (cur.name, cur.version)
            if k in seen:
                break
            seen.add(k)
            src = reg_def.get(k)
            if isinstance(src, M.Register):
                cur = src
                continue
            return src if src is not None else cur
        return cur

    def key_type_str(val):
        """A short type name for a box KEY tail: the recovered ABI encoding if
        guessed, else the register's own ir_type (a uint64/bytes[N] encoded key is
        still informative here), else a byte size."""
        if isinstance(val, M.Register) and id(val) in guesses:
            return str(guesses[id(val)].encoding)
        if isinstance(val, M.Register):
            return str(val.ir_type)
        if isinstance(val, M.BytesConstant):
            return f"bytes[{len(val.value)}]"
        return None

    def value_info(val):
        """``(type_str, confident)`` for a box VALUE operand/result. A recovered
        ABI encoding carries its speculative/confident bit; a specific IR type
        (sized bytes, account, biguint, ...) is the REAL type, so confident; plain
        ``bytes`` / ``uint64`` is uninformative -> ``(None, ...)`` (rendered
        opaque)."""
        if isinstance(val, M.Register) and id(val) in guesses:
            return str(guesses[id(val)].encoding), bool(confident.get(id(val)))
        if isinstance(val, M.Register):
            s = str(val.ir_type)
            return (s, True) if s not in ("bytes", "uint64", "any", "bool") \
                else (None, False)
        if isinstance(val, M.BytesConstant):
            return f"bytes[{len(val.value)}]", True
        return None, False

    # group -> BoxSchema, keyed by ('Box', name) / ('BoxMap', prefix) / ('dynamic',)
    groups: dict = {}

    def group_for(kind, name):
        gk = (kind, name)
        if gk not in groups:
            groups[gk] = BoxSchema(kind=kind, name=name)
        return groups[gk]

    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic)
                        and src.op.name.startswith("box_") and src.args):
                    continue
                op = src.op.name
                key_src = resolve(src.args[0])
                # classify the key shape
                if isinstance(key_src, M.BytesConstant):
                    sch = group_for("Box", key_src.value)
                elif (isinstance(key_src, M.Intrinsic) and key_src.op is AVMOp.concat
                      and len(key_src.args) == 2
                      and isinstance(resolve(key_src.args[0]), M.BytesConstant)):
                    prefix = resolve(key_src.args[0]).value
                    sch = group_for("BoxMap", prefix)
                    kt = key_type_str(key_src.args[1])
                    if kt and sch.key_type in (None, kt):
                        sch.key_type = kt
                else:
                    sch = group_for("dynamic", None)
                sch.ops.add(op)
                # recover the value type
                v = None
                if op in _VALUE_ARG and len(src.args) > _VALUE_ARG[op]:
                    v = src.args[_VALUE_ARG[op]]
                elif op in _VALUE_RESULT and isinstance(o, M.Assignment) and o.targets:
                    v = o.targets[0]
                if v is not None:
                    vt, vc = value_info(v)
                    if vt and sch.value_type in (None, vt):
                        sch.value_type, sch.value_confident = vt, vc

    return sorted(groups.values(),
                  key=lambda x: (x.kind, x.name or b""))
