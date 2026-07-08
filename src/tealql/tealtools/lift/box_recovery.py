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

A box key built in a caller and passed into a box helper as a PARAMETER is
resolved INTERPROCEDURALLY -- the whole program is in the IR, so ``deref`` hops a
parameter back to the caller's argument through the ``InvokeSubroutine`` edges
(when every call site passes a key that resolves the same way). Only a genuinely
divergent / unresolved key (different call sites build different boxes) stays a
``dynamic`` group.

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

    subs_all = [main, *subs]
    reg_def: dict = {}          # (sub_id, name, ver) -> defining source
    param_idx: dict = {}        # (sub_id, name, ver) -> parameter position
    callsites: dict = {}        # (callee_id, index) -> [(caller_sub, arg_value)]
    for s in subs_all:
        for i, p in enumerate(s.parameters):
            param_idx[(s.id, p.name, p.version)] = i
        for bb in s.body:
            for o in bb.ops:
                src0 = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[(s.id, t.name, t.version)] = o.source
                if isinstance(src0, M.InvokeSubroutine):
                    for i, a in enumerate(src0.args):
                        callsites.setdefault((src0.target.id, i), []).append((s, a))

    def _keysig(v, s):
        """A structural signature used to check that all call sites of a helper
        pass the SAME box key: a const's bytes, or a concat's constant prefix,
        else the value's own identity (which won't match across sites)."""
        if isinstance(v, M.BytesConstant):
            return ("c", v.value)
        if isinstance(v, M.Register):
            d = reg_def.get((s.id, v.name, v.version))
            if isinstance(d, M.Intrinsic) and d.op is AVMOp.concat and len(d.args) == 2:
                p, _ = deref(d.args[0], s)
                if isinstance(p, M.BytesConstant):
                    return ("m", p.value)
            return ("r", s.id, v.name, v.version)
        return ("?", id(v))

    def deref(val, sub, seen=frozenset()):
        """Resolve ``val`` (living in ``sub``) to its meaningful source, following
        register copies AND -- INTERPROCEDURALLY -- a subroutine PARAMETER back to
        the caller's argument through the ``InvokeSubroutine`` edges, when every
        call site passes a key that resolves the same way (the whole program is in
        the IR, so a box key built in a caller and passed into a box helper is
        recoverable). Returns ``(value, sub)`` stopped at a const or a Register
        whose def is an intrinsic; an unresolved / disagreeing param stays put
        (=> a dynamic box)."""
        cur, csub = val, sub
        while isinstance(cur, M.Register):
            k = (csub.id, cur.name, cur.version)
            if k in seen:
                return cur, csub
            seen = seen | {k}
            if k in param_idx:
                ds = [deref(a, cs, seen)
                      for cs, a in callsites.get((csub.id, param_idx[k]), [])]
                sigs = {_keysig(v, s) for v, s in ds}
                if len(sigs) == 1 and next(iter(sigs))[0] != "?":
                    cur, csub = ds[0]
                    continue
                return cur, csub                 # 0 / disagreeing call sites
            src = reg_def.get(k)
            if isinstance(src, M.Register):
                cur = src
                continue
            return cur, csub                     # register defined by intrinsic / const
        return cur, csub

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

    for s in subs_all:
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic)
                        and src.op.name.startswith("box_") and src.args):
                    continue
                op = src.op.name
                kv, ksub = deref(src.args[0], s)
                # classify the key shape (interprocedurally resolved)
                if isinstance(kv, M.BytesConstant):
                    sch = group_for("Box", kv.value)
                else:
                    kd = (reg_def.get((ksub.id, kv.name, kv.version))
                          if isinstance(kv, M.Register) else None)
                    if (isinstance(kd, M.Intrinsic) and kd.op is AVMOp.concat
                            and len(kd.args) == 2):
                        p, _ = deref(kd.args[0], ksub)
                    else:
                        p = None
                    if isinstance(p, M.BytesConstant):
                        sch = group_for("BoxMap", p.value)
                        kt = key_type_str(kd.args[1])
                        if kt and sch.key_type in (None, kt):
                            sch.key_type = kt
                    else:
                        sch = group_for("dynamic", None)
                sch.ops.add(op)
                # recover the value type (also resolving a value passed in as a param)
                v = None
                if op in _VALUE_ARG and len(src.args) > _VALUE_ARG[op]:
                    v = src.args[_VALUE_ARG[op]]
                elif op in _VALUE_RESULT and isinstance(o, M.Assignment) and o.targets:
                    v = o.targets[0]
                if v is not None:
                    vv, _ = deref(v, s)
                    vt, vc = value_info(vv)
                    if vt and sch.value_type in (None, vt):
                        sch.value_type, sch.value_confident = vt, vc

    return sorted(groups.values(),
                  key=lambda x: (x.kind, x.name or b""))
