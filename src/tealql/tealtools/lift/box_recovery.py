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
# box ops that MODIFY a box (vs read it) -- a write to an attacker-chosen box is
# worse than a read.
_WRITE_OPS = frozenset({"box_put", "box_replace", "box_splice", "box_del",
                        "box_create", "box_resize"})


class _BoxFlow:
    """Shared interprocedural dataflow over a lifted program's box ops: the
    def-use map, the parameter->call-site-argument edges, and the two walks both
    the schema recovery and the access-control detector need -- ``deref`` (resolve
    a value to its source, hopping params to the caller) and ``roots`` (the set of
    source-op tags a value is built from, e.g. txn Sender / ApplicationArgs)."""

    def __init__(self, main, subs):
        import puya.ir.models as M
        from puya.ir.avm_ops import AVMOp
        self.M, self.AVMOp = M, AVMOp
        self.subs_all = [main, *subs]
        self.reg_def: dict = {}      # (sub_id, name, ver) -> defining source
        self.param_idx: dict = {}    # (sub_id, name, ver) -> parameter position
        self.callsites: dict = {}    # (callee_id, index) -> [(caller_sub, arg)]
        for s in self.subs_all:
            for i, p in enumerate(s.parameters):
                self.param_idx[(s.id, p.name, p.version)] = i
            for bb in s.body:
                for o in bb.ops:
                    src0 = o.source if isinstance(o, M.Assignment) else o
                    if isinstance(o, M.Assignment):
                        for t in o.targets:
                            self.reg_def[(s.id, t.name, t.version)] = o.source
                    if isinstance(src0, M.InvokeSubroutine):
                        for i, a in enumerate(src0.args):
                            self.callsites.setdefault(
                                (src0.target.id, i), []).append((s, a))

    def _keysig(self, v, s):
        M, AVMOp = self.M, self.AVMOp
        if isinstance(v, M.BytesConstant):
            return ("c", v.value)
        if isinstance(v, M.Register):
            d = self.reg_def.get((s.id, v.name, v.version))
            if isinstance(d, M.Intrinsic) and d.op is AVMOp.concat and len(d.args) == 2:
                p, _ = self.deref(d.args[0], s)
                if isinstance(p, M.BytesConstant):
                    return ("m", p.value)
            return ("r", s.id, v.name, v.version)
        return ("?", id(v))

    def deref(self, val, sub, seen=frozenset()):
        """Resolve ``val`` (in ``sub``) to its meaningful source, following register
        copies AND -- INTERPROCEDURALLY -- a subroutine PARAMETER back to the
        caller's argument through the ``InvokeSubroutine`` edges, when every call
        site passes a value that resolves the same way. Returns ``(value, sub)``."""
        M = self.M
        cur, csub = val, sub
        while isinstance(cur, M.Register):
            k = (csub.id, cur.name, cur.version)
            if k in seen:
                return cur, csub
            seen = seen | {k}
            if k in self.param_idx:
                ds = [self.deref(a, cs, seen)
                      for cs, a in self.callsites.get((csub.id, self.param_idx[k]), [])]
                sigs = {self._keysig(v, s) for v, s in ds}
                if len(sigs) == 1 and next(iter(sigs))[0] != "?":
                    cur, csub = ds[0]
                    continue
                return cur, csub
            src = self.reg_def.get(k)
            if isinstance(src, M.Register):
                cur = src
                continue
            return cur, csub
        return cur, csub

    def roots(self, val, sub):
        """The set of SOURCE-OP tags reachable BACKWARD from ``val`` -- the txn
        fields / arg reads it is built from. Interprocedural (hops params to every
        caller argument) and full (walks all intrinsic operands). Tags: ``Sender``
        (``txn Sender``), ``AppArgs`` (``txna ApplicationArgs``)."""
        M = self.M
        out: set = set()
        seen: set = set()
        stack = [(val, sub)]
        while stack:
            v, s = stack.pop()
            if not isinstance(v, M.Register):
                continue
            k = (s.id, v.name, v.version)
            if k in seen:
                continue
            seen.add(k)
            if k in self.param_idx:
                for cs, a in self.callsites.get((s.id, self.param_idx[k]), []):
                    stack.append((a, cs))
                continue
            d = self.reg_def.get(k)
            if isinstance(d, M.Intrinsic):
                nm = d.op.name
                imm = " ".join(str(x) for x in d.immediates)
                if nm in ("txn", "gtxns", "gtxnsas") and "Sender" in imm:
                    out.add("Sender")
                if nm in ("txna", "txnas", "gtxna", "gtxnas") and "ApplicationArgs" in imm:
                    out.add("AppArgs")
                for a in d.args:
                    stack.append((a, s))
            elif isinstance(d, M.Register):
                stack.append((d, s))
        return out

    def has_sender_arg_check(self):
        """Whether the program compares an ApplicationArgs-derived value against a
        Sender-derived one anywhere (``eq`` / ``neq``) -- evidence it VALIDATES a
        caller-supplied identity against the real sender, which makes a
        caller-supplied address key safe. Used to suppress the access-control
        finding conservatively (favour precision)."""
        M, AVMOp = self.M, self.AVMOp
        for s in self.subs_all:
            for bb in s.body:
                for o in bb.ops:
                    src = o.source if isinstance(o, M.Assignment) else o
                    if isinstance(src, M.Intrinsic) and src.op in (AVMOp.eq, AVMOp.neq) \
                            and len(src.args) == 2:
                        r = self.roots(src.args[0], s) | self.roots(src.args[1], s)
                        if "Sender" in r and "AppArgs" in r:
                            return True
        return False


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

    flow = _BoxFlow(main, subs)
    subs_all, reg_def, deref = flow.subs_all, flow.reg_def, flow.deref

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


@dataclass
class BoxAccessFinding:
    prefix: bytes
    key_type: str
    written: bool = False
    ops: set = field(default_factory=set)

    def render(self) -> str:
        mode = "WRITE" if self.written else "read-only"
        return (f"BoxMap prefix={self.prefix.decode('latin-1')!r} "
                f"key={self.key_type} — CALLER-SUPPLIED address, not sender-bound "
                f"({mode})  [{','.join(sorted(self.ops))}]")


def box_access_control(main, subs, guesses=None, confident=None) -> list:
    """Access-control leads over box storage: an ADDRESS-keyed ``BoxMap``
    (``BoxMap[Account, V]`` -- per-user data) whose key is CALLER-SUPPLIED (traces
    to ``ApplicationArgs``) instead of bound to ``txn Sender``. The caller then
    chooses WHOSE box to touch, so an attacker can read -- or, worse, overwrite --
    any account's slot: cross-user box access / impersonation.

    Precise by construction: it keys on the recovered address KEY TYPE (NOT "any
    caller-supplied key" -- a listing / auction-id map is legitimately
    caller-chosen), and it is SUPPRESSED when the program validates a caller
    identity against the sender anywhere (:meth:`_BoxFlow.has_sender_arg_check`).
    Interprocedural: the key is resolved and its provenance traced through call
    edges. Read-only. One :class:`BoxAccessFinding` per offending prefix; the
    ``written`` flag marks a map an attacker can WRITE (not just read)."""
    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp

    from . import to_puya_ir
    if guesses is None:
        guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)

    flow = _BoxFlow(main, subs)
    if flow.has_sender_arg_check():
        return []                        # validates caller vs sender -> safe

    from puya.ir.types_ import SizedBytesType

    def _addr_label(tail):
        """The address key label if ``tail`` is RECOGNISABLY a 32-byte address,
        else None -- the whole precision of the detector. Three ways a key tail is
        known to be an address: the usage-backward ``account`` ir_type (used as an
        address elsewhere); a provably 32-byte value (``SizedBytesType(32)`` -- a
        real per-account key decodes/slices to address width, which a numeric id
        never does); or the speculative arc4.Address guess. A raw untyped
        caller value of unknown width is NOT flagged -- we genuinely can't tell an
        address from an opaque id, so we stay silent rather than false-positive."""
        if not isinstance(tail, M.Register):
            return None
        t = tail.ir_type
        if str(t) == "account":
            return "account"
        if isinstance(t, SizedBytesType) and t.num_bytes == 32:
            return "bytes[32] (address-width)"
        e = guesses.get(id(tail))
        if e is not None and to_puya_ir.is_address_encoding(e):
            return "arc4.Address"
        return None

    found: dict = {}
    for s in flow.subs_all:
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic)
                        and src.op.name.startswith("box_") and src.args):
                    continue
                kv, ksub = flow.deref(src.args[0], s)
                kd = (flow.reg_def.get((ksub.id, kv.name, kv.version))
                      if isinstance(kv, M.Register) else None)
                if not (isinstance(kd, M.Intrinsic) and kd.op is AVMOp.concat
                        and len(kd.args) == 2):
                    continue
                p, _ = flow.deref(kd.args[0], ksub)
                if not isinstance(p, M.BytesConstant):
                    continue
                label = _addr_label(kd.args[1])
                if label is None:
                    continue
                rr = flow.roots(kd.args[1], ksub)
                if not ("AppArgs" in rr and "Sender" not in rr):
                    continue
                f = found.get(p.value)
                if f is None:
                    f = found[p.value] = BoxAccessFinding(p.value, label)
                f.ops.add(src.op.name)
                if src.op.name in _WRITE_OPS:
                    f.written = True
    return sorted(found.values(), key=lambda x: x.prefix)
