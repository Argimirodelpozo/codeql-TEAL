"""STORAGE-SCHEMA recovery: reconstruct Puya's ``ContractState`` model -- the
GLOBAL / LOCAL / BOX storage keys and maps -- from the lifted IR.

Puya treats the three storages identically (``ContractMetaData`` holds a
``dict[str, ContractState]`` for each of ``global_state`` / ``local_state`` /
``boxes``), and each :class:`ContractState` is either a single key (``is_map =
False``, ``key_or_prefix`` is the whole key) or a MAP (``is_map = True``,
``key_or_prefix`` is a constant prefix). That ARC-56 metadata is NOT in the
deployed bytecode, so recovering it is genuine decompilation. This mirrors it in
:class:`StorageEntry`.

The recoverable fingerprint, uniform across all three storages:

* a CONSTANT key => a single stored value (``is_map = False``);
* a runtime-COMPUTED key => a MAP (``is_map = True``). ``concat(const_prefix,
  encode(k))`` => a prefixed map named by the constant; a prefixless computed key
  (``encode(k)`` / ``concat(encode(k1), encode(k2), ...)``) => an unprefixed map
  whose ``key_or_prefix`` is empty.

Crucially, the map PREFIX (always a compile-time constant, possibly empty) and the
KEY TYPE (scalar OR a tuple / struct) are ORTHOGONAL -- exactly as Puya's
``StorageMap`` has them (``prefix: str | None`` + ``keyType: ABIType`` which can be
a tuple). So a per-holder balance key ``concat(Sender, itob(asset))`` is an
unprefixed map with a ``(address, uint64)`` tuple key -- NOT a special kind. The
key/value TYPES come straight off the register's already-recovered ``ir_type`` /
:func:`guess_encoded_types_scored` -- no new inference here.

Key operand position by op (:data:`_STORAGE_OPS`): box ops key on ``arg0``;
``app_global_*`` key on ``arg0`` (``app_global_get_ex`` on ``arg1``, after the
foreign-app id); ``app_local_*`` key on ``arg1`` (after the account ``arg0`` --
the implicit per-account axis), ``app_local_get_ex`` on ``arg2``.

A key built in a caller and passed into a helper as a PARAMETER is resolved
INTERPROCEDURALLY (:meth:`_BoxFlow.deref` hops it back through the
``InvokeSubroutine`` edges). Side-channel / read-only: never mutates the IR.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StorageEntry:
    """One recovered storage declaration, mirroring Puya's ``ContractState``.
    ``kind`` is the storage it lives in; ``is_map`` splits Puya's ``StorageKey``
    (single) from ``StorageMap``; ``key_or_prefix`` is the whole key (single) or
    the constant prefix (map, empty bytes if unprefixed); the ARC-56 key / value
    types are recovered (a key may be a tuple, e.g. ``(address,uint64)``);
    ``storage_type`` is the value's AVM type (Puya's ``storage_type``)."""
    kind: str                          # 'global' | 'local' | 'box'
    is_map: bool
    key_or_prefix: bytes
    arc56_key_type: "str | None" = None
    arc56_value_type: "str | None" = None
    storage_type: str = "bytes"        # 'uint64' | 'bytes'
    value_confident: bool = False
    ops: set = field(default_factory=set)
    # The declared NAME from an ARC-56 spec, when one was matched to this entry
    # (an OPTIONAL enrichment — None on a spec-less recovery).
    name: "str | None" = None

    def render(self) -> str:
        kp = repr(self.key_or_prefix.decode("latin-1")) if self.key_or_prefix else "''"
        val = self.arc56_value_type or self.storage_type
        conf = "" if self.value_confident or self.arc56_value_type is None \
            else " (speculative)"
        ops = ",".join(sorted(self.ops))
        nm = f"{self.name} " if self.name else ""
        if self.is_map:
            return (f"{self.kind} map {nm}prefix={kp} key={self.arc56_key_type or '?'} "
                    f"value={val}{conf}  [{ops}]")
        return f"{self.kind} {nm}key={kp} value={val}{conf}  [{ops}]"


def annotate_with_arc56(entries: list, spec) -> list:
    """Fill each recovered :class:`StorageEntry` with the AUTHORITATIVE name and
    value/key types from a matching ARC-56 :class:`tealql.tealtools.arc56.StateEntry`
    (matched on ``kind`` + ``is_map`` + the constant key / prefix bytes). An OPTIONAL
    enrichment: entries with no spec match are left exactly as recovered, and a
    ``None`` / empty spec is a no-op. The spec value type is treated as confident
    (it is the declared contract, not a recovery guess). Mutates and returns
    ``entries``."""
    import base64
    if spec is None:
        return entries

    def _b64(s):
        try:
            return base64.b64decode(s) if s else b""
        except Exception:
            return None

    scoped = {"global": spec.global_state, "local": spec.local_state,
              "box": spec.box_state}
    # index spec state by (kind, is_map, key/prefix bytes); skip ambiguous keys
    index: dict = {}
    ambiguous: set = set()
    for kind, states in scoped.items():
        for st in states:
            kb = _b64(st.prefix_b64 if st.is_map else st.key_b64)
            if kb is None:
                continue
            gk = (kind, st.is_map, kb)
            if gk in index:
                ambiguous.add(gk)
            index[gk] = st
    for e in entries:
        gk = (e.kind, e.is_map, e.key_or_prefix)
        st = index.get(gk)
        if st is None or gk in ambiguous:
            continue
        e.name = st.name
        if st.value_type:
            e.arc56_value_type, e.value_confident = st.value_type, True
        if e.is_map and st.key_type:
            e.arc56_key_type = st.key_type
    return entries


# op -> (kind, key_arg_index, value_arg_index | None, value_is_a_result_target).
# The key/value operand positions differ per storage; see the module docstring.
_STORAGE_OPS = {
    "box_create": ("box", 0, None, False), "box_put": ("box", 0, 1, False),
    "box_replace": ("box", 0, 2, False), "box_splice": ("box", 0, 3, False),
    "box_del": ("box", 0, None, False), "box_resize": ("box", 0, None, False),
    "box_len": ("box", 0, None, False), "box_get": ("box", 0, None, True),
    "box_extract": ("box", 0, None, True),
    "app_global_put": ("global", 0, 1, False),
    "app_global_del": ("global", 0, None, False),
    "app_global_get": ("global", 0, None, True),
    "app_global_get_ex": ("global", 1, None, True),
    "app_local_put": ("local", 1, 2, False),
    "app_local_del": ("local", 1, None, False),
    "app_local_get": ("local", 1, None, True),
    "app_local_get_ex": ("local", 2, None, True),
}


def _arc56_encoding(enc) -> str:
    """An ARC-56-ish type name for a recovered ABI encoding (recursive): a 32-byte
    header-less byte array is ``address``; ``uintN``; a static / dynamic array;
    a tuple; bool; string; else its repr."""
    from puya.ir.encodings import (ArrayEncoding, Bool8Encoding, BoolEncoding,
                                   TupleEncoding, UIntEncoding, UTF8Encoding)
    if isinstance(enc, UIntEncoding):
        return f"uint{enc.n}"
    if isinstance(enc, (Bool8Encoding, BoolEncoding)):
        return "bool"
    if isinstance(enc, UTF8Encoding):
        return "string"
    if isinstance(enc, ArrayEncoding):
        if (enc.size == 32 and not enc.length_header
                and isinstance(enc.element, UIntEncoding) and enc.element.n == 8):
            return "address"
        el = _arc56_encoding(enc.element)
        return f"{el}[]" if enc.length_header else f"{el}[{enc.size}]"
    if isinstance(enc, TupleEncoding):
        return "(" + ",".join(_arc56_encoding(e) for e in enc.elements) + ")"
    return str(enc)


def _arc56_irtype(t) -> "str | None":
    """An ARC-56-ish type name for a register ir_type (an EncodedType renders via
    :func:`_arc56_encoding`; account -> address; SizedBytesType(n) -> byte[n];
    scalar primitives map through)."""
    from puya.ir.types_ import EncodedType, PrimitiveIRType as PT, SizedBytesType
    if isinstance(t, EncodedType):
        return _arc56_encoding(t.encoding)
    if isinstance(t, SizedBytesType):
        return f"byte[{t.num_bytes}]"
    return {PT.account: "address", PT.uint64: "uint64", PT.bytes: "bytes",
            PT.biguint: "uint512", PT.bool: "bool"}.get(t, str(t))
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


def recover_storage_schema(main, subs, guesses=None, confident=None) -> list:
    """Reconstruct the GLOBAL / LOCAL / BOX storage schema of a lifted program as
    a list of :class:`StorageEntry` (one per distinct storage + key/prefix +
    key-type), mirroring Puya's ``ContractState`` model. ``guesses`` / ``confident``
    may be supplied to reuse an existing :func:`guess_encoded_types_scored` run."""
    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp
    from puya.ir.types_ import PrimitiveIRType as PT

    from . import to_puya_ir
    if guesses is None:
        guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)
    confident = confident or {}
    flow = _BoxFlow(main, subs)

    def _type_of(val):
        """``(arc56_type | None, confident, storage_type)`` for a key tail / value:
        the recovered ABI encoding (guess or ir_type) rendered ARC-56-style, plus
        the value's AVM storage type ('uint64' / 'bytes')."""
        if isinstance(val, M.BytesConstant):
            return f"byte[{len(val.value)}]", True, "bytes"
        if not isinstance(val, M.Register):
            return None, False, "bytes"
        st = "uint64" if val.ir_type.avm_type == PT.uint64.avm_type else "bytes"
        e = guesses.get(id(val))
        if e is not None:
            return _arc56_encoding(e.encoding), bool(confident.get(id(val))), st
        return _arc56_irtype(val.ir_type), True, st

    def _classify_key(key_val, sub):
        """``(is_map, key_or_prefix, arc56_key_type)`` -- a constant key is a single
        value; a computed key is a map (prefixed if ``concat(const, tail)``, else
        unprefixed with its key type read off the register's recovered type)."""
        kv, ksub = flow.deref(key_val, sub)
        if isinstance(kv, M.BytesConstant):
            return False, kv.value, None                      # single stored value
        kd = (flow.reg_def.get((ksub.id, kv.name, kv.version))
              if isinstance(kv, M.Register) else None)
        if isinstance(kd, M.Intrinsic) and kd.op is AVMOp.concat and len(kd.args) == 2:
            p, _ = flow.deref(kd.args[0], ksub)
            if isinstance(p, M.BytesConstant):
                tail, _ = flow.deref(kd.args[1], ksub)
                if isinstance(tail, M.BytesConstant):
                    # BOTH halves constant -> a single fixed box (e.g.
                    # concat("balance_", "v2") == the one box "balance_v2"),
                    # NOT a map. The unfolded IR doesn't const-fold the concat,
                    # so without this the fixed key masquerades as a BoxMap.
                    return False, p.value + tail.value, None
                kt, _, _ = _type_of(kd.args[1])               # prefixed map
                return True, p.value, kt
        kt, _, _ = _type_of(kv)                               # unprefixed / composite map
        return True, b"", kt

    groups: dict = {}
    for s in flow.subs_all:
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic):
                    continue
                meta = _STORAGE_OPS.get(src.op.name)
                if meta is None or len(src.args) <= meta[1]:
                    continue
                kind, kidx, vidx, v_is_result = meta
                is_map, kp, kt = _classify_key(src.args[kidx], s)
                gk = (kind, is_map, kp, kt or "")
                e = groups.get(gk)
                if e is None:
                    e = groups[gk] = StorageEntry(
                        kind=kind, is_map=is_map, key_or_prefix=kp, arc56_key_type=kt)
                e.ops.add(src.op.name)
                # recover the value type (resolving a value passed in as a param)
                vv = None
                if v_is_result and isinstance(o, M.Assignment) and o.targets:
                    vv = o.targets[0]
                elif vidx is not None and len(src.args) > vidx:
                    vv, _ = flow.deref(src.args[vidx], s)
                if vv is not None:
                    vt, vc, st = _type_of(vv)
                    if vt and e.arc56_value_type in (None, vt):
                        e.arc56_value_type, e.value_confident, e.storage_type = vt, vc, st
    return sorted(groups.values(),
                  key=lambda x: (x.kind, x.key_or_prefix, x.arc56_key_type or ""))


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
