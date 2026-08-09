"""STORAGE-SCHEMA recovery: reconstruct Puya's ``ContractState`` model -- the
GLOBAL / LOCAL / BOX storage keys and maps -- from the lifted IR. Read-only.

HAZARD: the single-vs-MAP classification is the whole recovery, and it rests on ONE
fingerprint, uniform across the three storages: a CONSTANT key is a single stored
value (``is_map = False``, ``key_or_prefix`` is the whole key); a runtime-COMPUTED
key is a map (``is_map = True``) -- ``concat(const, encode(k))`` prefixed by the
constant, anything else unprefixed with an empty ``key_or_prefix``. Prefix and KEY
TYPE are ORTHOGONAL (as in Puya's ``StorageMap``), so ``concat(Sender,
itob(asset))`` is an unprefixed map with a ``(address, uint64)`` tuple key, not a
kind of its own. A ``concat`` of two CONSTANTS is still a constant key: the IR never
folds it, so it must not be read as a map.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StorageEntry:
    """One recovered storage declaration, mirroring Puya's ``ContractState`` — the
    ARC-56 metadata is NOT in the deployed bytecode, so this is decompiled."""
    kind: str                          # 'global' | 'local' | 'box'
    is_map: bool
    key_or_prefix: bytes
    arc56_key_type: "str | None" = None
    arc56_value_type: "str | None" = None
    storage_type: str = "bytes"        # 'uint64' | 'bytes'
    value_confident: bool = False
    ops: set = field(default_factory=set)
    # declared name from a matched ARC-56 spec; None on a spec-less recovery
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
    """Fill each :class:`StorageEntry` with the declared name / types from a matching
    ARC-56 :class:`tealql.tealtools.metadata.arc56.StateEntry` (matched on ``kind`` +
    ``is_map`` + key/prefix bytes) — an OPTIONAL enrichment that mutates and returns
    ``entries``, leaving unmatched ones exactly as recovered."""
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
# The key position differs per storage: box + app_global on arg0 (app_global_get_ex
# on arg1, after the foreign-app id), app_local on arg1 (after the account arg0),
# app_local_get_ex on arg2. Read the wrong slot and the schema is silently wrong.
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
    """An ARC-56-ish type name for a recovered ABI encoding, recursively."""
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
    """An ARC-56-ish type name for a register ``ir_type``."""
    from puya.ir.types_ import EncodedType, PrimitiveIRType as PT, SizedBytesType
    if isinstance(t, EncodedType):
        return _arc56_encoding(t.encoding)
    if isinstance(t, SizedBytesType):
        return f"byte[{t.num_bytes}]"
    return {PT.account: "address", PT.uint64: "uint64", PT.bytes: "bytes",
            PT.biguint: "uint512", PT.bool: "bool"}.get(t, str(t))
# box ops that MODIFY a box -- an attacker-chosen box WRITE is worse than a read
_WRITE_OPS = frozenset({"box_put", "box_replace", "box_splice", "box_del",
                        "box_create", "box_resize"})


class _BoxFlow:
    """Interprocedural def-use + param->argument edges shared by the schema recovery
    and the access-control detector, walked by ``deref`` and ``roots``."""

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
        """Resolve ``val`` to its source ``(value, sub)`` through register copies and
        — interprocedurally — a PARAMETER back to the caller's argument, but only when
        every call site passes a value that resolves the same way."""
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
        """The SOURCE-OP tags ``val`` is built from, backward and interprocedurally:
        ``Sender`` (``txn Sender``) and ``AppArgs`` (``txna ApplicationArgs``)."""
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
        Sender-derived one ANYWHERE (``eq``/``neq``) — evidence it validates a
        caller-supplied identity, which suppresses the access-control finding."""
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
    """The lifted program's storage schema as :class:`StorageEntry` list, one per
    distinct storage + key/prefix + key-type; ``guesses`` / ``confident`` may be
    supplied to reuse an existing :func:`guess_encoded_types_scored` run."""
    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp
    from puya.ir.types_ import PrimitiveIRType as PT

    from . import to_puya_ir
    if guesses is None:
        guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)
    confident = confident or {}
    flow = _BoxFlow(main, subs)

    def _type_of(val):
        """``(arc56_type | None, confident, storage_type)`` for a key tail / value —
        types are READ OFF the existing recovery, never inferred here."""
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
        """``(is_map, key_or_prefix, arc56_key_type)`` per the module's fingerprint:
        constant key => single value, computed key => map."""
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
                    # BOTH halves constant -> ONE fixed box (concat("balance_","v2")
                    # is the single box "balance_v2"), never a map.
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
    """Access-control leads: one :class:`BoxAccessFinding` per ADDRESS-keyed
    ``BoxMap`` whose key is CALLER-SUPPLIED (traces to ``ApplicationArgs``, not to
    ``txn Sender``), so an attacker picks whose slot to read or overwrite.

    HAZARD: two conditions carry the precision — it keys on the recovered ADDRESS key
    type (a listing / auction-id map is legitimately caller-chosen), and it is
    suppressed outright when the program checks a caller identity against the sender
    (:meth:`_BoxFlow.has_sender_arg_check`). Relaxing either floods false
    positives."""
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
        """The address key label if ``tail`` is RECOGNISABLY an address — an
        ``account`` ir_type, a provably 32-byte value, or an arc4.Address guess.

        HAZARD: a raw untyped caller value of unknown width returns None on purpose.
        An address is indistinguishable from an opaque id there, so the detector stays
        silent rather than false-positive on every id-keyed map."""
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
