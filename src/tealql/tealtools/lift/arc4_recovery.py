"""ARC-4 encoded-type recovery — guess each lifted register's ABI encoded type
(``arc4.Address`` / ``arc4.String`` / dynamic arrays / structs / static arrays)
from producer + decode idioms, score each guess by confidence, and propagate
guesses along identity-preserving relations.

Operates purely on lowered ``puya.ir.models`` objects (``main`` + ``subs`` from
:func:`.to_puya_ir.to_puya`); the dependency is one-way, ``to_puya_ir`` importing
:func:`_recover_encoded_types` and :func:`guess_encoded_types_scored` back from
here.

HAZARD: two STRICTLY separated tiers. The CONFIDENT tier
(:func:`_confident_encoding_for`, applied by :func:`_recover_encoded_types`) is
the only one that writes ``ir_type``, and admits only idioms whose byte layout
unambiguously IS the ABI encoding. Everything else is SPECULATIVE -- an
ASSUMPTION about well-formed ABI input, collected into a side-channel that never
reaches ``ir_type``, so a wrong guess cannot change codegen. Consumers must
attribute anything a guess enables as speculative.
"""
from __future__ import annotations

import logging

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.ir.types_ import PrimitiveIRType as PT

from . import _puya_compat as _compat

logger = logging.getLogger("tealql.tealtools.lift")

def _static_byte_len(value, reg_def: dict):
    """The statically-known byte length of an IR value, or ``None`` -- a bytes
    constant's length, a ``SizedBytesType`` width, or a constant ``bzero N``."""
    from puya.ir.types_ import SizedBytesType
    if isinstance(value, M.BytesConstant):
        return len(value.value)
    if isinstance(value, M.Register):
        if isinstance(value.ir_type, SizedBytesType):
            return value.ir_type.num_bytes
        d = reg_def.get(id(value))
        if (d is not None and isinstance(d.source, M.Intrinsic)
                and d.source.op is AVMOp.bzero and d.source.args
                and isinstance(d.source.args[0], M.UInt64Constant)):
            return d.source.args[0].value
    return None


def _static_encoding_elements(value):
    """The element ``Encoding`` list of ``value`` IF it is a STATIC (fixed-size)
    ABI element, else ``None``, flattening a tuple operand so nested binary concats
    build one flat N-tuple. Confident sources only: a static ``EncodedType``
    register (a dynamic encoding uses the head/tail offset layout, not a plain
    concat), and an ``account`` register, unambiguously the 32 bytes that
    ``arc4.Address`` wire-identically is.

    HAZARD: a plain ``bytes[N]``, or a bytes constant reinterpreted as
    ``StaticArray<Byte, N>``, must NOT be admitted -- raw bytes do not
    disambiguate a byte array from a uint128 / hash / selector, so that is a guess
    and belongs in the speculative tier."""
    from puya.ir.encodings import ArrayEncoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    if not isinstance(value, M.Register):
        return None
    t = value.ir_type
    if isinstance(t, EncodedType):
        if t.num_bytes is None:
            return None
        enc = t.encoding
        return list(enc.elements) if isinstance(enc, TupleEncoding) else [enc]
    if t is PT.account:
        return [ArrayEncoding(element=UIntEncoding(8), size=32, length_header=False)]
    return None


def _is_bool_encoding(enc) -> bool:
    from puya.ir.encodings import Bool8Encoding, BoolEncoding
    return isinstance(enc, (Bool8Encoding, BoolEncoding))


def _confident_encoding_for(intrinsic: "M.Intrinsic", reg_def: dict):
    """The ARC4 ``EncodedType`` a producing op's result provably wire-encodes, or
    ``None`` -- the CONFIDENT tier, applied to ``ir_type`` by
    :func:`_recover_encoded_types`.

    HAZARD: the admission standard is "the byte layout unambiguously IS the ABI
    encoding", so a recovered type is faithful to the bytes whatever the source
    intended. Do NOT add an idiom that needs a length/offset proof or a confidence
    score -- those live in :func:`_guess_encoding_for` and must never touch
    ``ir_type``.

      - ``itob X`` -> ``arc4.UInt64``: ``itob`` emits exactly the big-endian
        8-byte encoding, which IS the ABI ``uint64`` wire format.
      - ``setbit base 0 b`` on a single byte -> ``arc4.Bool``: this writes the
        bool into the high bit of a lone byte, the standalone ABI ``bool`` form.
      - ``concat A B`` of two already-recovered STATIC encoded types -> a static
        ``arc4.Tuple``: a static tuple's wire format IS the concatenation of its
        element encodings, and nested binary concats flatten into one N-tuple.
        EXCLUDED: a bool|bool boundary, since the ABI packs runs of bools into
        shared bits; a lone bool adjacent to a non-bool is fine."""
    from puya.ir.encodings import Bool8Encoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    op = intrinsic.op
    if op is AVMOp.itob:
        return EncodedType(UIntEncoding(64))
    if op is AVMOp.setbit and len(intrinsic.args) == 3:
        base, index, _value = intrinsic.args
        if (isinstance(index, M.UInt64Constant) and index.value == 0
                and _static_byte_len(base, reg_def) == 1):
            return EncodedType(Bool8Encoding())
    if op is AVMOp.concat and len(intrinsic.args) == 2:
        le = _static_encoding_elements(intrinsic.args[0])
        re = _static_encoding_elements(intrinsic.args[1])
        if le and re and not (_is_bool_encoding(le[-1]) and _is_bool_encoding(re[0])):
            return EncodedType(TupleEncoding([*le, *re]))
    if op is AVMOp.extract and len(intrinsic.args) == 1 \
            and len(intrinsic.immediates) == 2:
        # `extract START LEN` taking the LOW K bytes of a uintN (the extract
        # reaches the end: START + K == width) -> the narrower arc4.UInt(K*8): a
        # big-endian UIntK's wire form IS the trailing K bytes of the wider uint.
        start, length = intrinsic.immediates
        base = intrinsic.args[0]
        if (isinstance(start, int) and isinstance(length, int)
                and isinstance(base, M.Register)
                and isinstance(base.ir_type, EncodedType)
                and isinstance(base.ir_type.encoding, UIntEncoding)
                and base.ir_type.num_bytes is not None):
            total = base.ir_type.num_bytes
            k = length if length > 0 else total - start
            if 0 < k < total and start + k == total:
                return EncodedType(UIntEncoding(k * 8))
    return None


def _same_register(a, b) -> bool:
    """SSA-value identity: the same ``Register`` object, or two naming the same
    ``name#version`` (frozen-attrs rebuilds produce distinct objects per value)."""
    return (a is b) or (
        isinstance(a, M.Register) and isinstance(b, M.Register)
        and (a.name, a.version) == (b.name, b.version)
    )


def _def_intrinsic(value, reg_def: dict, op) -> "M.Intrinsic | None":
    """``value``'s defining :class:`M.Intrinsic` when it is a register produced
    by ``op``, else ``None`` -- the one-step def-walk the guess idioms chain."""
    if not isinstance(value, M.Register):
        return None
    d = reg_def.get(id(value))
    if d is not None and isinstance(d.source, M.Intrinsic) and d.source.op is op:
        return d.source
    return None


def _is_uint16_of_len(prefix, data, reg_def: dict) -> bool:
    """PROOF that ``prefix`` is the big-endian uint16 of ``len(data)`` -- the ABI
    dynamic length header. Recognises the chains ending in ``itob(len(data))``,
    whose low two bytes ARE ``uint16(len(data))``: ``extract 6 2`` (immediate),
    ``extract3 … 6 2`` (stack), and the pre-v5 ``substring 6 8``."""
    itob_arg = None
    ex = _def_intrinsic(prefix, reg_def, AVMOp.extract)
    if ex is not None and list(ex.immediates) == [6, 2] and ex.args:
        itob_arg = ex.args[0]
    if itob_arg is None:
        ex3 = _def_intrinsic(prefix, reg_def, AVMOp.extract3)
        if (ex3 is not None and len(ex3.args) == 3
                and isinstance(ex3.args[1], M.UInt64Constant)
                and isinstance(ex3.args[2], M.UInt64Constant)
                and ex3.args[1].value == 6 and ex3.args[2].value == 2):
            itob_arg = ex3.args[0]
    if itob_arg is None:
        ss = _def_intrinsic(prefix, reg_def, AVMOp.substring)
        if ss is not None and list(ss.immediates) == [6, 8] and ss.args:
            itob_arg = ss.args[0]
    if itob_arg is None:
        return False
    itob = _def_intrinsic(itob_arg, reg_def, AVMOp.itob)
    if itob is None or not itob.args:
        return False
    ln = _def_intrinsic(itob.args[0], reg_def, AVMOp.len_)
    return ln is not None and bool(ln.args) and _same_register(ln.args[0], data)


def _guess_encoding_for(intrinsic: "M.Intrinsic", reg_def: dict):
    """The ARC4 ``EncodedType`` a producing op's result is MOST LIKELY but not
    provably encoded as, or ``None`` -- the SPECULATIVE producer-side tier.

    The bar: a NAMED idiom with a discharged local proof, where the byte layout is
    still not self-evidently one ABI type (a program could hand-roll the same
    shape for a non-ABI format).

      - ``concat(P, D)`` with ``P`` PROVEN to be ``uint16(len(D))``
        (:func:`_is_uint16_of_len`) -> the ARC4 dynamic-sequence ENCODE idiom,
        ``ArrayEncoding(byte, length_header=True)``. ``arc4.String`` is this plus
        a UTF-8 claim the dataflow cannot make; :func:`_guess_const_encoding`
        covers the provable-text case.

    HAZARD: anything added here is collected into a SIDE-CHANNEL by
    :func:`guess_encoded_types_scored` and must never be written to a register's
    ``ir_type``, so a wrong guess can neither change codegen nor weaken the
    confident, TEAL-neutral IR."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    if intrinsic.op is AVMOp.concat and len(intrinsic.args) == 2:
        prefix, data = intrinsic.args
        if _is_uint16_of_len(prefix, data, reg_def):
            return EncodedType(ArrayEncoding(
                element=UIntEncoding(8), size=None, length_header=True))
    return None


def _guess_const_encoding(raw: bytes):
    """A bytes CONSTANT that is a self-describing ``arc4.String`` literal, or
    ``None`` -- all checkable from the constant alone: a 2-byte big-endian length
    prefix equal to the remaining length, a non-empty UTF-8 payload, NO embedded
    null byte, and PRINTABLE decoded text.

    The no-null + printable rules are what make it strict -- they reject a zero
    buffer, a NESTED structure carrying its own inner length prefix, and
    control-byte binary. Combined with the ~1/65536 odds of a random prefix
    matching, a survivor is very likely genuine, but it is still a guess:
    side-channel only, never ``ir_type``."""
    from puya.ir.encodings import UTF8Encoding
    from puya.ir.types_ import EncodedType
    if len(raw) < 3 or int.from_bytes(raw[:2], "big") != len(raw) - 2:
        return None
    payload = raw[2:]
    if b"\x00" in payload:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():        # reject control-byte binary (e.g. 0x010204)
        return None
    return EncodedType(UTF8Encoding())


def _guess_decoded_dynamic(main, subs) -> dict:
    """Recognise a value DECODED as a uint16-length-prefixed dynamic array/string
    and map it to the right ``arc4.DynamicArray<T>``: ``{id(Register): EncodedType}``.

    Decode shape: ``X`` qualifies when it is BOTH read at offset 0 as a uint16
    (the length prefix) AND has its payload taken with ``extract X 2 0`` (start 2,
    length 0 = TO-END). The to-end payload extract is what makes it the canonical
    dynamic decode -- a fixed-length slice from offset 2 would be a struct field.

    ELEMENT type, from how the payload (or ``X`` itself, for the offset table) is
    then accessed: ``extract_uint64`` / ``extract_uint32`` -> that width;
    ``extract_uint16`` whose result is a slice START -> an OFFSET into a head/tail
    layout, so the elements are DYNAMIC; ``extract_uint16`` used as a VALUE ->
    ``UInt16``; else ``Byte``.

    Uniquely valuable because it types INPUTS the producer-side recovery cannot
    reach (``txna ApplicationArgs N`` / sub params). Best-effort -- a struct whose
    first field is a uint16 could still match -- so side-channel only."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    len_read: set = set()        # id(X): extract_uint16(X, 0)  -- the count/length
    payload_of: dict = {}        # id(X): the `extract X 2 0` (to-end) result register
    elem_bits: dict = {}         # id(base): 64/32 from extract_uint64/32 chunking
    u16_elem: dict = {}          # id(base): [result id] for extract_uint16 at offset != 0
    slice_starts: set = set()    # id(reg) used as a slice START of extract3/substring3
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)):
                    continue
                src = o.source
                a = src.args
                if src.op is AVMOp.extract_uint16 and len(a) == 2 \
                        and isinstance(a[0], M.Register):
                    if isinstance(a[1], M.UInt64Constant) and a[1].value == 0:
                        len_read.add(id(a[0]))             # the count / length prefix
                    elif o.targets:                        # an element / offset read
                        u16_elem.setdefault(id(a[0]), []).append(id(o.targets[0]))
                elif (src.op is AVMOp.extract and a and isinstance(a[0], M.Register)
                        and len(src.immediates) >= 2 and src.immediates[0] == 2
                        and src.immediates[1] == 0 and o.targets):
                    payload_of[id(a[0])] = o.targets[0]
                elif (src.op is AVMOp.extract_uint64 and a
                        and isinstance(a[0], M.Register)):
                    elem_bits[id(a[0])] = 64
                elif (src.op is AVMOp.extract_uint32 and a
                        and isinstance(a[0], M.Register)):
                    elem_bits.setdefault(id(a[0]), 32)
                if src.op in (AVMOp.extract3, AVMOp.substring3) and len(a) >= 2 \
                        and isinstance(a[1], M.Register):
                    slice_starts.add(id(a[1]))
    def _dyn(element):
        return EncodedType(
            ArrayEncoding(element=element, size=None, length_header=True))
    dyn_byte = UIntEncoding(8)
    out: dict = {}
    for rid in len_read:
        pay = payload_of.get(rid)
        if pay is None:
            continue
        bases = (rid, id(pay))
        u16 = [r for b in bases for r in u16_elem.get(b, [])]
        bits = elem_bits.get(id(pay)) or elem_bits.get(rid)
        if any(r in slice_starts for r in u16):       # offset table -> dynamic elements
            out[rid] = _dyn(ArrayEncoding(
                element=dyn_byte, size=None, length_header=True))
        elif bits:                                    # static wide chunks
            out[rid] = _dyn(UIntEncoding(bits))
        elif u16:                                     # uint16 values -> UInt16 elements
            out[rid] = _dyn(UIntEncoding(16))
        else:                                         # string / dynamic bytes
            out[rid] = _dyn(dyn_byte)
    return out


def _guess_struct_encodings(main, subs, dynamic_guesses) -> dict:
    """Reconstruct a dynamic struct / dynamic tuple from its decode, as
    ``{id(Register): EncodedType(TupleEncoding(...))}``.

    ``X`` is a struct when its head is read at MULTIPLE FIXED positions whose
    uint16 results are used as slice STARTS -- the offset table of a fixed shape
    (a dynamic ARRAY uses a count plus a COMPUTED offset in a loop, so it is
    excluded):
      - ``extract_uint16(X, p_const)`` feeding a slice start -> a DYNAMIC field at
        head position ``p``, typed by its ``substring3`` bracket: a NESTED struct
        recurses, else a ``dynamic_guesses`` entry, else dynamic bytes;
      - ``extract_uintN(X, p_const)`` used as a value -> a static ``UIntN`` field;
      - fields ordered by head position, an UNREAD gap modeled as a ``uint8[gap]``
        blob (the byte count is known from the positions, the type is not).

    PARTIAL by nature -- only decoded fields are seen, the tail beyond the last
    read is omitted -- so speculative side-channel only, never ``ir_type``."""
    from puya.ir.encodings import ArrayEncoding, TupleEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    slots: dict = {}             # id(X) -> {pos: (kind, head_size, info)}
    u16res: dict = {}            # id(result) -> (id(base), const pos or None)
    field_of: dict = {}          # id(offset result) -> field slice register
    slice_starts: set = set()
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)):
                    continue
                src = o.source
                a = src.args
                if src.op is AVMOp.extract_uint16 and len(a) == 2 \
                        and isinstance(a[0], M.Register) and o.targets:
                    pos = a[1].value if isinstance(a[1], M.UInt64Constant) else None
                    u16res[id(o.targets[0])] = (id(a[0]), pos)
                elif src.op is AVMOp.extract_uint64 and len(a) >= 2 \
                        and isinstance(a[0], M.Register) \
                        and isinstance(a[1], M.UInt64Constant):
                    slots.setdefault(id(a[0]), {}).setdefault(
                        a[1].value, ("static", 8, UIntEncoding(64)))
                elif src.op is AVMOp.extract_uint32 and len(a) >= 2 \
                        and isinstance(a[0], M.Register) \
                        and isinstance(a[1], M.UInt64Constant):
                    slots.setdefault(id(a[0]), {}).setdefault(
                        a[1].value, ("static", 4, UIntEncoding(32)))
                if src.op in (AVMOp.substring3, AVMOp.extract3) and len(a) >= 2 \
                        and isinstance(a[1], M.Register):
                    slice_starts.add(id(a[1]))
                    if o.targets:
                        field_of[id(a[1])] = o.targets[0]
    for rid, (base, pos) in u16res.items():
        if pos is None:
            continue
        d = slots.setdefault(base, {})
        if rid in slice_starts:                      # offset slot -> dynamic field
            d[pos] = ("dyn", 2, rid)
        else:                                        # inlined uint16 value -> static field
            d.setdefault(pos, ("static", 2, UIntEncoding(16)))
    dyn_byte = ArrayEncoding(element=UIntEncoding(8), size=None, length_header=True)
    struct_bases = {
        b for b, sl in slots.items()
        if any(k == "dyn" for (k, _, _) in sl.values()) and len(sl) >= 2
    }
    memo: dict = {}                                  # id(base) -> TupleEncoding | None

    def _struct_enc(base, building):
        """The ``TupleEncoding`` for a struct base, recursing on nested-struct
        fields; ``None`` if the head reads are inconsistent."""
        if base in memo:
            return memo[base]
        if base in building:                         # cyclic (shouldn't happen) -> bail
            return None
        building = building | {base}
        fields = []
        expected = 0
        for pos in sorted(slots[base]):
            kind, size, info = slots[base][pos]
            if pos > expected:                       # unread head bytes -> byte blob
                fields.append(ArrayEncoding(
                    element=UIntEncoding(8), size=pos - expected, length_header=False))
            elif pos < expected:                     # overlapping reads -> inconsistent
                memo[base] = None
                return None
            if kind == "static":
                fields.append(info)
            else:                                    # dynamic field
                fld = field_of.get(info)
                nested = (_struct_enc(id(fld), building)
                          if fld is not None and id(fld) in struct_bases else None)
                if nested is not None:               # a NESTED struct field
                    fields.append(nested)
                elif fld is not None and id(fld) in dynamic_guesses:
                    fields.append(dynamic_guesses[id(fld)].encoding)
                else:
                    fields.append(dyn_byte)
            expected = pos + size
        enc = TupleEncoding(fields) if fields else None
        memo[base] = enc
        return enc

    out: dict = {}
    for base in struct_bases:
        enc = _struct_enc(base, set())
        if enc is not None:
            out[base] = EncodedType(enc)
    return out


def _guess_decoded_static_arrays(main, subs) -> dict:
    """Recognise a value DECODED as an ``arc4.StaticArray<UIntN, K>`` -- the
    consumer-side counterpart to :func:`_guess_static_arrays`.

    ``X`` qualifies when it is read only via same-width fixed-offset
    ``extract_uint64`` / ``extract_uint32`` (element width ``w``) at >= 2 distinct
    constant positions each a multiple of ``w``; has NO ``extract_uint16(X, 0)``
    read; and has a STATICALLY KNOWN total length ``M`` divisible by ``w``. Then
    ``K = M / w`` is EXACT -- taken from the length, not the read count, so
    partial element access still gives the true size.

    HAZARD: ``uint16`` elements are deliberately EXCLUDED. An offset-0 uint16 is
    indistinguishable from a dynamic array's length prefix or a struct table's
    first offset, so admitting it would swallow both.
    Homogeneous-but-actually-a-struct is the inherent speculation, hence
    side-channel only."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType

    def kv(r):
        return (r.name, r.version)

    reg_def: dict = {}      # (sub_id, name, version) -> defining assignment
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o

    width = {AVMOp.extract_uint64: 8, AVMOp.extract_uint32: 4}
    reads: dict = {}                 # (name,version) -> set[(pos, w)]
    len_prefixed: set = set()        # (name,version) with an offset-0 uint16 read
    obj: dict = {}                   # (name,version) -> a representative Register
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic):
                    continue
                a = src.args
                if not (len(a) >= 2 and isinstance(a[0], M.Register)
                        and isinstance(a[1], M.UInt64Constant)):
                    continue
                if src.op is AVMOp.extract_uint16 and a[1].value == 0:
                    len_prefixed.add(kv(a[0]))
                elif src.op in width:
                    reads.setdefault(kv(a[0]), set()).add((a[1].value, width[src.op]))
                    obj.setdefault(kv(a[0]), a[0])

    out: dict = {}
    for k, rs in reads.items():
        if k in len_prefixed or len(rs) < 2:
            continue
        widths = {w for _, w in rs}
        if len(widths) != 1:
            continue
        w = next(iter(widths))
        if any(p % w for p, _ in rs):
            continue
        m = _static_byte_len(obj[k], reg_def)
        if m is None or m == 0 or m % w or m // w < 2:
            continue
        if any(p >= m for p, _ in rs):
            continue
        out[id(obj[k])] = EncodedType(ArrayEncoding(
            element=UIntEncoding(w * 8), size=m // w, length_header=False))
    return out


def _guess_static_arrays(main, subs) -> dict:
    """Recognise a producer-built ``arc4.StaticArray<T, N>``: a ``concat`` that
    flattens to N >= 2 elements of ALL the identical STATIC ABI encoding is, on the
    wire, exactly a static array of that element. The element count N is exact,
    every element being a visible concat operand.

    Calling it an ARRAY rather than a homogeneous tuple is the SPECULATION -- a
    ``Tuple<Address, Address>`` and an ``Address[2]`` are wire-identical -- so it
    lives only in the side-channel. N == 2 is the weakest case, a homogeneous pair
    being as likely a struct as an array.

    Only the OUTERMOST concat is emitted; an inner concat feeding another is an
    intermediate partial array, matched by SSA ``name#version`` identity since a
    register duplicates as distinct objects."""
    from puya.ir.encodings import ArrayEncoding
    from puya.ir.types_ import EncodedType

    def kv(r):
        return (r.name, r.version)

    fed_to_concat: set = set()
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(src, M.Intrinsic) and src.op is AVMOp.concat:
                    for a in src.args:
                        if isinstance(a, M.Register):
                            fed_to_concat.add(kv(a))

    out: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not (isinstance(o, M.Assignment)
                        and isinstance(o.source, M.Intrinsic)
                        and o.source.op is AVMOp.concat
                        and len(o.source.args) == 2):
                    continue
                le = _static_encoding_elements(o.source.args[0])
                re = _static_encoding_elements(o.source.args[1])
                if le is None or re is None:
                    continue
                elems = le + re
                if len(elems) < 2 or len({str(e) for e in elems}) != 1:
                    continue
                et = EncodedType(ArrayEncoding(
                    element=elems[0], size=len(elems), length_header=False))
                for t in o.targets:
                    if isinstance(t, M.Register) and kv(t) not in fed_to_concat \
                            and t.ir_type.avm_type == et.avm_type:
                        out[id(t)] = et
    return out


# The transaction fields whose value IS a 32-byte address, single-sourced from
# the canonical langspec-derived set in ``avm.py``.
from ..language.avm import ADDRESS_TXN_FIELDS as _ACCOUNT_TXN_FIELDS  # noqa: E402

# Ops whose FIRST operand (``args[0]``) is an account address: the local-state
# family plus the account-parameter reads.
_ACCOUNT_OPERAND_OPS = (
    AVMOp.app_local_get, AVMOp.app_local_get_ex, AVMOp.app_local_put,
    AVMOp.app_opted_in, AVMOp.balance, AVMOp.min_balance,
    AVMOp.acct_params_get, AVMOp.asset_holding_get,
)


def _is_zero_address(a) -> bool:
    """``a`` is the 32-byte zero-address constant the lift folds ``global
    ZeroAddress`` into."""
    return isinstance(a, M.BytesConstant) and a.value == b"\x00" * 32


def _guess_address_usage(main, subs) -> dict:
    """USAGE-side speculative tier: a bytes value CONSUMED at a langspec ADDRESS
    operand position is guessed ``arc4.Address``, as ``{id(Register): EncodedType}``.

    Reads how a value is USED rather than how it was BUILT. Each idiom's proof is
    the operand position's langspec type: the operand of ``itxn_field <F>`` for an
    account-typed ``F``; the account operand of a local-state / account-parameter
    op; and an operand compared for equality against the zero address.

    Kept SPECULATIVE because "it is an address value" is weaker than "it is
    ABI-encoded as ``arc4.Address``" -- the value may never be round-tripped
    through ABI. Lowest priority in the merge, so a producer/decode guess for the
    same register wins."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType
    address = EncodedType(ArrayEncoding(
        element=UIntEncoding(8), size=32, length_header=False))
    out: dict = {}

    def mark(a):
        if isinstance(a, M.Register) and a.ir_type.avm_type == address.avm_type:
            out.setdefault(id(a), address)

    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic) or not src.args:
                    continue
                op = src.op
                if op is AVMOp.itxn_field and src.immediates:
                    if str(src.immediates[0]).strip() in _ACCOUNT_TXN_FIELDS:
                        mark(src.args[0])
                elif op in _ACCOUNT_OPERAND_OPS:
                    mark(src.args[0])
                elif op in (AVMOp.eq, AVMOp.neq) \
                        and any(_is_zero_address(a) for a in src.args):
                    for a in src.args:
                        mark(a)
    return out


def guess_encoded_types_scored(main, subs):
    """The speculative recovery split into two honest confidence classes: returns
    ``(guesses, confident)``, where ``confident[id(Register)]`` is ``True`` for
    FULLY and ``False`` for SOMEWHAT confident. (Only two states; a finer scale
    would be invented precision.)

    ``True`` iff the idiom's proof FORCES the exact guessed type -- no other ABI
    value produces the same observable: a strict self-describing ``arc4.String``
    constant (:func:`_guess_const_encoding`), and a value the AVM REQUIRES to be a
    32-byte address at its operand position (:func:`_guess_address_usage`).

    ``False`` for a structural shape that FITS but is not forced, an alternative
    ABI type carrying the same bytes: decoded dynamic arrays/strings (String vs
    DynamicBytes vs DynamicArray<T> share a shape), offset-table structs (partial),
    static arrays (array vs homogeneous struct), and the length-proven ENCODE
    idiom (coarse element).

    A later, more-specific source overrides both the guess and its class.
    :func:`_propagate_guesses` then flows each guess along identity-preserving
    relations; a derived guess stays confident only if the whole path preserves
    it."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o

    guesses: dict = {}
    confident: dict = {}

    def bulk(d: dict, sure: bool):
        for rid, et in d.items():                  # overrides guess + class
            guesses[rid] = et
            confident[rid] = sure

    def bulk_default(d: dict, sure: bool):
        for rid, et in d.items():                  # gap-fill only
            if rid not in guesses:
                guesses[rid] = et
                confident[rid] = sure

    bulk(_guess_decoded_dynamic(main, subs), False)
    bulk(_guess_struct_encodings(main, subs, guesses), False)
    bulk(_guess_decoded_static_arrays(main, subs), False)
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if not isinstance(o, M.Assignment):
                    continue
                src = o.source
                if isinstance(src, M.Intrinsic):
                    et, sure = _guess_encoding_for(src, reg_def), False
                elif isinstance(src, M.BytesConstant):
                    et, sure = _guess_const_encoding(src.value), True
                else:
                    et = None
                if et is None:
                    continue
                for tgt in o.targets:
                    if tgt.ir_type.avm_type == et.avm_type:
                        guesses[id(tgt)] = et       # producer wins over decode
                        confident[id(tgt)] = sure
    # Inline constants: the lift const-inlines aggressively, so a literal usually
    # appears as an INTRINSIC ARG, never as an assignment source.
    for s_ in (main, *subs):
        for bb in s_.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not isinstance(src, M.Intrinsic):
                    continue
                for a in src.args:
                    if isinstance(a, M.BytesConstant) and id(a) not in guesses:
                        et = _guess_const_encoding(a.value)
                        if et is not None:
                            guesses[id(a)] = et
                            confident[id(a)] = True
    # Producer-side homogeneous static arrays: shape fits but array-vs-struct is
    # unforced -> somewhat.
    bulk(_guess_static_arrays(main, subs), False)
    # Usage-side address evidence -- the AVM forces a 32-byte address here, so the
    # 'it is an address' call is FULLY confident. Gap-fill (lowest priority).
    bulk_default(_guess_address_usage(main, subs), True)

    _propagate_guesses(main, subs, guesses, confident)
    return guesses, confident


# State ops whose values can carry an encoding through storage. Indices are in
# Puya/AVM order (the pre-IR's top-first order has already been reversed).
# HAZARD: selecting the first constant as the key or the first register as the
# value confuses app_local_put's ACCOUNT with its VALUE, recovering a later
# ``itob(uint64)`` read as arc4.Address.
_STATE_PUT_LAYOUT = {
    AVMOp.app_global_put: ("global", 0, 1),
    AVMOp.app_local_put: ("local", 1, 2),
}
_STATE_GET_KEY_IDX = {
    AVMOp.app_global_get: ("global", 0),
    AVMOp.app_local_get: ("local", 1),
    AVMOp.app_global_get_ex: ("global", 1),
    AVMOp.app_local_get_ex: ("local", 2),
}


def _propagate_guesses(main, subs, guesses: dict, confident: dict = None) -> None:
    """Flow the per-register speculative encodings along IDENTITY-preserving
    relations, so a guess reaches the whole value web it feeds. In-place: adds
    ``id(register) -> EncodedType`` entries to ``guesses`` for every register
    OBJECT whose SSA value carries a propagated encoding (registers duplicate as
    distinct objects for one ``name#version``, so propagation keys on that logical
    identity and is then stamped onto every object).

    Relations, all preserving the value's bytes and hence its ARC4 encoding: a
    register COPY; a PHI, iff every register arg has an encoding and they all
    AGREE (a disagreeing or unknown arm blocks it); and a state PUT->GET, iff
    every ``app_*_put`` to that key wrote the same encoding.

    HAZARD: ``confident`` propagates in lock-step and a derived guess is NEVER
    more confident than its source -- a phi is confident only if EVERY agreeing
    arm is, and a state round-trip never is, all-writes-agree being an assumption
    rather than a proof. Side-channel throughout, so a wrong hop cannot reach
    ``ir_type`` or lowering."""
    confident = confident if confident is not None else {}
    from puya.ir.types_ import EncodedType

    # HAZARD: SSA register names are unique only WITHIN a subroutine (params
    # `p%i`, locals `l%slot` recur across subs), so the propagation identity must
    # include the owning sub — else a guess on sub A's `p%0` stamps onto sub B's
    # `p%0` and surfaces as a wrong abi-audit / box-audit finding. Copy/phi
    # relations are all intra-sub and state round-trips key on state-key bytes, so
    # per-sub keys are both sufficient and correct.
    reg_sub: dict = {}
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                reg_sub[id(ph.register)] = s.id
                for pa in ph.args:
                    if isinstance(pa.value, M.Register):
                        reg_sub[id(pa.value)] = s.id
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        if isinstance(t, M.Register):
                            reg_sub[id(t)] = s.id
                            reg_def[(s.id, t.name, t.version)] = o
                if isinstance(src, M.Intrinsic):
                    for a in src.args:
                        if isinstance(a, M.Register):
                            reg_sub[id(a)] = s.id

    def key(r):
        return (reg_sub.get(id(r)), r.name, r.version)

    # Seed: logical-identity -> encoding (+ confident bool), from the base guesses.
    enc: dict = {}
    enc_conf: dict = {}                   # (sub,name,version) -> bool
    objs: dict = {}                       # (sub,name,version) -> [register objects]

    def note(r):
        if isinstance(r, M.Register):
            objs.setdefault(key(r), []).append(r)
            if id(r) in guesses and key(r) not in enc:
                enc[key(r)] = guesses[id(r)]
                enc_conf[key(r)] = confident.get(id(r), False)

    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                note(ph.register)
                for pa in ph.args:
                    note(pa.value)
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        note(t)
                if isinstance(src, M.Intrinsic):
                    for a in src.args:
                        note(a)

    # State keys: encodings written to each (key-bytes, op-family). A key whose
    # writes disagree (or any write is unguessed-but-present) is poisoned.
    def _state_key(src):
        layout = (_STATE_PUT_LAYOUT[src.op][:2] if src.op in _STATE_PUT_LAYOUT
                  else _STATE_GET_KEY_IDX.get(src.op))
        if layout is None:
            return None
        scope, idx = layout
        if idx >= len(src.args):
            return None
        key_value = src.args[idx]
        return ((scope, key_value.value)
                if isinstance(key_value, M.BytesConstant) else None)

    def _reads_current_app(src) -> bool:
        """An ``*_get_ex`` read belongs to the state round-trip only for this app."""
        app_idx = (0 if src.op is AVMOp.app_global_get_ex
                   else 1 if src.op is AVMOp.app_local_get_ex else None)
        if app_idx is None:
            return True
        app = src.args[app_idx]
        if isinstance(app, M.UInt64Constant):
            return app.value == 0
        d = reg_def.get(key(app)) if isinstance(app, M.Register) else None
        return (d is not None and isinstance(d.source, M.Intrinsic)
                and d.source.op is AVMOp.global_
                and any(str(i).strip() == "CurrentApplicationID"
                        for i in d.source.immediates))

    def _run_state():
        writes: dict = {}       # (scope, keybytes) -> set(encodings) | None(poisoned)
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    src = o.source if isinstance(o, M.Assignment) else o
                    if not (isinstance(src, M.Intrinsic)
                            and src.op in _STATE_PUT_LAYOUT):
                        continue
                    kb = _state_key(src)
                    if kb is None or writes.get(kb, "unset") is None:
                        continue                     # unknown key or already poisoned
                    value_idx = _STATE_PUT_LAYOUT[src.op][2]
                    val = src.args[value_idx] if value_idx < len(src.args) else None
                    if isinstance(val, M.Register):
                        e = enc.get(key(val))
                        if e is None and isinstance(val.ir_type, EncodedType):
                            e = val.ir_type       # confident tier -> state side-channel
                    else:
                        e = guesses.get(id(val)) if val is not None else None
                    if e is None:
                        writes[kb] = None            # an unencoded write poisons the key
                    else:
                        writes.setdefault(kb, set()).add(e)
        se = {kb: next(iter(es)) for kb, es in writes.items()
              if isinstance(es, set) and len(es) == 1}
        # A state round-trip is an all-writes-agree ASSUMPTION, not a proof ->
        # never fully confident.
        sc = {kb: False for kb in se}
        return se, sc

    changed = True
    while changed:
        changed = False
        state_enc, state_conf = _run_state()
        for s in (main, *subs):
            for bb in s.body:
                for ph in bb.phis:
                    k = key(ph.register)
                    if k in enc:
                        continue
                    arms = [(enc.get(key(pa.value)), enc_conf.get(key(pa.value)))
                            for pa in ph.args if isinstance(pa.value, M.Register)]
                    arm_encs = [e for e, _ in arms]
                    if arm_encs and all(e is not None for e in arm_encs) \
                            and len(set(arm_encs)) == 1:
                        enc[k] = arm_encs[0]
                        enc_conf[k] = all(c for _, c in arms)   # confident iff every arm is
                        changed = True
                for o in bb.ops:
                    if not isinstance(o, M.Assignment):
                        continue
                    src = o.source
                    e = ec = None
                    if isinstance(src, M.Register):
                        e, ec = enc.get(key(src)), enc_conf.get(key(src))
                    elif (isinstance(src, M.Intrinsic)
                          and src.op in _STATE_GET_KEY_IDX
                          and _reads_current_app(src)):
                        kb = _state_key(src)
                        e, ec = state_enc.get(kb), state_conf.get(kb)
                    if e is None:
                        # BACKWARD copy (``t = r``): when the copy RESULT carries a
                        # guess but the source does not, the source — the same
                        # bytes — inherits it. This is what carries a
                        # usage-evidence guess back past a rename to the real def.
                        if isinstance(src, M.Register) and key(src) not in enc:
                            te = [(enc.get(key(t)), enc_conf.get(key(t)))
                                  for t in o.targets if isinstance(t, M.Register)]
                            tenc = [x for x, _ in te]
                            if tenc and all(x is not None for x in tenc) \
                                    and len(set(tenc)) == 1 \
                                    and src.ir_type.avm_type == tenc[0].avm_type:
                                enc[key(src)] = tenc[0]
                                enc_conf[key(src)] = all(c for _, c in te)
                                changed = True
                        continue
                    for t in o.targets:
                        if isinstance(t, M.Register) and key(t) not in enc \
                                and t.ir_type.avm_type == e.avm_type:
                            enc[key(t)] = e
                            enc_conf[key(t)] = bool(ec)
                            changed = True

    # Stamp every register OBJECT of an encoded SSA value (incl. use-site copies).
    for k, e in enc.items():
        for r in objs.get(k, ()):
            if id(r) not in guesses and r.ir_type.avm_type == e.avm_type:
                guesses[id(r)] = e
                confident[id(r)] = enc_conf.get(k, False)


# Fund / asset-transfer itxn fields whose operand is an address the CONTRACT pays
# out to: a recovered arc4.Address arriving here is a payout recipient.
_FUND_SINK_FIELDS = frozenset({
    "Receiver", "AssetReceiver", "CloseRemainderTo", "AssetCloseTo",
    "AssetSender", "RekeyTo",
})
# The transaction-arg reads exposing an ABI method argument (a caller-chosen
# value); ``txnas``/``gtxnas`` take the index off the stack, ``txna`` inlines it.
_ABI_ARG_OPS = (AVMOp.txna, AVMOp.txnas, AVMOp.gtxna, AVMOp.gtxnas)


def is_address_encoding(et) -> bool:
    """``et`` is the arc4.Address shape: a fixed 32-element, header-less array of
    BYTES. HAZARD: the ELEMENT type must be checked too — a 32-element static
    array of a wider type also has ``size == 32`` but is NOT an address."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    enc = et.encoding
    return (isinstance(enc, ArrayEncoding)
            and enc.size == 32 and not enc.length_header
            and isinstance(enc.element, UIntEncoding) and enc.element.n == 8)


def abi_address_fund_flows(main, subs, guesses=None) -> list:
    """TYPE-DRIVEN security leads: every fund / asset-transfer sink whose recipient
    operand is a value RECOVERED as ``arc4.Address``. The type recovery is what
    tells us a 32-byte operand is a caller-meaningful ADDRESS rather than an opaque
    blob, turning ``itxn_field Receiver`` into a 'who gets the money' question.

    Each lead is tagged over a BACKWARD SLICE of the recipient value (transitively
    through intrinsic operands, register copies and phis; memoised, cycle-safe),
    so it survives the ABI-decode chain compiled contracts interpose:
      - ``caller_supplied`` -- the slice roots in an ABI method-argument read;
      - ``guarded`` -- some value on the slice is an ``eq``/``neq`` operand, a
        'was it pinned' proxy.
    ``caller_supplied and not guarded`` is the arbitrary-recipient shape.

    The slice is INTRA-procedural, so a value arriving as a subroutine frame
    parameter breaks the chain -- a known gap; taint's interprocedural bridge is
    the fuller answer. Returns dicts ``{field, subroutine, encoding, confident,
    caller_supplied, guarded}``; side-channel in, report out, never ``ir_type``."""
    if guesses is None:
        guesses, confident = guess_encoded_types_scored(main, subs)
    else:
        confident = {}

    def kv(r):
        return (r.name, r.version)

    # Backward def-use graph: each identity -> its predecessors, plus the sets of
    # identities that ARE a raw ApplicationArgs read and that are eq/neq operands.
    preds: dict = {}
    is_arg: set = set()
    compared: set = set()
    origin_of: dict = {}                  # arg-read identity -> 'ApplicationArgs:N'

    def _add_pred(dst, srcs):
        bucket = preds.setdefault(dst, set())
        for s_ in srcs:
            if isinstance(s_, M.Register):
                bucket.add(kv(s_))

    for s in (main, *subs):
        for bb in s.body:
            for ph in bb.phis:
                _add_pred(kv(ph.register), [pa.value for pa in ph.args])
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(o, M.Assignment):
                    ins = ([o.source] if isinstance(o.source, M.Register)
                           else list(src.args) if isinstance(src, M.Intrinsic) else [])
                    for t in o.targets:
                        if isinstance(t, M.Register):
                            _add_pred(kv(t), ins)
                            if isinstance(src, M.Intrinsic) and src.op in _ABI_ARG_OPS \
                                    and src.immediates \
                                    and "ApplicationArgs" in str(src.immediates[0]):
                                is_arg.add(kv(t))
                                idx = (src.immediates[1]
                                       if len(src.immediates) > 1 else None)
                                if isinstance(idx, int):
                                    origin_of[kv(t)] = f"ApplicationArgs:{idx}"
                if isinstance(src, M.Intrinsic) and src.op in (AVMOp.eq, AVMOp.neq):
                    for a in src.args:
                        if isinstance(a, M.Register):
                            compared.add(kv(a))

    # Arg-origin closure over `compared`: comparing ONE read of ApplicationArgs N
    # validates the arg, so every distinct-SSA read of the same constant index
    # counts as compared — catches a `validate arg0` / `pay arg0` split.
    compared_origins = {origin_of[x] for x in compared if x in origin_of}
    if compared_origins:
        for idn, org in origin_of.items():
            if org in compared_origins:
                compared.add(idn)

    _slice_cache: dict = {}

    def bslice(start):
        """The backward slice (set of identities) reachable from ``start``."""
        if start in _slice_cache:
            return _slice_cache[start]
        seen: set = set()
        stack = [start]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(preds.get(n, ()))
        _slice_cache[start] = seen
        return seen

    leads: list = []
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic) and src.op is AVMOp.itxn_field
                        and src.immediates and src.args):
                    continue
                field = str(src.immediates[0]).strip()
                if field not in _FUND_SINK_FIELDS:
                    continue
                a = src.args[0]
                if not (isinstance(a, M.Register) and id(a) in guesses
                        and is_address_encoding(guesses[id(a)])):
                    continue
                sl = bslice(kv(a))
                leads.append({
                    "field": field,
                    "subroutine": s.id,
                    "encoding": str(guesses[id(a)]),
                    "confident": bool(confident.get(id(a), False)),
                    "caller_supplied": bool(sl & is_arg),
                    "guarded": bool(sl & compared),
                })
    return leads


def _recover_encoded_types(main, subs) -> int:
    """CONFIDENT encoded-type recovery: refine a result register to the ARC4
    ``EncodedType`` its producing op provably wire-encodes
    (:func:`_confident_encoding_for`), rebuilding the intrinsic's ``types`` to
    match. Only moves a register whose ``avm_type`` already matches. Returns the
    count refined.

    HAZARD: unlike the scalar refinements an ``EncodedType`` is LAYOUT-BEARING, so
    this is NOT guaranteed a free annotation by the avm_type argument alone — its
    TEAL-neutrality rests on the gate. It is the only encoded-type pass wired into
    :func:`to_puya`'s default IR; the SPECULATIVE tier
    (:func:`guess_encoded_types_scored`) is side-channelled so it can never reach
    this IR."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o
    # Iterate to a fixpoint: `concat` reads its operands' recovered types, so a
    # nested `concat(concat(a, b), c)` resolves over successive rounds. Monotonic
    # (coarse -> richer encoding of the same avm_type), so it terminates.
    n = 0
    changed = True
    while changed:
        changed = False
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    if not (isinstance(o, M.Assignment)
                            and isinstance(o.source, M.Intrinsic)):
                        continue
                    et = _confident_encoding_for(o.source, reg_def)
                    if et is None:
                        continue
                    touched = False
                    for tgt in o.targets:
                        if tgt.ir_type.avm_type == et.avm_type and tgt.ir_type != et:
                            _compat.set_ir_type(tgt, et)
                            touched = changed = True
                            n += 1
                    if touched:
                        _compat.set_intrinsic_types(
                            o.source, (t.ir_type for t in o.targets))
    return n
