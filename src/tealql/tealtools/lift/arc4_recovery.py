"""ARC-4 encoded-type recovery — the SPECULATIVE side-channel that guesses each
lifted register's ABI encoded type (``arc4.Address`` / ``arc4.String`` / dynamic
arrays / structs / static arrays) from producer + decode idioms, scores each guess
by confidence (a forced idiom vs a shape that merely fits), and propagates guesses
along identity-preserving relations.

Extracted verbatim from :mod:`.to_puya_ir` (a 2000-line god module): this is a
DISTINCT concern from the SSA->puya translation and the sound langspec IR-type
recovery that stay there. Operates purely on lowered ``puya.ir.models`` objects
(``main`` + ``subs`` from :func:`.to_puya_ir.to_puya`); it never lifts or
translates, so the dependency is one-way (``to_puya_ir`` imports the two entry
points it needs -- :func:`_recover_encoded_types`, :func:`guess_encoded_types_scored`
-- back from here). The guesses are ASSUMPTIONS about well-formed ABI input, never
proofs; consumers (box schema, ABI fund-flow, the relational bounds speculative
tier) attribute anything they enable as speculative.
"""
from __future__ import annotations

import logging

import puya.ir.models as M
from puya.ir.avm_ops import AVMOp
from puya.ir.types_ import PrimitiveIRType as PT

from . import _puya_compat as _compat

logger = logging.getLogger("tealql.tealtools.lift")

def _static_byte_len(value, reg_def: dict):
    """The statically-known byte length of an IR value, or ``None``: a bytes
    constant's literal length, a ``SizedBytesType`` register's width, or a register
    defined by ``bzero N`` with a constant ``N``."""
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
    """The element ``Encoding`` list of ``value`` IF it is a *static* (fixed-size)
    ABI element -- so a ``concat`` of statics can be recognised as a static tuple --
    else ``None``. Flattens a tuple operand into its elements so nested binary
    concats build one flat N-tuple. Confident element sources only:

      - a static ``EncodedType`` register (``num_bytes`` known; a dynamic encoding
        uses the head/tail offset layout, not a plain concat, so it's excluded);
      - an ``account`` register -> ``arc4.Address`` (``StaticArray<Byte, 32>``):
        ``account`` is unambiguously a 32-byte address and arc4.Address IS that
        static byte array, wire-identical. (The account register itself stays
        ``account`` -- only its tuple-element encoding is taken here.)

    NOT included (would be guesses, belong in the speculative tier): a plain
    ``bytes[N]`` / a bytes constant reinterpreted as ``StaticArray<Byte, N>`` -- the
    raw bytes don't disambiguate a byte array from a uint128 / hash / selector."""
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
    """The ARC4 / ABI ``EncodedType`` a producing op's *result wire-encodes*, or
    ``None`` -- the **CONFIDENT** tier: only idioms whose byte layout unambiguously
    IS the ABI encoding (the "byte layout == the type" standard), so the recovered
    structured type is faithful to the bytes regardless of the source's intent.
    These are applied to ``ir_type`` by :func:`_recover_encoded_types` and are proven
    TEAL-neutral. The *speculative* counterpart -- idioms that need a length/offset
    proof or a confidence score (dynamic arrays / strings / dynamic tuples) -- lives
    entirely separately in :func:`_guess_encoding_for` / :func:`_guess_encoded_types`
    and never touches ``ir_type``; do NOT add a non-wire-provable idiom here.

    Recognised so far:
      - ``itob X`` -> ``arc4.UInt64`` (``UIntEncoding(64)``): ``itob`` emits exactly
        the big-endian 8-byte encoding, which IS the ABI ``uint64`` wire format.
      - ``setbit base 0 b`` where ``base`` is a single byte (``bzero 1`` / a 1-byte
        ``0x00`` constant) -> ``arc4.Bool`` (``Bool8Encoding``): this writes the bool
        into the high bit of a lone byte, the standalone ABI ``bool`` form.
      - ``concat A B`` where A and B are BOTH already-recovered *static* encoded
        types -> a static ``arc4.Tuple`` (``TupleEncoding``): a static ABI tuple's
        wire format IS exactly the concatenation of its element encodings (no length
        prefix, no head/tail offset table -- those appear only for *dynamic*
        elements). Nested binary concats flatten into one N-tuple. EXCLUDED: a
        bool|bool boundary (the ABI packs runs of bools into shared bits, so
        ``concat(bool8, bool8)`` is NOT the tuple form) -- a single bool adjacent to
        a non-bool is fine (one byte, which IS how a lone tuple bool encodes).

    Speculative idioms (dynamic arrays / strings / dynamic tuples) do NOT go here --
    see :func:`_guess_encoding_for`."""
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
        # `extract START LEN <uintN encoding>` taking the LOW K bytes (the extract
        # reaches the end: START + K == width) -> the narrower arc4.UInt(K*8): a
        # big-endian UIntK's wire form IS the trailing K bytes of the wider uint.
        # (`itob x` -> Encoded(uint64), then `extract 6 2` -> arc4.UInt16, etc.)
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
    """SSA-value identity for two IR operands: the same ``Register`` object, or
    two ``Register`` instances naming the same ``name#version`` (frozen-attrs
    rebuilds can produce distinct objects for one SSA value)."""
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
    dynamic length header. Recognised prefix chains (all ending in
    ``itob(len(data))``, whose low two bytes ARE ``uint16(len(data))``):

      - ``extract 6 2 (itob (len data))``   (immediate form)
      - ``extract3 (itob (len data)) 6 2``  (stack form, constant 6/2)
      - ``substring 6 8 (itob (len data))`` (pre-v5 spelling)
    """
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
    """The ARC4 / ABI ``EncodedType`` a producing op's result is *most likely* but
    NOT provably encoded as, or ``None`` -- the **SPECULATIVE** producer-side tier,
    kept deliberately separate from :func:`_confident_encoding_for`.

    The bar here: a guess needs a NAMED idiom with a discharged local proof, but
    the byte layout still isn't *self-evidently* one ABI type (a program could
    hand-roll the same shape for a non-ABI format), so it stays out of ``ir_type``.

    Recognised:
      - ``concat(P, D)`` where ``P`` is PROVEN to be ``uint16(len(D))``
        (:func:`_is_uint16_of_len` -- the ``extract 6 2 (itob (len D))`` chain and
        its spellings) -> the ARC4 dynamic-sequence ENCODE idiom:
        ``ArrayEncoding(byte, length_header=True)`` (``arc4.DynamicBytes``-shaped).
        ``arc4.String`` is this plus a UTF-8 claim the dataflow can't make -- the
        constant tier (:func:`_guess_const_encoding`) handles the provable-text
        case.

    Still to mine (documented, not implemented): ``bytes[N]`` reinterpreted as
    ``arc4.StaticArray<Byte, N>`` / ``arc4.Address`` -- 32 bytes don't
    disambiguate an address from a hash, so that needs usage evidence, not a
    producer idiom.

    Anything added here is best-effort: it is collected into a SIDE-CHANNEL by
    :func:`_guess_encoded_types` and never written to a register's ``ir_type``, so
    a wrong guess can neither change codegen nor weaken the confident, TEAL-neutral
    IR. (Consumers that tolerate imprecision -- e.g. structure-aware fuzzing --
    read the side-channel; a verifier would treat a guess as a
    proposed-and-discharged obligation.)"""
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
    ``None``. STRICT-PROOF, all checkable from the constant alone (no data-flow):

      - a 2-byte big-endian length prefix that provably equals the remaining length
        (``uint16(raw[:2]) == len(raw) - 2``) -- the arc4.String / dynamic-array wire
        shape;
      - a non-empty payload that decodes as UTF-8;
      - NO embedded null byte; and the decoded text is PRINTABLE.

    The no-null + printable rules are what make it strict: a length-consistent
    constant whose payload parses as UTF-8 only because it is full of ``0x00`` (a
    zero buffer), contains its own inner length prefix (a NESTED structure, e.g.
    ``<13><0x000b "Hello World">``), or is control-byte binary (``0x010204``) is
    rejected -- a real flat text string is printable and almost never carries
    embedded nulls. Combined with the ~1/65536 odds of a random prefix matching, a
    survivor is very likely a genuine ``arc4.String``.

    Still a guess (a constant *could* coincidentally be a self-describing UTF-8 blob),
    so it lives only in the speculative side-channel, never in ``ir_type``."""
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
    """Recognise a value being DECODED as a uint16-length-prefixed dynamic
    array/string and map it to the right ``arc4.DynamicArray<T>``: ``{id(Register):
    EncodedType}``.

    PROVABLE decode shape (#3): a value ``X`` is decoded that way when it is BOTH
      - read at offset 0 as a uint16 -- the length prefix, ``extract_uint16 X 0`` --
        AND
      - has its payload taken with ``extract X 2 0`` (start 2, length 0 = TO-END):
        strip the 2-byte length prefix, take the rest.
    The to-end payload extract is what makes it the canonical dynamic decode (a
    fixed-length slice from offset 2 would be a struct field, not a dynamic array),
    so this is much tighter than a bare ``slice-from-2`` co-occurrence.

    ELEMENT type (#1/#2): inferred from how the payload (the ``extract X 2 0``
    result -- or ``X`` itself, for the offset table) is then accessed:
      - ``extract_uint64`` -> ``DynamicArray<UInt64>``, ``extract_uint32`` -> ``<UInt32>``;
      - ``extract_uint16`` whose result is used as a slice START (an OFFSET into
        the head/tail layout) -> the elements are DYNAMIC: ``DynamicArray<DynamicBytes>``
        (the offset-table signature -- a dynamic tuple/array-of-dynamics; the exact
        element types are #3's full reconstruction, this is the approximation);
      - ``extract_uint16`` whose result is used as a VALUE -> ``DynamicArray<UInt16>``;
      - else ``Byte`` (a string / dynamic bytes).
    The uint16 value-vs-offset split (#2) is what resolves the ambiguity that left
    every uint16-accessed payload as ``Byte`` before.

    Uniquely valuable because it types INPUTS the producer-side recovery can't reach
    (``txna ApplicationArgs N`` / sub params). Best-effort (a struct whose first
    field is a uint16 and rest is a tail could still match), so side-channel only."""
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
    """Reconstruct a dynamic struct / dynamic *tuple* type from its decode, as
    ``{id(Register): EncodedType(TupleEncoding(...))}``.

    A value ``X`` is a struct (fixed-shape aggregate with >=1 dynamic field) when its
    head is read at MULTIPLE FIXED positions whose uint16 results are used as slice
    STARTS -- the offset table of a fixed shape (a dynamic ARRAY uses a count + a
    COMPUTED offset in a loop instead, so it's excluded here). Reconstruction:
      - ``extract_uint16(X, p_const)`` whose result is a slice start -> a DYNAMIC
        field at head position ``p`` (2-byte offset slot); its type is the bracket
        ``substring3(X, off_p, off_q)`` slice -- a NESTED struct (the bracket itself
        decoded as a struct) recurses, else a ``dynamic_guesses`` String/DynamicArray,
        else dynamic bytes;
      - ``extract_uintN(X, p_const)`` (used as a value) -> a static ``UIntN`` field;
      - fields ordered by head position, with any UNREAD head gap modeled as a
        ``uint8[gap]`` byte BLOB (we know the byte count from the positions, just not
        the type -- partial reconstruction, still useful).

    PARTIAL by nature (only decoded fields are seen; the tail beyond the last read is
    omitted), so speculative side-channel only -- never ``ir_type``."""
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
                if src.op is AVMOp.substring3 and len(a) >= 2 \
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
        """The ``TupleEncoding`` reconstructed for a struct base, recursing on
        nested-struct fields (a dynamic field whose sliced-out value is itself
        decoded as a struct). ``None`` if the head reads are inconsistent."""
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
    consumer-side counterpart to :func:`_guess_static_arrays`. ``{id(Register):
    EncodedType}``.

    A value ``X`` is a static array when ALL of:
      - it is read only via same-width fixed-offset ``extract_uint64`` /
        ``extract_uint32`` (homogeneous element width ``w`` in {8, 4}) at >= 2
        distinct constant positions, each a multiple of ``w``;
      - it has NO ``extract_uint16(X, 0)`` read -- that offset-0 uint16 is the
        length prefix of a DYNAMIC array or the first offset of a struct table,
        both of which this must not swallow;
      - its total byte length ``M`` is STATICALLY KNOWN (:func:`_static_byte_len`
        -- a ``SizedBytesType`` register or a constant, which a fixed-length ABI
        static-array arg / ``extract Y a b`` slice is) and divisible by ``w``.
    Then ``K = M / w`` is EXACT (from the length, not the read count -- so partial
    element access still gives the true size) and every read lands inside ``[0,
    M)``.

    ``uint16`` elements are deliberately EXCLUDED: an offset-0 uint16 is
    indistinguishable from a length prefix / offset-table slot, so admitting it
    would misread dynamic arrays and structs. Homogeneous-but-actually-a-struct
    (e.g. ``Tuple<UInt64, UInt64>``) is the inherent speculation, hence
    side-channel only. Pairs with the struct recogniser, which only fires for a
    shape with >= 1 DYNAMIC field -- a pure-static homogeneous value is this."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    from puya.ir.types_ import EncodedType

    def kv(r):
        return (r.name, r.version)

    reg_def: dict = {}
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
    """Recognise a producer-built ``arc4.StaticArray<T, N>`` -- ``{id(Register):
    EncodedType}``. A ``concat`` that flattens (nested binary concats included) to
    N >= 2 elements that are ALL the identical STATIC ABI encoding is, on the wire,
    exactly a static array of that element: identical layout to the homogeneous
    static ``Tuple`` the CONFIDENT tier already puts in ``ir_type``.

    Calling it an ARRAY rather than a homogeneous tuple is the SPECULATION (the
    bytes don't say which the author meant -- a ``Tuple<Address, Address>`` and an
    ``Address[2]`` are wire-identical), so it lives only in the side-channel. The
    exact element count N is KNOWN (every element is a visible concat operand); the
    idiom (``concat`` of identical statics) and its proof (the shared
    :func:`_static_encoding_elements` encoding) are discharged -- attributed
    speculation. N == 2 is the ambiguous case (a homogeneous pair is as likely a
    struct as an array), kept but inherently the weakest.

    Only the OUTERMOST concat is emitted: an inner concat whose result feeds
    another concat is an intermediate partial array, skipped (matched by SSA
    ``name#version`` identity, since a register duplicates as distinct objects)."""
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


# The transaction fields whose value IS a 32-byte address (Receiver / Sender /
# CloseRemainderTo / RekeyTo / the AssetXxx address fields) — the canonical
# langspec-derived set in ``avm.py`` (verified identical to puya's account-wtype
# registry). Single-sourced here so the address-field decision lives in one place.
from ..avm import ADDRESS_TXN_FIELDS as _ACCOUNT_TXN_FIELDS  # noqa: E402

# Ops whose FIRST operand (``args[0]`` -- verified against the lift's arg order)
# is an account address: the local-state family + the account-parameter reads.
_ACCOUNT_OPERAND_OPS = (
    AVMOp.app_local_get, AVMOp.app_local_get_ex, AVMOp.app_local_put,
    AVMOp.app_opted_in, AVMOp.balance, AVMOp.min_balance,
    AVMOp.acct_params_get, AVMOp.asset_holding_get,
)


def _is_zero_address(a) -> bool:
    """``a`` is the 32-byte zero address constant (``global ZeroAddress``, which
    the lift const-folds to a ``BytesConstant`` of 32 null bytes)."""
    return isinstance(a, M.BytesConstant) and a.value == b"\x00" * 32


def _guess_address_usage(main, subs) -> dict:
    """USAGE-side speculative tier: a bytes value CONSUMED at a langspec ADDRESS
    operand position is guessed ``arc4.Address`` (``StaticArray<Byte, 32>``).
    Returns ``{id(Register): EncodedType}``.

    The complement of the producer / consumer / constant idioms: instead of
    reading how a value was BUILT, it reads how a value is USED. The named idioms,
    each with a discharged local proof (the operand position's langspec type):

      - the single operand of ``itxn_field <F>`` where ``F`` is an account-typed
        field (:data:`_ACCOUNT_TXN_FIELDS`) -- the AVM requires a 32-byte address
        there, so the value IS an address;
      - the account operand (``args[0]``) of a local-state / account-parameter op
        (:data:`_ACCOUNT_OPERAND_OPS`);
      - an operand compared for equality (``eq`` / ``neq``) against the zero
        address (:func:`_is_zero_address`) -- a canonical address presence check.

    Kept SPECULATIVE (not confident) because "it is an address value" is weaker
    than "it is ABI-encoded as ``arc4.Address``": the value may never be
    round-tripped through ABI. Side-channel only, and lowest priority in the merge
    (a producer/decode guess for the same register wins), then
    :func:`_propagate_guesses` -- including the backward-copy hop -- carries it
    from the use site back to the value's definition."""
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


def _guess_encoded_types(main, subs) -> dict:
    """SPECULATIVE encoded-type recovery as a SIDE-CHANNEL ``{id(M.Register):
    EncodedType}`` map (never mutates ``ir_type``; not on :func:`to_puya`'s default
    path). The guesses only -- see :func:`guess_encoded_types_scored` for the same
    map plus, per guess, whether it is fully or only somewhat confident."""
    return guess_encoded_types_scored(main, subs)[0]


def guess_encoded_types_scored(main, subs):
    """The speculative recovery split into two honest confidence classes: returns
    ``(guesses, confident)`` where ``guesses`` is ``{id(Register): EncodedType}``
    and ``confident`` is ``{id(Register): bool}`` -- ``True`` = FULLY confident,
    ``False`` = SOMEWHAT confident. (Only two states; a finer scale would be
    invented precision.)

    ``True`` iff the idiom's proof FORCES the exact guessed type -- no other ABI
    value produces the same observable:
      - a self-describing ``arc4.String`` CONSTANT (strict: length + UTF-8 +
        printable + no-null), :func:`_guess_const_encoding`;
      - a value the AVM REQUIRES to be a 32-byte address at its operand position,
        :func:`_guess_address_usage` -> ``arc4.Address``.

    ``False`` (a structural shape that FITS but isn't forced -- an alternative ABI
    type carries the same bytes, so it's a lead, not a guarantee):
      - decoded length-prefixed dynamic arrays/strings, :func:`_guess_decoded_dynamic`
        (String vs DynamicBytes vs DynamicArray<T> all share the shape);
      - offset-table STRUCTS / tuples, :func:`_guess_struct_encodings` (partial);
      - static arrays, producer + decode (:func:`_guess_static_arrays` /
        :func:`_guess_decoded_static_arrays`) -- array vs homogeneous struct;
      - the length-proven ENCODE idiom, :func:`_guess_encoding_for` (element coarse).

    A later, more-specific source overrides the guess AND its class for a register.
    Then :func:`_propagate_guesses` flows each guess along identity-preserving
    relations; a derived guess stays confident only if the whole path preserves it
    (a copy inherits, a phi needs every arm confident, a state round-trip -- an
    assumption, not a proof -- is never confident)."""
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


# State-write ops whose (key, value) a get of the same key can inherit an
# encoding from (all-writes-agree). uint64/box put/del excluded -- box values
# are handled by the decode-side guesses, and del carries no value.
_STATE_PUT_OPS = (AVMOp.app_global_put, AVMOp.app_local_put)
_STATE_GET_OPS = (AVMOp.app_global_get, AVMOp.app_local_get,
                  AVMOp.app_global_get_ex, AVMOp.app_local_get_ex)


def _propagate_guesses(main, subs, guesses: dict, confident: dict = None) -> None:
    """Flow the per-register speculative encodings along IDENTITY-preserving
    relations, so a guess reaches the whole value web it feeds -- not just the
    one op that produced it. In-place: adds ``id(register) -> EncodedType``
    entries to ``guesses`` for every register-OBJECT whose SSA value carries a
    propagated encoding (registers duplicate as distinct objects for one
    ``name#version``, so propagation is keyed by that logical identity, then
    stamped onto every object).

    Relations (all preserve the value's bytes, hence its ARC4 encoding):
      - register COPY (``t = r``): ``t`` inherits ``r``'s encoding;
      - PHI: the joined register inherits iff every register arg has an
        encoding and they all AGREE (MUST -- a disagreeing or unknown arm
        blocks it);
      - state PUT->GET: a ``app_*_get KEY`` result inherits iff every
        ``app_*_put`` to that KEY wrote a value with the SAME encoding
        (all-writes-agree, mirroring the state-resolution soundness elsewhere).

    ``confident`` (optional ``{id: bool}``) is propagated in lock-step: a copy
    inherits the source class, a phi is confident only if EVERY agreeing arm is,
    and a state round-trip is never confident (all-writes-agree is an assumption,
    not a proof). A derived guess is never more confident than what it came from.

    Speculative + side-channel throughout: never touches ``ir_type``, so a
    wrong hop cannot affect lowering -- only what a tolerant consumer reads."""
    confident = confident if confident is not None else {}

    # SSA register names are unique only WITHIN a subroutine (params `p%i`, locals
    # `l%slot` recur across subs), so a propagation identity must include the
    # owning subroutine — else a guess on sub A's `p%0` stamps onto sub B's `p%0`
    # (a spurious cross-sub guess that surfaces as a wrong abi-audit/box-audit
    # finding). Map every register OBJECT to its sub; all copy/phi relations are
    # intra-sub, and state round-trips key on state-key-bytes, so per-sub keys are
    # both sufficient and correct.
    reg_sub: dict = {}
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
    def _key_const(args):
        for x in args:
            if isinstance(x, M.BytesConstant):
                return x.value
        return None

    def _run_state():
        writes: dict = {}                 # keybytes -> set(encodings) | None(poisoned)
        for s in (main, *subs):
            for bb in s.body:
                for o in bb.ops:
                    src = o.source if isinstance(o, M.Assignment) else o
                    if not (isinstance(src, M.Intrinsic) and src.op in _STATE_PUT_OPS):
                        continue
                    kb = _key_const(src.args)
                    if kb is None or writes.get(kb, "unset") is None:
                        continue                     # unknown key or already poisoned
                    val = next((a for a in src.args if isinstance(a, M.Register)), None)
                    e = enc.get(key(val)) if val is not None else None
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
                    elif isinstance(src, M.Intrinsic) and src.op in _STATE_GET_OPS:
                        kb = _key_const(src.args)
                        e, ec = state_enc.get(kb), state_conf.get(kb)
                    if e is None:
                        # BACKWARD copy (``t = r``): if the copy result already
                        # carries a guess (e.g. a use-site address stamp) but the
                        # source does not, the source -- the same bytes -- inherits
                        # it. This is what carries a usage-evidence guess back past
                        # a rename to the value's real definition.
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


# Fund / asset-transfer itxn fields whose operand is an address the CONTRACT
# pays out to -- a recovered arc4.Address arriving here is a payout recipient.
_FUND_SINK_FIELDS = frozenset({
    "Receiver", "AssetReceiver", "CloseRemainderTo", "AssetCloseTo",
    "AssetSender", "RekeyTo",
})
# The transaction-arg reads that expose an ABI method argument (a caller-chosen
# value). ``txnas`` / ``gtxnas`` take the index off the stack; ``txna`` inlines it.
_ABI_ARG_OPS = (AVMOp.txna, AVMOp.txnas, AVMOp.gtxna, AVMOp.gtxnas)


def is_address_encoding(et) -> bool:
    """``et`` is the arc4.Address shape: a fixed 32-element, header-less array of
    BYTES (``StaticArray<Byte, 32>``). The element type must be checked too — a
    32-element static array of a wider type (e.g. ``StaticArray<UInt64, 32>``)
    also has ``size == 32`` but is NOT an address (mirrors ``_arc56_encoding``)."""
    from puya.ir.encodings import ArrayEncoding, UIntEncoding
    enc = et.encoding
    return (isinstance(enc, ArrayEncoding)
            and enc.size == 32 and not enc.length_header
            and isinstance(enc.element, UIntEncoding) and enc.element.n == 8)


def abi_address_fund_flows(main, subs, guesses=None) -> list:
    """TYPE-DRIVEN security leads -- the first CONSUMER of the speculative ABI
    type side-channel. Reports every fund / asset-transfer sink
    (:data:`_FUND_SINK_FIELDS`) whose recipient operand is a value RECOVERED as
    ``arc4.Address``: the type recovery is precisely what tells us a 32-byte
    operand is a caller-meaningful ADDRESS rather than an opaque blob, which is
    what turns ``itxn_field Receiver`` into a 'who gets the money' question.

    Each lead is tagged over a BACKWARD SLICE of the recipient value (its def-use
    predecessors, transitively -- through intrinsic operands, register copies and
    phis, memoised, cycle-safe), so it survives the ABI-decode chain real
    compiled contracts interpose (the address is ``extract``-ed out of the args
    tuple, not read raw at the sink):
      - ``caller_supplied`` -- the slice roots in an ABI method-argument read
        (:data:`_ABI_ARG_OPS` on ``ApplicationArgs``): the caller chooses the
        address;
      - ``guarded`` -- some value on the slice is an ``eq`` / ``neq`` operand (a
        'was it pinned/validated' proxy).

    ``caller_supplied and not guarded`` is the arbitrary-recipient shape: the
    caller passes an ABI address and the contract pays it without checking. The
    slice is INTRA-procedural -- a value arriving as a subroutine frame parameter
    breaks the chain (documented gap; taint's interprocedural bridge is the fuller
    answer). Op-granular (Puya IR carries no source line on this path); returns
    dicts ``{field, subroutine, encoding, confident, caller_supplied, guarded}``,
    where ``confident`` (bool) is whether the recovered address type is fully or
    only somewhat confident (see :func:`guess_encoded_types_scored`). Side-channel
    in, report out -- never touches ``ir_type``."""
    if guesses is None:
        guesses, confident = guess_encoded_types_scored(main, subs)
    else:
        confident = {}

    def kv(r):
        return (r.name, r.version)

    # Backward def-use graph: each identity -> its predecessor identities, plus
    # the set of identities that ARE a raw ApplicationArgs read, and those used
    # as an eq/neq operand.
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
    # validates the arg, so every (distinct-SSA) read of the same constant-index
    # arg counts as compared -- catches a `validate arg0` / `pay arg0` pattern
    # where the two reads are separate registers (uncommon post-CSE, but sound).
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
    """**CONFIDENT** encoded-type recovery: refine a result register to the ARC4
    ``EncodedType`` its producing op provably wire-encodes
    (:func:`_confident_encoding_for`). Only moves a register whose ``avm_type``
    already matches (an ``EncodedType``'s ``avm_type`` is ``bytes`` for the
    byte-backed encodings, so it sits over the same ``bytes``/``bytes[N]`` the
    sized-bytes pass left), and rebuilds the intrinsic's ``types`` to match. This is
    the only encoded-type pass wired into :func:`to_puya`'s default IR.

    NOTE: unlike the scalar refinements, an ``EncodedType`` is *layout-bearing*, so
    this is the first recovery that is NOT guaranteed a free annotation by
    construction -- its TEAL-neutrality is established by the gate, not by the
    avm_type argument alone (measured 247/0). The SPECULATIVE tier
    (:func:`_guess_encoded_types`) is kept strictly separate and side-channelled so
    it can never reach this IR. Returns the count refined."""
    reg_def: dict = {}
    for s in (main, *subs):
        for bb in s.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        reg_def[id(t)] = o
    # Iterate to a fixpoint: `concat` reads its operands' recovered types, so a
    # nested `concat(concat(a, b), c)` resolves over successive rounds. Monotonic
    # (a register only ever moves from a coarse/smaller encoding to a richer one of
    # the same avm_type), so it terminates.
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
