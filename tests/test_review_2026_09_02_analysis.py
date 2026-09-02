"""Pins for the 2026-09-02 audit's analysis-layer defects (findings 1.4, 1.5,
3.2, 3.3, 3.5). One test per defect, controls folded in."""
from __future__ import annotations

from tealql.tealtools.ssa import SSAProgram

_PARTIAL_GUARD = (
    "#pragma version 10\n"
    "txna ApplicationArgs 0\nextract 0 4\nbyte 0x11223344\n==\nassert\n"
    "itxn_begin\nint pay\nitxn_field TypeEnum\nint 1000\nitxn_field Amount\n"
)
_PAY_TAIL = "itxn_field Receiver\nitxn_submit\nint 1\nreturn\n"
_TABLE = "byte 0x" + "11" * 32 + "22" * 32 + "33" * 32 + "\n"


def _partial_findings(teal: str):
    from tealql.security import DETECTORS
    prog = SSAProgram.from_text(teal, name="t")
    prog.propagate_constants()
    return DETECTORS["partial-tainted-fund-flow"](prog).detect()


def _fires_high(teal: str) -> bool:
    found = _partial_findings(teal)
    return bool(found) and all(f.severity.lower() == "high" for f in found)


def test_byte_taint_fallback_channel_follows_output_type():
    """1.4: the generic fallback tagged every bytes-producing op SCALAR, so
    ``sha512`` (absent from the hand-rolled hash list) and ``txnas Accounts`` at
    an attacker index left an empty byte map and the next ``extract`` dropped the
    taint — partial-tainted-fund-flow silent where the sha256 control fired."""
    sha256 = _PARTIAL_GUARD + "txna ApplicationArgs 0\nsha256\nextract 0 32\n" + _PAY_TAIL
    sha512 = _PARTIAL_GUARD + "txna ApplicationArgs 0\nsha512\nextract 0 32\n" + _PAY_TAIL
    txnas = (_PARTIAL_GUARD + "txna ApplicationArgs 0\nint 4\nextract_uint64\n"
             "txnas Accounts\nextract 0 32\n" + _PAY_TAIL)
    assert _fires_high(sha256), "control: sha256 digest slice must fire"
    assert _fires_high(sha512), "sha512 digest slice read as clean"
    assert _fires_high(txnas), "Accounts[attacker index] slice read as clean"

    # Engine view: the digest carries its true width (64), not the hash list's 32.
    from tealql.tealtools.dataflow.byte_taint import byte_taint
    prog = SSAProgram.from_text(sha512, name="t")
    r = byte_taint(prog)
    digest = next(a for a in prog.assignments if a.op == "sha512").outputs[0]
    assert r.tainted_bytes(digest).parts == ((0, 64),)

    # With NO recovered type (the view's kind is a by-product of the
    # byte-length / range passes and is absent on e.g. arithmetic over
    # legacy-sub scratch params), the channel comes from the langspec result
    # family, never "both": a `-` is uint64 (byte taint on it made the partial
    # detector report 28 mainnet Amount sinks) and `txnas Accounts` is bytes.
    from tealql.tealtools.dataflow.byte_taint import _byte_taint_impl
    untyped = SSAProgram.from_text(
        "#pragma version 10\ntxna ApplicationArgs 0\nbtoi\ndup\nint 3\n-\npop\n"
        "txnas Accounts\npop\nint 1\nreturn\n", name="t")
    assert all(getattr(o, "type", None) is None
               for a in untyped.assignments for o in a.outputs)   # canonical: untyped
    r = _byte_taint_impl(untyped)
    minus = next(a for a in untyped.assignments if a.op == "-").outputs[0]
    acct = next(a for a in untyped.assignments if a.op == "txnas").outputs[0]
    assert r.is_scalar_tainted(minus) and not r.tainted_bytes(minus)
    assert r.tainted_bytes(acct) and not r.is_scalar_tainted(acct)


def test_byte_taint_attacker_index_into_clean_buffer_is_tainted():
    """1.5: an attacker-chosen OFFSET/INDEX into a CLEAN buffer selects which
    bytes emerge — attacker influence (engine ``SLICE_PROPAGATION_RULE``, and the
    engine's own ``setbyte`` rule) — but ``extract3`` / ``getbyte`` /
    ``extract_uint*`` consulted only the buffer's tainted bytes. Controls: a
    CONST offset into the same clean table stays clean (no finding), and a
    tainted COUNT with a const offset keeps the positional mapping exact."""
    from tealql.tealtools.dataflow.byte_taint import byte_taint

    dyn_offset = (_PARTIAL_GUARD + _TABLE + "txna ApplicationArgs 0\nint 4\n"
                  "extract_uint64\nint 32\nextract3\n" + _PAY_TAIL)
    const_offset = _PARTIAL_GUARD + _TABLE + "int 32\nint 32\nextract3\n" + _PAY_TAIL
    assert _fires_high(dyn_offset), "attacker-chosen window of a clean table read as clean"
    assert not _partial_findings(const_offset), "control: const window of a clean table"

    # Scalar bridge: tainted index into clean bytes -> tainted scalar; a
    # tainted COUNT alone does not move byte positions (precision kept).
    idx = ("#pragma version 10\n" + _TABLE + "txna ApplicationArgs 0\nbtoi\n"
           "extract_uint64\npop\nint 1\nreturn\n")
    prog = SSAProgram.from_text(idx, name="t")
    r = byte_taint(prog)
    v = next(a for a in prog.assignments if a.op == "extract_uint64").outputs[0]
    assert r.is_scalar_tainted(v)
    count = ("#pragma version 10\n" + _TABLE + "int 0\ntxna ApplicationArgs 0\nbtoi\n"
             "extract3\npop\nint 1\nreturn\n")
    prog = SSAProgram.from_text(count, name="t")
    r = byte_taint(prog)
    v = next(a for a in prog.assignments if a.op == "extract3").outputs[0]
    assert not r.tainted_bytes(v), "const offset + tainted count moves no byte"


def test_application_self_only_never_fabricates_not_self():
    """3.3: ``int 1..255`` as an application operand is a ``txn.Applications``
    offset — the same denotation as ``txna Applications i`` — and the array may
    hold the current app, yet the small-int branch returned ``False`` ("proven
    not self") while the array branch abstained. Control: ``int 0`` IS self."""
    from tealql.tealtools.analysis.resource_demand import resource_demand

    def self_only(app_operand: str):
        prog = SSAProgram.from_text(
            "#pragma version 10\n" + app_operand + '\nbyte "k"\napp_global_get_ex\n'
            "pop\npop\nint 1\nreturn\n", name="t")
        (read,) = resource_demand(prog).foreign_app_state
        return read.self_only

    assert self_only("int 0") is True                       # control: current app
    assert self_only("int 1") is None, "offset 1 read as proven-foreign"
    assert self_only("txna Applications 1") is None         # same denotation


def test_range_at_same_block_compares_blocks_by_value():
    """3.2: ``AssertDominance.dominates`` tested the same-block case with ``is``;
    a derived-view copy of the block (value-equal, distinct object) fell through
    to the reach test — in which the guard block never sits — so a use BEFORE the
    assert in the same block was refined by it. Control: the canonical block."""
    from tealql.tealtools.analysis import DerivedProfile, FactDomain, derived_program

    teal = ("#pragma version 10\ntxna ApplicationArgs 0\nbtoi\ndup\nitxn_begin\n"
            "int pay\nitxn_field TypeEnum\nitxn_field Amount\nint 10\n<\nassert\n"
            "int 1\nreturn\n")
    p = SSAProgram.from_text(teal, name="t")
    facts = p.facts(FactDomain.CONSTANTS, FactDomain.RANGES)

    def find(prog, op, imm=None):
        return next(a for a in prog.assignments
                    if a.op == op and (imm is None or a.immediates.strip() == imm))

    x = find(p, "btoi").outputs[0]
    full = (0, (1 << 64) - 1)
    canonical = facts.range_at(x, find(p, "itxn_field", "Amount"))
    assert (canonical.lo, canonical.hi) == full                # control
    g = derived_program(p, DerivedProfile.GUARDED)
    view = facts.range_at(x, find(g, "itxn_field", "Amount"))
    assert (view.lo, view.hi) == full, "pre-assert use refined via a view copy"
    # And the refinement DOES apply past the guard, through the view copy too.
    after = facts.range_at(x, find(g, "return"))
    assert (after.lo, after.hi) == (0, 9)


def test_op_cost_consults_avm_tables_before_puya_dynamic_verdict():
    """3.5: ``op_cost`` returned Puya's "dynamic, lower=1" before consulting the
    AVM immediate/length tables, so ``ecdsa_verify`` answered a floor of 1 to
    every metadata-only consumer (viz, loop_bounds ``1+``). Controls: a fixed
    op and an op Puya has not shipped (``sha512``) are unchanged."""
    from tealql.tealtools.budget.costs import op_cost

    assert op_cost("ecdsa_verify").lower == 1700
    assert op_cost("ecdsa_verify", "Secp256r1").lower == 2500
    assert op_cost("base64_decode", "StdEncoding").lower == 1          # true floor
    assert op_cost("sha256").exact and op_cost("sha256").lower == 35   # control
    sha512 = op_cost("sha512")
    assert sha512.lower >= 1 and not sha512.exact                      # control
