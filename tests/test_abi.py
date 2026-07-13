"""ABI method-table recovery from source high-level info (`tealtools.abi`).

Signatures survive as source text (`method "sig"` pseudo-ops + `// method "sig"`
comments); we compute the selector FORWARD and never reverse the hash. Optional:
raw bytecode with no `method` text yields an empty table.
"""
from __future__ import annotations

import glob

from tealql.tealtools.abi import (
    parse_signature, method_selector, abi_type_byte_length, extract_method_table,
)


class TestSelector:
    def test_matches_the_compiler_hash(self):
        # the corpus emits `pushbytes 0x03b5c0af // method "add_one(uint64)uint64"`
        assert method_selector("add_one(uint64)uint64").hex() == "03b5c0af"

    def test_selector_hex_property(self):
        m = parse_signature("add_one(uint64)uint64")
        assert m.selector_hex == "0x03b5c0af"


class TestParse:
    def test_simple(self):
        m = parse_signature("store(address,uint64,uint64)void")
        assert m.name == "store"
        assert m.arg_types == ("address", "uint64", "uint64")
        assert m.return_type == "void"

    def test_no_args(self):
        m = parse_signature("acc_ret()address")
        assert m.name == "acc_ret" and m.arg_types == () and m.return_type == "address"

    def test_nested_tuple_arg_and_return_tuple(self):
        # the args list is balanced on the FIRST paren, so a tuple return doesn't
        # get mis-parsed as an argument.
        m = parse_signature("foo((uint64,bool),byte[])(uint64,address)")
        assert m.arg_types == ("(uint64,bool)", "byte[]")
        assert m.return_type == "(uint64,address)"

    def test_malformed_returns_none(self):
        assert parse_signature("not a signature") is None
        assert parse_signature("(uint64)void") is None       # no name
        assert parse_signature("foo(uint64") is None          # unbalanced


class TestByteLength:
    def test_scalars(self):
        assert abi_type_byte_length("uint64") == 8
        assert abi_type_byte_length("uint256") == 32
        assert abi_type_byte_length("address") == 32
        assert abi_type_byte_length("bool") == 1
        assert abi_type_byte_length("byte") == 1
        assert abi_type_byte_length("ufixed64x2") == 8

    def test_static_composites(self):
        assert abi_type_byte_length("byte[32]") == 32
        assert abi_type_byte_length("uint64[4]") == 32
        assert abi_type_byte_length("(uint64,address)") == 40

    def test_bools_bit_pack(self):
        assert abi_type_byte_length("bool[8]") == 1
        assert abi_type_byte_length("bool[9]") == 2
        assert abi_type_byte_length("(bool,bool,bool)") == 1       # 3 bits -> 1 byte
        assert abi_type_byte_length("(bool,uint64,bool)") == 10    # 1 + 8 + 1

    def test_dynamic_and_transaction_are_none(self):
        for t in ("string", "byte[]", "uint64[]", "pay", "axfer", "appl",
                  "(uint64,byte[])"):
            assert abi_type_byte_length(t) is None, t

    def test_reference_types_are_uint8(self):
        # account/asset/application encode as a uint8 foreign-array index.
        for t in ("account", "asset", "application"):
            assert abi_type_byte_length(t) == 1, t


class TestAppArgMapping:
    def test_direct_mapping(self):
        m = parse_signature("store(address,uint64,uint64)void")
        # ApplicationArgs[0]=selector; [1]=address(32), [2]=uint64(8), [3]=uint64(8)
        assert m.app_arg_byte_length(1) == 32
        assert m.app_arg_byte_length(2) == 8
        assert m.app_arg_byte_length(3) == 8
        assert m.app_arg_byte_length(0) is None      # the selector, not an arg
        assert m.app_arg_byte_length(4) is None      # past the args

    def test_transaction_args_shift_the_index(self):
        # a `pay` arg rides as a group txn, so it does NOT consume an ApplicationArg:
        # ApplicationArgs[1] is the uint64, not the payment.
        m = parse_signature("deposit(pay,uint64)void")
        assert m.app_arg_types == ("uint64",)
        assert m.app_arg_byte_length(1) == 8

    def test_reference_arg_occupies_a_slot(self):
        m = parse_signature("optin(account,uint64)void")
        assert m.app_arg_types == ("account", "uint64")
        assert m.app_arg_byte_length(1) == 1         # account -> uint8 index
        assert m.app_arg_byte_length(2) == 8


class TestExtract:
    def test_pseudo_op_and_comment_forms(self):
        src = (
            '#pragma version 10\n'
            '    method "transfer(uint64,address)void"\n'          # pseudo-op form
            '    pushbytes 0x03b5c0af // method "add_one(uint64)uint64"\n'  # comment form
        )
        tbl = extract_method_table(src)
        names = {m.name for m in tbl.values()}
        assert names == {"transfer", "add_one"}
        assert tbl["0x03b5c0af"].arg_types == ("uint64",)

    def test_empty_on_raw_bytecode(self):
        # no `method "..."` text -> optional layer contributes nothing
        assert extract_method_table("#pragma version 8\npushbytes 0x03b5c0af\nint 1\nreturn\n") == {}

    def test_corpus_selectors_match_source(self):
        # SOUNDNESS on real compiler output: every recovered selector must actually
        # appear as a pushbytes/pushbytess operand in the source (forward hash ==
        # what the compiler emitted).
        seen = 0
        for f in glob.glob("tests/experimental_IR_lift/puya/*/src/*.teal"):
            src = open(f).read()
            tbl = extract_method_table(src)
            for sel in tbl:
                assert sel[2:] in src, (f, sel)
            seen += len(tbl)
        assert seen > 20            # the ABI-router corpus contracts contribute plenty
