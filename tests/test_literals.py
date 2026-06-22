"""Unit tests for TEAL literal / operand parsing (``tealtools.ast.literals``) —
the pure-text helpers the parse layer owns (no puya dependency).
"""
from tealtools.ast.literals import decode_byte_literal, tokenize_operands


class TestDecodeByteLiteral:
    def test_hex(self):
        assert decode_byte_literal("0xdeadbeef") == (b"\xde\xad\xbe\xef", "base16")
        # bare hex (no 0x prefix) is accepted as base16
        assert decode_byte_literal("deadbeef") == (b"\xde\xad\xbe\xef", "base16")

    def test_quoted_string_and_escapes(self):
        assert decode_byte_literal('"hello"') == (b"hello", "utf8")
        # \xNN, \n, \t, \\ , \"
        raw, enc = decode_byte_literal(r'"a\x41b\n\t\\\""')
        assert raw == b'aAb\n\t\\"'
        assert enc == "utf8"

    def test_base64_forms(self):
        assert decode_byte_literal("b64 aGk=") == (b"hi", "base64")
        assert decode_byte_literal("base64 aGk=") == (b"hi", "base64")
        assert decode_byte_literal("base64(aGk=)") == (b"hi", "base64")
        # TEAL writes base64 without padding -> re-padded internally
        assert decode_byte_literal("b64 aGk") == (b"hi", "base64")

    def test_base32_forms(self):
        assert decode_byte_literal("b32 NBSWY3DP") == (b"hello", "base32")
        assert decode_byte_literal("base32(NBSWY3DP)") == (b"hello", "base32")

    def test_non_hex_text_falls_back_to_utf8(self):
        assert decode_byte_literal("xyz") == (b"xyz", "utf8")


class TestTokenizeOperands:
    def test_plain(self):
        assert tokenize_operands("ApplicationArgs 0") == ["ApplicationArgs", "0"]

    def test_quoted_string_with_spaces(self):
        assert tokenize_operands('"x y" 5') == ['"x y"', "5"]

    def test_base64_group_with_spaces_and_slash(self):
        # parenthesised base64(..) is one token even with spaces and '/'
        assert tokenize_operands("base64(a b/c==) 1") == ["base64(a b/c==)", "1"]

    def test_stops_at_inline_comment(self):
        assert tokenize_operands("5 6 // trailing") == ["5", "6"]

    def test_empty(self):
        assert tokenize_operands("") == []
        assert tokenize_operands("   ") == []


class TestFoldByteKeywords:
    # bytecblock-literal mode: `b64 <data>` etc. fold into one token.
    def test_keyword_data_folds(self):
        assert tokenize_operands("b64 AAAA", fold_byte_keywords=True) == ["b64 AAAA"]
        assert tokenize_operands(
            "0x01 base64 aGk= \"x\" b32 NBSW", fold_byte_keywords=True
        ) == ["0x01", "base64 aGk=", '"x"', "b32 NBSW"]

    def test_without_fold_keyword_and_data_are_separate(self):
        assert tokenize_operands("b64 AAAA") == ["b64", "AAAA"]

    def test_base64_parens_still_one_token(self):
        assert tokenize_operands(
            "base64(aGk=) 0x02", fold_byte_keywords=True
        ) == ["base64(aGk=)", "0x02"]

    def test_matches_legacy_split_byte_literals(self):
        # the const_values alias must produce identical tokens for the
        # bytecblock forms it was written for.
        from tealtools.const_values import _split_byte_literals
        for imms in ['0x01 0x02', 'b64 aGk= "hi"', 'base64(AAAA==) 0x00',
                     'b32 NBSWY3DP base32(NBSW)', '5 6 7']:
            assert _split_byte_literals(imms) == tokenize_operands(
                imms, fold_byte_keywords=True), imms
