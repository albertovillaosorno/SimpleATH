# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic Mach-O fixtures for the offline embedding symbol parser."""

from dataclasses import dataclass
import struct
import unittest

from tools import embed_macho_parser as parser

MACHO_MAGIC = 0xFEEDFACF
X86_64_CPU = 0x1000007
SYMBOL_KIND = 0xF
SYMBOL_ADDRESS = 0x1000
COMMAND_OFFSET = 32
COMMAND_SIZE_OFFSET = 36
SYMTAB_OFFSET = 40
SYMBOL_COUNT_OFFSET = 44
STRING_OFFSET = 48
STRING_LENGTH_OFFSET = 52
SYMBOL_OFFSET = 56
NAME_OFFSET = 1
STRING_TABLE_OFFSET = 72
SAMPLE_NAME = "_ath"
SYMTAB_COMMAND = 2
STRING_BYTES = b"\0_ath\0"


@dataclass(frozen=True)
class _FakeImage:
    """Only the in-memory byte property required by the parser."""

    data: bytes


def _valid() -> bytearray:
    header = struct.pack("<8I", MACHO_MAGIC, X86_64_CPU, 3, 2, 1, 24, 0, 0)
    table = struct.pack("<6I", 2, 24, 56, 1, 72, len(STRING_BYTES))
    symbol = struct.pack(
        "<IBBHQ", NAME_OFFSET, SYMBOL_KIND, 1, 0, SYMBOL_ADDRESS
    )
    return bytearray(header + table + symbol + STRING_BYTES)


def _replace(offset: int, value: int, *, format_string: str = "<I") -> bytes:
    data = _valid()
    struct.pack_into(format_string, data, offset, value)
    return bytes(data)


def _rejects(data: bytes | bytearray) -> bool:
    try:
        _ = parser.parse(_FakeImage(bytes(data)))
    except ValueError:
        return True
    return False


class EmbedParserBoundsTests(unittest.TestCase):
    """Malformed pinned Mach-O metadata must fail before embed allocation."""

    @staticmethod
    def test_valid_image_retains_build_interface() -> None:
        """Return mutable commands and exact five-field symbol records."""
        payload = bytes(_valid())
        commands, symbols = parser.parse(_FakeImage(payload))
        assert commands == [(2, bytearray(payload[32:56]))]
        assert symbols == [(SAMPLE_NAME, SYMBOL_KIND, 1, 0, SYMBOL_ADDRESS)]
        commands[0][1][0] = 0
        assert payload[COMMAND_OFFSET] == SYMTAB_COMMAND

    @staticmethod
    def test_truncated_or_wrong_architecture_header_rejected() -> None:
        """Require complete x86_64 little-endian Mach-O metadata."""
        assert _rejects(b"")
        assert _rejects(bytes(_valid()[:31]))
        assert _rejects(_replace(0, 0))
        assert _rejects(_replace(4, 0x0100000C))

    @staticmethod
    def test_out_of_bounds_command_table_rejected() -> None:
        """Do not parse claimed command counts beyond their byte region."""
        assert _rejects(_replace(16, 2))
        assert _rejects(_replace(20, 0xFFFFFFF0))
        assert _rejects(_replace(COMMAND_SIZE_OFFSET, 0))
        assert _rejects(_replace(COMMAND_SIZE_OFFSET, 4))
        assert _rejects(_replace(COMMAND_SIZE_OFFSET, 25))
        assert _rejects(_replace(COMMAND_SIZE_OFFSET, 88))
        assert _rejects(_replace(20, 32))

    @staticmethod
    def test_missing_or_duplicate_symtab_fails_closed() -> None:
        """Exactly one complete symbol table is required for embedding."""
        assert _rejects(_replace(COMMAND_OFFSET, 0x19))
        assert _rejects(_replace(COMMAND_SIZE_OFFSET, 16))
        duplicate = _valid()
        duplicate[56:56] = duplicate[32:56]
        struct.pack_into("<II", duplicate, 16, 2, 48)
        assert _rejects(duplicate)

    @staticmethod
    def test_out_of_bounds_symbol_array_rejected() -> None:
        """Reject overflowing and truncated nlist64 metadata."""
        assert _rejects(_replace(SYMTAB_OFFSET, 0xFFFFFFFF))
        assert _rejects(_replace(SYMBOL_COUNT_OFFSET, 0xFFFFFFFF))
        assert _rejects(_replace(SYMTAB_OFFSET, STRING_TABLE_OFFSET + 2))
        assert _rejects(_replace(SYMBOL_COUNT_OFFSET, 2))

    @staticmethod
    def test_out_of_bounds_string_array_rejected() -> None:
        """String table bounds cannot exceed the actual image length."""
        assert _rejects(_replace(STRING_OFFSET, 0xFFFFFFFF))
        assert _rejects(_replace(STRING_LENGTH_OFFSET, 0xFFFFFFFF))
        assert _rejects(_replace(STRING_OFFSET, 76))

    @staticmethod
    def test_invalid_or_unterminated_symbol_name_rejected() -> None:
        """Check full string-table containment before decoding names."""
        assert _rejects(_replace(SYMBOL_OFFSET, len(STRING_BYTES)))
        unterminated = _valid()
        unterminated[STRING_TABLE_OFFSET:] = b"\0_abcx"
        assert _rejects(unterminated)
        invalid_utf8 = _valid()
        invalid_utf8[STRING_TABLE_OFFSET + 1] = 0xFF
        assert _rejects(invalid_utf8)

    @staticmethod
    def test_zero_symbol_table_allowed_with_valid_strings() -> None:
        """A bounded zero-symbol table has no synthetic symbol entries."""
        commands, symbols = parser.parse(
            _FakeImage(_replace(SYMBOL_COUNT_OFFSET, 0))
        )
        assert len(commands) == 1
        assert symbols == []
