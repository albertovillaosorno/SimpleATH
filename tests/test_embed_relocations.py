# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline relocation parser preflight before legacy payload expansion."""

from pathlib import Path
import struct
import sys
from unittest import TestCase

# Legacy embed CLI uses script-relative imports; import never calls generate.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from embed import DYSYMTAB_COMMAND
from embed import DYSYMTAB_COMMAND_BYTES
from embed import MAX_EMBED_RELOCATIONS
from embed import checked_dysymtab_fields
from embed import checked_relocation_entries

RELOC_BYTES = 8
SAMPLE_ADDRESS = 8
SAMPLE_SYMBOL = 2
SAMPLE_COUNT = 1
SAMPLE_SYMBOL_COUNT = 3
EXTERNAL_SYMBOL = 1 << 27
BOUNDS_MESSAGE = "source bounds"
NEGATIVE_MESSAGE = "Negative"
INVALID_SYMBOL_MESSAGE = "out of range"
DYSYMTAB_SHAPE_MESSAGE = "exactly one complete"
DYSYMTAB_HEADER_MESSAGE = "Malformed"


def _bad(data: bytes, offset: int, count: int, *, symbol_count: int) -> str:
    """Return the fail-closed diagnostic from invalid source metadata.

    Returns:
        The ValueError diagnostic, or empty string for accepted input.

    """
    try:
        _ = checked_relocation_entries(data, offset, count, symbol_count)
    except ValueError as error:
        return str(error)
    return ""


class EmbedRelocationSafetyTests(TestCase):
    """No out-of-range source metadata reaches the legacy embed generator."""

    @staticmethod
    def test_valid_local_and_external_relocations() -> None:
        """Keep accepted addresses, bits and external symbol indexes exact."""
        external = EXTERNAL_SYMBOL | SAMPLE_SYMBOL
        data = struct.pack("<iI", SAMPLE_ADDRESS, external)
        data += struct.pack("<iI", SAMPLE_ADDRESS + RELOC_BYTES, 1)
        assert checked_relocation_entries(data, 0, 2, SAMPLE_SYMBOL_COUNT) == [
            (SAMPLE_ADDRESS, external),
            (SAMPLE_ADDRESS + RELOC_BYTES, 1),
        ]
        assert checked_relocation_entries(data, 0, 0, 0) == []
        assert checked_relocation_entries(data, RELOC_BYTES, 1, 0) == [
            (SAMPLE_ADDRESS + RELOC_BYTES, 1)
        ]

    @staticmethod
    def test_truncated_and_oversize_spans_rejected_first() -> None:
        """Refuse huge, negative, overflow and truncated table metadata."""
        good = struct.pack("<iI", SAMPLE_ADDRESS, EXTERNAL_SYMBOL)
        for start, count in (
            (-1, SAMPLE_COUNT),
            (0, -1),
            (1, SAMPLE_COUNT),
            (RELOC_BYTES + 1, SAMPLE_COUNT),
            (0, MAX_EMBED_RELOCATIONS + 1),
        ):
            assert BOUNDS_MESSAGE in _bad(good, start, count, symbol_count=1)

    @staticmethod
    def test_negative_addresses_and_unknown_externals_rejected() -> None:
        """Avoid accepting malformed signed addresses or unsafe indexing."""
        negative = struct.pack("<iI", -1, EXTERNAL_SYMBOL)
        assert NEGATIVE_MESSAGE in _bad(negative, 0, 1, symbol_count=1)
        absent = struct.pack("<iI", SAMPLE_ADDRESS, EXTERNAL_SYMBOL | 3)
        assert INVALID_SYMBOL_MESSAGE in _bad(
            absent, 0, 1, symbol_count=SAMPLE_SYMBOL_COUNT
        )
        assert BOUNDS_MESSAGE in _bad(absent, 0, 1, symbol_count=-1)


def _bad_dysymtab(commands: list[tuple[int, bytearray]]) -> str:
    """Return the malformed command diagnostic without invoking a build.

    Returns:
        The ValueError message, or an empty string when accepted.

    """
    try:
        _ = checked_dysymtab_fields(commands)
    except ValueError as error:
        return str(error)
    return ""


class EmbedDynamicSymbolPreflightTests(TestCase):
    """Reject corrupted legacy Mach-O layout before any output generation."""

    @staticmethod
    def test_exactly_one_complete_command() -> None:
        """Return exact metadata fields when the DYSYMTAB is complete."""
        fields = tuple(range(18))
        valid = bytearray(
            struct.pack(
                "<II18I", DYSYMTAB_COMMAND, DYSYMTAB_COMMAND_BYTES, *fields
            )
        )
        assert (
            checked_dysymtab_fields([(2, bytearray(24)), (11, valid)]) == fields
        )

    @staticmethod
    def test_missing_duplicate_or_truncated_command_rejected() -> None:
        """Never select a first-of-many or unpack a partial command."""
        valid = bytearray(
            struct.pack("<II18I", DYSYMTAB_COMMAND, 80, *([0] * 18))
        )
        for commands in (
            [],
            [(DYSYMTAB_COMMAND, valid[:-1])],
            [(DYSYMTAB_COMMAND, valid), (DYSYMTAB_COMMAND, valid)],
        ):
            assert DYSYMTAB_SHAPE_MESSAGE in _bad_dysymtab(commands)

    @staticmethod
    def test_inconsistent_command_header_rejected() -> None:
        """Do not trust a checked tuple tag with contradictory binary bytes."""
        valid = bytearray(
            struct.pack("<II18I", DYSYMTAB_COMMAND, 80, *([0] * 18))
        )
        for offset, value in ((0, 2), (4, 72)):
            invalid = bytearray(valid)
            struct.pack_into("<I", invalid, offset, value)
            assert DYSYMTAB_HEADER_MESSAGE in _bad_dysymtab([
                (DYSYMTAB_COMMAND, invalid)
            ])
