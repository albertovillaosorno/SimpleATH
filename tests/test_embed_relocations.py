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
from embed import MAX_EXPANDED_PAYLOAD_BYTES
from embed import checked_dysymtab_fields
from embed import checked_payload_size
from embed import checked_relocation_entries
from embed import checked_relocation_width
from embed import remap_file_offset
from embed_payload_codec import align

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


MAPPED_START = 0x1000
MAPPED_LAST = 0x100F
UNMAPPED_MESSAGE = "Unmapped"


def _bad_file_offset(
    offset: int, segments: list[tuple[str, int, int, int, int]]
) -> str:
    """Return an invalid segment offset's rejection diagnostic.

    Returns:
        The RuntimeError message, or empty text for mapped offsets.

    """
    try:
        _ = remap_file_offset(offset, segments)
    except RuntimeError as error:
        return str(error)
    return ""


RELOCATION_REJECT = "Unsupported"
ABSOLUTE_BYTES = 8
RELATIVE_BYTES = 4
LOCAL_BRANCH_REJECT = "Local"


def _bad_relocation_width(bits: int, *, external: bool) -> str:
    """Return the rejected synthetic encoding's diagnostic.

    Returns:
        The ValueError message, or empty text on a supported relocation.

    """
    try:
        _ = checked_relocation_width(bits, external=external)
    except ValueError as error:
        return str(error)
    return ""


class EmbedRelocationEncodingTests(TestCase):
    """Enforce complete x86_64 relocation shape and table ownership."""

    @staticmethod
    def test_absolute_and_branch_shapes_accepted() -> None:
        """Preserve supported 64-bit absolute and 32-bit PC-relative forms."""
        absolute_external = (3 << 25) | EXTERNAL_SYMBOL
        absolute_local = 3 << 25
        relative_branch = (2 << 28) | (2 << 25) | (1 << 24) | EXTERNAL_SYMBOL
        assert (
            checked_relocation_width(absolute_external, external=True)
            == ABSOLUTE_BYTES
        )
        assert (
            checked_relocation_width(absolute_local, external=False)
            == ABSOLUTE_BYTES
        )
        assert (
            checked_relocation_width(relative_branch, external=True)
            == RELATIVE_BYTES
        )

    @staticmethod
    def test_conflicting_table_and_unsupported_shape_rejected() -> None:
        """Do not reinterpret external slots as internal section records."""
        absolute_external = (3 << 25) | EXTERNAL_SYMBOL
        relative_local = (2 << 28) | (2 << 25) | (1 << 24)
        invalid_width = (1 << 25) | EXTERNAL_SYMBOL
        assert RELOCATION_REJECT in _bad_relocation_width(
            absolute_external, external=False
        )
        assert LOCAL_BRANCH_REJECT in _bad_relocation_width(
            relative_local, external=False
        )
        assert RELOCATION_REJECT in _bad_relocation_width(
            invalid_width, external=True
        )


class EmbeddedSegmentMappingTests(TestCase):
    """Relocation source file offsets must map through a bounded segment."""

    @staticmethod
    def test_mapped_offsets_and_exclusive_terminal_bound() -> None:
        """Preserve section-relative addresses without an inclusive end."""
        segments = [("__TEXT", MAPPED_START, 0x100, 0x20, 0x10)]
        assert remap_file_offset(0x20, segments) == MAPPED_START
        assert remap_file_offset(0x2F, segments) == MAPPED_LAST
        for invalid in (0x1F, 0x30, -1):
            assert UNMAPPED_MESSAGE in _bad_file_offset(invalid, segments)


BAD_SEGMENT_BOUNDS = "source bounds"
BAD_SEGMENT_OVERLAP = "overlap"
BAD_SEGMENT_LIMIT = "virtual limit"
BAD_SEGMENT_MISSING = "no segments"
BAD_SEGMENT_ZERO = "no mapped virtual bytes"
EXPECTED_VIRTUAL_SPAN = 24


def _bad_payload(
    data: bytes, rows: list[tuple[str, int, int, int, int]]
) -> str:
    """Return malformed synthetic virtual image metadata diagnostics.

    Returns:
        The ValueError message, or empty text when all regions are safe.

    """
    try:
        _ = checked_payload_size(data, rows)
    except ValueError as error:
        return str(error)
    return ""


class PayloadVirtualImageSafetyTests(TestCase):
    """A corrupted segment never truncates or overallocates an embedding."""

    @staticmethod
    def test_complete_disjoint_segments_are_accepted() -> None:
        """Size a source-backed image with virtual zero-fill and padding."""
        rows = [("__TEXT", 0, 9, 0, 5), ("__DATA", 16, 8, 5, 3)]
        assert checked_payload_size(b"abcdefgh", rows) == align(
            EXPECTED_VIRTUAL_SPAN
        )

    @staticmethod
    def test_source_spans_and_virtual_lengths_rejected() -> None:
        """Disallow missing bytes, negative fields and virtual shortfalls."""
        data = b"abc"
        for row in (
            ("__TEXT", 0, 4, 1, 3),
            ("__TEXT", 0, 2, 0, 3),
            ("__TEXT", 0, 2, -1, 1),
            ("__TEXT", -1, 2, 0, 1),
        ):
            assert BAD_SEGMENT_BOUNDS in _bad_payload(data, [row])

    @staticmethod
    def test_oversized_virtual_image_and_overlaps_rejected() -> None:
        """Avoid huge allocation and mapped-region alias ambiguity."""
        source = b"abc"
        huge = [("__TEXT", 0, MAX_EXPANDED_PAYLOAD_BYTES + 1, 0, 1)]
        assert BAD_SEGMENT_LIMIT in _bad_payload(source, huge)
        overlapping = [("__TEXT", 0, 8, 0, 1), ("__DATA", 7, 9, 1, 2)]
        assert BAD_SEGMENT_OVERLAP in _bad_payload(source, overlapping)
        assert BAD_SEGMENT_MISSING in _bad_payload(source, [])
        assert BAD_SEGMENT_ZERO in _bad_payload(
            source, [("__TEXT", 0, 0, 0, 0)]
        )
