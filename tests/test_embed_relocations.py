# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline relocation parser preflight before legacy payload expansion."""

from datetime import datetime
from pathlib import Path
import plistlib
import struct
import sys
from unittest import TestCase

# Legacy embed CLI uses script-relative imports; import never calls generate.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from embed import ALIASES
from embed import CommandLayout
from embed import DYSYMTAB_COMMAND
from embed import DYSYMTAB_COMMAND_BYTES
from embed import MAX_EMBED_RELOCATIONS
from embed import MAX_EXPANDED_PAYLOAD_BYTES
from embed import RelocationContext
from embed import checked_alias_name
from embed import checked_dysymtab_fields
from embed import checked_info_plist
from embed import checked_payload_size
from embed import checked_relocation_entries
from embed import checked_relocation_width
from embed import expanded_legacy_image
from embed import image_relocations
from embed import remap_file_offset
from embed import require_embed
from embed import vtable_class_name
from embed_payload_codec import align
from macho import Image
from native_payload import SkywalkPlan

RELOC_BYTES = 8
BUNDLE_ID = "dev.test.payload"
SAMPLE_BINARY_DATA = b"\x00\xff"
SAMPLE_DATE = datetime.fromisoformat("2026-01-01")
CHILD_VTABLE = "__ZTV5Child"
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
ALIAS_REJECT = "inconsistent"


def _bad(data: bytes, offset: int, count: int, *, symbol_count: int) -> str:
    """Return the fail-closed diagnostic from invalid source metadata.

    Returns:
        The ValueError diagnostic, or empty string for accepted input.

    """
    try:
        _ = checked_relocation_entries(
            data, offset, count, symbol_count=symbol_count
        )
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
        assert checked_relocation_entries(
            data, 0, 2, symbol_count=SAMPLE_SYMBOL_COUNT
        ) == [
            (SAMPLE_ADDRESS, external),
            (SAMPLE_ADDRESS + RELOC_BYTES, 1),
        ]
        assert checked_relocation_entries(data, 0, 0, symbol_count=0) == []
        assert checked_relocation_entries(
            data, RELOC_BYTES, 1, symbol_count=0
        ) == [(SAMPLE_ADDRESS + RELOC_BYTES, 1)]

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


class EmbedAlwaysCheckedInvariantsTests(TestCase):
    """Source artifact guards must not depend on Python assert statements."""

    @staticmethod
    def test_valid_condition_is_noop() -> None:
        """Preserve successful input without changing the generated data."""
        require_embed(condition=True, message="unused")

    @staticmethod
    def test_invalid_condition_preserves_diagnostic() -> None:
        """Reject unsafe metadata with a stable, explicit ValueError."""
        message = "Synthetic unsupported generator metadata"
        try:
            require_embed(condition=False, message=message)
        except ValueError as error:
            received = str(error)
        else:
            received = ""
        assert received == message


class EmbedExtractedMetadataTests(TestCase):
    """Isolated source image fixtures verify generator helper semantics."""

    @staticmethod
    def test_vtable_class_mangling_requires_exact_name_length() -> None:
        """Recognize exact source and parent metadata, not prefix aliases."""
        assert (
            vtable_class_name("__ZN5Child10superClassE", "10superClassE")
            == CHILD_VTABLE
        )
        assert (
            vtable_class_name("__ZN5Child10gMetaClassE", "10gMetaClassE")
            == CHILD_VTABLE
        )
        assert (
            vtable_class_name("__ZN6Child10superClassE", "10superClassE")
            is None
        )
        assert (
            vtable_class_name("__ZN5Child10gMetaClassE", "10superClassE")
            is None
        )

    @staticmethod
    def _image() -> Image:
        """Return a synthetic in-memory Image without loading a native file.

        Returns:
            Source bytes, segments and section bounds for offline tests.

        """
        image = Image.__new__(Image)
        image.data = bytes(512)
        image.segments = [("__TEXT", 0, 512, 0, 512)]
        image.sections = [("__text", "__TEXT", 0, 1, 256)]
        image.symbols = {}
        return image

    @staticmethod
    def test_external_and_local_relocations_keep_fields_and_order() -> None:
        """Preserve decoded targets, addends and section ownership."""
        image = EmbedExtractedMetadataTests._image()
        data = bytearray(image.data)
        struct.pack_into("<q", data, 0, 4)
        struct.pack_into("<q", data, 8, 24)
        external_bits = (3 << 25) | EXTERNAL_SYMBOL
        local_bits = (3 << 25) | 1
        struct.pack_into("<iI", data, 16, 0, external_bits)
        struct.pack_into("<iI", data, 24, 8, local_bits)
        image.data = bytes(data)
        fields = [0] * 18
        fields[14:18] = [16, 1, 24, 1]
        model = SkywalkPlan.__new__(SkywalkPlan)
        context = RelocationContext(
            0,
            image,
            [("_defined", 15, 1, 0, 12)],
            tuple(fields),
            [{}],
            model,
            {},
        )
        assert image_relocations(context) == (
            [(0, 12, 4, 0, 8), (8, 24, 0, 0, 8)],
            0,
        )

    @staticmethod
    def test_compatibility_alias_requires_exact_source_slot() -> None:
        """Do not silently accept a mismatched compatibility address."""
        image = EmbedExtractedMetadataTests._image()
        image.symbols = {"__ZTV34AirPort_Brcm43xxLLSkywalkInterface": 256}
        context = RelocationContext(
            0,
            image,
            [],
            tuple([0] * 18),
            [{}],
            SkywalkPlan.__new__(SkywalkPlan),
            {},
        )
        name, replacement = next(iter(ALIASES.items()))
        address = 256 + 16 + 0xA70
        assert checked_alias_name(context, name, (address, 8, 0)) == replacement
        for invalid in ((address + 8, 8, 0), (address, 4, 0), (address, 8, 1)):
            rejected = False
            try:
                _ = checked_alias_name(context, name, invalid)
            except ValueError as error:
                rejected = ALIAS_REJECT in str(error)
            assert rejected

    @staticmethod
    def test_rebased_load_commands_preserve_mapped_offsets() -> None:
        """Rebase checked symbol and dynamic tables without executing source."""
        image = EmbedExtractedMetadataTests._image()
        symtab = bytearray(struct.pack("<6I", 2, 24, 300, 0, 320, 8))
        dysymtab = bytearray(struct.pack("<II18I", 11, 80, *([0] * 18)))
        layout = CommandLayout(
            image,
            [(2, symtab), (11, dysymtab)],
            [],
            512,
            4096,
        )
        expanded, values = expanded_legacy_image(layout)
        assert values == []
        assert struct.unpack_from("<II", expanded, 16) == (3, 176)
        assert struct.unpack_from("<4I", expanded, 40) == (300, 0, 320, 8)
        assert struct.unpack_from("<II", expanded, 32 + 24 + 80) == (25, 72)


class EmbedInfoPlistTypeSafetyTests(TestCase):
    """Retain legal plist values while checking required source dependencies."""

    @staticmethod
    def test_binary_and_date_plist_values_are_preserved() -> None:
        """Only required fields are constrained; plist bytes are not dropped."""
        original: dict[str, object] = {
            "CFBundleIdentifier": BUNDLE_ID,
            "OSBundleLibraries": {"com.apple.iokit.IOPCIFamily": "2.9"},
            "Data": SAMPLE_BINARY_DATA,
            "Date": SAMPLE_DATE,
        }
        info, identifier, libraries = checked_info_plist(
            plistlib.dumps(original)
        )
        assert identifier == BUNDLE_ID
        assert libraries == {"com.apple.iokit.IOPCIFamily": "2.9"}
        assert info["Data"] == SAMPLE_BINARY_DATA
        assert info["Date"] == SAMPLE_DATE
        _ = plistlib.dumps(info)

    @staticmethod
    def test_invalid_required_identity_and_libraries_rejected() -> None:
        """Reject malformed bundle metadata before any output is written."""
        cases: list[dict[str, object]] = [
            {"CFBundleIdentifier": 5, "OSBundleLibraries": {}},
            {"CFBundleIdentifier": "dev.test", "OSBundleLibraries": []},
            {"CFBundleIdentifier": "dev.test", "OSBundleLibraries": {"x": 5}},
        ]
        for entry in cases:
            rejected = False
            try:
                _ = checked_info_plist(plistlib.dumps(entry))
            except TypeError, ValueError:
                rejected = True
            assert rejected
