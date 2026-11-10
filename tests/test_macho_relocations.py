# Copyright (c) 2026 SimpleATH contributors.
"""Bounded Mach-O relocation regression on synthetic bytes, no KDK reads."""

import struct
from unittest import TestCase

from tools import macho
from tools import profiles

HEADER_SIZE = 32
SYMTAB_SIZE = 24
DYSYMTAB_SIZE = 80
SYMBOL_SIZE = 16
RELOCATION_SIZE = 8
COPY_SYMBOL = b"\0_copyin\0"
SYNTHETIC_DATA = b"test"


def _image_bytes() -> bytes:
    """Construct a bounded synthetic symbol/dynamic relocation table.

    Returns:
        A minimal in-memory header and relocation record for the parser.

    """
    command_offset = HEADER_SIZE
    symbols_offset = command_offset + SYMTAB_SIZE + DYSYMTAB_SIZE
    strings_offset = symbols_offset + SYMBOL_SIZE
    relocation_offset = strings_offset + len(COPY_SYMBOL)
    data = bytearray(relocation_offset + RELOCATION_SIZE)
    struct.pack_into("<II", data, 16, 2, SYMTAB_SIZE + DYSYMTAB_SIZE)
    struct.pack_into("<II", data, command_offset, 2, SYMTAB_SIZE)
    struct.pack_into(
        "<IIII",
        data,
        command_offset + 8,
        symbols_offset,
        1,
        strings_offset,
        len(COPY_SYMBOL),
    )
    struct.pack_into(
        "<II",
        data,
        command_offset + SYMTAB_SIZE,
        0xB,
        DYSYMTAB_SIZE,
    )
    struct.pack_into(
        "<II",
        data,
        command_offset + SYMTAB_SIZE + 8 + 14 * 4,
        relocation_offset,
        1,
    )
    struct.pack_into("<I", data, symbols_offset, 1)
    data[strings_offset:relocation_offset] = COPY_SYMBOL
    struct.pack_into("<II", data, relocation_offset, 0x123, 1 << 25)
    return bytes(data)


def _image(data: bytes) -> macho.Image:
    """Create only the parsing view; do not open a real image file.

    Returns:
        A fake in-memory Image with the synthetic binary bytes.

    """
    image = object.__new__(macho.Image)
    image.data = data
    return image


class MachoRelocationBoundaries(TestCase):
    """Accept valid relocation metadata, reject malformed ranges."""

    @staticmethod
    def test_valid_copyin_relocation() -> None:
        """Preserve address, width, name and kind from a valid record."""
        result = profiles.relocations(_image(_image_bytes()))
        assert result == [(0x123, 2, "_copyin", 0)]

    @staticmethod
    def test_command_bytes_and_count_must_match_header() -> None:
        """Reject metadata parsed past the declared load-command area."""
        data = bytearray(_image_bytes())
        command_bytes = SYMTAB_SIZE + DYSYMTAB_SIZE
        struct.pack_into("<I", data, 20, command_bytes - 1)
        assert _rejects(bytes(data), "Invalid Mach-O load command size")
        struct.pack_into("<I", data, 20, command_bytes + 8)
        assert _rejects(bytes(data), "do not fill declared command range")
        struct.pack_into("<II", data, 16, 0xFFFFFFFF, command_bytes)
        assert _rejects(bytes(data), "load commands exceed")

    @staticmethod
    def test_unbacked_command_tail_rejected_before_symbol_reads() -> None:
        """Require the declared command extent to fit physical file bytes."""
        data = bytearray(_image_bytes())
        struct.pack_into("<I", data, 20, len(data))
        assert _rejects(bytes(data), "load commands exceed")

    @staticmethod
    def test_missing_symbol_tables_rejected() -> None:
        """Never dereference a missing symbol or relocation command."""
        data = bytearray(_image_bytes())
        struct.pack_into("<I", data, HEADER_SIZE, 0)
        assert _rejects(bytes(data), "Missing Mach-O relocation")

    @staticmethod
    def test_truncated_records_rejected() -> None:
        """Refuse a declared relocation count beyond the available file."""
        data = bytearray(_image_bytes())
        struct.pack_into(
            "<I",
            data,
            HEADER_SIZE + SYMTAB_SIZE + 8 + 15 * 4,
            2,
        )
        assert _rejects(bytes(data), "exceed file bounds")

    @staticmethod
    def test_missing_symbol_index_rejected() -> None:
        """Reject an indirect reference beyond the available nsyms."""
        data = bytearray(_image_bytes())
        struct.pack_into("<I", data, len(data) - 4, (1 << 25) | 1)
        assert _rejects(bytes(data), "missing symbol")

    @staticmethod
    def test_unterminated_symbol_name_rejected() -> None:
        """Require NUL termination within the declared string table."""
        data = bytearray(_image_bytes())
        strings_offset = HEADER_SIZE + SYMTAB_SIZE + DYSYMTAB_SIZE + SYMBOL_SIZE
        data[strings_offset + len(COPY_SYMBOL) - 1] = ord("x")
        assert _rejects(bytes(data), "unterminated")

    @staticmethod
    def test_negative_or_truncated_mapped_reads_rejected() -> None:
        """Never return a shorter slice as if it were a mapped byte range."""
        image = _image(SYNTHETIC_DATA)
        image.segments = [("synthetic", 100, 6, 0, 6)]
        assert image.read(100, 4) == SYNTHETIC_DATA
        assert all(
            _read_rejected(image, address, size)
            for address, size in ((-1, 1), (100, -1), (102, 4))
        )


def _rejects(data: bytes, expected: str) -> bool:
    """Check a particular malformed relocation error.

    Returns:
        True when the intended data-integrity boundary rejects bytes.

    """
    try:
        _ = profiles.relocations(_image(data))
    except ValueError as error:
        return expected in str(error)
    return False


def _read_rejected(image: macho.Image, address: int, size: int) -> bool:
    """Check that an invalid virtual byte range fails.

    Returns:
        True when the memory range is rejected.

    """
    try:
        _ = image.read(address, size)
    except ValueError:
        return True
    return False
