# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic Mach-O parser safety checks with no real system images."""

import mmap
import os
from pathlib import Path
import struct
import tempfile
from typing import TYPE_CHECKING
from unittest import TestCase
from unittest import mock

from tools import native_abi

if TYPE_CHECKING:
    from collections.abc import Callable

FILE_SIZE = 512
VM_BASE = 0x1000
CPU_X86_64 = 0x01000007
MAGIC_64 = 0xFEEDFACF
SEGMENT_COMMAND = 25
SEGMENT_COMMAND_SIZE = 72
SYMTAB_COMMAND = 2
DYSYMTAB_COMMAND = 11
SYMBOL_OFFSET = 256
STRING_OFFSET = 272
RELOCATION_OFFSET = 320
SEGMENT_SECTIONS_OFFSET = 64
FAT_OFFSET = 64
EXPORTED = "_foo"
EMPTY_BYTES = b""


def _segment(*, section: bytes = b"") -> bytes:
    """Make a file-backed 64-bit segment with optional synthetic section.

    Returns:
        Bytes for one self-contained segment command.

    """
    return (
        struct.pack(
            "<II16sQQQQiiII",
            SEGMENT_COMMAND,
            SEGMENT_COMMAND_SIZE + len(section),
            b"__TEXT",
            VM_BASE,
            FILE_SIZE,
            0,
            FILE_SIZE,
            7,
            5,
            bool(section),
            0,
        )
        + section
    )


def _symtab(*, offset: int = SYMBOL_OFFSET, count: int = 1) -> bytes:
    return struct.pack(
        "<6I", SYMTAB_COMMAND, 24, offset, count, STRING_OFFSET, 16
    )


def _dysym(*, offset: int = RELOCATION_OFFSET, count: int = 1) -> bytes:
    fields = [0] * 18
    fields[14:16] = [offset, count]
    return struct.pack("<20I", DYSYMTAB_COMMAND, 80, *fields)


def _thin(*commands: bytes, section: bytes = b"") -> bytearray:
    """Prepare a bounded synthetic Mach-O containing only parsed fields.

    Returns:
        Mutable bytes for synthetic fault injection.

    Raises:
        ValueError: The generated fixture exceeds its bounded file size.

    """
    all_commands = (_segment(section=section), *commands)
    body = b"".join(all_commands)
    header = struct.pack(
        "<8I", MAGIC_64, CPU_X86_64, 3, 2, len(all_commands), len(body), 0, 0
    )
    payload = header + body
    if len(payload) > FILE_SIZE:
        message = "Synthetic test image exceeded file size"
        raise ValueError(message)
    return bytearray(payload.ljust(FILE_SIZE, b"\x00"))


def _with_symbols(*extra_commands: bytes, section: bytes = b"") -> bytearray:
    image = _thin(_symtab(), *extra_commands, section=section)
    struct.pack_into("<IBBHQ", image, SYMBOL_OFFSET, 1, 15, 1, 0, VM_BASE)
    image[STRING_OFFSET : STRING_OFFSET + 7] = b"\x00_foo\x00\x00"
    return image


def _open(
    data: bytes | bytearray, action: Callable[[native_abi.Mach], object]
) -> object:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.macho"
        _ = path.write_bytes(data)
        image = native_abi.Mach(path)
        if not isinstance(image, native_abi.Mach):
            message = "Expected a synthetic Mach-O rather than JSON reference"
            raise TypeError(message)
        try:
            return action(image)
        finally:
            image.close()


def _reject(data: bytes | bytearray) -> bool:
    try:
        _ = _open(data, lambda _: None)
    except ValueError:
        return True
    return False


def _reject_reloc(data: bytes | bytearray) -> bool:
    try:
        _ = _open(data, lambda image: image.relocs())
    except ValueError:
        return True
    return False


def _reject_action(
    data: bytes | bytearray, action: Callable[[native_abi.Mach], object]
) -> bool:
    try:
        _ = _open(data, action)
    except ValueError:
        return True
    return False


def _reject_named_entry(data: bytes | bytearray, name: str) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.macho"
        _ = path.write_bytes(data)
        try:
            image = native_abi.Mach(path, name)
        except ValueError:
            return True
        image.close()
    return False


class NativeAbiMachoBoundsTests(TestCase):
    """Reject crafted malformed files rather than reading outside mappings."""

    @staticmethod
    def test_thin_and_fat_images_keep_valid_file_backed_reads() -> None:
        """Map expected x86_64 virtual bytes in a synthetic thin/FAT image."""
        thin = _thin()
        assert _open(thin, lambda image: image.read(VM_BASE, 4)) == thin[:4]
        fat_header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
        fat_arch = struct.pack(">5I", CPU_X86_64, 3, FAT_OFFSET, len(thin), 0)
        fat = (fat_header + fat_arch).ljust(FAT_OFFSET, b"\x00") + thin
        assert _open(fat, lambda image: image.read(VM_BASE, 4)) == thin[:4]
        assert _open(thin, lambda image: image.off(VM_BASE)) == 0
        assert _open(fat, lambda image: image.off(VM_BASE)) == FAT_OFFSET

    @staticmethod
    def test_reject_malformed_fat_architectures() -> None:
        """Fail closed on missing, short or out-of-bounds FAT architecture."""
        thin = _thin()
        header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
        assert _reject(header)
        for offset, size in ((64, 20), (2000, len(thin)), (64, 2048)):
            arch = struct.pack(">5I", CPU_X86_64, 3, offset, size, 0)
            data = (header + arch).ljust(64, b"\x00") + thin
            assert _reject(data)
        no_intel = struct.pack(">5I", 12, 3, 64, len(thin), 0)
        assert _reject((header + no_intel).ljust(64, b"\x00") + thin)

    @staticmethod
    def test_reject_load_command_sizes_and_segment_sections() -> None:
        """Reject bogus command count and truncated or invalid segments."""
        image = _thin()
        struct.pack_into("<I", image, 16, 99)
        assert _reject(image)
        image = _thin()
        struct.pack_into("<I", image, 32 + 4, 71)
        assert _reject(image)
        image = _thin()
        struct.pack_into("<I", image, 32 + SEGMENT_SECTIONS_OFFSET, 1)
        assert _reject(image)
        image = _thin()
        struct.pack_into("<Q", image, 32 + 48, 2048)
        assert _reject(image)
        image = _thin()
        struct.pack_into("<Q", image, 32 + 40, FILE_SIZE)
        assert _reject(image)

    @staticmethod
    def test_reject_malformed_symbol_ranges_and_unterminated_names() -> None:
        """Never use nlist and string offsets beyond declared tables."""
        image = _thin(_symtab(offset=FILE_SIZE))
        assert _reject(image)
        image = _with_symbols()
        struct.pack_into("<I", image, SYMBOL_OFFSET, 20)
        assert _reject(image)
        image = _with_symbols()
        image[STRING_OFFSET : STRING_OFFSET + 16] = b"X" * 16
        assert _reject(image)

    @staticmethod
    def test_good_nlist_preserves_external_symbol_lookup() -> None:
        """Keep legacy symbol dictionary and typed source behavior."""
        image = _with_symbols()
        assert _open(image, lambda mach: EXPORTED in mach.defined())
        assert _open(image, lambda mach: mach.off(VM_BASE)) == 0

    @staticmethod
    def test_reloc_symbol_index_and_table_span_reject() -> None:
        """Reject invalid relocations before symbol indexing or struct reads."""
        image = _with_symbols(_dysym())
        struct.pack_into("<iI", image, RELOCATION_OFFSET, 8, 1 << 27)
        assert _open(image, lambda mach: mach.relocs()[8][0]) == EXPORTED
        struct.pack_into("<iI", image, RELOCATION_OFFSET, 8, (1 << 27) | 7)
        assert _reject_reloc(image)
        struct.pack_into("<iI", image, RELOCATION_OFFSET, -1, 1 << 27)
        assert _reject_reloc(image)
        image = _with_symbols(_dysym(offset=FILE_SIZE, count=1))
        assert _reject_reloc(image)

    @staticmethod
    def test_invalid_range_and_bad_fileset_entry_reject() -> None:
        """Reject negative reads, absent filesets and oversized spans."""
        image = _thin()
        assert _open(image, lambda mach: mach.read(VM_BASE, 0)) == EMPTY_BYTES
        assert _reject_action(image, lambda mach: mach.read(VM_BASE, -1))
        assert _reject_action(
            image, lambda mach: mach.read(VM_BASE, FILE_SIZE + 1)
        )
        assert _reject_action(image, lambda mach: mach.off(-1))
        assert _reject_named_entry(image, "missing-entry")

    @staticmethod
    def test_fat_slice_does_not_read_neighbors() -> None:
        """Never parse bytes that lie beyond a declared FAT architecture."""
        thin = _thin()
        header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
        short = struct.pack(">5I", CPU_X86_64, 3, FAT_OFFSET, 80, 0)
        neighbor = (header + short).ljust(FAT_OFFSET, b"\x00") + thin
        assert _reject(neighbor)

    @staticmethod
    def test_section_relocations_keep_section_virtual_addresses() -> None:
        """Bound relocation rows and use the source section virtual base."""
        section = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text",
            b"__TEXT",
            VM_BASE,
            16,
            0,
            0,
            RELOCATION_OFFSET,
            1,
            0,
            0,
            0,
            0,
        )
        image = _with_symbols(section=section)
        struct.pack_into("<iI", image, RELOCATION_OFFSET, 8, 1 << 27)
        assert (
            _open(image, lambda mach: mach.relocs()[VM_BASE + 8][0]) == EXPORTED
        )
        malformed = _with_symbols(section=section)
        struct.pack_into("<iI", malformed, RELOCATION_OFFSET, 8, 1 << 27 | 5)
        assert _reject_reloc(malformed)
        out_of_range = bytearray(section)
        struct.pack_into("<I", out_of_range, 56, FILE_SIZE)
        assert _reject_reloc(_with_symbols(section=bytes(out_of_range)))

    @staticmethod
    def test_reference_json_dispatch_preserves_reference_image_contract() -> (
        None
    ):
        """Keep snapshot dispatch separate from binary Mach-O parsing."""
        sentinel = object()
        path = Path("synthetic.json")
        entry = "com.example.synthetic"
        with mock.patch.object(
            native_abi, "ReferenceImage", return_value=sentinel
        ) as reference:
            assert native_abi.Mach(path, entry) is sentinel
            reference.assert_called_once_with(path, entry)


class MachOResourceLifecycleTests(TestCase):
    """Keep mmap ownership consistent when parsing fails early."""

    @staticmethod
    def test_failed_parse_closes_mmap_even_on_truncated_command() -> None:
        """Release mapped storage after a rejected malformed command."""
        image = _thin()
        struct.pack_into("<I", image, 32 + 4, 71)
        handles: list[mmap.mmap] = []
        actual_mapper = mmap.mmap

        def tracing_mapper(
            fileno: int, length: int, *, access: int
        ) -> mmap.mmap:
            handle = actual_mapper(fileno, length, access=access)
            handles.append(handle)
            return handle

        with mock.patch.object(mmap, "mmap", side_effect=tracing_mapper):
            assert _reject(image)
        assert len(handles) == 1
        assert handles[0].closed


class MachOInputPathSafetyTests(TestCase):
    """No mmap or blocked FIFO open for untrusted native source paths."""

    @staticmethod
    def _refuses_path(path: Path) -> bool:
        """Check that only a validated regular file reaches the mapper.

        Returns:
            True when the source fails without creating a mapped image.

        """
        try:
            opened = native_abi.Mach(path)
        except OSError, ValueError:
            return True
        opened.close()
        return False

    @staticmethod
    def test_symlinks_and_fifo_are_refused_without_mapping() -> None:
        """Avoid symlink traversal and blocking nonregular device streams."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "valid.macho"
            _ = original.write_bytes(_thin())
            link = root / "link.macho"
            link.symlink_to(original)
            pipe = root / "pipe.macho"
            os.mkfifo(pipe)
            with mock.patch.object(mmap, "mmap", side_effect=AssertionError):
                assert MachOInputPathSafetyTests._refuses_path(link)
                assert MachOInputPathSafetyTests._refuses_path(pipe)

    @staticmethod
    def test_empty_and_sparse_oversized_images_rejected_before_mmap() -> None:
        """Validate metadata without reading or mapping a giant fixture."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.macho"
            _ = empty.write_bytes(b"")
            oversized = root / "sparse.macho"
            _ = oversized.touch()
            os.truncate(oversized, native_abi.MAX_NATIVE_MACHO_BYTES + 1)
            with mock.patch.object(mmap, "mmap", side_effect=AssertionError):
                assert MachOInputPathSafetyTests._refuses_path(empty)
                assert MachOInputPathSafetyTests._refuses_path(oversized)

    @staticmethod
    def test_valid_regular_image_keeps_existing_mapped_reads() -> None:
        """Preserve Mach-O bytes and resource cleanup for normal files."""
        data = _thin()
        assert _open(data, lambda mach: mach.read(VM_BASE, 4)) == data[:4]
