# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic Mach-O symbol inventory boundaries; no host images or KDK reads."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from typing import cast
from unittest import TestCase
import uuid

from tools import inspect_platform_abi as inspector

if TYPE_CHECKING:
    from collections.abc import Callable

MAGIC = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
CPU_X86_64 = 0x01000007
MH_FILESET = 0xC
MH_KEXT_BUNDLE = 0xB
LC_UUID = 0x1B
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x80000035
LC_EXPORTS_TRIE = 0x80000033
LC_DYLD_INFO_ONLY = 0x80000022
HEADER_SIZE = 32
UUID_COMMAND_SIZE = 24
FILESET_COMMAND_SIZE = 40
N_LIST_SIZE = 16
CHILD_OFFSET = 160
SYMTAB_OFFSET = 320
STRING_OFFSET = 352
FAT_HEADER_SIZE = 8
FAT_ARCH_SIZE = 20
SAMPLE_UUID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ENTRY_NAME = "io.pci"
PUBLIC_SYMBOL = "_IOPCIProbe"
PRIVATE_SYMBOL = "_Hidden"
SYMBOL_EVIDENCE = "global_definition_candidate"
CANDIDATE_EVIDENCE = "defined_global_nlist_candidates"


class MachInventory:
    """Expose expected dynamic inventory fields for synthetic fixtures."""

    def __init__(self, raw: object) -> None:
        """Validate returned structure before checking its evidence content.

        Raises:
            TypeError: The result is not an inventory dictionary.

        """
        if not isinstance(raw, dict):
            message = "Mach-O inventory did not return an object"
            raise TypeError(message)
        self.raw: dict[str, object] = raw

    def field(self, key: str) -> object:
        """Fetch a top-level result field without implying ABI approval.

        Returns:
            The untrusted inventory field, for value assertions only.

        """
        return self.raw.get(key)


def _inventory(data: bytes, offset: int = 0) -> MachInventory:
    reader = cast("Callable[[bytes, int], object]", inspector.image_inventory)
    return MachInventory(reader(data, offset))


def _rejected(data: bytes, offset: int = 0) -> bool:
    """Report parser rejection of malformed or inconsistent Mach-O bytes.

    Returns:
        True if the parser rejected the synthetic input.

    """
    try:
        _ = _inventory(data, offset)
    except ValueError, struct.error:
        return True
    return False


def _fat_rejected(picker: Callable[[bytes], bytes], data: bytes) -> bool:
    """Test fail-closed FAT slice validation with a pure in-memory fixture.

    Returns:
        True if the given malformed FAT blob was rejected.

    """
    try:
        _ = picker(data)
    except ValueError:
        return True
    return False


def _header(filetype: int, commands: bytes, count: int) -> bytes:
    return (
        struct.pack(
            "<8I", MAGIC, CPU_X86_64, 0, filetype, count, len(commands), 0, 0
        )
        + commands
    )


def _uuid_command() -> bytes:
    return struct.pack("<II", LC_UUID, UUID_COMMAND_SIZE) + SAMPLE_UUID.bytes


def _fileset_command() -> bytes:
    return (
        struct.pack(
            "<IIQQII",
            LC_FILESET_ENTRY,
            FILESET_COMMAND_SIZE,
            0,
            CHILD_OFFSET,
            HEADER_SIZE,
            0,
        )
        + ENTRY_NAME.encode()
        + b"\0\0"
    )


def _child_symbols() -> bytes:
    names = (
        b"\0" + PUBLIC_SYMBOL.encode() + b"\0" + PRIVATE_SYMBOL.encode() + b"\0"
    )
    first = struct.pack("<IBBHQ", 1, 0xF, 1, 0, 0)
    second = struct.pack("<IBBHQ", len(PUBLIC_SYMBOL) + 2, 0x1F, 1, 0, 0)
    symtab = struct.pack(
        "<6I",
        LC_SYMTAB,
        UUID_COMMAND_SIZE,
        SYMTAB_OFFSET,
        2,
        STRING_OFFSET,
        len(names),
    )
    header = _header(MH_KEXT_BUNDLE, symtab, 1)
    prefix = bytearray(
        _header(MH_FILESET, _uuid_command() + _fileset_command(), 2)
    )
    prefix.extend(b"\0" * (CHILD_OFFSET - len(prefix)))
    prefix.extend(header)
    prefix.extend(b"\0" * (SYMTAB_OFFSET - len(prefix)))
    prefix.extend(first + second)
    prefix.extend(b"\0" * (STRING_OFFSET - len(prefix)))
    prefix.extend(names)
    return bytes(prefix)


class MachInventoryBoundaryTests(TestCase):
    """Validate candidate-only nlists and fail-closed offset boundaries."""

    @staticmethod
    def test_nested_fileset_uses_absolute_offsets_not_child_offsets() -> None:
        """Retain one public definition but exclude private candidates."""
        sample = _child_symbols()
        root = _inventory(sample)
        assert root.field("filetype") == MH_FILESET
        assert root.field("uuid") == str(SAMPLE_UUID).upper()
        assert root.field("entries") == {ENTRY_NAME: CHILD_OFFSET}
        child = _inventory(sample, CHILD_OFFSET)
        assert child.field("symbols") == {PUBLIC_SYMBOL: SYMBOL_EVIDENCE}
        assert child.field("symbolEvidence") == CANDIDATE_EVIDENCE
        assert child.field("exportTriePresent") is False

    @staticmethod
    def test_reject_bad_header_command_count_and_sizes() -> None:
        """Reject zero-size, incomplete, and miscounted commands."""
        valid = _uuid_command()
        malformed = (
            b"",
            _header(MH_FILESET, valid, 2),
            _header(MH_FILESET, struct.pack("<II", LC_UUID, 0), 1),
            _header(MH_FILESET, struct.pack("<II", LC_UUID, 8), 1),
            _header(MH_FILESET, valid + b"\0", 1),
        )
        for blob in malformed:
            assert _rejected(blob)

    @staticmethod
    def test_reject_out_of_range_string_table_and_bad_fileset_entry() -> None:
        """Reject external nlist or entry offsets beyond the input buffer."""
        sample = _child_symbols()
        bad_symtab = bytearray(sample)
        struct.pack_into(
            "<I", bad_symtab, CHILD_OFFSET + HEADER_SIZE + 8, len(sample)
        )
        assert _rejected(bytes(bad_symtab), CHILD_OFFSET)
        bad_name = bytearray(sample)
        entry_command = HEADER_SIZE + UUID_COMMAND_SIZE
        struct.pack_into(
            "<I", bad_name, entry_command + 24, FILESET_COMMAND_SIZE
        )
        assert _rejected(bytes(bad_name))

    @staticmethod
    def test_reject_duplicate_uuid_and_missing_child_header() -> None:
        """Duplicate UUID metadata and short fileset offsets are invalid."""
        command = _uuid_command()
        assert _rejected(_header(MH_FILESET, command + command, 2))
        malformed = bytearray(_child_symbols())
        struct.pack_into(
            "<Q",
            malformed,
            HEADER_SIZE + UUID_COMMAND_SIZE + 16,
            len(malformed) - HEADER_SIZE + 1,
        )
        assert _rejected(bytes(malformed))

    @staticmethod
    def test_export_trie_metadata_is_not_an_export_allowlist() -> None:
        """A bounded trie command marks presence but proves no KPI exports."""
        offset = HEADER_SIZE + 16
        trie = struct.pack("<4I", LC_EXPORTS_TRIE, 16, offset, 2)
        payload = _header(MH_KEXT_BUNDLE, trie, 1) + b"\0\0"
        report = _inventory(payload)
        assert report.field("exportTriePresent") is True
        assert report.field("symbols") == {}
        assert _rejected(_header(MH_KEXT_BUNDLE, trie, 1))
        invalid_info = struct.pack("<II", LC_DYLD_INFO_ONLY, 16) + b"\0" * 8
        assert _rejected(_header(MH_KEXT_BUNDLE, invalid_info, 1))

    @staticmethod
    def test_valid_fat_x86_slice_and_malformed_arch_tables() -> None:
        """Select a bounded x86_64 slice and reject malformed FAT tables."""
        thin = _header(MH_FILESET, b"", 0)
        offset = FAT_HEADER_SIZE + FAT_ARCH_SIZE
        arch = struct.pack(">5I", CPU_X86_64, 0, offset, len(thin), 0)
        fat = struct.pack(">2I", FAT_MAGIC, 1) + arch + thin
        picker = cast("Callable[[bytes], bytes]", inspector.x86_slice)
        assert picker(fat) == thin
        assert picker(thin) == thin
        corrupted = (
            fat[:FAT_HEADER_SIZE],
            struct.pack(">2I", FAT_MAGIC, 2) + arch + arch + thin,
            struct.pack(">2I", FAT_MAGIC, 1)
            + struct.pack(">5I", CPU_X86_64, 0, offset, len(thin) + 1, 0)
            + thin,
        )
        for data in corrupted:
            assert _fat_rejected(picker, data)
