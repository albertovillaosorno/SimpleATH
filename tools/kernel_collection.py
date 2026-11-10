# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 laobamac. All rights reserved.
"""Bounded offline x86_64 Mach-O kernel-collection metadata reader."""

from __future__ import annotations

import importlib
import mmap
from pathlib import Path
import struct
from typing import Never
from typing import Protocol
from typing import final
from typing import runtime_checkable

if __package__:
    from tools.abi_types import byte_string
    from tools.abi_types import integer
    from tools.abi_types import plist_object
    from tools.abi_types import string
    from tools.abi_types import unpack_integers
    from tools.abi_types import unpack_values
else:
    from abi_types import byte_string
    from abi_types import integer
    from abi_types import plist_object
    from abi_types import string
    from abi_types import unpack_integers
    from abi_types import unpack_values

MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
CPU_X86_64 = 0x01000007
HEADER_SIZE = 32
COMMAND_SIZE = 8
SEGMENT_COMMAND = 0x19
SEGMENT_SIZE = 72
SECTION_SIZE = 80
SYMTAB_COMMAND = 2
SYMTAB_SIZE = 24
UUID_COMMAND = 0x1B
UUID_SIZE = 24
FILESET_COMMAND = 0x80000035
FILESET_SIZE = 32
SYMBOL_SIZE = 16
MAX_SYMBOL_NAME = 2048
MAX_U64 = (1 << 64) - 1
TEXT_SEGMENT = "__TEXT"
KERNEL_NAME = "com.apple.kernel"
JSON_SUFFIX = ".json"
PLIST_SIZE_LIMIT = 1024 * 1024
VERSION_SYMBOLS = ("_version_major", "_version_minor", "_version_revision")
SECTION_TYPE_MASK = 0xFF
ZERO_FILL_TYPES = frozenset({1, 12, 18})
SYMBOL_SECTION_TYPE = 0xE
FIXUP_KERNEL_TOP = 0xFFFF

type BinarySource = bytes | mmap.mmap
type Segment = tuple[str, int, int, int, int]
type Section = tuple[str, str, int, int, int]


def _invalid(message: str) -> Never:
    raise ValueError(message)


def _span(data: BinarySource, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or size > len(data) - offset:
        _invalid("Mach-O range exceeds the source bounds")


def _name(data: bytes, *, terminated: bool = False) -> str:
    prefix, sep, _ = data.partition(b"\0")
    if terminated and not sep:
        _invalid("Mach-O string lacks a bounded terminator")
    return prefix.decode("utf-8")


def _segment(
    data: BinarySource, position: int, size: int
) -> tuple[Segment, list[Section]]:
    if size < SEGMENT_SIZE:
        _invalid("Truncated Mach-O segment command")
    fields = unpack_values(data, "<16sQQQQiiII", position + COMMAND_SIZE)
    name = _name(byte_string(fields[0]))
    address, length, file_offset, file_size = (
        integer(value) for value in fields[1:5]
    )
    section_count = integer(fields[7])
    if section_count > (size - SEGMENT_SIZE) // SECTION_SIZE:
        _invalid("Mach-O section count exceeds its load command")
    if file_size > length or address + length > MAX_U64:
        _invalid("Mach-O segment has inconsistent virtual/file size")
    _span(data, file_offset, file_size)
    segment = (name, address, length, file_offset, file_size)
    sections = [
        _section(data, position + SEGMENT_SIZE + index * SECTION_SIZE, segment)
        for index in range(section_count)
    ]
    return (name, address, length, file_offset, file_size), sections


def _section(data: BinarySource, position: int, segment: Segment) -> Section:
    row = unpack_values(data, "<16s16sQQIIIIIIII", position)
    address, size, off = (integer(value) for value in row[2:5])
    _, start, length, file_start, file_length = segment
    if address < start or size > start + length - address:
        _invalid("Mach-O section crosses its virtual segment")
    is_zerofill = integer(row[8]) & SECTION_TYPE_MASK in ZERO_FILL_TYPES
    if not is_zerofill and (
        off < file_start or size > file_start + file_length - off
    ):
        _invalid("Mach-O section exceeds its file-backed segment")
    return (
        _name(byte_string(row[1])),
        _name(byte_string(row[0])),
        address,
        size,
        off,
    )


def _symtab(
    data: BinarySource, position: int, size: int
) -> tuple[int, int, int, int]:
    if size < SYMTAB_SIZE:
        _invalid("Truncated Mach-O symbol-table command")
    off, count, strings, string_size = unpack_integers(
        data, "<IIII", position + COMMAND_SIZE
    )
    _span(data, off, count * SYMBOL_SIZE)
    _span(data, strings, string_size)
    return off, count, strings, string_size


def _symbol_name(
    data: BinarySource, strings: int, size: int, *, index: int
) -> str:
    if index >= size:
        _invalid("Mach-O symbol offset exceeds string table")
    end = min(index + MAX_SYMBOL_NAME, size)
    return _name(data[strings + index : strings + end], terminated=True)


def _symbols(
    data: BinarySource, table: tuple[int, int, int, int]
) -> tuple[dict[str, int], set[str]]:
    off, count, strings, string_size = table
    symbols: dict[str, int] = {}
    exports: set[str] = set()
    for index in range(count):
        record = unpack_integers(data, "<IBBHQ", off + index * SYMBOL_SIZE)
        number, kind = record[0], record[1]
        if not number or kind & SYMBOL_SECTION_TYPE != SYMBOL_SECTION_TYPE:
            continue
        name = _symbol_name(data, strings, string_size, index=number)
        symbols[name] = record[4]
        if kind & 1:
            exports.add(name)
    return symbols, exports


def _fileset_name(
    data: BinarySource, position: int, size: int
) -> tuple[str, int, int]:
    if size < FILESET_SIZE:
        _invalid("Truncated Mach-O fileset command")
    address, offset, name_offset, _ = unpack_integers(
        data, "<QQII", position + COMMAND_SIZE
    )
    if name_offset < FILESET_SIZE or name_offset >= size:
        _invalid("Mach-O fileset name offset is outside its command")
    _span(data, offset, HEADER_SIZE)
    raw = data[position + name_offset : position + size]
    return _name(raw, terminated=True), address, offset


def _header(data: BinarySource, offset: int) -> tuple[int, int, int]:
    _span(data, offset, HEADER_SIZE)
    if data[offset : offset + 4] != MAGIC_64_LE:
        _invalid("Expected a 64-bit little-endian kernel image")
    if unpack_integers(data, "<I", offset + 4)[0] != CPU_X86_64:
        _invalid("Expected an x86_64 kernel image")
    count, commands_size = unpack_integers(data, "<II", offset + 16)
    position = offset + HEADER_SIZE
    _span(data, position, commands_size)
    if count > commands_size // COMMAND_SIZE:
        _invalid("Mach-O command count exceeds the declared command bytes")
    return position, count, position + commands_size


@final
class KernelImage:
    """Read bounded metadata from a kernel or fileset Mach-O image."""

    def __init__(self, data: BinarySource, offset: int = 0) -> None:
        """Parse validated commands while retaining the supplied byte owner."""
        position, count, end = _header(data, offset)
        self.data = data
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self.entries: dict[str, tuple[int, int]] = {}
        self.symbols: dict[str, int] = {}
        self.exports: set[str] = set()
        self.uuid: str | None = None
        self.base = 0
        table = self._load_commands(data, position, count, end=end)
        text_segments = [
            segment[1]
            for segment in self.segments
            if segment[0] == TEXT_SEGMENT
        ]
        if not text_segments:
            _invalid("Mach-O image has no __TEXT segment")
        self.base = text_segments[0]
        if table is not None:
            self.symbols, self.exports = _symbols(data, table)

    def _load_commands(
        self, data: BinarySource, position: int, count: int, *, end: int
    ) -> tuple[int, int, int, int] | None:
        table: tuple[int, int, int, int] | None = None
        for _ in range(count):
            command, size = unpack_integers(data, "<II", position)
            if size < COMMAND_SIZE or size > end - position:
                _invalid("Mach-O load command escapes its header table")
            table = self._command(data, (position, command, size), table)
            position += size
        if position != end:
            _invalid("Mach-O load commands do not fill their declared extent")
        return table

    def _command(
        self,
        data: BinarySource,
        info: tuple[int, int, int],
        symbols: tuple[int, int, int, int] | None,
    ) -> tuple[int, int, int, int] | None:
        position, command, size = info
        if command == SEGMENT_COMMAND:
            segment, sections = _segment(data, position, size)
            self.segments.append(segment)
            self.sections.extend(sections)
            return symbols
        return self._other_command(data, info, symbols)

    def _other_command(
        self,
        data: BinarySource,
        info: tuple[int, int, int],
        symbols: tuple[int, int, int, int] | None,
    ) -> tuple[int, int, int, int] | None:
        position, command, size = info
        if command == SYMTAB_COMMAND:
            return _symtab(data, position, size)
        if command == UUID_COMMAND:
            if size < UUID_SIZE:
                _invalid("Truncated Mach-O UUID command")
            self.uuid = data[
                position + COMMAND_SIZE : position + UUID_SIZE
            ].hex()
        elif command == FILESET_COMMAND:
            name, address, off = _fileset_name(data, position, size)
            self.entries[name] = (address, off)
        return symbols

    def read(self, address: int, size: int) -> bytes:
        """Read only file-backed bytes at a validated virtual address.

        Returns:
            The exact requested bytes, or a validation error.

        """
        if address < 0 or size < 0 or address + size > MAX_U64:
            _invalid("Invalid Mach-O virtual read range")
        for _, start, length, file_off, file_size in self.segments:
            delta = address - start
            if delta >= 0 and delta <= length and size <= length - delta:
                if delta > file_size or size > file_size - delta:
                    _invalid("Mach-O virtual range is not file-backed")
                location = file_off + delta
                _span(self.data, location, size)
                return self.data[location : location + size]
        message = f"Unmapped kernel range {address:#x}+{size:#x}"
        _invalid(message)


@runtime_checkable
class _SnapshotCollection(Protocol):
    """Common checked collection operations for JSON and binary readers."""

    path: Path

    def pointer(self, address: int) -> int: ...

    def version(self) -> str: ...

    def close(self) -> None: ...


class KernelCollection:
    """Inspect an offline binary KC with existing JSON snapshot dispatch."""

    def __new__(
        cls, path: str | Path
    ) -> KernelCollection | _SnapshotCollection:
        """Retain the historical JSON snapshot factory interface.

        Returns:
            A binary collection or the legacy checked JSON collection.

        """
        if Path(path).suffix == JSON_SUFFIX:
            name = (
                "tools.native_references"
                if __package__
                else "native_references"
            )
            module = importlib.import_module(name)
            factory: object = vars(module).get("ReferenceCollection")
            if not callable(factory):
                _invalid("Native reference collection factory is not callable")
            candidate: object = factory(path)
            if not isinstance(candidate, _SnapshotCollection):
                _invalid(
                    "Native reference collection lacks required operations"
                )
            return candidate
        return super().__new__(cls)

    def __init__(self, path: str | Path) -> None:
        """Own the mapped collection, closing it after any parser failure.

        Raises:
            ValueError: Invalid binary layout.
            KeyError: Required kernel fileset is absent.
            StopIteration: No usable collection fixup base exists.
            struct.error: Invalid binary structure.

        """
        self.path: Path = Path(path)
        with self.path.open("rb") as source:
            self.data: mmap.mmap = mmap.mmap(
                source.fileno(), 0, access=mmap.ACCESS_READ
            )
        try:
            self.root: KernelImage = KernelImage(self.data)
            self.images: dict[str, KernelImage] = {
                name: KernelImage(self.data, off)
                for name, (_, off) in self.root.entries.items()
            }
            self.kernel: KernelImage = self.images[KERNEL_NAME]
            self.fixup_base: int = min(
                address
                for _, address, length, *_ in self.root.segments
                if address and length
            )
        except ValueError, KeyError, StopIteration, struct.error:
            self.data.close()
            raise

    def pointer(self, address: int) -> int:
        """Decode a local fixup or reject cross-collection references.

        Returns:
            The decoded kernel pointer value.

        """
        value = unpack_integers(self.root.read(address, 8), "<Q")[0]
        if value >> 48 == FIXUP_KERNEL_TOP:
            return value
        if (value >> 30) & 3:
            _invalid("Unsupported cross-collection pointer")
        return self.fixup_base + (value & 0x3FFFFFFF)

    def version(self) -> str:
        """Read three defined kernel version fields from mapped symbols.

        Returns:
            The major.minor.revision version string.

        """
        return ".".join(
            str(
                unpack_integers(
                    self.kernel.read(self.kernel.symbols[name], 4), "<I"
                )[0]
            )
            for name in VERSION_SYMBOLS
        )

    def close(self) -> None:
        """Release the mmap owner after successful use."""
        self.data.close()


def system_version(volume: str | Path) -> tuple[str, str]:
    """Report the checked offline system build and kernel version.

    Returns:
        Exact build label and decoded kernel version.

    """
    root = Path(volume)
    version = root / "System/Library/CoreServices/SystemVersion.plist"
    if version.stat().st_size > PLIST_SIZE_LIMIT:
        _invalid("System version plist exceeds the offline parse limit")
    info = plist_object(version.read_bytes())
    collection = KernelCollection(
        root / "System/Library/KernelCollections/BootKernelExtensions.kc"
    )
    if not isinstance(collection, KernelCollection):
        _invalid("Expected a binary kernel collection for system version")
    try:
        return string(info.get("ProductBuildVersion")), collection.version()
    finally:
        collection.close()
