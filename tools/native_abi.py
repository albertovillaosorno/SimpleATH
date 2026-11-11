# Copyright:
#   - Copyright © 2026 laobamac. All rights reserved.
# SPDX-License-Identifier:
#   - LicenseRef-SimpleBCM-All-Rights-Reserved
# Confidential:
#   - false
# License-File:
#   - LICENSE-SIMPLEBCM
# Provenance:
#   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
#   - Originally authored by laobamac on 2026/11/1.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for native abi.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for native abi.
# - Description:
#   - Implements or verifies the native_abi source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for native abi.

"""Bounded native Mach-O ABI inspection and source-only model verification."""

from __future__ import annotations

import argparse
import collections
from contextlib import ExitStack
import ctypes
from dataclasses import dataclass
import functools
import hashlib
from itertools import pairwise
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import stat
import struct
# Offline fixed-argv c++filt and xcrun only.
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import sys
from typing import Protocol
from typing import TYPE_CHECKING
from typing import TypedDict
from typing import final
from typing import runtime_checkable
import uuid

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterable
    from collections.abc import Iterator
    from collections.abc import Mapping
    from typing import BinaryIO

if __package__:
    from tools.abi_types import unpack_integers
    from tools.native_references import ReferenceImage
    from tools.native_references import reference_paths
    from tools.profiles import IMAGES
    from tools.system_profiles import SYSTEMS
else:
    from abi_types import unpack_integers
    from native_references import ReferenceImage
    from native_references import reference_paths
    from profiles import IMAGES
    from system_profiles import SYSTEMS

EXPECTED_SOURCES = {
    "OldSky": (
        "0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b"
    ),
    "Legacy": (
        "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894"
    ),
    "BrcmTahoe": (
        "0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775"
    ),
    "BrcmOriginal": (
        "884e90b27cff151e432bb36275936f57b43e72419e95b51b3ac067d3f2ccd331"
    ),
}
PATHS = {
    key: IMAGES[label]
    for key, label in (
        ("OldSky", "Skywalk"),
        ("Legacy", "Legacy"),
        ("BrcmTahoe", "AirPort"),
        ("BrcmOriginal", "AirPortOriginal"),
    )
}


MAX_NATIVE_MACHO_BYTES = 2 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
FAT32_MAGIC = b"\xca\xfe\xba\xbe"
FAT64_MAGIC = b"\xca\xfe\xba\xbf"
FAT_HEADER_BYTES = 8
MAX_FAT_ARCHITECTURES = 256
MAX_FAT_ALIGNMENT = 62
CPU_X86_64 = 0x01000007
MACHO_HEADER_BYTES = 32
MACHO_MAGIC_64 = 0xFEEDFACF
LOAD_COMMAND_HEADER_BYTES = 8
LC_SEGMENT_64 = 25
LC_SYMTAB = 2
LC_DYSYMTAB = 11
LC_UUID = 27
LC_FILESET_ENTRY = 0x80000035
NATIVE_TEXT_SECTION = "__text"
JSON_SUFFIX = ".json"
LOCAL_RELOCATION = "LOCAL"
ABSENT_SLOT = "absent"
KERNEL_FIXUP_UPPER_HALF = 0xFFFF
DARWIN_TAHOE = 25
EXPECTED_CLASS_TABLES = 18
VERIFY_ACTION = "verify"
EXPECTED_LEGACY_IMPORTS = 113
EXPECTED_BRCM_IMPORTS = 148
OLD_INIT_BSD = "initBSDInterfaceParameters"
NEW_LOGICAL_LINK = "registerNetworkInterfaceWithLogicalLink"
OLD_PROXY_METHOD = "hwConfigNicProxyData"
NEW_RESERVED_METHOD = "_RESERVEDIOSkywalkEthernetInterface0"


def _open_mach_source(path: Path) -> BinaryIO:
    """Open an immutable-path, bounded regular Mach-O image for mmap.

    Returns:
        The caller-owned binary stream, positioned at its start.

    Raises:
        ValueError: A source is empty, nonregular or exceeds the byte limit.

    System opening errors, including symlink rejection, propagate as OSError.

    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with ExitStack() as resources:
        stream = resources.enter_context(os.fdopen(os.open(path, flags), "rb"))
        info = os.fstat(stream.fileno())
        valid_size = 0 < info.st_size <= MAX_NATIVE_MACHO_BYTES
        if not stat.S_ISREG(info.st_mode) or not valid_size:
            message = "Mach-O source must be a bounded regular file"
            raise ValueError(message)
        _ = resources.pop_all()
        return stream


def hash_mach_source(path: Path) -> str:
    """Hash an unchanged, bounded source without loading it into memory.

    Returns:
        SHA-256 digest of the exact regular input bytes.

    Raises:
        ValueError: The file changed, was empty, or exceeded the byte limit.

    """
    with _open_mach_source(path) as stream:
        before = os.fstat(stream.fileno())
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = stream.read(min(remaining, HASH_CHUNK_BYTES))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        excess = stream.read(1)
        after = os.fstat(stream.fileno())
    attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        remaining
        or excess
        or any(
            getattr(before, attribute) != getattr(after, attribute)
            for attribute in attributes
        )
    ):
        message = "Native Mach-O source changed while hashing"
        raise ValueError(message)
    return digest.hexdigest()


def _require_span(start: int, size: int, limit: int) -> None:
    """Reject negative or out-of-range file/mapping spans.

    Raises:
        ValueError: The requested span escapes the containing buffer.

    """
    negative_span = start < 0 or size < 0
    oversized_span = start > limit or size > limit - start
    if negative_span or oversized_span:
        message = "Mach-O source span escapes the mapped file"
        raise ValueError(message)


def _fat_architecture(
    data: mmap.mmap, index: int, table_end: int, *, wide: bool
) -> tuple[int, int, int]:
    """Validate one FAT entry including non-selected architecture slices.

    Returns:
        CPU type, slice offset and size, all checked against the file.

    Raises:
        ValueError: A slice overlaps the table or has invalid bounds.

    """
    entry = FAT_HEADER_BYTES + index * (32 if wide else 20)
    cpu = unpack_integers(data, ">I", entry)[0]
    offset, size = unpack_integers(data, ">QQ" if wide else ">II", entry + 8)
    alignment = unpack_integers(data, ">I", entry + (24 if wide else 16))[0]
    bad_size_or_position = not size or offset < table_end
    bad_alignment = alignment > MAX_FAT_ALIGNMENT or offset % (1 << alignment)
    if bad_size_or_position or bad_alignment:
        message = "Malformed FAT architecture slice alignment or bounds"
        raise ValueError(message)
    _require_span(offset, size, len(data))
    return cpu, offset, size


def _fat_table_metadata(data: mmap.mmap, *, wide: bool) -> tuple[int, int]:
    """Check the FAT table's complete bounded architecture record budget.

    Returns:
        Architecture count and table end offset.

    Raises:
        ValueError: Header or record budget is invalid or truncated.

    """
    _require_span(0, FAT_HEADER_BYTES, len(data))
    count = unpack_integers(data, ">I", 4)[0]
    row_size = 32 if wide else 20
    if (
        not 0 < count <= MAX_FAT_ARCHITECTURES
        or count > (len(data) - FAT_HEADER_BYTES) // row_size
    ):
        message = "Truncated or excessive FAT architecture table"
        raise ValueError(message)
    return count, FAT_HEADER_BYTES + count * row_size


def _require_disjoint_fat_ranges(ranges: list[tuple[int, int]]) -> None:
    """Reject any pair of intersecting FAT architecture file spans.

    Raises:
        ValueError: Overlapping FAT slices.

    """
    if any(left[1] > right[0] for left, right in pairwise(sorted(ranges))):
        message = "Overlapping FAT architecture slices"
        raise ValueError(message)


def _unique_fat_x86_64(
    data: mmap.mmap, count: int, table_end: int, *, wide: bool
) -> tuple[int, int]:
    """Check all FAT records and select only one complete x86_64 image.

    Returns:
        The unique slice offset and length in the full mapped file.

    Raises:
        ValueError: Missing, ambiguous or overlapping architectures.

    """
    ranges: list[tuple[int, int]] = []
    selected: tuple[int, int] | None = None
    for index in range(count):
        cpu, offset, size = _fat_architecture(data, index, table_end, wide=wide)
        ranges.append((offset, offset + size))
        if cpu == CPU_X86_64:
            if selected is not None or size < MACHO_HEADER_BYTES:
                message = "Ambiguous or truncated x86_64 FAT architecture"
                raise ValueError(message)
            selected = (offset, size)
    _require_disjoint_fat_ranges(ranges)
    if selected is None:
        message = "FAT Mach-O has no x86_64 image"
        raise ValueError(message)
    return selected


def _fat_x86_64_range(data: mmap.mmap) -> tuple[int, int] | None:
    """Select a unique bounded FAT32/FAT64 x86_64 slice, or keep thin.

    Returns:
        Offset and length of the selected architecture, or None for thin.

    Invalid FAT tables are rejected by the bounded catalog reader.

    """
    magic = data[:4]
    if magic not in {FAT32_MAGIC, FAT64_MAGIC}:
        return None
    wide = magic == FAT64_MAGIC
    count, table_end = _fat_table_metadata(data, wide=wide)
    return _unique_fat_x86_64(data, count, table_end, wide=wide)


class Mach:
    """Own a bounded offline Mach-O image and its typed metadata indices."""

    path: str
    f: BinaryIO
    b: mmap.mmap
    base: int
    slice_end: int
    h: int
    typ: int
    fixup_base: int
    segs: list[tuple[str, int, int, int, int]]
    sects: list[
        tuple[str, str, int, int, int, int, int, int, int, int, int, int]
    ]
    entries: dict[str, tuple[int, int]]
    syms: list[tuple[str, int, int, int, int]]
    symtab: tuple[int, int, int, int] | None
    dysym: tuple[int, ...] | None
    uuid: str | None
    names: dict[str, tuple[str, int, int, int, int]]
    byaddr: collections.defaultdict[int, list[str]]

    def __new__(
        cls, path: str | Path, entry: str | None = None
    ) -> Mach | ReferenceImage:
        """Return a pinned reference view for a snapshot JSON path.

        Returns:
            An opened source Mach image or a named checked snapshot view.

        Raises:
            ValueError: Snapshot selection omits its required entry name.

        """
        if Path(path).suffix == JSON_SUFFIX:
            if entry is None:
                message = "Snapshot image requires an explicit entry name"
                raise ValueError(message)
            return ReferenceImage(path, entry)
        return super().__new__(cls)

    def __init__(self, path: str | Path, entry: str | None = None) -> None:
        """Map a bounded Mach image and parse all declared commands."""
        self.path = str(path)
        self.base = 0
        self.slice_end = 0
        self.h = 0
        self.fixup_base = 0
        self._initialize_catalogs()
        self.f = _open_mach_source(Path(path))
        try:
            self.b = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            self.f.close()
            raise
        try:
            self._initialize_image(entry)
        except BaseException:
            self.close()
            raise

    def _initialize_catalogs(self) -> None:
        """Populate empty typed catalogs before parsing any file data."""
        self.typ = 0
        self.segs = []
        self.sects = []
        self.entries = {}
        self.syms = []
        self.symtab = None
        self.dysym = None
        self.uuid = None
        self.names = {}
        self.byaddr = collections.defaultdict(list)

    def _initialize_image(self, entry: str | None) -> None:
        """Derive the source segment base and optional fileset image.

        Raises:
            ValueError: No mapped segment or requested fileset entry exists.

        """
        self.base = 0
        self.slice_end = len(self.b)
        self._select_header()
        self.h = self.base
        self._parse()
        bases = [va for _, va, size, _, _ in self.segs if va and size]
        if not bases:
            message = "Mach-O image has no mapped virtual segment"
            raise ValueError(message)
        self.fixup_base = min(bases)
        if entry is not None:
            self._select_fileset_entry(entry)

    def _select_fileset_entry(self, entry: str) -> None:
        """Select a fileset subimage only if its header is complete.

        Raises:
            ValueError: The entry is absent or escapes the mapped source.

        """
        if entry not in self.entries:
            message = "Mach-O fileset entry does not exist"
            raise ValueError(message)
        self.h = self.base + self.entries[entry][1]
        _require_span(self.h, MACHO_HEADER_BYTES, self.slice_end)
        self._parse()

    def _select_header(self) -> None:
        selected = _fat_x86_64_range(self.b)
        if selected is not None:
            offset, size = selected
            self.base = offset
            self.slice_end = offset + size

    def _parse(self) -> None:
        """Parse bounded Mach-O commands and symbol names.

        Raises:
            ValueError: Any load command or symbol record is invalid.

        """
        _require_span(self.h, MACHO_HEADER_BYTES, self.slice_end)
        magic, cpu, _, typ, count, command_bytes, _, _ = unpack_integers(
            self.b, "<8I", self.h
        )
        if magic != MACHO_MAGIC_64 or cpu != CPU_X86_64:
            message = "Expected an x86_64 Mach-O image"
            raise ValueError(message)
        _require_span(
            self.h + MACHO_HEADER_BYTES, command_bytes, self.slice_end
        )
        if count > command_bytes // LOAD_COMMAND_HEADER_BYTES:
            message = "Mach-O command count exceeds the command byte budget"
            raise ValueError(message)
        self.typ = typ
        self.segs = []
        self.sects = []
        self.entries = {}
        self.syms = []
        self.symtab = None
        self.dysym = None
        self.uuid = None
        self._parse_commands(count, self.h + MACHO_HEADER_BYTES + command_bytes)
        self._parse_symbols()
        self._index_symbols()

    def _parse_commands(self, count: int, command_end: int) -> None:
        """Walk all declared command records before any symbol decoding.

        Raises:
            ValueError: Truncated or inconsistent load command budget.

        """
        cursor = self.h + MACHO_HEADER_BYTES
        for _ in range(count):
            _require_span(cursor, LOAD_COMMAND_HEADER_BYTES, command_end)
            command, length = unpack_integers(self.b, "<II", cursor)
            if length < LOAD_COMMAND_HEADER_BYTES:
                message = "Invalid Mach-O load command size"
                raise ValueError(message)
            _require_span(cursor, length, command_end)
            self._parse_command(command, cursor, length)
            cursor += length
        if cursor != command_end:
            message = "Mach-O command sizes do not match their byte budget"
            raise ValueError(message)

    def _parse_command(self, command: int, cursor: int, length: int) -> None:
        """Decode only relevant load-command types using bounded readers."""
        handlers: dict[int, Callable[[int, int], None]] = {
            LC_SEGMENT_64: self._parse_segment,
            LC_SYMTAB: self._parse_symtab,
            LC_DYSYMTAB: self._parse_dysym,
            LC_UUID: self._parse_uuid,
            LC_FILESET_ENTRY: self._parse_fileset,
        }
        handler = handlers.get(command)
        if handler is not None:
            handler(cursor, length)

    def _parse_segment(self, cursor: int, length: int) -> None:
        """Validate a segment and its entire fixed-width section catalog.

        Raises:
            ValueError: Truncated sections or inconsistent segment spans.

        """
        _require_span(cursor, 72, cursor + length)
        segment, va, vmsize, fileoff, filesize, _, _, sections, _ = (
            struct.unpack_from("<16sQQQQiiII", self.b, cursor + 8)
        )
        if sections > (length - 72) // 80 or filesize > vmsize:
            message = "Truncated or inconsistent Mach-O segment"
            raise ValueError(message)
        _require_span(self.base + fileoff, filesize, self.slice_end)
        name = segment.rstrip(b"\x00").decode()
        self.segs.append((name, va, vmsize, fileoff, filesize))
        for index in range(sections):
            fields = struct.unpack_from(
                "<16s16sQQIIIIIIII", self.b, cursor + 72 + 80 * index
            )
            self.sects.append((
                fields[0].rstrip(b"\x00").decode(),
                fields[1].rstrip(b"\x00").decode(),
                *fields[2:],
            ))

    def _parse_symtab(self, cursor: int, length: int) -> None:
        """Validate symbol and string table extents before indexing.

        Raises:
            ValueError: A duplicate or out-of-range symbol table.

        """
        if self.symtab is not None:
            message = "Duplicate Mach-O symbol table command"
            raise ValueError(message)
        _require_span(cursor, 24, cursor + length)
        symboloff, symbols, stringoff, strings = unpack_integers(
            self.b, "<IIII", cursor + 8
        )
        _require_span(self.base + symboloff, symbols * 16, self.slice_end)
        _require_span(self.base + stringoff, strings, self.slice_end)
        self.symtab = (symboloff, symbols, stringoff, strings)

    def _parse_dysym(self, cursor: int, length: int) -> None:
        """Record the unique complete dynamic symbol-table command.

        Raises:
            ValueError: The dynamic table is duplicate or truncated.

        """
        if self.dysym is not None:
            message = "Duplicate Mach-O dynamic symbol table command"
            raise ValueError(message)
        _require_span(cursor, 80, cursor + length)
        self.dysym = unpack_integers(self.b, "<18I", cursor + 8)

    def _parse_uuid(self, cursor: int, length: int) -> None:
        """Decode the unique UUID identity with checked command bounds.

        Raises:
            ValueError: The UUID is duplicate or truncated.

        """
        if self.uuid is not None:
            message = "Duplicate Mach-O UUID command"
            raise ValueError(message)
        _require_span(cursor, 24, cursor + length)
        self.uuid = str(
            uuid.UUID(bytes=self.b[cursor + 8 : cursor + 24])
        ).upper()

    def _parse_fileset(self, cursor: int, length: int) -> None:
        """Decode a bounded, uniquely named fileset image entry.

        Raises:
            ValueError: Fileset name or nested image is malformed.

        """
        _require_span(cursor, 32, cursor + length)
        va, fileoff, offset, _ = struct.unpack_from("<QQII", self.b, cursor + 8)
        if offset < MACHO_HEADER_BYTES:
            message = "Invalid Mach-O fileset name offset"
            raise ValueError(message)
        _require_span(self.base + fileoff, MACHO_HEADER_BYTES, self.slice_end)
        _require_span(cursor + offset, 1, cursor + length)
        ending = self.b.find(b"\x00", cursor + offset, cursor + length)
        if ending < 0:
            message = "Unterminated Mach-O fileset entry name"
            raise ValueError(message)
        name = self.b[cursor + offset : ending].decode()
        if not name or name in self.entries:
            message = "Empty or duplicate Mach-O fileset entry name"
            raise ValueError(message)
        self.entries[name] = (va, fileoff)

    def _symbol_name(self, offset: int, stringoff: int, size: int) -> str:
        """Read one bounded nlist string from the declared table.

        Returns:
            Original symbol name, with replacement for corrupt UTF-8.

        Raises:
            ValueError: The name is outside or not terminated in the table.

        """
        if not offset:
            return ""
        if offset >= size:
            message = "Mach-O symbol string offset is outside table"
            raise ValueError(message)
        begin = self.base + stringoff + offset
        ending = self.b.find(b"\x00", begin, self.base + stringoff + size)
        if ending < 0:
            message = "Unterminated Mach-O symbol name"
            raise ValueError(message)
        return self.b[begin:ending].decode(errors="replace")

    def _parse_symbols(self) -> None:
        """Populate all bounded nlist records from the symbol command."""
        if self.symtab is None:
            return
        offset, count, stringoff, stringsize = self.symtab
        for index in range(count):
            nameoff, kind, section, desc, address = struct.unpack_from(
                "<IBBHQ", self.b, self.base + offset + 16 * index
            )
            name = self._symbol_name(nameoff, stringoff, stringsize)
            self.syms.append((name, kind, section, desc, address))

    def _index_symbols(self) -> None:
        """Rebuild named and by-address views for the current parsed image."""
        self.names = {
            symbol[0]: symbol for symbol in self.syms if not symbol[1] & 224
        }
        self.byaddr = collections.defaultdict(list)
        for symbol in self.syms:
            if symbol[4] and symbol[0] and (not symbol[1] & 224):
                self.byaddr[symbol[4]].append(symbol[0])

    def off(self, va: int) -> int:
        """Map a virtual byte address to its file offset.

        Returns:
            Checked offset within a file-backed virtual segment.

        Raises:
            ValueError: The address does not map to a file byte.

        """
        for _, v, _, o, fs in self.segs:
            if v <= va < v + fs:
                offset = self.base + o + va - v
                _require_span(offset, 1, self.slice_end)
                return offset
        message = hex(va)
        raise ValueError(message)

    def read(self, va: int, n: int) -> bytes:
        """Read a complete virtual-address range.

        Returns:
            Immutable source bytes for a mapped file range.

        Raises:
            ValueError: The requested range is unmapped.

        """
        for _, v, _, o, fs in self.segs:
            if n >= 0 and v <= va and (va + n <= v + fs):
                offset = self.base + o + va - v
                _require_span(offset, n, self.slice_end)
                return self.b[offset : offset + n]
        message = f"Unmapped range {va:#x}+{n:#x}"
        raise ValueError(message)

    def close(self) -> None:
        """Release both the source mmap and its owned file descriptor."""
        self.b.close()
        self.f.close()

    def defined(self) -> set[str]:
        """List ordinary exported nlist symbol names.

        Returns:
            Complete exported name set from this source image.

        """
        return {
            n
            for n, t, _, _, _ in self.syms
            if t & 1 and t & 14 in {2, 14} and (not t & 224)
        }

    def undef(self) -> set[str]:
        """List ordinary undefined nlist symbols.

        Returns:
            Complete undefined name set from this source image.

        """
        return {
            n for n, t, _, _, _ in self.syms if t & 14 == 0 and (not t & 224)
        }

    def relocs(self) -> dict[int, tuple[str, int, int, int]]:
        """Read complete source relocation tables.

        Returns:
            Relocation records indexed by virtual address.

        """
        result: dict[int, tuple[str, int, int, int]] = {}
        relocation_tables: list[tuple[int, int, int]] = []
        if self.dysym is not None:
            offset, count = self.dysym[14:16]
            relocation_tables.append((self.base + offset, count, 0))
        for section in self.sects:
            offset, count = section[6:8]
            relocation_tables.append((self.base + offset, count, section[2]))
        for offset, count, start in relocation_tables:
            _require_span(offset, count * 8, self.slice_end)
            for index in range(count):
                relative, relocation = self._read_relocation(offset + 8 * index)
                result[start + relative] = relocation
        return result

    def _read_relocation(
        self, offset: int
    ) -> tuple[int, tuple[str, int, int, int]]:
        """Decode one checked relocation without trusting its symbol index.

        Returns:
            Relative byte offset and decoded relocation metadata.

        Raises:
            ValueError: Offset or external symbol index is invalid.

        """
        relative, word = unpack_integers(self.b, "<iI", offset)
        symbol_index = word & 0xFFFFFF
        external = bool(word >> 27 & 1)
        if external and symbol_index >= len(self.syms):
            message = "Mach-O relocation refers to an absent symbol"
            raise ValueError(message)
        if relative < 0:
            message = "Mach-O relocation has a negative address"
            raise ValueError(message)
        name = self.syms[symbol_index][0] if external else LOCAL_RELOCATION
        return relative, (name, word >> 28, word >> 24 & 1, word >> 25 & 3)

    def funcs(self) -> list[tuple[int, str]]:
        """List sorted executable section functions and their addresses.

        Returns:
            All named text-section addresses and function names.

        """
        return sorted(
            (s[4], s[0])
            for s in self.syms
            if s[2]
            and s[2] <= len(self.sects)
            and (self.sects[s[2] - 1][0] == NATIVE_TEXT_SECTION)
            and (not s[1] & 224)
        )

    def funcbytes(self, name: str) -> tuple[int, bytes]:
        """Read a named function until the next symbol boundary.

        Returns:
            Virtual address and bounded source function bytes.

        """
        a = self.names[name][4]
        ends = [x for x, _ in self.funcs() if x > a]
        e = min(ends) if ends else a + 512
        return (a, self.read(a, e - a))


def sky(ver: str) -> Mach | ReferenceImage:
    """Open a named Skywalk source image or reference snapshot.

    Returns:
        The selected system's bounded Skywalk image.

    """
    return Mach(reference_paths()[ver], "com.apple.iokit.IOSkywalkFamily")


def _installed_program(name: str) -> str:
    """Find an installed tool executable without invoking a shell.

    Returns:
        A concrete resolved executable path from the host PATH.

    Raises:
        FileNotFoundError: No matching installed executable is found.

    """
    resolved = shutil.which(name)
    if resolved is None:
        raise FileNotFoundError(name)
    return str(Path(resolved).resolve())


def dem(names: Iterable[str]) -> list[str]:
    """Demangle candidate class and method names with a system tool.

    Returns:
        One readable method name per submitted mangled symbol.

    """
    symbols = list(names)
    # The installed executable and argv are fixed: no shell or user commands.
    return subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]
        [_installed_program("c++filt")],
        input="\n".join(symbols) + "\n",
        text=True,
    ).splitlines()


@runtime_checkable
class _CreateDisassembler(Protocol):
    """Checked callable surface of LLVMCreateDisasm."""

    # Preserve LLVMCreateDisasm's fixed five-argument C ABI.
    def __call__(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]
        self, triple: bytes, info: None, tag: int, callback: None, symbol: None
    ) -> int | None: ...


@runtime_checkable
class _DecodeInstruction(Protocol):
    """Checked callable surface of LLVMDisasmInstruction."""

    # Preserve LLVMDisasmInstruction's fixed six-argument C ABI.
    def __call__(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]
        self,
        context: int,
        data: object,
        size: int,
        address: int,
        output: object,
        capacity: int,
    ) -> int: ...


def _llvm_export(library: ctypes.CDLL, name: str) -> object:
    """Fetch an initialized symbol from the library's loaded export map.

    Returns:
        The exported callable C function.

    Raises:
        TypeError: The named export is absent or not callable.

    """
    exports: Mapping[str, object] = vars(library)
    symbol = exports.get(name)
    if not callable(symbol):
        message = f"LLVM library is missing callable symbol {name}"
        raise TypeError(message)
    return symbol


@functools.lru_cache(maxsize=1)
def disassembler() -> tuple[ctypes.CDLL, int]:
    """Load the selected Apple LLVM disassembler from its system toolchain.

    Returns:
        LLVM library handle and its valid x86_64 decoder context.

    Raises:
        RuntimeError: The selected LLVM disassembler cannot initialize.
        TypeError: The toolchain contains an incompatible LLVM symbol.

    """
    toolchain = Path(
        subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]
            [_installed_program("xcrun"), "--find", "llvm-objdump"], text=True
        ).strip()
    ).parent.parent
    library = ctypes.CDLL(str(toolchain / "lib/libLTO.dylib"))
    library.LLVMCreateDisasm.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.LLVMCreateDisasm.restype = ctypes.c_void_p
    library.LLVMDisasmInstruction.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    library.LLVMDisasmInstruction.restype = ctypes.c_size_t
    library.lto_initialize_disassembler()
    creator = _llvm_export(library, "LLVMCreateDisasm")
    if not isinstance(creator, _CreateDisassembler):
        message = "Missing LLVM disassembler construction entrypoint"
        raise TypeError(message)
    context = creator(b"x86_64-apple-darwin", None, 0, None, None)
    if not isinstance(context, int) or context == 0:
        message = "Unable to initialize the x86_64 disassembler"
        raise RuntimeError(message)
    return library, context


def insns(data: bytes, addr: int) -> Iterator[tuple[int, int, str, bytes]]:
    """Disassemble bounded source bytes.

    Yields:
        Address, size, instruction text and original bytes.

    Raises:
        TypeError: The installed LLVM function is incompatible.
        ValueError: LLVM reports an invalid instruction length.

    """
    library, context = disassembler()
    decode = _llvm_export(library, "LLVMDisasmInstruction")
    if not isinstance(decode, _DecodeInstruction):
        message = "Missing LLVM instruction decoding entrypoint"
        raise TypeError(message)
    buf = ctypes.create_string_buffer(data)
    o = 0
    while o < len(data):
        out = ctypes.create_string_buffer(512)
        length = decode(
            context, ctypes.byref(buf, o), len(data) - o, addr + o, out, 512
        )
        if length <= 0 or length > len(data) - o:
            message = f"Undecodable instruction at {addr + o:#x}"
            raise ValueError(message)
        yield (
            addr + o,
            length,
            bytes(out).split(b"\x00", 1)[0].decode().strip(),
            data[o : o + length],
        )
        o += length


NATIVE_CLASSES = (
    "IOSkywalkInterface",
    "IOSkywalkNetworkInterface",
    "IOSkywalkEthernetInterface",
    "IOSkywalkPacket",
    "IOSkywalkNetworkPacket",
    "IOSkywalkPacketBufferPool",
    "IOSkywalkPacketQueue",
    "IOSkywalkTxSubmissionQueue",
    "IOSkywalkRxSubmissionQueue",
    "IOSkywalkTxCompletionQueue",
    "IOSkywalkRxCompletionQueue",
    "IOSkywalkPacketBuffer",
    "IOSkywalkMemorySegment",
)
LEGACY_CLASSES = (
    ("Legacy", "IO80211SkywalkInterface", "IOSkywalkEthernetInterface"),
    ("Legacy", "IO80211InfraInterface", "IO80211SkywalkInterface"),
    (
        "BrcmTahoe",
        "AirPort_Brcm43xxLLSkywalkInterface",
        "IO80211InfraInterface",
    ),
    ("BrcmTahoe", "AirPort_Brcm43xxSkywalkPacket", "IOSkywalkNetworkPacket"),
    (
        "BrcmTahoe",
        "AirPort_Brcm43xxSkywalkPacketBufferPool",
        "IOSkywalkPacketBufferPool",
    ),
)


def vtable_name(cls: str) -> str:
    """Build an Itanium-mangled vtable symbol name.

    Returns:
        A mangled symbol matching the supplied class name.

    """
    return "__ZTV" + str(len(cls)) + cls


METHOD_KEYS: dict[str, str] = {}


def prime_method_keys(names: Iterable[str]) -> None:
    """Preload readable class-method keys in symbol order."""
    names = sorted(set(names) - METHOD_KEYS.keys())
    if not names:
        return
    for name, readable in zip(names, dem(names), strict=True):
        key = readable.split("::", 1)[-1].replace("ether_addr_t", "ether_addr")
        destructor = re.search(r"D([012])Ev$", name)
        METHOD_KEYS[name] = "destructor" + destructor[1] if destructor else key


def method_key(name: str) -> str:
    """Look up the canonical readable signature of a method.

    Returns:
        The demangled canonical method key.

    """
    if name not in METHOD_KEYS:
        prime_method_keys([name])
    return METHOD_KEYS[name]


MAX_VTABLE_SLOTS = 4096
VTABLE_HEADER_BYTES = 16
VTABLE_SLOT_BYTES = 8


def _vtable_addresses(start: int, end: int) -> range:
    """Bound vtable slots before touching any untrusted image bytes.

    Returns:
        Validated pointer-slot addresses within the symbol span.

    Raises:
        ValueError: The vtable span is empty, unaligned or too large.

    """
    payload = end - start - VTABLE_HEADER_BYTES
    invalid_start = start < 0 or payload <= 0
    invalid_slots = (
        payload % VTABLE_SLOT_BYTES
        or payload // VTABLE_SLOT_BYTES > MAX_VTABLE_SLOTS
    )
    if invalid_start or invalid_slots:
        message = "Malformed or oversized native ABI vtable span"
        raise ValueError(message)
    return range(start + VTABLE_HEADER_BYTES, end, VTABLE_SLOT_BYTES)


def _vtable_target(raw: int, kernel: Mach | ReferenceImage | None) -> int:
    """Decode a kernel collection fixup to its address or refuse the format.

    Returns:
        Validated target address for the raw slot value.

    Raises:
        ValueError: A compact fixup has an unsupported encoding.
        TypeError: A fixup requires a full mapped kernel image.

    """
    if kernel is None or raw >> 48 == KERNEL_FIXUP_UPPER_HALF:
        return raw
    if raw >> 30 & 3 or raw >> 63:
        message = "Unsupported kernel collection fixup"
        raise ValueError(message)
    if not isinstance(kernel, Mach):
        message = "Kernel fixup resolution requires a Mach-O image"
        raise TypeError(message)
    return (raw & 1073741823) + kernel.fixup_base


def _vtable_slot(
    image: Mach,
    address: int,
    *,
    relocs: dict[int, tuple[str, int, int, int]],
    kernel: Mach | ReferenceImage | None,
) -> tuple[str | None, int | None]:
    """Resolve one slot without assuming a relocation is an import.

    Returns:
        Method name and optional target, or two None values for an empty slot.

    """
    raw = struct.unpack("<Q", image.read(address, VTABLE_SLOT_BYTES))[0]
    relocated = relocs.get(address)
    if relocated is not None and relocated[0] != LOCAL_RELOCATION:
        return relocated[0], None
    if not raw:
        return None, None
    target = _vtable_target(raw, kernel)
    names = image.byaddr.get(target, []) or (
        kernel.byaddr.get(target, []) if kernel else []
    )
    return (names[0] if names else None), target


def _table_end(image: Mach, cls: str) -> tuple[int, int]:
    """Find a validated vtable symbol and its next closing symbol.

    Returns:
        Start and exclusive end virtual addresses for a named vtable.

    Raises:
        ValueError: No following symbol bounds the table.

    """
    sym = image.names[vtable_name(cls)]
    start = sym[4]
    following = [
        symbol[4]
        for symbol in image.syms
        if symbol[2] == sym[2] and symbol[4] > start
    ]
    if not following:
        message = "Native ABI vtable has no terminating symbol"
        raise ValueError(message)
    return start, min(following)


def _nonempty_table(cls: str, values: list[str]) -> list[str]:
    """Reject an empty table without fabricating any symbol entries.

    Returns:
        The same non-empty physical method order.

    Raises:
        ValueError: No named entry was decoded in the table.

    """
    if not values:
        message = f"Empty vtable: {cls}"
        raise ValueError(message)
    return values


def table(
    image: Mach | ReferenceImage,
    cls: str,
    kernel: Mach | ReferenceImage | None = None,
) -> list[str]:
    """Resolve physical vtable slots with bounded relocation checks.

    Returns:
        Named methods in their original slot order.

    Raises:
        ValueError: Any slot or relocated target lacks source evidence.

    """
    if isinstance(image, ReferenceImage):
        return list(image.tables[cls])
    start, end = _table_end(image, cls)
    addresses = _vtable_addresses(start, end)
    relocs = image.relocs()
    result: list[str] = []
    for address in addresses:
        name, target = _vtable_slot(
            image, address, relocs=relocs, kernel=kernel
        )
        if name is None and target is None:
            break
        if name is None:
            message = f"Unnamed vtable entry {cls}: {address:#x} -> {target:#x}"
            raise ValueError(message)
        result.append(name)
    return _nonempty_table(cls, result)


class _Layout(TypedDict, total=False):
    """Optional constructor fields keyed by original class kind."""

    old: int
    native: int
    parent: str
    allocationTypeView: int
    allocationTypeSize: int


class _Imports(TypedDict):
    """Complete direct import and missing relocation manifest."""

    oldSkywalkImports: int
    missingInNative: list[str]
    relocations: dict[str, list[int]]


@dataclass
class _LegacySlots:
    """Owned mutable native view and superclass indexing during ABI mapping."""

    cls: str
    parent: str
    original: list[str]
    keyed: dict[str, int]
    new: list[str]
    physical: list[tuple[str, str, int]]
    logical: list[tuple[str, str, int]]


def _place_legacy_slot(
    slots: _LegacySlots,
    index: int,
    name: str,
    *,
    entry: tuple[str, str, int],
) -> None:
    """Assign a legacy override to its native slot or append a new slot.

    Raises:
        ValueError: An existing unmatched override cannot be translated.

    """
    if index < len(slots.original) and method_key(name) in slots.keyed:
        slot = slots.keyed[method_key(name)]
        slots.new[slot] = name
        slots.physical[slot] = entry
    elif index >= len(slots.original):
        slots.new.append(name)
        slots.physical.append(entry)
    elif entry[0] != ABSENT_SLOT:
        message = f"Unmapped override: {slots.cls} {name}"
        raise ValueError(message)


@final
class NativeModel:
    """Derive checked Skywalk class and method slots from pinned images."""

    def __init__(self, system: str = "Tahoe") -> None:
        """Validate source provenance and derive all cross-release ABI views."""
        self.system = system
        self.profile = SYSTEMS[system]
        self._open_images(system)
        self._initialize_tables()

    def _open_images(self, system: str) -> None:
        """Open the pinned source images after all source hashes match.

        Raises:
            ValueError: A checksum or release ABI identifier mismatches.

        """
        for key, expected in EXPECTED_SOURCES.items():
            if hash_mach_source(PATHS[key]) != expected:
                message = f"Unsupported source payload: {key}"
                raise ValueError(message)
        self.old: Mach | ReferenceImage = Mach(PATHS["OldSky"])
        self.native: Mach | ReferenceImage = sky(system)
        self.kernel: Mach | ReferenceImage = Mach(
            self.native.path, "com.apple.kernel"
        )
        major = self.kernel.names["_version_major"][4]
        if (
            struct.unpack("<I", self.kernel.read(major, 4))[0]
            != self.profile["kernel"]
        ):
            message = "Reference system kernel does not match its profile"
            raise ValueError(message)
        if self.native.uuid != self.profile["skywalk"]:
            message = "Reference Skywalk UUID does not match its profile"
            raise ValueError(message)
        self.airport_source = (
            "BrcmTahoe"
            if self.profile["kernel"] == DARWIN_TAHOE
            else "BrcmOriginal"
        )
        self.images: dict[str, Mach | ReferenceImage] = {
            "Legacy": Mach(PATHS["Legacy"]),
            "BrcmTahoe": Mach(PATHS[self.airport_source]),
        }

    def _initialize_tables(self) -> None:
        """Build native and legacy method views from complete catalogs."""
        self.old_tables: dict[str, list[str]] = {}
        self.new_tables: dict[str, list[str]] = {}
        self.old_views: dict[str, list[tuple[str, str, int]]] = {}
        self.tables: dict[str, list[tuple[str, str, int]]] = {}
        self.holes: list[tuple[str, int, str]] = []
        names: list[str] = []
        for cls in NATIVE_CLASSES:
            names.extend(table(self.old, cls))
            names.extend(table(self.native, cls, self.kernel))
        for label, cls, _ in LEGACY_CLASSES:
            names.extend(table(self.images[label], cls))
        prime_method_keys(names)
        for cls in NATIVE_CLASSES:
            self._map_native_class(cls)
        for label, cls, parent in LEGACY_CLASSES:
            self._map_legacy_class(label, cls, parent)

    def _map_native_class(self, cls: str) -> None:
        """Map one old Skywalk class onto its native method-key slots."""
        old = table(self.old, cls)
        new = table(self.native, cls, self.kernel)
        self.old_tables[cls] = old
        self.new_tables[cls] = new
        keyed = {method_key(name): index for index, name in enumerate(new)}
        entries: list[tuple[str, str, int]] = []
        for offset, name in enumerate(old):
            key = method_key(name)
            if key in keyed:
                entries.append(("native", cls, keyed[key] * VTABLE_SLOT_BYTES))
            else:
                entries.append((ABSENT_SLOT, name, 0))
                self.holes.append((cls, offset * VTABLE_SLOT_BYTES, name))
        self.old_views[cls] = entries
        self.tables[cls] = [
            ("native", cls, index * VTABLE_SLOT_BYTES)
            for index in range(len(new))
        ]

    def _legacy_entry(
        self, label: str, name: str, *, slots: _LegacySlots
    ) -> tuple[str, str, int]:
        """Resolve a legacy override from complete native/legacy sources.

        Returns:
            The physical method entry or an explicit absent-method marker.

        """
        image = self.images[label]
        legacy = self.images["Legacy"]
        if name in image.defined():
            entry = (label, name, image.names[name][4])
        elif name in legacy.defined():
            entry = ("Legacy", name, legacy.names[name][4])
        else:
            key = method_key(name)
            entry = (
                self.tables[slots.parent][slots.keyed[key]]
                if key in slots.keyed
                else (ABSENT_SLOT, name, 0)
            )
        return entry

    def _map_legacy_class(self, label: str, cls: str, parent: str) -> None:
        """Apply all legacy override slots to their native superclass view."""
        old = table(self.images[label], cls)
        self.old_tables[cls] = old
        slots = _LegacySlots(
            cls=cls,
            parent=parent,
            original=self.old_tables[parent],
            keyed={
                method_key(method): index
                for index, method in enumerate(self.new_tables[parent])
            },
            new=list(self.new_tables[parent]),
            physical=list(self.tables[parent]),
            logical=[],
        )
        for index, name in enumerate(old):
            if index < len(slots.original) and name == slots.original[index]:
                slots.logical.append(self.old_views[parent][index])
                continue
            entry = self._legacy_entry(label, name, slots=slots)
            slots.logical.append(entry)
            _place_legacy_slot(slots, index, name, entry=entry)
        self.new_tables[cls] = slots.new
        self.old_views[cls] = slots.logical
        self.tables[cls] = slots.physical

    def describe(self) -> dict[str, object]:
        """Describe source provenance, class slots and absent imports.

        Returns:
            JSON-ready source identity, class and dependency evidence.

        """
        sources = {
            "OldSky": PATHS["OldSky"],
            "Legacy": PATHS["Legacy"],
            "AirPort": PATHS[self.airport_source],
        }
        classes = {
            cls: {
                "oldSlotCount": len(self.old_tables[cls]),
                "nativeSlotCount": len(self.new_tables[cls]),
                "oldMethods": self.old_tables[cls],
                "nativeMethods": self.new_tables[cls],
                "legacyView": self.old_views[cls],
                "nativeView": self.tables[cls],
            }
            for cls in self.tables
        }
        return {
            "copyright": "Copyright © 2026 laobamac. All rights reserved.",
            "purpose": (
                "Raw ABI evidence used by native_payload.py; "
                "build.py validates the executable adapter"
            ),
            "implementationStatus": "implemented",
            "hardwareValidation": "not-run-by-build",
            "system": self.system,
            "nativeUUID": self.native.uuid,
            "airPortSource": self.airport_source,
            "sourceSHA256": {
                key: hash_mach_source(path) for key, path in sources.items()
            },
            "classes": classes,
            "removedMethods": self.holes,
            "layouts": self.layouts(),
            "imports": self.imports(),
        }

    def layouts(self) -> dict[str, _Layout]:
        """Return class allocation footprints from verified constructors.

        Returns:
            Layout and allocation metadata for each native class.

        """
        result: dict[str, _Layout] = {}
        for cls in NATIVE_CLASSES:
            result[cls] = {
                "old": class_size(self.old, cls),
                "native": class_size(self.native, cls),
            }
        for label, cls, parent in LEGACY_CLASSES:
            image = self.images[label]
            ktv = "__ZL" + str(len(cls) + 4) + cls + "_ktv"
            result[cls] = {
                "old": class_size(image, cls),
                "parent": parent,
                "allocationTypeView": image.names[ktv][4],
                "allocationTypeSize": struct.unpack(
                    "<I", image.read(image.names[ktv][4] + 44, 4)
                )[0],
            }
        return result

    def imports(self) -> dict[str, _Imports]:
        """Report unresolved imports from full symbol and relocation tables.

        Returns:
            Per-image counts and complete missing symbol relocation offsets.

        Raises:
            TypeError: Snapshot metadata lacks the full import catalog.

        """
        if not isinstance(self.old, Mach) or not isinstance(self.native, Mach):
            message = "Native import audit requires full Mach-O symbols"
            raise TypeError(message)
        result: dict[str, _Imports] = {}
        for label, image in self.images.items():
            if not isinstance(image, Mach):
                message = "Native import audit requires full Mach-O relocations"
                raise TypeError(message)
            references = image.undef() & self.old.defined()
            absent = references - self.native.defined()
            result[label] = {
                "oldSkywalkImports": len(references),
                "missingInNative": sorted(absent),
                "relocations": {
                    name: [
                        address
                        for address, entry in image.relocs().items()
                        if entry[0] == name
                    ]
                    for name in sorted(absent)
                },
            }
        return result

    def close(self) -> None:
        """Release all mapped native images or in-memory references."""
        for image in [
            self.old,
            self.native,
            self.kernel,
            *self.images.values(),
        ]:
            image.close()


def class_size(image: Mach | ReferenceImage, cls: str) -> int:
    """Extract a single metaclass constructor allocation size.

    Returns:
        Decoded class size in bytes.

    Raises:
        ValueError: A missing or ambiguous class-size instruction.

    """
    name = "__ZN" + str(len(cls)) + cls + "9MetaClassC2Ev"
    address, data = image.funcbytes(name)
    sizes = [
        int(match[1])
        for _, _, text, _ in insns(data, address)
        if (match := re.fullmatch(r"movl\s+\$(\d+), %ecx", text))
    ]
    if len(sizes) != 1:
        message = f"Ambiguous class-size initializer: {cls}"
        raise ValueError(message)
    return sizes[0]


def _verify_tahoe_slots(
    model: NativeModel, require: Callable[[bool, str], None]
) -> None:
    """Enforce the two exact-build Ethernet slot collisions, if applicable."""
    if model.profile["kernel"] != DARWIN_TAHOE:
        return
    cls = "IOSkywalkEthernetInterface"
    require(
        OLD_INIT_BSD in model.old_tables[cls][2256 // 8]
        and NEW_LOGICAL_LINK in model.new_tables[cls][2256 // 8],
        "Ethernet vtable collision at 0x8d0",
    )
    require(
        OLD_PROXY_METHOD in model.old_tables[cls][2736 // 8]
        and NEW_RESERVED_METHOD in model.new_tables[cls][2736 // 8],
        "Ethernet reserved-slot collision at 0xab0",
    )


def verify_model(model: NativeModel) -> list[str]:
    """Verify source ABI invariants against the pinned release profile.

    Returns:
        Names of the source-level ABI invariants that passed.

    """
    checks: list[str] = []

    # Invariant pairs are supplied positionally in the pinned ABI checklist.
    def require(condition: bool, name: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]
        if not condition:
            message = "ABI verification failed: " + name
            raise ValueError(message)
        checks.append(name)

    require(
        model.native.uuid == model.profile["skywalk"],
        model.system + " native UUID",
    )
    require(
        len(model.tables) == EXPECTED_CLASS_TABLES, "18 class tables decoded"
    )
    for cls, old_size, native_size in [
        ("IOSkywalkInterface", 184, 176),
        (
            "IOSkywalkNetworkInterface",
            208,
            224 if model.profile["kernel"] == DARWIN_TAHOE else 208,
        ),
        ("IOSkywalkEthernetInterface", 272, model.profile["ethernetSize"]),
        ("IOSkywalkPacketBufferPool", 184, model.profile["poolSize"]),
        ("IOSkywalkPacket", 120, 112),
        ("IOSkywalkNetworkPacket", 128, 120),
    ]:
        require(
            class_size(model.old, cls) == old_size
            and class_size(model.native, cls) == native_size,
            cls + " class sizes",
        )
    cls = "IOSkywalkEthernetInterface"
    require(
        len(model.new_tables[cls]) == model.profile["ethernetSlots"],
        "Native Ethernet vtable length",
    )
    _verify_tahoe_slots(model, require)
    old = model.images["Legacy"]
    require(
        old.read(683934, 7) == bytes.fromhex("48898318010000"),
        "Legacy controller pointer store at this+0x118",
    )
    name = "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary"
    address = model.native.names[name][4]
    offset = model.profile["ethernetSize"] - 8
    require(
        model.native.read(address + 38, 7)
        == b"\x48\x89\x83" + struct.pack("<I", offset),
        f"Native expansion pointer store at this+{offset:#x}",
    )
    refs = model.imports()
    require(
        refs["Legacy"]["oldSkywalkImports"] == EXPECTED_LEGACY_IMPORTS
        and refs["BrcmTahoe"]["oldSkywalkImports"] == EXPECTED_BRCM_IMPORTS,
        "Skywalk dependency counts",
    )
    counts = {23: (1, 2), 24: (2, 3), 25: (2, 4)}[model.profile["kernel"]]
    require(
        (
            len(refs["Legacy"]["missingInNative"]),
            len(refs["BrcmTahoe"]["missingInNative"]),
        )
        == counts,
        "Skywalk missing-entry counts",
    )
    layouts = model.layouts()
    for _, cls, _ in LEGACY_CLASSES:
        require(
            layouts[cls].get("old") is not None
            and layouts[cls].get("old")
            == layouts[cls].get("allocationTypeSize"),
            cls + " original allocation metadata",
        )
    return checks


def _audit_args() -> tuple[str, str, Path | None]:
    """Parse and validate the native ABI audit's typed command arguments.

    Returns:
        System profile, audit action and optional output file path.

    Raises:
        ValueError: A parsed value violates the expected CLI contract.
        TypeError: The CLI parser supplies an unexpected value type.

    """
    parser = argparse.ArgumentParser(
        description=(
            "Read-only native ABI audit; does not produce a bootable driver"
        )
    )
    _ = parser.add_argument("action", choices=["audit", "verify"])
    _ = parser.add_argument("--output", type=Path)
    _ = parser.add_argument("--system", choices=list(SYSTEMS), default="Tahoe")
    values: dict[str, object] = vars(parser.parse_args())
    system = values.get("system")
    action = values.get("action")
    output = values.get("output")
    if not isinstance(system, str):
        message = "Invalid native ABI system profile type"
        raise TypeError(message)
    valid_action = isinstance(action, str) and action in {"verify", "audit"}
    valid_output = output is None or isinstance(output, Path)
    if system not in SYSTEMS or not valid_action or not valid_output:
        message = "Invalid native ABI audit arguments"
        raise ValueError(message)
    if not isinstance(action, str):
        message = "Invalid native ABI audit action type"
        raise TypeError(message)
    return system, action, output if isinstance(output, Path) else None


def _print_summary(model: NativeModel, checks: list[str]) -> None:
    """Write machine-readable ABI verification results to standard output."""
    _ = sys.stdout.write(
        json.dumps(
            {
                "nativeUUID": model.native.uuid,
                "classes": len(model.tables),
                "removedSlots": len(model.holes),
                "auditChecksPassed": len(checks),
                "outputKind": "abi-audit",
            },
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    """Run a read-only audit with reliable cleanup of mapped image files."""
    system, action, output = _audit_args()
    model = NativeModel(system)
    try:
        result = model.describe()
        checks = verify_model(model) if action == VERIFY_ACTION else []
        result["auditChecks"] = checks
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            _ = output.write_text(json.dumps(result, indent=2) + "\n")
        _print_summary(model, checks)
    finally:
        model.close()


if __name__ == "__main__":
    main()
