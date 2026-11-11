#!/usr/bin/env python3
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
#   - Originally authored by laobamac on 2026/9/6.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for macho.
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
#   - Host-side tooling for macho.
# - Description:
#   - Implements or verifies the macho source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for macho.

"""Read pinned Mach-O images for offline static ABI evidence only."""

import argparse
import bisect
from dataclasses import dataclass
import hashlib
from itertools import pairwise
import os
from pathlib import Path
import re
import shutil
import stat

# Fixed argv and explicit shell=False.
import subprocess
import sys

if __package__:
    from tools.abi_types import byte_string
    from tools.abi_types import integer
    from tools.abi_types import unpack_integers
    from tools.abi_types import unpack_values
else:
    from abi_types import byte_string
    from abi_types import integer
    from abi_types import unpack_integers
    from abi_types import unpack_values


MAX_MACHO_BYTES = 2 * 1024 * 1024 * 1024
MAX_FAT_ARCHITECTURES = 256
FAT32_MAGIC = b"\xca\xfe\xba\xbe"
FAT64_MAGIC = b"\xca\xfe\xba\xbf"
X86_64_CPU = 0x1000007
FAT_HEADER_SIZE = 8
MAX_FAT_ALIGNMENT_EXPONENT = 62
MACHO_HEADER_SIZE = 32
MACHO_MAGIC = b"\xcf\xfa\xed\xfe"
LOAD_COMMAND_MIN_BYTES = 8
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_UUID = 0x1B
SEGMENT_COMMAND_BYTES = 72
SECTION_BYTES = 80
SYMTAB_COMMAND_BYTES = 24
DYSYMTAB_COMMAND_BYTES = 80
DYLD_COMMAND_BYTES = 48
UUID_COMMAND_BYTES = 24
STUB_KIND = 8
INDIRECT_SECTION_KINDS = {6, 7, STUB_KIND}
SECTION_SYMBOL_KIND = 0xE
MAX_LEB_SHIFT = 70
NEAR_SYMBOL_DISTANCE = 0x10000
NULL_BYTE = b"\0"
INDIRECT_JUMP_SIGNATURE = b"\xff\x25"
CSTRING_SECTION = "__cstring"
BIND_OPCODE_SLEB = 0x60
BIND_OPCODE_SYMBOL = 0x40
BIND_OPCODE_SEGMENT = 0x70
BIND_OPCODE_OFFSET = 0x80
BIND_OPCODE_WITH_SKIP = 0xA0
BIND_OPCODE_WITH_IMMEDIATE = 0xB0
BIND_OPCODE_REPEAT = 0xC0
BIND_OPCODE_DIRECT = 0x90
PRINTABLE_ASCII_START = 32
PRINTABLE_ASCII_END = 127
READ_COMPONENTS = 2
_METADATA_COMMAND_NAMES: dict[int, str] = {
    LC_SYMTAB: "symbol table",
    LC_DYSYMTAB: "dynamic symbol table",
    LC_DYLD_INFO: "dyld metadata",
    LC_DYLD_INFO_ONLY: "dyld metadata",
}
_METADATA_COMMAND_FORMATS: dict[int, tuple[int, str]] = {
    LC_SYMTAB: (SYMTAB_COMMAND_BYTES, "<IIII"),
    LC_DYSYMTAB: (DYSYMTAB_COMMAND_BYTES, "<18I"),
    LC_DYLD_INFO: (DYLD_COMMAND_BYTES, "<10I"),
    LC_DYLD_INFO_ONLY: (DYLD_COMMAND_BYTES, "<10I"),
}


@dataclass(slots=True)
class _BindCursor:
    """Bound one dyld binding program's position and pointer-write budget."""

    limit: int
    position: int = 0
    address: int = 0
    visits: int = 0
    symbol: str = ""


def _fat_architecture(
    data: bytes, entry: int, table_end: int, *, wide: bool
) -> tuple[int, int, int]:
    """Parse one complete, bounded, aligned fat architecture row.

    Returns:
        CPU identifier, slice offset and length.

    Raises:
        ValueError: A malformed, unaligned or overlapping-table slice.

    """
    cpu = unpack_integers(data, ">I", entry)[0]
    offset, size = unpack_integers(data, ">QQ" if wide else ">II", entry + 8)
    alignment = unpack_integers(data, ">I", entry + (24 if wide else 16))[0]
    if not size or offset < table_end or offset > len(data):
        message = "Invalid Mach-O fat slice bounds or alignment"
        raise ValueError(message)
    if size > len(data) - offset:
        message = "Invalid Mach-O fat slice bounds or alignment"
        raise ValueError(message)
    if alignment > MAX_FAT_ALIGNMENT_EXPONENT or offset % (1 << alignment):
        message = "Invalid Mach-O fat slice bounds or alignment"
        raise ValueError(message)
    return cpu, offset, size


def _require_disjoint_slices(ranges: list[tuple[int, int]]) -> None:
    """Reject fat images with any overlapping declared architecture slices.

    Raises:
        ValueError: Two architecture records describe overlapping bytes.

    """
    ranges.sort()
    if any(left[1] > right[0] for left, right in pairwise(ranges)):
        message = "Overlapping Mach-O fat slices"
        raise ValueError(message)


def _fat_x86_64_range(
    data: bytes, count: int, *, wide: bool, entry_size: int
) -> tuple[int, int]:
    """Find exactly one disjoint, bounded x86_64 fat architecture.

    Returns:
        Selected offset and length within the original container.

    Raises:
        ValueError: Missing or ambiguous x86_64 selection.

    """
    ranges: list[tuple[int, int]] = []
    selected: tuple[int, int] | None = None
    table_end = FAT_HEADER_SIZE + count * entry_size
    for index in range(count):
        cpu, offset, size = _fat_architecture(
            data, FAT_HEADER_SIZE + index * entry_size, table_end, wide=wide
        )
        ranges.append((offset, offset + size))
        if cpu == X86_64_CPU:
            if selected is not None:
                message = "Ambiguous x86_64 Mach-O fat slices"
                raise ValueError(message)
            selected = (offset, size)
    _require_disjoint_slices(ranges)
    if selected is None:
        message = "No x86_64 slice"
        raise ValueError(message)
    return selected


def _select_x86_64_slice(data: bytes) -> bytes:
    """Select a unique bounded x86_64 fat slice, preserving thin images.

    Returns:
        The bounded thin x86_64 slice, or the unchanged standalone input.

    Raises:
        ValueError: A malformed or ambiguous fat architecture table.

    """
    if data[:4] not in {FAT32_MAGIC, FAT64_MAGIC}:
        return data
    if len(data) < FAT_HEADER_SIZE:
        message = "Truncated Mach-O fat header"
        raise ValueError(message)
    wide = data[:4] == FAT64_MAGIC
    count = unpack_integers(data, ">I", 4)[0]
    entry_size = 32 if wide else 20
    if (
        not 0 < count <= MAX_FAT_ARCHITECTURES
        or count > (len(data) - FAT_HEADER_SIZE) // entry_size
    ):
        message = "Truncated or excessive Mach-O fat architecture table"
        raise ValueError(message)
    offset, size = _fat_x86_64_range(
        data, count, wide=wide, entry_size=entry_size
    )
    return data[offset : offset + size]


def read_macho_source(path: Path) -> bytes:
    """Read bounded regular image bytes without following symbolic links.

    Returns:
        The stable, complete image bytes.

    Raises:
        ValueError: Invalid source file type, size or concurrent mutation.

    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_MACHO_BYTES
        ):
            message = "Mach-O input must be a bounded regular file"
            raise ValueError(message)
        data = stream.read(MAX_MACHO_BYTES + 1)
        after = os.fstat(stream.fileno())
    stable_identity = (
        after.st_dev == before.st_dev
        and after.st_ino == before.st_ino
        and after.st_size == before.st_size
    )
    stable_content = (
        len(data) == before.st_size and after.st_mtime_ns == before.st_mtime_ns
    )
    if not stable_identity or not stable_content:
        message = "Mach-O input changed while being read"
        raise ValueError(message)
    return data


class Image:
    """Parse pinned offline Mach-O metadata; never load or execute an image."""

    def __init__(self, path: str | Path) -> None:
        """Read and validate the selected x86_64 Mach-O byte stream.

        Raises:
            ValueError: Inconsistent, ambiguous or truncated Mach-O metadata.

        """
        self.path: Path = Path(path)
        source = read_macho_source(self.path)
        self.source_sha256: str = hashlib.sha256(source).hexdigest()
        self.data: bytes = _select_x86_64_slice(source)
        if len(self.data) < MACHO_HEADER_SIZE or self.data[:4] != MACHO_MAGIC:
            message = "Expected complete little-endian Mach-O 64 header"
            raise ValueError(message)
        command_count, command_bytes = unpack_integers(self.data, "<II", 16)
        if (
            command_bytes > len(self.data) - MACHO_HEADER_SIZE
            or command_count > command_bytes // LOAD_COMMAND_MIN_BYTES
        ):
            message = "Mach-O command area exceeds file bounds"
            raise ValueError(message)
        self.segments: list[tuple[str, int, int, int, int]] = []
        self.sections: list[tuple[str, str, int, int, int]] = []
        self.symbols: dict[str, int] = {}
        self.binds: dict[int, str] = {}
        self.stubs: dict[int, str] = {}
        self.uuid: str | None = None
        symtab, dysymtab, dyld = self._load_commands(
            command_count, command_bytes
        )
        names = self._load_symbols(symtab)
        self._load_indirect_symbols(dysymtab, names, command_count)
        self.addresses: list[tuple[int, str]] = sorted(
            (address, name) for name, address in self.symbols.items()
        )
        self.keys: list[int] = [entry[0] for entry in self.addresses]
        self._load_dyld_binds(dyld)

    def _load_segment(self, position: int, size: int) -> None:
        """Collect bounded segment and section rows without dereferencing.

        Raises:
            ValueError: Truncated segment or section load command.

        """
        if size < SEGMENT_COMMAND_BYTES:
            message = "Truncated Mach-O segment command"
            raise ValueError(message)
        fields = unpack_values(self.data, "<16sQQQQiiII", position + 8)
        name = byte_string(fields[0]).rstrip(NULL_BYTE).decode()
        address, length, offset, file_size = (
            integer(value) for value in fields[1:5]
        )
        count = integer(fields[7])
        if count > (size - SEGMENT_COMMAND_BYTES) // SECTION_BYTES:
            message = "Mach-O segment sections exceed command"
            raise ValueError(message)
        self.segments.append((name, address, length, offset, file_size))
        for index in range(count):
            self._load_section(
                position + SEGMENT_COMMAND_BYTES + SECTION_BYTES * index
            )

    def _load_section(self, position: int) -> None:
        """Read one complete 64-bit section row from a validated command."""
        fields = unpack_values(self.data, "<16s16sQQI", position)
        section = byte_string(fields[0]).rstrip(NULL_BYTE).decode()
        segment = byte_string(fields[1]).rstrip(NULL_BYTE).decode()
        self.sections.append((
            segment,
            section,
            integer(fields[2]),
            integer(fields[3]),
            integer(fields[4]),
        ))

    def _load_commands(
        self, count: int, command_bytes: int
    ) -> tuple[
        tuple[int, ...] | None, tuple[int, ...] | None, tuple[int, ...] | None
    ]:
        """Validate and collect unique load-command metadata tables.

        Returns:
            Optional symbol, dynamic symbol and dyld binding tables.

        Raises:
            ValueError: Invalid command extent or duplicate metadata.

        """
        commands: dict[int, tuple[int, ...]] = {}
        position = MACHO_HEADER_SIZE
        for _ in range(count):
            command, size = unpack_integers(self.data, "<II", position)
            if (
                size < LOAD_COMMAND_MIN_BYTES
                or size > MACHO_HEADER_SIZE + command_bytes - position
            ):
                message = "Invalid Mach-O load command bounds"
                raise ValueError(message)
            self._dispatch_load_command(
                command, position, size, commands=commands
            )
            position += size
        if position != MACHO_HEADER_SIZE + command_bytes:
            message = "Mach-O command bytes/count disagree"
            raise ValueError(message)
        return (
            commands.get(LC_SYMTAB),
            commands.get(LC_DYSYMTAB),
            commands.get(LC_DYLD_INFO),
        )

    def _dispatch_load_command(
        self,
        command: int,
        position: int,
        size: int,
        *,
        commands: dict[int, tuple[int, ...]],
    ) -> None:
        """Interpret one already bounded load-command descriptor."""
        if command == LC_SEGMENT_64:
            self._load_segment(position, size)
        elif command == LC_UUID:
            self._load_uuid(position, size)
        elif command in _METADATA_COMMAND_FORMATS:
            self._load_metadata_command(
                command, position, size, commands=commands
            )

    def _load_uuid(self, position: int, size: int) -> None:
        """Refuse conflicting UUID claims from repeated load commands.

        Raises:
            ValueError: A duplicate or truncated UUID load command.

        """
        if self.uuid is not None:
            message = "Duplicate Mach-O UUID command"
            raise ValueError(message)
        if size < UUID_COMMAND_BYTES:
            message = "Truncated Mach-O UUID"
            raise ValueError(message)
        self.uuid = self.data[position + 8 : position + 24].hex()

    def _load_metadata_command(
        self,
        command: int,
        position: int,
        size: int,
        *,
        commands: dict[int, tuple[int, ...]],
    ) -> None:
        """Parse one fixed-size symbol or dyld command.

        Raises:
            ValueError: A duplicate or undersized command.

        """
        normalized = LC_DYLD_INFO if command == LC_DYLD_INFO_ONLY else command
        if normalized in commands:
            message = (
                f"Duplicate Mach-O {_METADATA_COMMAND_NAMES[command]} command"
            )
            raise ValueError(message)
        required, fmt = _METADATA_COMMAND_FORMATS[command]
        if size < required:
            message = (
                f"Truncated Mach-O {_METADATA_COMMAND_NAMES[command]} command"
            )
            raise ValueError(message)
        commands[normalized] = unpack_integers(self.data, fmt, position + 8)

    def _load_symbols(self, symtab: tuple[int, ...] | None) -> list[str]:
        """Load validated symbol names and section-defined addresses.

        Returns:
            Names indexed by their original Mach-O symbol table positions.

        Raises:
            ValueError: Invalid string table ranges or unterminated names.

        """
        if symtab is None:
            return []
        offset, count, strings, strings_size = symtab
        if offset > len(self.data) or count > (len(self.data) - offset) // 16:
            message = "Mach-O symbol table exceeds file bounds"
            raise ValueError(message)
        if strings > len(self.data) or strings_size > len(self.data) - strings:
            message = "Mach-O symbol table exceeds file bounds"
            raise ValueError(message)
        return [
            self._append_symbol(offset + 16 * index, strings, strings_size)
            for index in range(count)
        ]

    def _append_symbol(self, offset: int, strings: int, size: int) -> str:
        """Record one symbol's name and any valid defined-section address.

        Returns:
            Symbol name for its indirect-symbol index.

        """
        name, kind, _, _, address = unpack_integers(self.data, "<IBBHQ", offset)
        text = self._load_symbol_name(name, strings, size)
        if (
            name
            and address > 1
            and kind & SECTION_SYMBOL_KIND == SECTION_SYMBOL_KIND
        ):
            self.symbols[text] = address
        return text

    def _load_symbol_name(self, name: int, strings: int, size: int) -> str:
        """Read one NUL-terminated symbol within its declared string table.

        Returns:
            A replacement-decoded name, or empty for index zero.

        Raises:
            ValueError: Invalid offset or missing NUL terminator.

        """
        if name >= size:
            message = "Mach-O symbol name outside string table"
            raise ValueError(message)
        if not name:
            return ""
        raw = self.data[strings + name : strings + size]
        if NULL_BYTE not in raw:
            message = "Unterminated Mach-O symbol name"
            raise ValueError(message)
        return raw.split(NULL_BYTE, 1)[0].decode(errors="replace")

    def _load_indirect_symbols(
        self, dynamic: tuple[int, ...] | None, names: list[str], count: int
    ) -> None:
        """Associate bounded indirect section slots with known symbols.

        Raises:
            ValueError: The indirect symbol table exceeds file bounds.

        """
        if dynamic is None:
            return
        offset, total = dynamic[12:14]
        if offset > len(self.data) or total > (len(self.data) - offset) // 4:
            message = "Mach-O indirect symbols exceed file bounds"
            raise ValueError(message)
        position = MACHO_HEADER_SIZE
        for _ in range(count):
            command, size = unpack_integers(self.data, "<II", position)
            if command == LC_SEGMENT_64:
                self._load_indirect_segment(position, (offset, total), names)
            position += size

    def _load_indirect_segment(
        self, position: int, table: tuple[int, int], names: list[str]
    ) -> None:
        """Associate every declared section in one bounded segment."""
        sections = unpack_integers(self.data, "<I", position + 64)[0]
        for index in range(sections):
            self._load_indirect_section(
                position + SEGMENT_COMMAND_BYTES + SECTION_BYTES * index,
                table,
                names,
            )

    def _load_indirect_section(
        self, section: int, table: tuple[int, int], names: list[str]
    ) -> None:
        """Expand at most the declared indirect symbols into section slots.

        Raises:
            ValueError: Invalid section stride or indirect index.

        """
        address, length = unpack_integers(self.data, "<QQ", section + 32)
        flags, first, stride = unpack_integers(self.data, "<III", section + 64)
        kind = flags & 255
        if kind not in INDIRECT_SECTION_KINDS:
            return
        stride = stride if kind == STUB_KIND else 8
        if stride == 0 or length // stride > table[1] - first:
            message = "Mach-O indirect symbol index or stride exceeds table"
            raise ValueError(message)
        target = self.stubs if kind == STUB_KIND else self.binds
        for index in range(length // stride):
            symbol = unpack_integers(
                self.data, "<I", table[0] + 4 * (first + index)
            )[0]
            if symbol < len(names):
                target[address + index * stride] = names[symbol]

    def _load_dyld_binds(self, dyld: tuple[int, ...] | None) -> None:
        """Parse bounded dyld bind ranges, preserving their original order.

        Raises:
            ValueError: A binding range exceeds the inspected image.

        """
        if dyld is None:
            return
        for offset, size in ((dyld[2], dyld[3]), (dyld[6], dyld[7])):
            if size:
                if offset > len(self.data) or size > len(self.data) - offset:
                    message = "Mach-O dyld binding exceeds image bounds"
                    raise ValueError(message)
                self.parse_binds(self.data[offset : offset + size])

    @staticmethod
    def leb(
        data: bytes, position: int, *, signed: bool = False
    ) -> tuple[int, int]:
        """Decode a bounded unsigned/signed LEB128 value and next offset.

        Returns:
            The decoded value and position following its final byte.

        Raises:
            ValueError: The encoding is truncated or exceeds 64-bit limits.

        """
        value = shift = 0
        while True:
            if position >= len(data) or shift >= MAX_LEB_SHIFT:
                message = "Truncated or oversized Mach-O LEB128"
                raise ValueError(message)
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                return Image._checked_leb_value(
                    value, shift, signed=signed
                ), position

    @staticmethod
    def _checked_leb_value(value: int, shift: int, *, signed: bool) -> int:
        """Reject a terminal LEB integer exceeding the 64-bit word width.

        Returns:
            Signed or unsigned 64-bit decoded integer.

        Raises:
            ValueError: Signed/unsigned value cannot fit in 64 bits.

        """
        if signed and value & (1 << (shift - 1)):
            value -= 1 << shift
        valid = (
            (-(1 << 63) <= value < (1 << 63))
            if signed
            else (0 <= value < (1 << 64))
        )
        if not valid:
            message = "Mach-O LEB128 value exceeds 64-bit limits"
            raise ValueError(message)
        return value

    def parse_binds(self, data: bytes) -> None:
        """Decode bounded symbol bindings from the selected Mach-O image."""
        # Count visits rather than distinct keys: a malicious repeat can
        # overwrite the same address repeatedly without growing the map.
        cursor = _BindCursor(limit=len(self.data) // 8)
        while cursor.position < len(data):
            byte = data[cursor.position]
            cursor.position += 1
            if not self._bind_metadata_opcode(data, byte, cursor):
                self._bind_write_opcode(data, byte, cursor)

    def _bind_metadata_opcode(
        self, data: bytes, byte: int, cursor: _BindCursor
    ) -> bool:
        """Decode non-writing bind opcodes and update parser metadata.

        Returns:
            True when the opcode was a recognized non-write operation.

        """
        opcode, immediate = byte & 0xF0, byte & 15
        recognized = True
        if opcode in {0, 0x10, 0x30, 0x50}:
            pass
        elif opcode in {0x20, BIND_OPCODE_SLEB}:
            _, cursor.position = self.leb(
                data, cursor.position, signed=opcode == BIND_OPCODE_SLEB
            )
        elif opcode == BIND_OPCODE_SYMBOL:
            end = data.index(0, cursor.position)
            cursor.symbol = data[cursor.position : end].decode()
            cursor.position = end + 1
        elif opcode in {BIND_OPCODE_SEGMENT, BIND_OPCODE_OFFSET}:
            self._bind_address_opcode(data, opcode, immediate, cursor=cursor)
        else:
            recognized = False
        return recognized

    def _bind_address_opcode(
        self,
        data: bytes,
        opcode: int,
        immediate: int,
        *,
        cursor: _BindCursor,
    ) -> None:
        """Update the bounded segment-based binding address.

        Raises:
            ValueError: A segment ordinal does not exist in this image.

        """
        if opcode == BIND_OPCODE_SEGMENT:
            if immediate >= len(self.segments):
                message = "Mach-O bind segment ordinal out of bounds"
                raise ValueError(message)
            offset, cursor.position = self.leb(data, cursor.position)
            cursor.address = self.segments[immediate][1] + offset
        else:
            offset, cursor.position = self.leb(data, cursor.position)
            cursor.address += offset

    def _bind_write_opcode(
        self, data: bytes, byte: int, cursor: _BindCursor
    ) -> None:
        """Dispatch a bounded one-slot or repeated dyld bind instruction.

        Raises:
            ValueError: An unsupported opcode or pointer count overflow.

        """
        opcode = byte & 0xF0
        if opcode in {
            BIND_OPCODE_DIRECT,
            BIND_OPCODE_WITH_SKIP,
            BIND_OPCODE_WITH_IMMEDIATE,
        }:
            self._bind_one(data, opcode, byte & 15, cursor=cursor)
        elif opcode == BIND_OPCODE_REPEAT:
            self._bind_repeated(data, cursor)
        else:
            message = f"Unsupported bind opcode {byte:#x}"
            raise ValueError(message)

    def _bind_one(
        self, data: bytes, opcode: int, immediate: int, *, cursor: _BindCursor
    ) -> None:
        """Record one pointer write while charging the cumulative budget.

        Raises:
            ValueError: This bind program exhausted its pointer limit.

        """
        if cursor.visits >= cursor.limit:
            message = "Mach-O bind count exceeds image pointer slots"
            raise ValueError(message)
        cursor.visits += 1
        self.binds[cursor.address] = cursor.symbol
        if opcode == BIND_OPCODE_WITH_SKIP:
            skip, cursor.position = self.leb(data, cursor.position)
        elif opcode == BIND_OPCODE_WITH_IMMEDIATE:
            skip = immediate * 8
        else:
            skip = 0
        cursor.address += 8 + skip

    def _bind_repeated(self, data: bytes, cursor: _BindCursor) -> None:
        """Charge a repeated bind count before mutating the binding map.

        Raises:
            ValueError: The repeated bind exceeds the pointer-write budget.

        """
        count, cursor.position = self.leb(data, cursor.position)
        skip, cursor.position = self.leb(data, cursor.position)
        if count > cursor.limit - cursor.visits:
            message = "Mach-O bind count exceeds image pointer slots"
            raise ValueError(message)
        cursor.visits += count
        for _ in range(count):
            self.binds[cursor.address] = cursor.symbol
            cursor.address += 8 + skip

    def read(self, address: int, size: int) -> bytes:
        """Read a complete mapped virtual interval from bounded file bytes.

        Returns:
            The requested bytes; never a truncated mapping.

        Raises:
            ValueError: A negative, unmapped or truncated range.

        """
        if address < 0 or size < 0:
            message = "Negative Mach-O address or size"
            raise ValueError(message)
        for _, start, _, offset, length in self.segments:
            if start <= address and address + size <= start + length:
                location = offset + address - start
                if location < 0 or location + size > len(self.data):
                    message = "Truncated Mach-O mapping"
                    raise ValueError(message)
                return self.data[location : location + size]
        message = f"Unmapped range {address:#x}+{size:#x}"
        raise ValueError(message)

    def name(self, address: int) -> str:
        """Resolve a known symbol or a nearby address to a printable name.

        Returns:
            The resolved symbol or an empty string if none is known.

        """
        if address in self.binds:
            return self.binds[address]
        index = bisect.bisect_right(self.keys, address) - 1
        if index >= 0:
            start, name = self.addresses[index]
            if address - start < NEAR_SYMBOL_DISTANCE:
                return f"{name}+{address - start:#x}"
        return ""

    def _call_annotation(self, line: str) -> str:
        """Resolve one safe direct call or jump-site annotation.

        Returns:
            The known label, or empty if the site is not mapped.

        """
        match = re.search(r"(?:callq?|jmpq?)\s+(0x[0-9a-f]+)", line)
        if not match:
            return ""
        address = int(match[1], 16)
        try:
            raw = self.read(address, 6)
        except ValueError:
            return ""
        if address in self.stubs:
            label = self.stubs[address]
        elif raw[:2] == INDIRECT_JUMP_SIGNATURE:
            target = address + 6 + unpack_integers(raw, "<i", 2)[0]
            label = self.binds.get(target, self.name(target))
        else:
            label = self.name(address)
        return label

    def _cstring_annotation(self, line: str) -> str:
        """Resolve a known C-string pointer in a validated section.

        Returns:
            The decoded printable CString, or empty if not applicable.

        """
        match = re.search(r"## (0x[0-9a-f]+)", line)
        if not match:
            return ""
        address = int(match[1], 16)
        for _, name, start, size, _ in self.sections:
            if name == CSTRING_SECTION and start <= address < start + size:
                raw = self.read(address, min(256, start + size - address))
                return repr(raw.split(NULL_BYTE, 1)[0].decode(errors="replace"))
        return ""

    def annotate(self, line: str) -> str:
        """Annotate offline assembly using only validated image metadata.

        Returns:
            Original disassembly with recognized source labels.

        """
        labels = (self._call_annotation(line), self._cstring_annotation(line))
        suffix = " | ".join(label for label in labels if label)
        return line + (" ; " + suffix if suffix else "")

    def _require_original_image(self) -> None:
        """Require the offline disassembler input to match parsed source bytes.

        Raises:
            ValueError: The original bounded input changed since parsing.

        """
        observed = hashlib.sha256(read_macho_source(self.path)).hexdigest()
        if observed != self.source_sha256:
            message = "Mach-O disassembly source changed after inspection"
            raise ValueError(message)

    def disassemble(self, pattern: str) -> str:
        """Disassemble pinned symbols with an explicit argument vector.

        Returns:
            Annotated disassembly text from the installed xcrun objdump.

        Raises:
            ValueError: No symbols match or the source changed.
            FileNotFoundError: No xcrun installation was found.

        """
        names = [name for name in self.symbols if re.search(pattern, name)]
        if not names:
            message = "No matching symbols"
            raise ValueError(message)
        xcrun = shutil.which("xcrun")
        if xcrun is None:
            message = "xcrun is required for offline disassembly"
            raise FileNotFoundError(message)
        self._require_original_image()
        # Fixed argument vector without shell interpolation.
        output = subprocess.run(
            [
                xcrun,
                "llvm-objdump",
                "--arch=x86_64",
                "-d",
                "--no-show-raw-insn",
                "--disassemble-symbols=" + ",".join(names),
                str(self.path),
            ],
            check=True,
            shell=False,
            text=True,
            capture_output=True,
        ).stdout
        self._require_original_image()
        return "\n".join(self.annotate(line) for line in output.splitlines())


class _Arguments(argparse.Namespace):
    image: str = ""
    disassemble: str | None = None
    symbols: str | None = None
    read: str | None = None


def _print_symbols(image: Image, pattern: str) -> None:
    """Emit only symbol rows matching a selected CLI regular expression."""
    for address, name in image.addresses:
        if re.search(pattern, name):
            _ = sys.stdout.write(f"{address:016x} {name}\n")


def _print_read(image: Image, text: str) -> None:
    """Emit a bounded hex dump from one mapped Mach-O interval.

    Raises:
        ValueError: The given interval is malformed or unmapped.

    """
    parts = text.split(":")
    if len(parts) != READ_COMPONENTS:
        message = "Expected read range address:size"
        raise ValueError(message)
    address, size = (int(part, 0) for part in parts)
    data = image.read(address, size)
    for index in range(0, len(data), 16):
        part = data[index : index + 16]
        printable = "".join(
            chr(byte)
            if PRINTABLE_ASCII_START <= byte < PRINTABLE_ASCII_END
            else "."
            for byte in part
        )
        _ = sys.stdout.write(
            f"{address + index:016x} {part.hex(" "):47s} {printable}\n"
        )


def main() -> None:
    """Read one offline image and print a bounded diagnostic summary.

    Raises:
        ValueError: A missing image path or malformed byte range.

    """
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("image")
    _ = parser.add_argument("--disassemble")
    _ = parser.add_argument("--symbols")
    _ = parser.add_argument("--read")
    args = parser.parse_args(namespace=_Arguments())
    if not args.image:
        message = "Missing Mach-O image path"
        raise ValueError(message)
    image = Image(args.image)
    if args.disassemble:
        _ = sys.stdout.write(image.disassemble(args.disassemble) + "\n")
    elif args.symbols:
        _print_symbols(image, args.symbols)
    elif args.read:
        _print_read(image, args.read)
    else:
        _ = sys.stdout.write(
            f"UUID={image.uuid} SHA256={image.source_sha256}\n"
        )


if __name__ == "__main__":
    main()
