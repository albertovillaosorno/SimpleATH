# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Read bounded Mach-O symbol and load-command records for offline embeds."""

from __future__ import annotations

from typing import Protocol

if __package__:
    from tools.abi_types import unpack_integers
else:
    from abi_types import unpack_integers

MACH_HEADER_SIZE = 32
LOAD_COMMAND_SIZE = 8
SYMTAB_COMMAND_SIZE = 24
SYMBOL_SIZE = 16
SYMTAB_COMMAND = 2
MACHO_MAGIC = b"\xcf\xfa\xed\xfe"
X86_64_CPU = 0x1000007

type LoadCommand = tuple[int, bytearray]
type ParsedSymbol = tuple[str, int, int, int, int]


class _ImageData(Protocol):
    """Read-only image data from an inspected Mach-O file or fake fixture."""

    @property
    def data(self) -> bytes: ...


def _command_header(data: bytes) -> tuple[int, int]:
    if len(data) < MACH_HEADER_SIZE or data[:4] != MACHO_MAGIC:
        message = "Expected complete little-endian Mach-O 64 header"
        raise ValueError(message)
    if unpack_integers(data, "<I", 4)[0] != X86_64_CPU:
        message = "Expected x86_64 Mach-O image"
        raise ValueError(message)
    count, total_size = unpack_integers(data, "<II", 16)
    if (
        total_size > len(data) - MACH_HEADER_SIZE
        or count > total_size // LOAD_COMMAND_SIZE
    ):
        message = "Mach-O load commands exceed file bounds"
        raise ValueError(message)
    return count, MACH_HEADER_SIZE + total_size


def _commands(data: bytes) -> list[LoadCommand]:
    count, limit = _command_header(data)
    position = MACH_HEADER_SIZE
    result: list[LoadCommand] = []
    for _ in range(count):
        command, size = unpack_integers(data, "<II", position)
        if (
            size < LOAD_COMMAND_SIZE
            or size % LOAD_COMMAND_SIZE != 0
            or size > limit - position
        ):
            message = "Invalid Mach-O load-command length"
            raise ValueError(message)
        result.append((command, bytearray(data[position : position + size])))
        position += size
    if position != limit:
        message = "Mach-O load-command sizes do not match header"
        raise ValueError(message)
    return result


def _symbol_layout(
    commands: list[LoadCommand], data: bytes
) -> tuple[int, int, int, int]:
    tables = [
        record for command, record in commands if command == SYMTAB_COMMAND
    ]
    if len(tables) != 1 or len(tables[0]) < SYMTAB_COMMAND_SIZE:
        message = "Expected one complete Mach-O symbol table command"
        raise ValueError(message)
    offset, count, strings, length = unpack_integers(bytes(tables[0]), "<4I", 8)
    if offset > len(data) or count > (len(data) - offset) // SYMBOL_SIZE:
        message = "Mach-O symbol table exceeds file bounds"
        raise ValueError(message)
    if strings > len(data) or length > len(data) - strings:
        message = "Mach-O string table exceeds file bounds"
        raise ValueError(message)
    return offset, count, strings, length


def _symbol_name(data: bytes, address: int, limit: int) -> str:
    end = data.find(b"\0", address, limit)
    if end < 0:
        message = "Unterminated Mach-O symbol name"
        raise ValueError(message)
    return data[address:end].decode()


def _symbol_entry(
    data: bytes, address: int, strings: tuple[int, int]
) -> ParsedSymbol:
    name_offset, kind, section, desc, value = unpack_integers(
        data, "<IBBHQ", address
    )
    start, limit = strings
    if name_offset >= limit - start:
        message = "Mach-O symbol name outside string table"
        raise ValueError(message)
    return (
        _symbol_name(data, start + name_offset, limit),
        kind,
        section,
        desc,
        value,
    )


def _symbols(
    data: bytes, layout: tuple[int, int, int, int]
) -> list[ParsedSymbol]:
    offset, count, strings, length = layout
    return [
        _symbol_entry(
            data, offset + index * SYMBOL_SIZE, (strings, strings + length)
        )
        for index in range(count)
    ]


def parse(image: _ImageData) -> tuple[list[LoadCommand], list[ParsedSymbol]]:
    """Extract checked load commands and full symbol entries without execution.

    Returns:
        Mutable command copies and symbol tuples as used by embed and build.

    """
    commands = _commands(image.data)
    return commands, _symbols(image.data, _symbol_layout(commands, image.data))
