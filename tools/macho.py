#!/usr/bin/env python3
#
#  macho.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/6.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Read pinned Mach-O images for offline static ABI evidence only."""

import argparse
import bisect
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Fixed argv and explicit shell=False.

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
        """Read and validate the selected x86_64 Mach-O byte stream."""
        self.path: Path = Path(path)
        self.data: bytes = read_macho_source(self.path)
        if self.data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            if len(self.data) < 8:
                raise ValueError("Truncated Mach-O fat header")
            wide = self.data[3] == 0xBF
            count = unpack_integers(self.data, ">I", 4)[0]
            entry_size = 32 if wide else 20
            if count > (len(self.data) - 8) // entry_size:
                raise ValueError("Truncated Mach-O fat architecture table")
            for index in range(count):
                entry = 8 + index * entry_size
                cpu = unpack_integers(self.data, ">I", entry)[0]
                if cpu == 0x1000007:
                    offset, size = unpack_integers(
                        self.data, ">QQ" if wide else ">II", entry + 8
                    )
                    if (
                        not size
                        or offset > len(self.data)
                        or size > len(self.data) - offset
                    ):
                        raise ValueError("Invalid Mach-O fat slice bounds")
                    self.data = self.data[offset : offset + size]
                    break
            else:
                raise ValueError("No x86_64 slice")
        if len(self.data) < 32 or self.data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("Expected complete little-endian Mach-O 64 header")
        command_count, command_bytes = unpack_integers(self.data, "<II", 16)
        if (
            command_bytes > len(self.data) - 32
            or command_count > command_bytes // 8
        ):
            raise ValueError("Mach-O command area exceeds file bounds")
        self.segments: list[tuple[str, int, int, int, int]] = []
        self.sections: list[tuple[str, str, int, int, int]] = []
        self.symbols: dict[str, int] = {}
        self.binds: dict[int, str] = {}
        self.stubs: dict[int, str] = {}
        self.uuid: str | None = None
        self.addresses: list[tuple[int, str]] = []
        self.keys: list[int] = []
        symtab: tuple[int, ...] | None = None
        dysymtab: tuple[int, ...] | None = None
        dyld: tuple[int, ...] | None = None
        position = 32
        for _ in range(command_count):
            command, size = unpack_integers(self.data, "<II", position)
            if size < 8 or size > 32 + command_bytes - position:
                raise ValueError("Invalid Mach-O load command bounds")
            if command == 0x19:
                if size < 72:
                    raise ValueError("Truncated Mach-O segment command")
                fields = unpack_values(self.data, "<16sQQQQiiII", position + 8)
                name = byte_string(fields[0]).rstrip(b"\0").decode()
                address, length, offset, file_size = (
                    integer(value) for value in fields[1:5]
                )
                count = integer(fields[7])
                if count > (size - 72) // 80:
                    raise ValueError("Mach-O segment sections exceed command")
                self.segments.append((name, address, length, offset, file_size))
                for index in range(count):
                    section_fields = unpack_values(
                        self.data, "<16s16sQQI", position + 72 + 80 * index
                    )
                    sec = byte_string(section_fields[0]).rstrip(b"\0").decode()
                    seg = byte_string(section_fields[1]).rstrip(b"\0").decode()
                    self.sections.append((
                        seg,
                        sec,
                        integer(section_fields[2]),
                        integer(section_fields[3]),
                        integer(section_fields[4]),
                    ))
            elif command == 2:
                if size < 24:
                    raise ValueError("Truncated Mach-O symbol table command")
                symtab = unpack_integers(self.data, "<IIII", position + 8)
            elif command == 0xB:
                if size < 80:
                    raise ValueError("Truncated Mach-O dynamic symbol table")
                dysymtab = unpack_integers(self.data, "<18I", position + 8)
            elif command in (0x22, 0x80000022):
                if size < 48:
                    raise ValueError("Truncated Mach-O dyld metadata")
                dyld = unpack_integers(self.data, "<10I", position + 8)
            elif command == 0x1B:
                if size < 24:
                    raise ValueError("Truncated Mach-O UUID")
                self.uuid = self.data[position + 8 : position + 24].hex()
            position += size
        names: list[str] = []
        if symtab:
            offset, count, strings, strings_size = symtab
            if (
                offset > len(self.data)
                or count > (len(self.data) - offset) // 16
                or strings > len(self.data)
                or strings_size > len(self.data) - strings
            ):
                raise ValueError("Mach-O symbol table exceeds file bounds")
            for index in range(count):
                name, kind, _, _, address = unpack_integers(
                    self.data, "<IBBHQ", offset + 16 * index
                )
                if name >= strings_size:
                    raise ValueError("Mach-O symbol name outside string table")
                if name:
                    raw_name = self.data[
                        strings + name : strings + strings_size
                    ]
                    if b"\0" not in raw_name:
                        raise ValueError("Unterminated Mach-O symbol name")
                    text = raw_name.split(b"\0", 1)[0].decode(errors="replace")
                else:
                    text = ""
                names.append(text)
                if name and address > 1 and kind & 0xE == 0xE:
                    self.symbols[text] = address
        if dysymtab:
            indirect = dysymtab[12]
            position = 32
            if (
                indirect > len(self.data)
                or dysymtab[13] > (len(self.data) - indirect) // 4
            ):
                raise ValueError("Mach-O indirect symbols exceed file bounds")
            for _ in range(command_count):
                command, size = unpack_integers(self.data, "<II", position)
                if command == 0x19:
                    count = unpack_integers(self.data, "<I", position + 64)[0]
                    for index in range(count):
                        section = position + 72 + index * 80
                        address, length = unpack_integers(
                            self.data, "<QQ", section + 32
                        )
                        flags, first, stride = unpack_integers(
                            self.data, "<III", section + 64
                        )
                        kind = flags & 255
                        if kind not in (6, 7, 8):
                            continue
                        stride = stride if kind == 8 else 8
                        for item in range(length // stride):
                            if first + item >= dysymtab[13]:
                                raise ValueError(
                                    "Mach-O indirect symbol index exceeds table"
                                )
                            symbol = unpack_integers(
                                self.data, "<I", indirect + 4 * (first + item)
                            )[0]
                            if symbol < len(names):
                                (self.stubs if kind == 8 else self.binds)[
                                    address + item * stride
                                ] = names[symbol]
                position += size
        self.addresses = sorted(
            (address, name) for name, address in self.symbols.items()
        )
        self.keys = [entry[0] for entry in self.addresses]
        if dyld:
            for offset, size in [(dyld[2], dyld[3]), (dyld[6], dyld[7])]:
                if size:
                    if (
                        offset > len(self.data)
                        or size > len(self.data) - offset
                    ):
                        raise ValueError(
                            "Mach-O dyld binding exceeds image bounds"
                        )
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
            if position >= len(data) or shift >= 70:
                raise ValueError("Truncated or oversized Mach-O LEB128")
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                if signed and byte & 64:
                    value -= 1 << shift
                return value, position

    def parse_binds(self, data: bytes) -> None:
        """Decode bounded symbol bindings from the selected Mach-O image."""
        position = address = visits = 0
        # One image can hold only a bounded number of pointer-sized slots.
        # Count visits, not dictionary keys: a malicious repeat may overwrite
        # the same address millions of times without increasing len(binds).
        max_visits = len(self.data) // 8
        symbol = ""
        while position < len(data):
            byte = data[position]
            position += 1
            opcode, immediate = byte & 0xF0, byte & 15
            if opcode in (0, 0x10, 0x30, 0x50):
                continue
            if opcode in (0x20, 0x60):
                _, position = self.leb(data, position, signed=opcode == 0x60)
            elif opcode == 0x40:
                end = data.index(0, position)
                symbol = data[position:end].decode()
                position = end + 1
            elif opcode == 0x70:
                if immediate >= len(self.segments):
                    raise ValueError(
                        "Mach-O bind segment ordinal out of bounds"
                    )
                offset, position = self.leb(data, position)
                address = self.segments[immediate][1] + offset
            elif opcode == 0x80:
                offset, position = self.leb(data, position)
                address += offset
            elif opcode in (0x90, 0xA0, 0xB0):
                if visits >= max_visits:
                    raise ValueError(
                        "Mach-O bind count exceeds image pointer slots"
                    )
                visits += 1
                self.binds[address] = symbol
                if opcode == 0xA0:
                    skip, position = self.leb(data, position)
                else:
                    skip = immediate * 8 if opcode == 0xB0 else 0
                address += 8 + skip
            elif opcode == 0xC0:
                count, position = self.leb(data, position)
                skip, position = self.leb(data, position)
                if count > max_visits - visits:
                    raise ValueError(
                        "Mach-O bind count exceeds image pointer slots"
                    )
                visits += count
                for _ in range(count):
                    self.binds[address] = symbol
                    address += 8 + skip
            else:
                raise ValueError(f"Unsupported bind opcode {byte:#x}")

    def read(self, address: int, size: int) -> bytes:
        if address < 0 or size < 0:
            raise ValueError("Negative Mach-O address or size")
        for _, start, _, offset, length in self.segments:
            if start <= address and address + size <= start + length:
                location = offset + address - start
                if location < 0 or location + size > len(self.data):
                    raise ValueError("Truncated Mach-O mapping")
                return self.data[location : location + size]
        raise ValueError(f"Unmapped range {address:#x}+{size:#x}")

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
            if address - start < 0x10000:
                return f"{name}+{address - start:#x}"
        return ""

    def annotate(self, line: str) -> str:
        """Annotate offline assembly using only validated image metadata.

        Returns:
            Original disassembly with recognized source labels.

        """
        labels: list[str] = []
        match = re.search(r"(?:callq?|jmpq?)\s+(0x[0-9a-f]+)", line)
        if match:
            address = int(match[1], 16)
            try:
                raw = self.read(address, 6)
                if address in self.stubs:
                    labels.append(self.stubs[address])
                elif raw[:2] == b"\xff\x25":
                    target = address + 6 + unpack_integers(raw, "<i", 2)[0]
                    labels.append(self.binds.get(target, self.name(target)))
                else:
                    labels.append(self.name(address))
            except ValueError:
                pass
        match = re.search(r"## (0x[0-9a-f]+)", line)
        if match:
            address = int(match[1], 16)
            for _, name, start, size, _ in self.sections:
                if name == "__cstring" and start <= address < start + size:
                    labels.append(
                        repr(
                            self
                            .read(address, min(256, start + size - address))
                            .split(b"\0", 1)[0]
                            .decode(errors="replace")
                        )
                    )
        return line + (
            " ; " + " | ".join(label for label in labels if label)
            if any(labels)
            else ""
        )

    def disassemble(self, pattern: str) -> str:
        """Disassemble pinned symbols with an explicit argument vector.

        Returns:
            Annotated disassembly text from the installed xcrun objdump.

        """
        names = [name for name in self.symbols if re.search(pattern, name)]
        if not names:
            raise ValueError("No matching symbols")
        xcrun = shutil.which("xcrun")
        if xcrun is None:
            raise FileNotFoundError("xcrun is required for offline disassembly")
        output = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - Fixed argument vector without shell interpolation.
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
        return "\n".join(self.annotate(line) for line in output.splitlines())


class _Arguments(argparse.Namespace):
    image: str = ""
    disassemble: str | None = None
    symbols: str | None = None
    read: str | None = None


def main() -> None:
    """Read one offline image and print a bounded diagnostic summary."""
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("image")
    _ = parser.add_argument("--disassemble")
    _ = parser.add_argument("--symbols")
    _ = parser.add_argument("--read")
    args = parser.parse_args(namespace=_Arguments())
    image_path = args.image
    disassemble = args.disassemble
    symbols = args.symbols
    read = args.read
    if not image_path:
        raise ValueError("Missing Mach-O image path")
    image = Image(image_path)
    if disassemble:
        print(image.disassemble(disassemble))
    elif symbols:
        for address, name in image.addresses:
            if re.search(symbols, name):
                print(f"{address:016x} {name}")
    elif read:
        parts = read.split(":")
        if len(parts) != 2:
            raise ValueError("Expected read range address:size")
        address, size = (int(part, 0) for part in parts)
        data = image.read(address, size)
        for index in range(0, len(data), 16):
            part = data[index : index + 16]
            print(
                f"{address + index:016x} {part.hex(" "):47s} {"".join(chr(c) if 32 <= c < 127 else "." for c in part)}"
            )
    else:
        print(
            f"UUID={image.uuid} SHA256={hashlib.sha256(image.path.read_bytes()).hexdigest()}"
        )


if __name__ == "__main__":
    main()
