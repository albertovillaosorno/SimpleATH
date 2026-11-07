#!/usr/bin/env python3
#
#  macho.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/6.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import bisect
import hashlib
import re
import struct
import subprocess
from pathlib import Path


class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            wide = self.data[3] == 0xBF
            count = struct.unpack_from(">I", self.data, 4)[0]
            for index in range(count):
                entry = 8 + index * (32 if wide else 20)
                cpu = struct.unpack_from(">I", self.data, entry)[0]
                if cpu == 0x1000007:
                    offset, size = struct.unpack_from(">QQ" if wide else ">II", self.data, entry + 8)
                    self.data = self.data[offset:offset + size]
                    break
            else:
                raise ValueError("No x86_64 slice")
        if self.data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("Expected little-endian Mach-O 64")
        self.segments = []
        self.sections = []
        self.symbols = {}
        self.binds = {}
        self.stubs = {}
        self.uuid = None
        symtab = None
        dysymtab = None
        dyld = None
        position = 32
        for _ in range(struct.unpack_from("<I", self.data, 16)[0]):
            command, size = struct.unpack_from("<II", self.data, position)
            if command == 0x19:
                name, address, length, offset, file_size, _, _, count, _ = struct.unpack_from(
                    "<16sQQQQiiII", self.data, position + 8)
                self.segments.append((name.rstrip(b"\0").decode(), address, length, offset, file_size))
                for index in range(count):
                    sec, seg, addr, length, offset = struct.unpack_from(
                        "<16s16sQQI", self.data, position + 72 + 80 * index)
                    self.sections.append((seg.rstrip(b"\0").decode(), sec.rstrip(b"\0").decode(), addr, length, offset))
            elif command == 2:
                symtab = struct.unpack_from("<IIII", self.data, position + 8)
            elif command == 0xB:
                dysymtab = struct.unpack_from("<18I", self.data, position + 8)
            elif command in (0x22, 0x80000022):
                dyld = struct.unpack_from("<10I", self.data, position + 8)
            elif command == 0x1B:
                self.uuid = self.data[position + 8:position + 24].hex()
            position += size
        names = []
        if symtab:
            offset, count, strings, _ = symtab
            for index in range(count):
                name, kind, _, _, address = struct.unpack_from("<IBBHQ", self.data, offset + 16 * index)
                text = self.data[strings + name:].split(b"\0", 1)[0].decode(errors="replace") if name else ""
                names.append(text)
                if name and address > 1 and kind & 0xE == 0xE:
                    self.symbols[text] = address
        if dysymtab:
            indirect = dysymtab[12]
            position = 32
            for _ in range(struct.unpack_from("<I", self.data, 16)[0]):
                command, size = struct.unpack_from("<II", self.data, position)
                if command == 0x19:
                    count = struct.unpack_from("<I", self.data, position + 64)[0]
                    for index in range(count):
                        section = position + 72 + index * 80
                        address, length = struct.unpack_from("<QQ", self.data, section + 32)
                        flags, first, stride = struct.unpack_from("<III", self.data, section + 64)
                        kind = flags & 255
                        if kind not in (6, 7, 8):
                            continue
                        stride = stride if kind == 8 else 8
                        for item in range(length // stride):
                            symbol = struct.unpack_from("<I", self.data, indirect + 4 * (first + item))[0]
                            if symbol < len(names):
                                (self.stubs if kind == 8 else self.binds)[address + item * stride] = names[symbol]
                position += size
        self.addresses = sorted((address, name) for name, address in self.symbols.items())
        self.keys = [entry[0] for entry in self.addresses]
        if dyld:
            for offset, size in [(dyld[2], dyld[3]), (dyld[6], dyld[7])]:
                if size:
                    self.parse_binds(self.data[offset:offset + size])

    @staticmethod
    def leb(data, position, signed=False):
        value = shift = 0
        while True:
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                if signed and byte & 64:
                    value -= 1 << shift
                return value, position

    def parse_binds(self, data):
        position = address = 0
        symbol = ""
        while position < len(data):
            byte = data[position]
            position += 1
            opcode, immediate = byte & 0xF0, byte & 15
            if opcode in (0, 0x10, 0x30, 0x50):
                continue
            if opcode in (0x20, 0x60):
                _, position = self.leb(data, position, opcode == 0x60)
            elif opcode == 0x40:
                end = data.index(0, position)
                symbol = data[position:end].decode()
                position = end + 1
            elif opcode == 0x70:
                offset, position = self.leb(data, position)
                address = self.segments[immediate][1] + offset
            elif opcode == 0x80:
                offset, position = self.leb(data, position)
                address += offset
            elif opcode in (0x90, 0xA0, 0xB0):
                self.binds[address] = symbol
                if opcode == 0xA0:
                    skip, position = self.leb(data, position)
                else:
                    skip = immediate * 8 if opcode == 0xB0 else 0
                address += 8 + skip
            elif opcode == 0xC0:
                count, position = self.leb(data, position)
                skip, position = self.leb(data, position)
                for _ in range(count):
                    self.binds[address] = symbol
                    address += 8 + skip
            else:
                raise ValueError(f"Unsupported bind opcode {byte:#x}")

    def read(self, address, size):
        for _, start, _, offset, length in self.segments:
            if start <= address and address + size <= start + length:
                location = offset + address - start
                return self.data[location:location + size]
        raise ValueError(f"Unmapped range {address:#x}+{size:#x}")

    def name(self, address):
        if address in self.binds:
            return self.binds[address]
        index = bisect.bisect_right(self.keys, address) - 1
        if index >= 0:
            start, name = self.addresses[index]
            if address - start < 0x10000:
                return f"{name}+{address - start:#x}"
        return ""

    def annotate(self, line):
        labels = []
        match = re.search(r"(?:callq?|jmpq?)\s+(0x[0-9a-f]+)", line)
        if match:
            address = int(match[1], 16)
            try:
                raw = self.read(address, 6)
                if address in self.stubs:
                    labels.append(self.stubs[address])
                elif raw[:2] == b"\xff\x25":
                    target = address + 6 + struct.unpack_from("<i", raw, 2)[0]
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
                    labels.append(repr(self.read(address, min(256, start + size - address)).split(b"\0", 1)[0].decode(errors="replace")))
        return line + (" ; " + " | ".join(label for label in labels if label) if any(labels) else "")

    def disassemble(self, pattern):
        names = [name for name in self.symbols if re.search(pattern, name)]
        if not names:
            raise ValueError("No matching symbols")
        output = subprocess.run(["xcrun", "llvm-objdump", "--arch=x86_64", "-d", "--no-show-raw-insn",
                                 "--disassemble-symbols=" + ",".join(names), str(self.path)],
                                check=True, text=True, capture_output=True).stdout
        return "\n".join(self.annotate(line) for line in output.splitlines())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--disassemble")
    parser.add_argument("--symbols")
    parser.add_argument("--read")
    args = parser.parse_args()
    image = Image(args.image)
    if args.disassemble:
        print(image.disassemble(args.disassemble))
    elif args.symbols:
        for address, name in image.addresses:
            if re.search(args.symbols, name):
                print(f"{address:016x} {name}")
    elif args.read:
        address, size = (int(part, 0) for part in args.read.split(":"))
        data = image.read(address, size)
        for index in range(0, len(data), 16):
            part = data[index:index + 16]
            print(f"{address + index:016x} {part.hex(' '):47s} {''.join(chr(c) if 32 <= c < 127 else '.' for c in part)}")
    else:
        print(f"UUID={image.uuid} SHA256={hashlib.sha256(image.path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
