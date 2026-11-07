#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate C++ source arrays from pinned permissive ath9k EEPROM templates.

This restricted initializer reader does not compile/execute C, create binary
files or run tests. Unknown grammar, macros, fields or input hashes fail closed.
The templates are reconstruction dictionaries, never board/calibration defaults.
"""

# Linux macro semantics used during serialization retain their notice:
# Copyright (c) 2008-2011 Atheros Communications Inc.
# Copyright (c) 2010-2011 Atheros Communications Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ATH9K = ROOT / "linux/drivers/net/wireless/ath/ath9k"
PINNED = {
    "ar9003_eeprom.c": "9af461f68c73fdbe553619534f0474dca637a7c5191729251fa479af2ad75dc6",
    "ar9003_eeprom.h": "4de071df42f0d91df022c91779f9bb7d0aac57fa7803f240530b4f0acd457bbd",
    "eeprom.h": "b6bc5f1bffd56f5b8828d14635eac4846487ff6f2ef06344d474ac4c1c11b7b0",
}
OUTPUT = ROOT / "src/hardware/generated/Ar9300EepromTemplates.hpp"
TEMPLATES = ("ar9300_default", "ar9300_x112", "ar9300_h116", "ar9300_h112", "ar9300_x113")


def uncomment(text):
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


@dataclass(frozen=True)
class Layout:
    size: int
    signed: bool = False
    fields: tuple = ()
    element: object = None
    count: int = 0


def layouts(header, eeprom_header):
    """Read only packed structs and decimal dimension constants in these files."""
    constants = {}
    for source in (header, eeprom_header):
        for name, number in re.findall(r"^#define\s+(\w+)\s+(\d+)\s*$", source, re.M):
            if name in constants and constants[name] != int(number):
                raise ValueError("Conflicting dimension constant: " + name)
            constants[name] = int(number)
    types = {"u8": Layout(1), "int8_t": Layout(1, signed=True),
             "__le16": Layout(2), "__le32": Layout(4)}
    for name, body in re.findall(r"struct\s+(\w+)\s*\{([^{}]*)\}\s*__packed;", header, re.S):
        fields = []
        size = 0
        for declaration in body.split(";"):
            if not declaration.strip():
                continue
            match = re.fullmatch(r"\s*(?:struct\s+)?(\w+)\s+(\w+)\s*((?:\[\w+\])*)\s*",
                                 declaration)
            if not match:
                raise ValueError("Unsupported packed field: " + declaration)
            typename, field, dimensions = match.groups()
            layout = types[typename]
            for dimension in reversed(re.findall(r"\[(\w+)\]", dimensions)):
                count = int(dimension) if dimension.isdecimal() else constants[dimension]
                layout = Layout(layout.size * count, element=layout, count=count)
            if any(field == item[0] for item in fields):
                raise ValueError("Duplicate packed field: " + field)
            fields.append((field, size, layout))
            size += layout.size
        types[name] = Layout(size, fields=tuple(fields))
    if types["ar9300_eeprom"].size != 1088:
        raise ValueError("Unexpected packed EEPROM size")
    return types["ar9300_eeprom"]


class Initializer:
    """Subset used by the pinned template initializers: lists, fields, OR, calls."""

    def __init__(self, text):
        token = re.compile(r'\s*("[A-Za-z0-9_-]*"|0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[{}(),.=|\-])')
        self.tokens = []
        position = 0
        while text[position:].strip():
            match = token.match(text, position)
            if not match:
                raise ValueError("Unsupported initializer token near " + text[position:position + 40])
            self.tokens.append(match[1])
            position = match.end()
        self.position = 0

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self, expected=None):
        value = self.peek()
        if value is None or (expected is not None and value != expected):
            raise ValueError(f"Expected {expected}, got {value}")
        self.position += 1
        return value

    def value(self):
        if self.peek() is not None and self.peek().startswith('"'):
            return self.take()[1:-1].encode("ascii")
        if self.peek() != "{":
            return self.expression()
        self.take("{")
        entries = []
        while self.peek() != "}":
            field = None
            if self.peek() == ".":
                self.take(".")
                field = self.take()
                self.take("=")
            entries.append((field, self.value()))
            if self.peek() != ",":
                break
            self.take(",")
        self.take("}")
        return entries

    def expression(self):
        value = self.atom()
        while self.peek() == "|":
            self.take("|")
            value |= self.atom()
        return value

    def atom(self):
        name = self.take()
        if name == "-":
            return -self.atom()
        if name[0].isdigit():
            return int(name, 16 if name.lower().startswith("0x") else 10)
        constants = {"AR5416_OPFLAGS_11A": 1, "AR5416_OPFLAGS_11G": 2,
                     "AR9300_EEPMISC_LITTLE_ENDIAN": 0, "AR9300_PWR_TABLE_OFFSET": 0}
        if name in constants:
            return constants[name]
        self.take("(")
        args = [self.expression()]
        while self.peek() == ",":
            self.take(",")
            args.append(self.expression())
        self.take(")")
        if name in ("LE16", "LE32") and len(args) == 1:
            # Output serialization below explicitly uses little endian.
            return args[0]
        if name == "CTL" and len(args) == 2:
            return args[0] | (args[1] << 6)
        if name == "FREQ2FBIN" and len(args) == 2 and args[1] in (0, 1):
            return args[0] - 2300 if args[1] else (args[0] - 4800) // 5
        raise ValueError("Unsupported initializer macro: " + name)


def serialize(layout, value, destination, offset=0):
    if layout.element is not None:
        if (isinstance(value, list) and len(value) == 1 and value[0][0] is None
                and isinstance(value[0][1], bytes)):
            value = value[0][1]
        if isinstance(value, bytes):
            if layout.element.size != 1 or layout.element.fields or len(value) > layout.count:
                raise ValueError("String initializer exceeds byte array")
            destination[offset:offset + len(value)] = value
            return  # Omitted bytes, including the NUL terminator, remain zero.
        if not isinstance(value, list) or len(value) > layout.count:
            raise ValueError("Array initializer count/type mismatch")
        for index, (field, item) in enumerate(value):
            if field is not None:
                raise ValueError("Array designator not supported")
            serialize(layout.element, item, destination, offset + index * layout.element.size)
    elif layout.fields:
        if not isinstance(value, list):
            raise ValueError("Structure initializer type mismatch")
        cursor = 0
        written = set()
        for field, item in value:
            if field is not None:
                matches = [i for i, definition in enumerate(layout.fields) if definition[0] == field]
                if len(matches) != 1:
                    raise ValueError("Unknown structure field: " + field)
                cursor = matches[0]
            if cursor >= len(layout.fields) or cursor in written:
                raise ValueError("Duplicate/out-of-range structure initializer")
            written.add(cursor)
            _, relative, child = layout.fields[cursor]
            serialize(child, item, destination, offset + relative)
            cursor += 1
    else:
        if not isinstance(value, int):
            raise ValueError("Expected scalar initializer")
        bits = layout.size * 8
        low = -(1 << (bits - 1)) if layout.signed else 0
        high = (1 << (bits - (1 if layout.signed else 0))) - 1
        if not low <= value <= high:
            raise ValueError("Scalar initializer outside declared field width")
        destination[offset:offset + layout.size] = value.to_bytes(
            layout.size, "little", signed=layout.signed)


def main():
    sources = {}
    for name, expected in PINNED.items():
        data = (ATH9K / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Pinned Linux source hash changed: " + name)
        sources[name] = data.decode()
    header = uncomment(sources["ar9003_eeprom.h"])
    layout = layouts(header, uncomment(sources["eeprom.h"]))
    source = uncomment(sources["ar9003_eeprom.c"])
    definitions = re.findall(r"static const struct ar9300_eeprom\s+(\w+)\s*=\s*(\{.*?\});",
                             source, re.S)
    if {name for name, _ in definitions} != set(TEMPLATES) or len(definitions) != len(TEMPLATES):
        raise ValueError("Unexpected upstream template inventory")
    images = {}
    ids = set()
    for name, initializer in definitions:
        reader = Initializer(initializer)
        values = reader.value()
        if reader.peek() is not None:
            raise ValueError("Unparsed initializer tokens")
        image = bytearray(layout.size)  # C's omitted aggregate members are zero.
        serialize(layout, values, image)
        if image[0] != 2 or image[1] in ids:
            raise ValueError("Unexpected EEPROM format or duplicate template ID")
        ids.add(image[1])
        images[name] = image
    notice = sources["ar9003_eeprom.c"].split("*/", 1)[0] + "*/"
    notice = notice.replace("/*\n", "/*\n * Copyright (c) 2008-2011 Atheros Communications Inc.\n", 1)
    lines = ["// Generated reconstruction dictionaries; NEVER use as board defaults."]
    for name, digest in PINNED.items():
        lines.append(f"// linux/drivers/net/wireless/ath/ath9k/{name}: {digest}")
    lines += [notice, "#ifndef SIMPLEATH_AR9300_EEPROM_TEMPLATES_HPP",
              "#define SIMPLEATH_AR9300_EEPROM_TEMPLATES_HPP", "#include <stdint.h>",
              "#include <stddef.h>", "namespace simpleath { namespace eeprom_templates {",
              "struct Template { uint8_t id; const uint8_t *bytes; size_t length; };"]
    for name in TEMPLATES:
        image = images[name]
        lines += [f"// Template ID {image[1]}; reconstructed SHA-256 {hashlib.sha256(image).hexdigest()}",
                  f"static const uint8_t {name}[] = {{"]
        for offset in range(0, len(image), 16):
            lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in image[offset:offset + 16]) + ",")
        lines.append("};")
    lines.append("static const Template kCatalog[] = {")
    for name in TEMPLATES:
        lines.append(f"    {{{images[name][1]}, {name}, sizeof({name})}},")
    lines += ["};", "} } // namespace simpleath::eeprom_templates", "#endif", ""]
    OUTPUT.write_text("\n".join(lines))
    print(f"Generated C++ source for {len(images)} pinned {layout.size}-byte templates: {OUTPUT}")
    print("No C/C++ compiler, binary output, tests or hardware access performed.")


if __name__ == "__main__":
    main()
