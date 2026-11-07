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

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
ATH9K = ROOT / "linux/drivers/net/wireless/ath/ath9k"
PINNED = {
    "ar9003_eeprom.c": (
        "9af461f68c73fdbe553619534f0474dca637a7c5191729251fa479af2ad75dc6"
    ),
    "ar9003_eeprom.h": (
        "4de071df42f0d91df022c91779f9bb7d0aac57fa7803f240530b4f0acd457bbd"
    ),
    "eeprom.h": (
        "b6bc5f1bffd56f5b8828d14635eac4846487ff6f2ef06344d474ac4c1c11b7b0"
    ),
}
OUTPUT = ROOT / "src/hardware/generated/Ar9300EepromTemplates.hpp"
TEMPLATES = (
    "ar9300_default",
    "ar9300_x112",
    "ar9300_h116",
    "ar9300_h112",
    "ar9300_x113",
)


def uncomment(text: str) -> str:
    """Remove comments from pinned ath9k source.

    Returns:
        Source text with block and line comments stripped.

    """
    return re.sub(
        r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    )


@dataclass(frozen=True)
class Layout:
    """A packed scalar, array, or struct layout with byte offsets."""

    size: int
    signed: bool = False
    fields: tuple[tuple[str, int, Layout], ...] = ()
    element: Layout | None = None
    count: int = 0


EXPECTED_EEPROM_SIZE = 1088


def _dimension_constants(header: str, eeprom_header: str) -> dict[str, int]:
    constants: dict[str, int] = {}
    for source in (header, eeprom_header):
        for found in re.finditer(
            r"^#define\s+(\w+)\s+(\d+)\s*$", source, re.MULTILINE
        ):
            name, number = found.group(1, 2)
            if name in constants and constants[name] != int(number):
                message = "Conflicting dimension constant: " + name
                raise ValueError(message)
            constants[name] = int(number)
    return constants


def _field_dimensions(
    initial: Layout, dimensions: str, constants: dict[str, int]
) -> Layout:
    layout = initial
    for match in reversed(list(re.finditer(r"\[(\w+)\]", dimensions))):
        dimension = match.group(1)
        count = (
            int(dimension) if dimension.isdecimal() else constants[dimension]
        )
        layout = Layout(layout.size * count, element=layout, count=count)
    return layout


def _packed_fields(
    body: str, types: dict[str, Layout], constants: dict[str, int]
) -> tuple[tuple[str, int, Layout], ...]:
    fields: list[tuple[str, int, Layout]] = []
    size = 0
    for declaration in body.split(";"):
        if not declaration.strip():
            continue
        match = re.fullmatch(
            r"\s*(?:struct\s+)?(\w+)\s+(\w+)\s*((?:\[\w+\])*)\s*",
            declaration,
        )
        if match is None:
            message = "Unsupported packed field: " + declaration
            raise ValueError(message)
        typename, field, dimensions = match.groups()
        layout = _field_dimensions(types[typename], dimensions, constants)
        if any(field == item[0] for item in fields):
            message = "Duplicate packed field: " + field
            raise ValueError(message)
        fields.append((field, size, layout))
        size += layout.size
    return tuple(fields)


def layouts(header: str, eeprom_header: str) -> Layout:
    """Read packed structs and decimal dimension constants from pinned files.

    Returns:
        The exact packed AR9300 EEPROM layout.

    Raises:
        ValueError: The grammar or layout is inconsistent.

    """
    constants = _dimension_constants(header, eeprom_header)
    types: dict[str, Layout] = {
        "u8": Layout(1),
        "int8_t": Layout(1, signed=True),
        "__le16": Layout(2),
        "__le32": Layout(4),
    }
    for match in re.finditer(
        r"struct\s+(\w+)\s*\{([^{}]*)\}\s*__packed;", header, re.DOTALL
    ):
        name, body = match.group(1, 2)
        fields = _packed_fields(body, types, constants)
        types[name] = Layout(
            sum(field_layout.size for _, _, field_layout in fields),
            fields=fields,
        )
    layout = types["ar9300_eeprom"]
    if layout.size != EXPECTED_EEPROM_SIZE:
        message = "Unexpected packed EEPROM size"
        raise ValueError(message)
    return layout


type InitValue = int | bytes | list[tuple[str | None, InitValue]]


OPEN_BRACE = "{"
CLOSE_BRACE = "}"
DESIGNATOR = "."
SEPARATOR = ","
BITWISE_OR = "|"
UNARY_MINUS = "-"
CONTROL_MACRO = "CTL"
FREQUENCY_MACRO = "FREQ2FBIN"
MACRO_ARGUMENT_PAIR = 2
EEPROM_FORMAT_VERSION = 2
FIXED_CONSTANTS = {
    "AR5416_OPFLAGS_11A": 1,
    "AR5416_OPFLAGS_11G": 2,
    "AR9300_EEPMISC_LITTLE_ENDIAN": 0,
    "AR9300_PWR_TABLE_OFFSET": 0,
}


def _apply_macro(name: str, args: list[int]) -> int:
    if name in {"LE16", "LE32"} and len(args) == 1:
        # Output serialization below explicitly uses little endian.
        value = args[0]
    elif name == CONTROL_MACRO and len(args) == MACRO_ARGUMENT_PAIR:
        value = args[0] | (args[1] << 6)
    elif (
        name == FREQUENCY_MACRO
        and len(args) == MACRO_ARGUMENT_PAIR
        and args[1] in {0, 1}
    ):
        value = args[0] - 2300 if args[1] else (args[0] - 4800) // 5
    else:
        message = "Unsupported initializer macro: " + name
        raise ValueError(message)
    return value


class Initializer:
    """Read the restricted initializer grammar used by pinned templates."""

    def __init__(self, text: str) -> None:
        """Tokenize the text and reject unsupported characters.

        Raises:
            ValueError: A token is not in the pinned initializer grammar.

        """
        token = re.compile(
            r'\s*("[A-Za-z0-9_-]*"|0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[{}(),.=|\-])'
        )
        self.tokens: list[str] = []
        position = 0
        while text[position:].strip():
            match = token.match(text, position)
            if not match:
                message = (
                    "Unsupported initializer token near "
                    + text[position : position + 40]
                )
                raise ValueError(message)
            self.tokens.append(match[1])
            position = match.end()
        self.position: int = 0

    def peek(self) -> str | None:
        """Return the next token, without consuming it, or None at EOF.

        Returns:
            The upcoming token, if present.

        """
        return (
            self.tokens[self.position]
            if self.position < len(self.tokens)
            else None
        )

    def take(self, expected: str | None = None) -> str:
        """Consume and return the expected token, rejecting end or mismatch.

        Returns:
            The consumed token.

        Raises:
            ValueError: The next token does not match the grammar.

        """
        value = self.peek()
        if value is None or (expected is not None and value != expected):
            message = f"Expected {expected}, got {value}"
            raise ValueError(message)
        self.position += 1
        return value

    def value(self) -> InitValue:
        """Read a scalar, ASCII byte string, or designated list initializer.

        Returns:
            A recursive initializer that serializer can validate by layout.

        """
        token = self.peek()
        if token is not None and token.startswith('"'):
            return self.take()[1:-1].encode("ascii")
        if token == OPEN_BRACE:
            return self._list()
        return self.expression()

    def _list(self) -> list[tuple[str | None, InitValue]]:
        _ = self.take(OPEN_BRACE)
        entries: list[tuple[str | None, InitValue]] = []
        while self.peek() != CLOSE_BRACE:
            field = None
            if self.peek() == DESIGNATOR:
                _ = self.take(DESIGNATOR)
                field = self.take()
                _ = self.take("=")
            entries.append((field, self.value()))
            if self.peek() != SEPARATOR:
                break
            _ = self.take(SEPARATOR)
        _ = self.take(CLOSE_BRACE)
        return entries

    def expression(self) -> int:
        """Read a bitwise OR of bounded integer/macro syntax.

        Returns:
            The parsed integral value, not yet narrowed to a C field width.

        """
        value = self.atom()
        while self.peek() == BITWISE_OR:
            _ = self.take(BITWISE_OR)
            value |= self.atom()
        return value

    def atom(self) -> int:
        """Read one signed literal, fixed identifier or allowed macro call.

        Returns:
            The parsed integer value.

        """
        name = self.take()
        if name == UNARY_MINUS:
            value = -self.atom()
        elif name[0].isdigit():
            value = int(name, 16 if name.lower().startswith("0x") else 10)
        elif name in FIXED_CONSTANTS:
            value = FIXED_CONSTANTS[name]
        else:
            value = self._macro(name)
        return value

    def _macro(self, name: str) -> int:
        _ = self.take("(")
        args = [self.expression()]
        while self.peek() == SEPARATOR:
            _ = self.take(SEPARATOR)
            args.append(self.expression())
        _ = self.take(")")
        return _apply_macro(name, args)


def _unwrap_array_string(value: InitValue) -> InitValue:
    if not isinstance(value, list) or len(value) != 1:
        return value
    field, item = value[0]
    if field is None and isinstance(item, bytes):
        return item
    return value


def _serialize_byte_string(
    layout: Layout,
    value: bytes,
    destination: bytearray,
    *,
    offset: int,
) -> None:
    element = layout.element
    if element is None:
        message = "Array element layout is missing"
        raise ValueError(message)
    if element.size != 1 or element.fields or len(value) > layout.count:
        message = "String initializer exceeds byte array"
        raise ValueError(message)
    # Omitted bytes, including the NUL terminator, remain zero.
    destination[offset : offset + len(value)] = value


def _serialize_array_members(
    layout: Layout,
    value: list[tuple[str | None, InitValue]],
    destination: bytearray,
    *,
    offset: int,
) -> None:
    element = layout.element
    if element is None:
        message = "Array element layout is missing"
        raise ValueError(message)
    if len(value) > layout.count:
        message = "Array initializer count/type mismatch"
        raise ValueError(message)
    for index, (field, item) in enumerate(value):
        if field is not None:
            message = "Array designator not supported"
            raise ValueError(message)
        serialize(
            element, item, destination, offset=offset + index * element.size
        )


def _serialize_array(
    layout: Layout, value: InitValue, destination: bytearray, *, offset: int
) -> None:
    element = layout.element
    if element is None:
        message = "Array element layout is missing"
        raise ValueError(message)
    value = _unwrap_array_string(value)
    if isinstance(value, bytes):
        _serialize_byte_string(layout, value, destination, offset=offset)
    elif isinstance(value, list):
        _serialize_array_members(layout, value, destination, offset=offset)
    else:
        message = "Array initializer count/type mismatch"
        raise ValueError(message)  # ruff: ignore[type-check-without-type-error] - Legacy initializer errors are ValueError.


def _field_index(
    layout: Layout,
    field: str | None,
    *,
    cursor: int,
    written: set[int],
) -> int:
    if field is not None:
        matches = [
            index
            for index, definition in enumerate(layout.fields)
            if definition[0] == field
        ]
        if len(matches) != 1:
            message = "Unknown structure field: " + field
            raise ValueError(message)
        cursor = matches[0]
    if cursor >= len(layout.fields) or cursor in written:
        message = "Duplicate/out-of-range structure initializer"
        raise ValueError(message)
    return cursor


def _serialize_struct(
    layout: Layout, value: InitValue, destination: bytearray, *, offset: int
) -> None:
    if not isinstance(value, list):
        message = "Structure initializer type mismatch"
        raise ValueError(message)  # ruff: ignore[type-check-without-type-error] - Legacy initializer errors are ValueError.
    cursor = 0
    written: set[int] = set()
    for field, item in value:
        cursor = _field_index(layout, field, cursor=cursor, written=written)
        written.add(cursor)
        _, relative, child = layout.fields[cursor]
        serialize(child, item, destination, offset=offset + relative)
        cursor += 1


def _serialize_scalar(
    layout: Layout, value: InitValue, destination: bytearray, *, offset: int
) -> None:
    if not isinstance(value, int):
        message = "Expected scalar initializer"
        raise ValueError(message)  # ruff: ignore[type-check-without-type-error] - Legacy initializer errors are ValueError.
    bits = layout.size * 8
    low = -(1 << (bits - 1)) if layout.signed else 0
    high = (1 << (bits - (1 if layout.signed else 0))) - 1
    if not low <= value <= high:
        message = "Scalar initializer outside declared field width"
        raise ValueError(message)
    destination[offset : offset + layout.size] = value.to_bytes(
        layout.size, "little", signed=layout.signed
    )


def _verify_destination_span(
    layout: Layout, destination: bytearray, offset: int
) -> None:
    """Require a complete, internally consistent span before mutating bytes.

    Raises:
        ValueError: The declared region or any child exceeds its parent.

    """
    invalid_offset = offset < 0 or offset > len(destination)
    if (
        invalid_offset
        or layout.size <= 0
        or layout.size > len(destination) - offset
    ):
        message = "Initializer exceeds destination bounds"
        raise ValueError(message)
    if layout.element is not None:
        invalid_element = layout.element.size <= 0 or layout.count <= 0
        if invalid_element or layout.size != layout.element.size * layout.count:
            message = "Inconsistent array initializer layout"
            raise ValueError(message)
    if any(
        relative < 0
        or child.size <= 0
        or relative > layout.size
        or child.size > layout.size - relative
        for _, relative, child in layout.fields
    ):
        message = "Structure initializer field exceeds parent layout"
        raise ValueError(message)


def serialize(
    layout: Layout,
    value: InitValue,
    destination: bytearray,
    *,
    offset: int = 0,
) -> None:
    """Serialize a restricted initializer to preallocated bytes.

    Invalid value/layout combinations fail with ValueError.
    """
    _verify_destination_span(layout, destination, offset)
    if layout.element is not None:
        _serialize_array(layout, value, destination, offset=offset)
    elif layout.fields:
        _serialize_struct(layout, value, destination, offset=offset)
    else:
        _serialize_scalar(layout, value, destination, offset=offset)


def _read_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for name, expected in PINNED.items():
        data = (ATH9K / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            message = "Pinned Linux source hash changed: " + name
            raise ValueError(message)
        sources[name] = data.decode()
    return sources


def _template_definitions(source: str) -> list[tuple[str, str]]:
    definitions = [
        (match.group(1), match.group(2))
        for match in re.finditer(
            r"static const struct ar9300_eeprom\s+(\w+)\s*=\s*(\{.*?\});",
            source,
            re.DOTALL,
        )
    ]
    if {name for name, _ in definitions} != set(TEMPLATES) or len(
        definitions
    ) != len(TEMPLATES):
        message = "Unexpected upstream template inventory"
        raise ValueError(message)
    return definitions


def _template_images(layout: Layout, source: str) -> dict[str, bytearray]:
    images: dict[str, bytearray] = {}
    ids: set[int] = set()
    for name, initializer in _template_definitions(source):
        reader = Initializer(initializer)
        values = reader.value()
        if reader.peek() is not None:
            message = "Unparsed initializer tokens"
            raise ValueError(message)
        image = bytearray(layout.size)  # Omitted C aggregate members are zero.
        serialize(layout, values, image)
        if image[0] != EEPROM_FORMAT_VERSION or image[1] in ids:
            message = "Unexpected EEPROM format or duplicate template ID"
            raise ValueError(message)
        ids.add(image[1])
        images[name] = image
    return images


def render_header(
    sources: dict[str, str], images: dict[str, bytearray]
) -> list[str]:
    """Render deterministic C++ lines entirely in memory.

    Returns:
        The complete generated C++ header as individual lines.

    """
    notice = sources["ar9003_eeprom.c"].split("*/", 1)[0] + "*/"
    notice = notice.replace(
        "/*\n",
        "/*\n * Copyright (c) 2008-2011 Atheros Communications Inc.\n",
        1,
    )
    lines = [
        "// Generated reconstruction dictionaries; NEVER use as board defaults."
    ]
    for name, digest in PINNED.items():
        lines.append(
            f"// linux/drivers/net/wireless/ath/ath9k/{name}: {digest}"
        )
    lines += [
        notice,
        "#ifndef SIMPLEATH_AR9300_EEPROM_TEMPLATES_HPP",
        "#define SIMPLEATH_AR9300_EEPROM_TEMPLATES_HPP",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "namespace simpleath { namespace eeprom_templates {",
        "struct Template { uint8_t id; const uint8_t *bytes; size_t length; };",
    ]
    for name in TEMPLATES:
        lines.extend(_template_lines(name, images[name]))
    lines.append("static const Template kCatalog[] = {")
    for name in TEMPLATES:
        lines.append(f"    {{{images[name][1]}, {name}, sizeof({name})}},")
    lines += [
        "};",
        "} } // namespace simpleath::eeprom_templates",
        "#endif",
        "",
    ]
    return lines


def _template_lines(name: str, image: bytearray) -> list[str]:
    lines = [
        f"// Template ID {image[1]}; reconstructed SHA-256 "
        + hashlib.sha256(image).hexdigest(),
        f"static const uint8_t {name}[] = {{",
    ]
    lines.extend(
        "    "
        + ", ".join(f"0x{byte:02x}" for byte in image[offset : offset + 16])
        + ","
        for offset in range(0, len(image), 16)
    )
    lines.append("};")
    return lines


def main() -> None:
    """Generate a pinned C++ header without compiling or running it."""
    sources = _read_sources()
    layout = layouts(
        uncomment(sources["ar9003_eeprom.h"]),
        uncomment(sources["eeprom.h"]),
    )
    images = _template_images(layout, uncomment(sources["ar9003_eeprom.c"]))
    lines = render_header(sources, images)
    _ = OUTPUT.write_text("\n".join(lines))
    description = f"{len(images)} pinned {layout.size}-byte templates: {OUTPUT}"
    _ = sys.stdout.write(f"Generated C++ source for {description}\n")
    notice = (
        "No C/C++ compiler, binary output, tests or hardware access performed."
    )
    _ = sys.stdout.write(f"{notice}\n")


if __name__ == "__main__":
    main()
