# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - SimpleATH original; independently developed or locally authored
#
# Boundary-Contract:
# - Owns:
#   - Offline regression cases for ar9300 templates.
# - Must-Not:
#   - Require physical hardware, mutate installed drivers, or suppress failures.
# - Allows:
#   - Inputs: isolated fixtures and reproducible source-under-test inputs.
#   - Outputs: assertions and observable regression verdicts.
#   - Side effects: test-local temporary files and bounded subprocesses only.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Offline regression cases for ar9300 templates.
# - Description:
#   - Implements or verifies the test_ar9300_templates source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for ar9300 templates.
"""Synthetic template grammar and byte-width regressions, fully offline."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest import TestCase

from tools import generate_ar9300_templates as generator

if TYPE_CHECKING:
    from collections.abc import Callable


def _rejected(action: Callable[[], object]) -> bool:
    """Check that rejected synthetic parser inputs raise layout or value errors.

    Returns:
        True if the supplied parse/serialize operation was rejected.

    """
    try:
        _ = action()
    except KeyError, ValueError:
        return True
    return False


class Ar9300TemplateParserTests(TestCase):
    """Test pinned initializer syntax without files or generated output."""

    @staticmethod
    def test_comment_strip_and_packed_layout() -> None:
        """Recognize dimensions, packed fields, and expected total size."""
        source = (
            "#define LENGTH 1088\n"
            "struct ar9300_eeprom { u8 bytes[LENGTH]; } __packed;"
        )
        layout = generator.layouts(source, "")
        assert layout.size == generator.EXPECTED_EEPROM_SIZE
        expected_name = "bytes"
        assert layout.fields[0][0] == expected_name
        assert layout.fields[0][2].count == generator.EXPECTED_EEPROM_SIZE
        expected_comment_stripped = "u8 a; \nu8 b;"
        assert (
            generator.uncomment("/*x*/u8 a; //z\nu8 b;")
            == expected_comment_stripped
        )

    @staticmethod
    def test_invalid_layouts_fail_without_defaults() -> None:
        """Reject unknown layouts, duplicate members, and wrong image sizes."""
        for source in (
            "struct ar9300_eeprom { u8 bytes[2]; } __packed;",
            "struct ar9300_eeprom { bad bytes[1088]; } __packed;",
            ("struct ar9300_eeprom { u8 bytes[1087]; u8 bytes; } __packed;"),
        ):
            assert _rejected(
                lambda source=source: generator.layouts(source, "")
            )

    @staticmethod
    def test_designators_macros_and_le_serialization() -> None:
        """Serialize a compact synthetic initializer in little-endian order."""
        byte = generator.Layout(1)
        packed = generator.Layout(
            7,
            fields=(
                ("header", 0, generator.Layout(2)),
                ("label", 2, generator.Layout(4, element=byte, count=4)),
                ("tail", 6, generator.Layout(1, signed=True)),
            ),
        )
        reader = generator.Initializer(
            '{.header = LE16(0x1234), .label = {"AB"}, .tail = -1}'
        )
        payload = bytearray(packed.size)
        generator.serialize(packed, reader.value(), payload)
        assert reader.peek() is None
        assert payload == bytes.fromhex("341241420000ff")

    @staticmethod
    def test_frequency_and_ctl_macros() -> None:
        """Retain the original fixed C-macro translation semantics."""
        vectors = (
            ("CTL(2,3)", 194),
            ("FREQ2FBIN(2412,1)", 112),
            ("FREQ2FBIN(5180,0)", 76),
            ("AR5416_OPFLAGS_11A | AR5416_OPFLAGS_11G", 3),
        )
        for expression, expected in vectors:
            reader = generator.Initializer(expression)
            assert reader.value() == expected
            assert reader.peek() is None

    @staticmethod
    def test_reject_unsupported_grammar() -> None:
        """Reject missing braces, disallowed macros and invalid characters."""
        for expression in ("{.x = 1", "NOPE(1)", "@", "LE16()"):
            assert _rejected(
                lambda expression=expression: generator.Initializer(
                    expression
                ).value()
            )

    @staticmethod
    def test_reject_duplicate_and_out_of_range_fields() -> None:
        """Reject overwrite, scalar overflow, and incompatible value types."""
        one_byte = generator.Layout(1)
        packed = generator.Layout(1, fields=(("item", 0, one_byte),))
        cases: tuple[tuple[generator.Layout, generator.InitValue], ...] = (
            (packed, [("item", 1), ("item", 2)]),
            (packed, [("absent", 1)]),
            (one_byte, 256),
            (one_byte, -1),
            (one_byte, b"A"),
        )
        for layout, value in cases:
            assert _rejected(
                lambda layout=layout, value=value: generator.serialize(
                    layout, value, bytearray(layout.size)
                )
            )

    @staticmethod
    def test_reject_overlong_or_designated_arrays() -> None:
        """Reject byte strings exceeding capacity and array designators."""
        byte = generator.Layout(1)
        packed = generator.Layout(2, element=byte, count=2)
        designated: list[tuple[str | None, generator.InitValue]] = [("foo", 1)]
        too_many: list[tuple[str | None, generator.InitValue]] = [
            (None, 1) for _ in range(3)
        ]
        values: tuple[generator.InitValue, ...] = (b"ABC", designated, too_many)
        for value in values:
            assert _rejected(
                lambda value=value: generator.serialize(
                    packed, value, bytearray(packed.size)
                )
            )

    @staticmethod
    def test_serializer_refuses_out_of_destination_writes() -> None:
        """Malformed size/offset cannot extend or wrap an output bytearray."""
        for offset, size in ((0, 5), (-1, 1), (5, 1)):
            target = bytearray(b"ABCD")
            before = bytes(target)
            assert _rejected(
                lambda target=target, offset=offset, size=size: (
                    generator.serialize(
                        generator.Layout(size), 65, target, offset=offset
                    )
                )
            )
            assert target == before

    @staticmethod
    def test_serializer_rejects_invalid_nested_spans() -> None:
        """A malformed child declaration cannot write beyond its parent."""
        invalid_struct = generator.Layout(
            1, fields=(("bad", 0, generator.Layout(2)),)
        )
        invalid_array = generator.Layout(
            1, element=generator.Layout(1), count=2
        )
        cases: tuple[tuple[generator.Layout, generator.InitValue], ...] = (
            (invalid_struct, [("bad", 256)]),
            (invalid_array, [(None, 1), (None, 2)]),
        )
        for layout, value in cases:
            target = bytearray(b"ABCD")
            before = bytes(target)
            assert _rejected(
                lambda layout=layout, value=value, target=target: (
                    generator.serialize(layout, value, target)
                )
            )
            assert target == before

    @staticmethod
    def test_header_render_does_not_write_output() -> None:
        """Generate only in-memory C++ lines with deterministic inventory."""
        images = {
            name: bytearray((generator.EEPROM_FORMAT_VERSION, index))
            for index, name in enumerate(generator.TEMPLATES)
        }
        sources = {"ar9003_eeprom.c": "/*\n synthetic source notice\n */"}
        lines = generator.render_header(sources, images)
        assert not lines[-1]
        assert lines.count("static const Template kCatalog[] = {") == 1
        assert sum(
            line.startswith("static const uint8_t kAr9300") for line in lines
        ) == len(generator.TEMPLATES)
