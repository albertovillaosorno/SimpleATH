# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic Mach-O bind expansion limits; no native images or disassembly."""

from __future__ import annotations

from unittest import TestCase

from tools.macho import Image


class MachoBoundedStreamsTests(TestCase):
    """Check malicious repeat counts before any unbounded pointer visits."""

    @staticmethod
    def _image() -> Image:
        image = Image.__new__(Image)
        image.data = b"\0" * 64
        image.segments = [("__DATA", 0, 64, 0, 64)]
        image.binds = {}
        return image

    def test_bind_repeat_accepts_bounded_pointer_slots(self) -> None:
        """Accept two in-range pointer writes in synthetic image storage."""
        image = self._image()
        image.parse_binds(b"\x70\x00\xc0\x02\x00")
        assert image.binds == {0: "", 8: ""}

    def test_bind_rejects_out_of_range_segment_ordinal(self) -> None:
        """Reject an invalid segment selector without IndexError."""
        assert self._rejects(b"\x71\x00", "segment ordinal")

    def test_bind_repeat_rejects_huge_and_cumulative_counts(self) -> None:
        """Bound one huge LEB count and two cumulative repeats."""
        for stream in (
            b"\xc0" + b"\xff" * 9 + b"\x01\x00",
            b"\xc0\x07\x00\xc0\x02\x00",
        ):
            with self.subTest(stream=stream):
                assert self._rejects(stream, "bind count")

    def test_bind_single_opcode_visits_are_bounded(self) -> None:
        """Prevent separate writes from bypassing the cumulative limit."""
        assert self._rejects(b"\x90" * 9, "bind count")

    @staticmethod
    def _rejects(stream: bytes, fragment: str) -> bool:
        """Return whether parser raises the expected fail-closed error.

        Returns:
            True only for the required ValueError diagnostic.

        """
        image = MachoBoundedStreamsTests._image()
        try:
            image.parse_binds(stream)
        except ValueError as error:
            return fragment in str(error)
        return False
