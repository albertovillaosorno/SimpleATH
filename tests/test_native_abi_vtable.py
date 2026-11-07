# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic bounded vtable decoding with no external image or disassembler."""

import struct
from typing import TYPE_CHECKING
from typing import cast
from unittest import TestCase

if TYPE_CHECKING:
    from collections.abc import Callable

from tools import native_abi

CLASS_NAME = "IOSkywalkInterface"
VTABLE_SYMBOL = f"__ZTV{len(CLASS_NAME)}{CLASS_NAME}"
VTABLE_START = 0x1000
METHOD_ADDRESS = 0x2000
EXPECTED_FIRST = "_athMethodOne"
EXPECTED_SECOND = "_athMethodTwo"
MINIMUM_SLOTS = 1
REQUIRED_SLOTS = 3


class _FakeImage:
    """Tiny object exposing only vtable-reader ABI surface."""

    def __init__(self, slot_count: int, *, delta: int = 0) -> None:
        self.names: dict[str, tuple[str, int, int, int, int]] = {
            VTABLE_SYMBOL: (VTABLE_SYMBOL, 0, 1, 0, VTABLE_START)
        }
        self.syms: list[tuple[str, int, int, int, int]] = [
            self.names[VTABLE_SYMBOL],
            (
                "_afterVtable",
                0,
                1,
                0,
                VTABLE_START
                + native_abi.VTABLE_HEADER_BYTES
                + slot_count * native_abi.VTABLE_SLOT_BYTES
                + delta,
            ),
        ]
        self.reads: list[int] = []
        self.byaddr: dict[int, list[str]] = {
            METHOD_ADDRESS: [EXPECTED_FIRST],
            METHOD_ADDRESS + native_abi.VTABLE_SLOT_BYTES: [EXPECTED_SECOND],
        }
        self.raw_entries: dict[int, int] = {
            VTABLE_START + native_abi.VTABLE_HEADER_BYTES: METHOD_ADDRESS,
            VTABLE_START
            + native_abi.VTABLE_HEADER_BYTES
            + native_abi.VTABLE_SLOT_BYTES: METHOD_ADDRESS
            + native_abi.VTABLE_SLOT_BYTES,
        }
        self.relocation_reads: int = 0

    def relocs(self) -> dict[int, tuple[str, int, int, int]]:
        """Track relocation access; malformed spans must fail first.

        Returns:
            An empty relocation map for the fake file.

        """
        self.relocation_reads += 1
        return {}

    def read(self, address: int, size: int) -> bytes:
        """Provide one bounded 64-bit pointer from test-owned data.

        Returns:
            The encoded pointer (or zero if the slot is empty).

        Raises:
            ValueError: The test requested a non-pointer read.

        """
        if size != native_abi.VTABLE_SLOT_BYTES:
            message = "Unbounded fake vtable read"
            raise ValueError(message)
        self.reads.append(address)
        return struct.pack("<Q", self.raw_entries.get(address, 0))


def _invoke_table(image: _FakeImage) -> list[str]:
    """Exercise the legacy untyped reader against our strict fake interface.

    Returns:
        The decoded synthetic native ABI vtable method names.

    """
    reader = cast("Callable[[_FakeImage, str], list[str]]", native_abi.table)
    return reader(image, CLASS_NAME)


def _reject_vtable(image: _FakeImage) -> bool:
    try:
        _ = _invoke_table(image)
    except ValueError:
        return True
    return False


class NativeAbiVtableBoundsTests(TestCase):
    """Check valid vtable symbols and reject untrusted oversized gaps."""

    @staticmethod
    def test_bounded_vtable_keeps_nonempty_named_slots() -> None:
        """Decode two valid pointer names and stop on an empty third slot."""
        image = _FakeImage(REQUIRED_SLOTS)
        assert _invoke_table(image) == [
            EXPECTED_FIRST,
            EXPECTED_SECOND,
        ]
        assert len(image.reads) == REQUIRED_SLOTS
        assert image.relocation_reads == 1

    @staticmethod
    def test_too_many_slots_reject_before_any_read() -> None:
        """Reject an inflated symbol gap without walking pointer slots."""
        image = _FakeImage(native_abi.MAX_VTABLE_SLOTS + 1)
        assert _reject_vtable(image)
        assert image.relocation_reads == 0
        assert not image.reads

    @staticmethod
    def test_missing_short_or_unaligned_boundaries_reject() -> None:
        """Require a complete, aligned vtable with a closing symbol."""
        for count, delta in ((0, 0), (MINIMUM_SLOTS, 1)):
            image = _FakeImage(count, delta=delta)
            assert _reject_vtable(image)
            assert not image.reads
        no_end = _FakeImage(REQUIRED_SLOTS)
        del no_end.syms[1]
        assert _reject_vtable(no_end)
        assert not no_end.reads

    @staticmethod
    def test_unknown_vtable_target_rejects() -> None:
        """Keep a missing executable name from becoming a synthetic slot."""
        image = _FakeImage(REQUIRED_SLOTS)
        image.byaddr.clear()
        assert _reject_vtable(image)
        assert image.relocation_reads == 1
