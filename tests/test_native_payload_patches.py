# Copyright (c) 2026 SimpleATH contributors.
"""Offline packet-call patch catalog checks with synthetic read callbacks."""

from pathlib import Path
import struct
import sys
from unittest import TestCase

# Retained legacy tool uses script-relative imports but never builds on import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from native_payload import PACKET_CALL_SITES
from native_payload import PATCH_INSTRUCTION_BYTES
from native_payload import PATCH_NATIVE_SLOT_DELTA
from native_payload import checked_packet_call_patches


def _read_patches(
    overrides: dict[int, bytes] | None = None,
) -> tuple[list[tuple[int, str]], dict[int, bytes]]:
    """Construct ordered fake function starts and source image instructions.

    Returns:
        Function names and the synthetic virtual-call encodings.

    """
    functions = [(address, prefix) for address, _, prefix in PACKET_CALL_SITES]
    patches = {
        address: b"\xff\x90" + struct.pack("<I", slot)
        for address, slot, _ in PACKET_CALL_SITES
    }
    patches.update(overrides or {})
    return functions, patches


def _check(
    functions: list[tuple[int, str]], patches: dict[int, bytes]
) -> list[tuple[int, int, int]]:
    """Run checked patch matching with in-memory byte streams.

    Returns:
        Accepted patch triples.

    """

    def read(address: int, length: int) -> bytes:
        assert length == PATCH_INSTRUCTION_BYTES
        return patches[address]

    return checked_packet_call_patches(functions, read)


EXPECTED_PATCH_COUNT = 7
MISSING_FUNCTION_MESSAGE = "Missing packet dispatch"
BAD_FUNCTION_ORDER_MESSAGE = "Unsorted or duplicate"
CROSS_FUNCTION_BOUNDARY_MESSAGE = "crosses function boundary"


def _failure(
    functions: list[tuple[int, str]], patches: dict[int, bytes]
) -> str:
    """Return a fail-closed parser diagnostic from a fake source image.

    Returns:
        Rejection text, or an empty string when no ValueError was raised.

    """
    try:
        _ = _check(functions, patches)
    except ValueError as error:
        return str(error)
    return ""


class NativePacketPatchContracts(TestCase):
    """No untrusted patch shape reaches native code generation."""

    @staticmethod
    def test_all_seven_real_layout_sites_have_three_fields() -> None:
        """Cover every pinned site, including the logTxPacket row."""
        functions, patches = _read_patches()
        expected = [
            (address + 2, slot, slot + PATCH_NATIVE_SLOT_DELTA)
            for address, slot, _ in PACKET_CALL_SITES
        ]
        assert len(PACKET_CALL_SITES) == EXPECTED_PATCH_COUNT
        assert _check(functions, patches) == expected

    def test_truncated_and_mismatched_instructions_rejected(self) -> None:
        """Refuse incomplete bytes or an unexpected encoded virtual slot."""
        address, slot, _ = PACKET_CALL_SITES[0]
        for raw, message in (
            (b"\xff\x90", "Unrecognized packet virtual call"),
            (b"\x90\x90" + struct.pack("<I", slot), "Unrecognized"),
            (b"\xff\x90" + struct.pack("<I", slot + 8), "slot mismatch"),
        ):
            with self.subTest(raw=raw):
                functions, patches = _read_patches({address: raw})
                assert message in _failure(functions, patches)

    @staticmethod
    def test_patches_cannot_cross_the_next_function_symbol() -> None:
        """Reject bytes that would overwrite the next function's prefix."""
        functions, patches = _read_patches()
        address, _, _ = PACKET_CALL_SITES[0]
        crossing = sorted([*functions, (address + 3, "_next_function")])
        assert CROSS_FUNCTION_BOUNDARY_MESSAGE in _failure(crossing, patches)
        # Adjacent symbols are valid only if the full instruction fits.
        adjacent = sorted([
            *functions,
            (address + PATCH_INSTRUCTION_BYTES, "_next_function"),
        ])
        assert _check(adjacent, patches) == _check(functions, patches)

    @staticmethod
    def test_missing_and_unsorted_function_addresses_rejected() -> None:
        """Never alias a preceding/final symbol for an unknown call site."""
        functions, patches = _read_patches()
        assert MISSING_FUNCTION_MESSAGE in _failure(functions[1:], patches)
        assert BAD_FUNCTION_ORDER_MESSAGE in _failure(
            list(reversed(functions)), patches
        )
        assert BAD_FUNCTION_ORDER_MESSAGE in _failure(
            functions + functions[-1:], patches
        )
