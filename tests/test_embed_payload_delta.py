# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Pure regressions against the native embedded-payload delta contract."""

import struct
from unittest import TestCase

from tools.embed_payload_codec import align
from tools.embed_payload_codec import checksum
from tools.embed_payload_codec import decode_payload_delta
from tools.embed_payload_codec import payload_delta

BASE = b"abcdefghij0123456789"
NATIVE_DELTA = struct.pack("<II", 0, 3) + b"XYZ"
FNV_ZERO = 14695981039346656037
MAX_U32 = 0xFFFFFFFF
DEFAULT_TARGET_SIZE = len(BASE)
MERGED_RECORD_COUNT = 2
EMPTY_DELTA = b""
ALIGN_SMALL = 8
ALIGN_LARGE = 16
FNV_A = 12638187200555641996


def _invalid(data: bytes, target_size: int = DEFAULT_TARGET_SIZE) -> bool:
    """Check malformed native records against an unchanged base.

    Returns:
        True when the supplied record fails closed.

    """
    try:
        _ = decode_payload_delta(BASE, data, target_size)
    except ValueError:
        return True
    return False


def _invalid_target(target: bytes) -> bool:
    """Check whether the encoder rejects an invalid target.

    Returns:
        True when encoding fails closed.

    """
    try:
        _ = payload_delta(BASE, target)
    except ValueError:
        return True
    return False


def _invalid_alignment(value: int, boundary: int) -> bool:
    """Check whether the alignment helper refuses invalid integers.

    Returns:
        True when the boundary or value is invalid.

    """
    try:
        _ = align(value, boundary)
    except ValueError:
        return True
    return False


class EmbedPayloadDeltaTests(TestCase):
    """Encoded deltas must agree with native src/Relocate.cpp validation."""

    @staticmethod
    def test_identical_target_produces_zero_records() -> None:
        """No edits are encoded when the bounded target is unchanged."""
        encoded, count = payload_delta(BASE, BASE)
        assert encoded == EMPTY_DELTA
        assert count == 0
        assert decode_payload_delta(BASE, encoded, len(BASE)) == BASE

    @staticmethod
    def test_spans_round_trip_and_coalesce_nearby_differences() -> None:
        """Merge eight-byte gaps but leave longer unchanged gaps untouched."""
        target = bytearray(BASE)
        target[0] = ord("X")
        target[9] = ord("Y")
        target[19] = ord("Z")
        encoded, count = payload_delta(BASE, target)
        assert count == MERGED_RECORD_COUNT
        assert decode_payload_delta(BASE, encoded, len(BASE)) == target
        assert encoded[:8] == struct.pack("<II", 0, 10)

    @staticmethod
    def test_truncated_target_and_native_vector() -> None:
        """A shorter target and real little-endian wire record round-trip."""
        target = b"XYZdef"
        encoded, count = payload_delta(BASE, target)
        assert count == 1
        assert encoded == NATIVE_DELTA
        assert decode_payload_delta(BASE, NATIVE_DELTA, len(target)) == target

    @staticmethod
    def test_missing_or_overflowing_headers_fail_closed() -> None:
        """Reject truncated headers, data and out-of-range lengths."""
        assert _invalid(b"\0")
        assert _invalid(struct.pack("<II", 1, 1))
        assert _invalid(struct.pack("<II", MAX_U32, 1) + b"x")
        assert _invalid(struct.pack("<II", 1, MAX_U32) + b"x")
        assert _invalid(struct.pack("<II", 0, 0))

    @staticmethod
    def test_overlaps_and_ill_ordered_records_fail_closed() -> None:
        """Reject overlapping, duplicate or descending replacement ranges."""
        prefix = struct.pack("<II", 2, 3) + b"XYZ"
        assert _invalid(prefix + struct.pack("<II", 4, 1) + b"X")
        assert _invalid(prefix + struct.pack("<II", 2, 1) + b"X")
        assert _invalid(prefix + struct.pack("<II", 0, 1) + b"X")

    @staticmethod
    def test_two_adjacent_records_and_trailing_header_preflight() -> None:
        """Accept disjoint adjacent spans and reject a malformed later one."""
        records = (
            struct.pack("<II", 1, 2) + b"XY" + struct.pack("<II", 3, 1) + b"Z"
        )
        expected = bytearray(BASE)
        expected[1:4] = b"XYZ"
        assert decode_payload_delta(BASE, records, len(BASE)) == expected
        assert _invalid(records + struct.pack("<II", len(BASE), 1) + b"X")
        assert _invalid(records + b"\x00")

    @staticmethod
    def test_out_of_bounds_target_and_alignment_fail_closed() -> None:
        """Never allocate beyond the uint32 native payload size contract."""
        assert _invalid_target(b"")
        assert _invalid_target(BASE + b"a")
        assert _invalid(NATIVE_DELTA, 0)
        assert _invalid(NATIVE_DELTA, len(BASE) + 1)
        for value, boundary in ((-1, 8), (MAX_U32, 4096), (1, 0), (1, 3)):
            assert _invalid_alignment(value, boundary)
        assert align(0) == 0
        assert align(1, ALIGN_SMALL) == ALIGN_SMALL
        assert align(ALIGN_LARGE, ALIGN_SMALL) == ALIGN_LARGE

    @staticmethod
    def test_checksum_matches_native_fnv1a() -> None:
        """Keep the 64-bit masked checksum compatible with native C++."""
        assert checksum(b"") == FNV_ZERO
        assert checksum(b"a") == FNV_A
        assert checksum(bytearray(b"a")) == checksum(b"a")
