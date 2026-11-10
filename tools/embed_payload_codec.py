# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Pure, bounded encoding for the native embedded-payload delta format.

Record layout matches the guarded decoder in src/Relocate.cpp: each record
is a little-endian uint32 offset, uint32 nonzero length and replacement bytes.
"""

import struct

UINT32_MAX = 0xFFFFFFFF
DEFAULT_ALIGNMENT = 4096
MAX_MERGE_GAP = 8
RECORD_HEADER_SIZE = 8
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211
UINT64_MASK = 0xFFFFFFFFFFFFFFFF


def align(value: int, alignment: int = DEFAULT_ALIGNMENT) -> int:
    """Align a uint32 payload size, rejecting invalid or overflowing inputs.

    Returns:
        The aligned native payload byte count.

    Raises:
        ValueError: The result cannot be represented by the native loader.

    """
    if value < 0 or value > UINT32_MAX:
        message = "Payload size must fit a nonnegative uint32"
        raise ValueError(message)
    if alignment <= 0 or alignment & (alignment - 1):
        message = "Payload alignment must be a positive power of two"
        raise ValueError(message)
    if alignment > UINT32_MAX:
        message = "Payload alignment exceeds uint32"
        raise ValueError(message)
    result = (value + alignment - 1) & -alignment
    if result > UINT32_MAX:
        message = "Aligned payload size exceeds uint32"
        raise ValueError(message)
    return result


def checksum(data: bytes | bytearray) -> int:
    """Compute the loader's 64-bit FNV-1a checksum without Python overflow.

    Returns:
        The native unsigned 64-bit checksum.

    """
    value = FNV_OFFSET
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & UINT64_MASK
    return value


def _validate_record(
    record: tuple[int, int], *, end: int, target_size: int, remaining: int
) -> None:
    """Validate a native record against its predecessors and remaining data.

    Raises:
        ValueError: The record is empty, overlapping or outside its payload.

    """
    offset, length = record
    if not length or offset < end or offset > target_size:
        message = "Invalid payload delta span or ordering"
        raise ValueError(message)
    if length > target_size - offset or length > remaining:
        message = "Payload delta record extends beyond its bounds"
        raise ValueError(message)


def _validate_records(encoded: bytes, target_size: int) -> None:
    """Complete the full wire-record preflight before modifying output.

    Raises:
        ValueError: A native record fails structural validation.

    """
    position = 0
    end = 0
    while position < len(encoded):
        if len(encoded) - position < RECORD_HEADER_SIZE:
            message = "Truncated payload delta header"
            raise ValueError(message)
        offset, length = struct.unpack_from("<II", encoded, position)
        position += RECORD_HEADER_SIZE
        _validate_record(
            (offset, length),
            end=end,
            target_size=target_size,
            remaining=len(encoded) - position,
        )
        end = offset + length
        position += length


def decode_payload_delta(
    base: bytes | bytearray, encoded: bytes, target_size: int
) -> bytes:
    """Decode strictly ordered, fully bounded native delta records.

    Validate all records before allocating or copying the output. The C++
    loader also performs this pass before modifying its mapped image.

    Returns:
        Independently reconstructed payload bytes.

    Raises:
        ValueError: A length, offset, ordering or record boundary is invalid.

    """
    if not 0 < target_size <= min(len(base), UINT32_MAX):
        message = "Payload target must be nonempty and fit the base"
        raise ValueError(message)
    if len(encoded) > UINT32_MAX:
        message = "Encoded payload delta exceeds uint32"
        raise ValueError(message)
    _validate_records(encoded, target_size)
    output = bytearray(base[:target_size])
    position = 0
    while position < len(encoded):
        offset, length = struct.unpack_from("<II", encoded, position)
        position += RECORD_HEADER_SIZE
        output[offset : offset + length] = encoded[position : position + length]
        position += length
    return bytes(output)


def _replacement_spans(
    base: bytes | bytearray, target: bytes | bytearray
) -> list[list[int]]:
    """Find disjoint changed regions while preserving nearby unchanged bytes.

    Returns:
        Ordered mutable start/end pairs for encoding.

    """
    ranges: list[list[int]] = []
    for offset, (before, after) in enumerate(zip(base, target, strict=False)):
        if before == after:
            continue
        if ranges and offset - ranges[-1][1] <= MAX_MERGE_GAP:
            ranges[-1][1] = offset + 1
        else:
            ranges.append([offset, offset + 1])
    return ranges


def payload_delta(
    base: bytes | bytearray, target: bytes | bytearray
) -> tuple[bytes, int]:
    """Encode modified spans, merging nearby changes without losing data.

    The result is compatible with the native two-pass decoder. Reject invalid
    sizes before iterating, and independently re-decode to check the result.

    Returns:
        Encoded replacement records and their count.

    Raises:
        ValueError: Empty, oversized or unreconstructable target.

    """
    if not 0 < len(target) <= min(len(base), UINT32_MAX):
        message = "Payload delta requires a bounded nonempty target"
        raise ValueError(message)
    ranges = _replacement_spans(base, target)
    encoded = b"".join(
        struct.pack("<II", start, end - start) + target[start:end]
        for start, end in ranges
    )
    if decode_payload_delta(base, encoded, len(target)) != target:
        message = "Payload delta does not reconstruct the target"
        raise ValueError(message)
    return encoded, len(ranges)
