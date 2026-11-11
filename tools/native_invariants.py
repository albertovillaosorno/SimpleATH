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
#   - Host-side tooling for native invariants.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for native invariants.
# - Description:
#   - Implements or verifies the native_invariants source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for native invariants.
"""Fail-closed native ABI invariants that remain active in optimized Python."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    import mmap
    from pathlib import Path

MAX_NATIVE_ARTIFACT_BYTES = 256 * 1024 * 1024


def require(condition: object, invariant: str) -> None:
    """Require the literal bool True even when Python -O removes assertions.

    Raises:
        ValueError: The native ABI invariant is not satisfied.

    """
    if condition is not True:
        message = f"Native ABI verification failed: {invariant}"
        raise ValueError(message)


def read_native_artifact(path: Path) -> bytes:
    """Read a bounded regular native artifact without following symlinks.

    Returns:
        The verified, unchanged source bytes.

    Raises:
        ValueError: A source is empty, nonregular, oversized or changed.

    Opening errors from the operating system propagate unchanged.

    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_NATIVE_ARTIFACT_BYTES
        ):
            message = "Native artifact must be a bounded regular file"
            raise ValueError(message)
        data = handle.read(MAX_NATIVE_ARTIFACT_BYTES + 1)
        after = os.fstat(handle.fileno())
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(data) != before.st_size or any(
        getattr(before, key) != getattr(after, key) for key in identity
    ):
        message = "Native artifact changed during verification"
        raise ValueError(message)
    return data


def _span_valid(start: int, size: int, limit: int) -> bool:
    """Check a nonnegative integer slice without overflowing its limit.

    Returns:
        True exactly when the complete slice is within the limit.

    """
    if start < 0 or size < 0:
        return False
    return start <= limit and size <= limit - start


def _verify_segment_spans(
    segments: Sequence[tuple[int, int, int]],
    *,
    source_size: int,
    target_size: int,
    base: int,
) -> None:
    """Preflight all embedded Mach-O file and virtual address spans.

    Raises:
        ValueError: Any segment refers outside a complete buffer.

    """
    for address, fileoff, length in segments:
        invalid_offset = fileoff < 0 or not _span_valid(
            base + fileoff, length, source_size
        )
        if invalid_offset or not _span_valid(address, length, target_size):
            message = "Embedded payload segment exceeds source or target"
            raise ValueError(message)


def reconstruct_payload_image(
    size: object,
    segments: Sequence[tuple[int, int, int]],
    source: bytes | mmap.mmap,
    *,
    base: int = 0,
) -> bytearray:
    """Reconstruct a bounded embedded image from checked Mach-O segments.

    Validate spans before allocating or writing, avoiding resized slices.

    Returns:
        Exact-length zero-filled payload with all validated segments copied.

    Raises:
        ValueError: Manifest length or any source/target span is invalid.

    """
    if type(size) is not int or not 0 < size <= MAX_NATIVE_ARTIFACT_BYTES:
        message = "Embedded payload size exceeds the supported limit"
        raise ValueError(message)
    if not _span_valid(base, 0, len(source)):
        message = "Embedded payload source base is outside the file"
        raise ValueError(message)
    _verify_segment_spans(
        segments, source_size=len(source), target_size=size, base=base
    )
    image = bytearray(size)
    for address, fileoff, length in segments:
        image[address : address + length] = source[
            base + fileoff : base + fileoff + length
        ]
    return image
