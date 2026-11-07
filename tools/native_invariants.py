# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Fail-closed native ABI invariants that remain active in optimized Python."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
