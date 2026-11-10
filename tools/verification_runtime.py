# Copyright (c) 2026 SimpleATH contributors.
"""Prevent checked native artifacts from being emitted with stripped asserts."""

import sys


def require_assertions_active(*, optimization_level: int | None = None) -> None:
    """Refuse optimized Python where required integrity assertions vanish.

    Raises:
        RuntimeError: A caller could bypass required artifact checks.

    """
    level = (
        sys.flags.optimize if optimization_level is None else optimization_level
    )
    if level != 0:
        message = (
            "Native generation, build, and package checks require unoptimized "
            "Python; remove -O, -OO, or PYTHONOPTIMIZE"
        )
        raise RuntimeError(message)
