# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Fail-closed native ABI invariants that remain active in optimized Python."""


def require(condition: object, invariant: str) -> None:
    """Require the literal bool True even when Python -O removes assertions.

    Raises:
        ValueError: The native ABI invariant is not satisfied.

    """
    if condition is not True:
        message = f"Native ABI verification failed: {invariant}"
        raise ValueError(message)
