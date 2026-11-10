# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Prove optimized Python cannot silently disable artifact integrity checks."""

import unittest

from tools.verification_runtime import require_assertions_active

ERROR = (
    "Native generation, build, and package checks require unoptimized Python"
)


def _rejects_optimization(level: int) -> bool:
    try:
        require_assertions_active(optimization_level=level)
    except RuntimeError as error:
        return ERROR in str(error)
    return False


class VerificationRuntimeTests(unittest.TestCase):
    """Assertions must remain enabled for checked native artifact operations."""

    @staticmethod
    def test_unoptimized_python_is_permitted() -> None:
        """Normal Python and explicit zero optimization preserve assertions."""
        require_assertions_active()
        require_assertions_active(optimization_level=0)

    @staticmethod
    def test_single_optimization_level_is_rejected() -> None:
        """Reject -O, which would delete the verification asserts."""
        assert _rejects_optimization(1)

    @staticmethod
    def test_double_optimization_level_is_rejected() -> None:
        """Reject -OO, which also strips required assertions."""
        assert _rejects_optimization(2)
