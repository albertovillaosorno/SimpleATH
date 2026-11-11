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
#   - Offline regression cases for verification runtime.
# - Must-Not:
#   - Require physical hardware, mutate installed drivers, or suppress failures.
# - Allows:
#   - Inputs: isolated fixtures and reproducible source-under-test inputs.
#   - Outputs: assertions and observable regression verdicts.
#   - Side effects: test-local temporary files and bounded subprocesses only.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Offline regression cases for verification runtime.
# - Description:
#   - Implements or verifies the test_verification_runtime source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for verification runtime.
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
