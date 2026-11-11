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
#   - Host-side tooling for verification runtime.
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
#   - Host-side tooling for verification runtime.
# - Description:
#   - Implements or verifies the verification_runtime source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for verification runtime.
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
