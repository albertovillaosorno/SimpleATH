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
#   - Offline regression cases for native references cli.
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
#   - Offline regression cases for native references cli.
# - Description:
#   - Implements or verifies the test_native_references_cli source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native references cli.
"""Offline CLI dispatch regressions; never invoke real native exporting."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys
from unittest import TestCase
from unittest import mock

from tools import native_references as references
from tools.system_profiles import SYSTEMS

SYNTHETIC_BINARY = Path("/synthetic/native-image")


class NativeReferencesCliTests(TestCase):
    """Keep verification feedback and export paths stable without I/O."""

    @staticmethod
    def test_verify_reads_each_checked_profile_and_reports_it() -> None:
        """The default CLI action verifies all expected saved snapshots."""
        output = StringIO()
        with (
            mock.patch.object(sys, "argv", ["native_references.py", "verify"]),
            mock.patch.object(references, "load_reference") as load,
            mock.patch.object(references, "export_references") as export,
            redirect_stdout(output),
        ):
            references.main()

        assert load.call_args_list == [
            mock.call(references.DIRECTORY / (name + ".json"))
            for name in SYSTEMS
        ]
        export.assert_not_called()
        assert output.getvalue() == (
            "Native ABI references verified: " + ", ".join(SYSTEMS) + "\n"
        )

    @staticmethod
    def test_explicit_export_binary_is_forwarded_without_running_it() -> None:
        """Only the explicit export action selects its writing path."""
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "native_references.py",
                    "export",
                    "--binary",
                    str(SYNTHETIC_BINARY),
                ],
            ),
            mock.patch.object(references, "load_reference") as load,
            mock.patch.object(references, "export_references") as export,
            redirect_stdout(StringIO()),
        ):
            references.main()

        export.assert_called_once_with(SYNTHETIC_BINARY)
        assert load.call_count == len(SYSTEMS)
