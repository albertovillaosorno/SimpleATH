# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
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
