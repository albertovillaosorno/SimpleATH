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
#   - Offline regression cases for manual debug.
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
#   - Offline regression cases for manual debug.
# - Description:
#   - Implements or verifies the test_manual_debug source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for manual debug.
"""Offline manual-debug contracts; no macOS utility or physical device runs."""

from __future__ import annotations

import ast
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from tools.debug import simpleath_debug as debug


class ManualDebugTests(TestCase):
    """Verify privilege, placement, deadlines and truthful command outcomes."""

    @staticmethod
    def test_python39_syntax_remains_compatible() -> None:
        """The macOS helper needs no modern Python syntax from the dev host."""
        source = Path(debug.__file__).read_text(encoding="utf-8")
        _ = ast.parse(source, feature_version=(3, 9))

    @staticmethod
    def test_refuses_non_macos_before_any_collection() -> None:
        """A Linux host test must never run diagnostic commands or sudo."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("os.posix_spawn") as execute,
        ):
            message = ""
            try:
                debug.require_macos_root(Path("unused-debug.py"))
            except RuntimeError as error:
                message = str(error)
        expected_failure = "macOS is required"
        assert expected_failure in message
        execute.assert_not_called()

    @staticmethod
    def test_mandatory_sudo_preserves_spaces_and_arguments() -> None:
        """The sudo child uses argv and preserves the original arguments."""
        script = Path("owner folder") / "SimpleATH-debug.py"
        args = [str(script), "--minutes", "25"]
        with (
            patch("platform.system", return_value="Darwin"),
            patch.object(sys, "argv", args),
            patch("os.geteuid", return_value=501),
            patch("os.posix_spawn", return_value=4321) as execute,
            patch("os.waitpid", return_value=(4321, 0)),
        ):
            code = None
            try:
                debug.require_macos_root(script)
            except SystemExit as error:
                code = error.code
        assert code == 0
        execute.assert_called_once_with(
            debug.SUDO_PATH,
            ("sudo", "--", sys.executable, str(script), "--minutes", "25"),
            os.environ.copy(),
        )

    @staticmethod
    def test_private_unique_logs_are_beside_script() -> None:
        """Collection ignores the caller directory and never overwrites."""
        with (
            TemporaryDirectory() as directory,
            patch.dict(os.environ, {"SUDO_UID": ""}),
        ):
            script = Path(directory) / "SimpleATH-debug.py"
            first, output = debug.open_report(script)
            payload = b"first"
            with output:
                _ = output.write(payload)
            second, output = debug.open_report(script)
            output.close()
            assert first.parent == script.parent
            assert first != second
            assert first.read_bytes() == payload
            expected_permissions = 0o600
            assert stat.S_IMODE(first.stat().st_mode) == expected_permissions

    @staticmethod
    def test_nonzero_exit_is_not_labeled_pass() -> None:
        """Retain raw diagnostics and the child's real failure status."""
        output = io.BytesIO()
        report = debug.Report(output)
        probe = debug.Probe(
            "synthetic failure",
            (sys.executable, "-c", "print('fixture'); raise SystemExit(7)"),
        )
        debug.capture(probe, report, 5)
        expected_message = b"fixture"
        expected_code = b"exit=7"
        assert expected_message in output.getvalue()
        assert expected_code in output.getvalue()
        assert report.counts == {"command-failed": 1}

    @staticmethod
    def test_deadline_stops_only_owned_synthetic_child() -> None:
        """No live macOS service is involved in the timeout regression."""
        output = io.BytesIO()
        report = debug.Report(output)
        probe = debug.Probe(
            "synthetic timeout",
            (sys.executable, "-c", "import time; time.sleep(30)"),
        )
        debug.capture(probe, report, 0)
        assert report.counts == {"timeout": 1}

    @staticmethod
    def test_output_is_bounded_and_truncation_explicit() -> None:
        """A noisy diagnostic cannot fill the report silently."""
        output = io.BytesIO()
        report = debug.Report(output)
        probe = debug.Probe(
            "synthetic output", (sys.executable, "-c", "print('x' * 512)")
        )
        with patch.object(debug, "SECTION_LIMIT", 64):
            debug.capture(probe, report, 5)
        assert report.counts == {"truncated": 1}
        assert b"x" * 65 not in output.getvalue()

    @staticmethod
    def test_hash_rejects_symlink_and_nonregular_source() -> None:
        """Driver hashing refuses symlinks and nonregular special files."""
        payload = b"synthetic driver bytes"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "driver"
            _ = source.write_bytes(payload)
            assert (
                debug.hash_driver_file(source)
                == hashlib.sha256(payload).hexdigest()
            )
            alias = Path(directory) / "alias"
            alias.symlink_to(source)
            rejected = False
            try:
                _ = debug.hash_driver_file(alias)
            except OSError:
                rejected = True
            assert rejected

    @staticmethod
    def test_probe_plan_covers_all_three_project_goals() -> None:
        """Inventory covers USB Bluetooth, AWDL and loaded kexts."""
        vectors = [
            p.argv for p in debug.system_probes() + debug.device_probes(30)
        ]
        assert ("/usr/bin/kmutil", "showloaded", "--list-only") in vectors
        assert ("/sbin/ifconfig", "awdl0") in vectors
        bluetooth_profile = "SPBluetoothDataType"
        usb_device_class = "IOUSBHostDevice"
        assert any(bluetooth_profile in vector for vector in vectors)
        assert any(usb_device_class in vector for vector in vectors)
        assert all(Path(vector[0]).is_absolute() for vector in vectors)
        forbidden_arguments = ("install", "load", "-setairportpower")
        assert not any(
            argument in vector
            for vector in vectors
            for argument in forbidden_arguments
        )


class MergedCollectorTests(TestCase):
    """The single debug tool covers the former USB collector evidence."""

    @staticmethod
    def test_legacy_collector_nvram_whitelist_is_preserved() -> None:
        """Request only the approved boot/SIP/OpenCore keys, never nvram -p."""
        commands = [p.argv for p in debug.system_probes()]
        for key in debug.NVRAM_KEYS:
            assert ("/usr/sbin/nvram", key) in commands
        assert len(debug.NVRAM_KEYS) == 5
        assert ("/usr/sbin/nvram", "-p") not in commands

    @staticmethod
    def test_historical_kernel_and_boot_queries_are_bounded() -> None:
        """The merged collector keeps both short and historical log windows."""
        probes = debug.unified_log_probes(30)
        durations = [p.argv[p.argv.index("--last") + 1] for p in probes]
        assert durations == ["30m", "24h", "2h", "24h"]
        assert all(p.argv[0] == "/usr/bin/log" for p in probes)
        assert any("SimpleRTN" in p.argv[-1] for p in probes)
        assert any("Previous shutdown cause" in p.argv[-1] for p in probes)
        assert any(p.argv[-1] == 'process == "kernel"' for p in probes)
        assert not any("delete" in p.argv for p in probes)

    @staticmethod
    def test_merged_collector_executes_all_queries_once() -> None:
        """The report composes rather than launching a second script."""
        report = debug.Report(io.BytesIO())
        options = debug.Options()
        with (
            patch.object(debug, "system_probes", return_value=[]),
            patch.object(debug, "device_probes", return_value=[]),
            patch.object(debug, "driver_files"),
            patch.object(debug, "recent_reports"),
            patch.object(debug, "capture") as capture,
        ):
            debug.collect(report, options)
        assert capture.call_count == len(
            debug.unified_log_probes(options.minutes)
        )
        actual_titles = [call.args[0].title for call in capture.call_args_list]
        assert actual_titles == [
            probe.title for probe in debug.unified_log_probes(15)
        ]
