# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
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

    def test_refuses_non_macos_before_any_collection(self) -> None:
        """A Linux host test must never run diagnostic commands or sudo."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("os.execv") as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "macOS is required"):
                debug.require_macos_root(Path("/tmp/unused-debug.py"))
        execute.assert_not_called()

    def test_mandatory_sudo_preserves_spaces_and_arguments(self) -> None:
        """The root relaunch uses an argv vector instead of shell interpolation."""
        script = Path("/tmp/owner folder/SimpleATH-debug.py")
        args = [str(script), "--minutes", "25"]
        with (
            patch("platform.system", return_value="Darwin"),
            patch.object(sys, "argv", args),
            patch("os.geteuid", return_value=501),
            patch(
                "os.execv", side_effect=RuntimeError("intercepted")
            ) as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "intercepted"):
                debug.require_macos_root(script)
        execute.assert_called_once_with(
            "/usr/bin/sudo",
            ("sudo", "--", sys.executable, str(script), "--minutes", "25"),
        )

    def test_private_unique_logs_are_beside_script(self) -> None:
        """Collection ignores the caller's working directory and never overwrites."""
        with (
            TemporaryDirectory() as directory,
            patch.dict(os.environ, {"SUDO_UID": ""}),
        ):
            script = Path(directory) / "SimpleATH-debug.py"
            first, output = debug.open_report(script)
            with output:
                _ = output.write(b"first")
            second, output = debug.open_report(script)
            output.close()
            assert first.parent == script.parent
            assert first != second
            assert first.read_bytes() == b"first"
            assert stat.S_IMODE(first.stat().st_mode) == 0o600

    def test_nonzero_exit_is_not_labeled_pass(self) -> None:
        """Retain raw diagnostics and the child's real failure status."""
        output = io.BytesIO()
        report = debug.Report(output)
        probe = debug.Probe(
            "synthetic failure",
            (sys.executable, "-c", "print('fixture'); raise SystemExit(7)"),
        )
        debug.capture(probe, report, 5)
        assert b"fixture" in output.getvalue()
        assert b"exit=7" in output.getvalue()
        assert report.counts == {"command-failed": 1}

    def test_deadline_stops_only_owned_synthetic_child(self) -> None:
        """No live macOS service is involved in the timeout regression."""
        output = io.BytesIO()
        report = debug.Report(output)
        probe = debug.Probe(
            "synthetic timeout",
            (sys.executable, "-c", "import time; time.sleep(30)"),
        )
        debug.capture(probe, report, 0)
        assert report.counts == {"timeout": 1}

    def test_output_is_bounded_and_truncation_explicit(self) -> None:
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
        """Driver identity cannot accidentally read an unbounded special file."""
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

    def test_probe_plan_covers_all_three_project_goals(self) -> None:
        """Inventory is read-only and includes USB Bluetooth, AWDL and loaded kexts."""
        vectors = [
            p.argv for p in debug.system_probes() + debug.device_probes(30)
        ]
        assert ("/usr/bin/kmutil", "showloaded", "--list-only") in vectors
        assert ("/sbin/ifconfig", "awdl0") in vectors
        assert any("SPBluetoothDataType" in vector for vector in vectors)
        assert any("IOUSBHostDevice" in vector for vector in vectors)
        assert all(Path(vector[0]).is_absolute() for vector in vectors)
        assert not any(
            "install" in vector
            or "load" in vector
            or "-setairportpower" in vector
            for vector in vectors
        )
