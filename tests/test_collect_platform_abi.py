# Copyright (c) 2026 Alberto Villa Osorno.
"""Offline synthetic ABI collector boundaries; never read the host OS."""

import hashlib
from io import StringIO
from pathlib import Path
import plistlib
import sys
import tempfile
from typing import TYPE_CHECKING
from unittest import TestCase
from unittest import mock

from tools import collect_platform_abi as collector

UNAVAILABLE = "unavailable"
COPIED = "copied"
UNSTABLE = "unstable"
EXPECTED_BUILD = "25G332"
OTHER_BUILD = "25G333"
OUTSIDE_ROOT = "outside"
BUILD_MISMATCH = "Nothing copied"

if TYPE_CHECKING:
    from collections.abc import Callable


def _rejected(action: Callable[[], object]) -> str:
    try:
        _ = action()
    except (ValueError, SystemExit) as error:
        return str(error)
    return ""


class CollectorBoundaryTests(TestCase):
    """Test bounded and exclusive evidence copying in synthetic temp trees."""

    @staticmethod
    def test_source_symlink_outside_selected_root_is_rejected() -> None:
        """Reject a symlink escaping the selected offline root."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = workspace / "offline-root"
            root.mkdir()
            external = workspace / "external.bin"
            _ = external.write_bytes(b"not-source")
            (root / "alias.bin").symlink_to(external)
            outcome = _rejected(
                lambda: collector.open_source(root, Path("alias.bin"))
            )
            assert OUTSIDE_ROOT in outcome

    @staticmethod
    def test_preexisting_destination_is_never_removed() -> None:
        """A failed exclusive copy must not clobber an existing file."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root, output = workspace / "root", workspace / "output"
            root.mkdir()
            output.mkdir()
            relative = Path("evidence.bin")
            _ = (root / relative).write_bytes(b"new-data")
            original = b"retain-this-original"
            _ = (output / relative).write_bytes(original)
            record = collector.copy_evidence(root, output, relative)
            assert record["status"] == UNAVAILABLE
            assert (output / relative).read_bytes() == original

    @staticmethod
    def test_rejected_postcopy_evidence_removes_only_new_file() -> None:
        """An unstable-source check discards this invocation's complete copy."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root, output = workspace / "root", workspace / "output"
            root.mkdir()
            output.mkdir()
            relative = Path("evidence.bin")
            _ = (root / relative).write_bytes(b"source-bytes")
            with mock.patch.object(
                collector, "_verify_source", side_effect=ValueError(UNSTABLE)
            ):
                record = collector.copy_evidence(root, output, relative)
            assert record["status"] == UNAVAILABLE
            assert UNSTABLE in record.get("error", "")
            assert not (output / relative).exists()

    @staticmethod
    def test_successful_evidence_has_exact_bytes_and_digest() -> None:
        """A complete synthetic file gets a matching SHA-256 and byte count."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root, output = workspace / "root", workspace / "output"
            root.mkdir()
            output.mkdir()
            relative = Path("nested/evidence.bin")
            (root / relative.parent).mkdir()
            data = b"synthetic-abi-reference\x00\x01"
            _ = (root / relative).write_bytes(data)
            record = collector.copy_evidence(root, output, relative)
            assert record["status"] == COPIED
            assert record.get("bytes") == len(data)
            assert record.get("sha256") == hashlib.sha256(data).hexdigest()
            assert (output / relative).read_bytes() == data

    @staticmethod
    def test_synthetic_wrong_build_is_rejected() -> None:
        """Reject a mismatched OS build before creating evidence output."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root, output = workspace / "root", workspace / "output"
            root.mkdir()
            version = root / collector.VERSION
            version.parent.mkdir(parents=True)
            _ = version.write_bytes(
                plistlib.dumps({
                    "ProductName": "Synthetic macOS",
                    "ProductVersion": "26.7.2",
                    "ProductBuildVersion": EXPECTED_BUILD,
                })
            )
            boot = root / collector.FILES[1]
            boot.parent.mkdir(parents=True)
            _ = boot.write_bytes(b"not-a-real-kernel-collection")
            observed = collector.read_version(root)
            assert observed["ProductBuildVersion"] == EXPECTED_BUILD
            arguments = [
                "collect_platform_abi.py",
                "--source-root",
                str(root),
                "--output",
                str(output),
                "--expected-build",
                OTHER_BUILD,
            ]
            error_output = StringIO()
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(sys, "stderr", error_output),
            ):
                result = _rejected(collector.main)
            assert result
            assert BUILD_MISMATCH in error_output.getvalue()
            assert not output.exists()
