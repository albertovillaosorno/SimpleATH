# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic supplied-SystemVersion boundary tests for offline ABI inventory."""

import hashlib
import os
from pathlib import Path
import plistlib
import tempfile
from unittest import TestCase
from unittest import mock

from tools import inspect_platform_abi as inspector

PRODUCT_VERSION = "26.7.2"
PRODUCT_BUILD = "25G332"


def _rejects_version(path: Path, expected: type[OSError | ValueError]) -> bool:
    """Return whether a malformed static SystemVersion path is rejected.

    Returns:
        True when the exact expected failure class is raised.

    """
    try:
        _ = inspector.read_system_version(path)
    except expected:
        return True
    return False


class SuppliedSystemVersionTests(TestCase):
    """Never follow symlinks or trust malformed external version metadata."""

    @staticmethod
    def test_valid_plist_preserves_digest_and_unverified_provenance() -> None:
        """Retain exact data hash but never assert a matched system image."""
        payload = plistlib.dumps({
            "ProductVersion": PRODUCT_VERSION,
            "ProductBuildVersion": PRODUCT_BUILD,
        })
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / "SystemVersion.plist"
            _ = version.write_bytes(payload)
            with mock.patch.object(
                inspector, "load_collection", return_value=("fake", {}, {})
            ):
                result = inspector.inventory(
                    Path(directory) / "synthetic-collection",
                    reference_mode=False,
                    system_version=version,
                )
            assert result["suppliedSystemVersion"] == {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "version": PRODUCT_VERSION,
                "build": PRODUCT_BUILD,
                "pairedToCollectionVerified": False,
            }

    @staticmethod
    def test_symlink_supplied_version_cannot_escape_selected_folder() -> None:
        """Reject a symlink even if its contents form a valid XML plist."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = plistlib.dumps({
                "ProductVersion": "26.7.2",
                "ProductBuildVersion": "25G332",
            })
            external = root / "external.plist"
            _ = external.write_bytes(content)
            selected = root / "SystemVersion.plist"
            selected.symlink_to(external)
            assert _rejects_version(selected, OSError)

    @staticmethod
    def test_fifo_never_blocks_inventory() -> None:
        """Reject a nonblocking FIFO without reading or parsing its data."""
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / "SystemVersion.plist"
            os.mkfifo(version)
            assert _rejects_version(version, ValueError)

    @staticmethod
    def test_nondict_or_missing_version_fields_are_rejected() -> None:
        """Fail before reporting a malformed plist as version evidence."""
        cases: tuple[object, ...] = (
            ["not-a-dictionary"],
            {},
            {"ProductVersion": "26.7.2"},
            {"ProductVersion": 26, "ProductBuildVersion": "25G332"},
            {"ProductVersion": "", "ProductBuildVersion": "25G332"},
        )
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / "SystemVersion.plist"
            for value in cases:
                _ = version.write_bytes(plistlib.dumps(value))
                assert _rejects_version(version, ValueError)

    @staticmethod
    def test_sparse_oversized_system_version_is_rejected_without_read() -> None:
        """Refuse a huge sparse version file before allocating its data."""
        with tempfile.TemporaryDirectory() as directory:
            version = Path(directory) / "SystemVersion.plist"
            with version.open("wb") as source:
                _ = source.truncate(inspector.KDK_FILE_LIMIT + 1)
            assert _rejects_version(version, ValueError)
