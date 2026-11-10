# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic supplied-SystemVersion boundary tests for offline ABI inventory."""

import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import struct
import tempfile
from unittest import TestCase
from unittest import mock

from tools import inspect_platform_abi as inspector

PRODUCT_VERSION = "26.7.2"
PRODUCT_BUILD = "25G332"
CLI_FAILURE = 2


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


def _rejects_bad_cli(parsed: argparse.Namespace) -> bool:
    """Assert the public CLI refuses untyped options before inventory.

    Returns:
        True if the public CLI exits with an error and does not inspect data.

    """
    with (
        mock.patch.object(
            argparse.ArgumentParser, "parse_args", return_value=parsed
        ),
        mock.patch.object(inspector, "inventory") as inventory,
        mock.patch.object(
            argparse.ArgumentParser, "exit", side_effect=SystemExit(2)
        ),
    ):
        try:
            inspector.main()
        except SystemExit as error:
            return error.code == CLI_FAILURE and inventory.call_count == 0
    return False


class InspectorCliBoundaryTests(TestCase):
    """Reject dynamically typed CLI values before reading OS ABI evidence."""

    @staticmethod
    def test_cli_rejects_invalid_namespace_types_without_inspection() -> None:
        """Refuse unexpected path values without reading a native image."""
        args = argparse.Namespace(
            reference=123,
            collection=None,
            kdk_root=None,
            system_version=None,
        )
        assert _rejects_bad_cli(args)


def _rejects_collection(
    path: Path, expected: type[OSError | ValueError]
) -> bool:
    """Identify the expected rejection of an offline fileset input.

    Returns:
        True when the source open or bounds validation refuses input.

    """
    try:
        _ = inspector.load_collection(path)
    except expected:
        return True
    return False


class CollectionReaderBoundaryTests(TestCase):
    """Inspect only bounded ordinary offline collections."""

    @staticmethod
    def test_valid_synthetic_fileset_is_inventory_only() -> None:
        """Keep a no-symbol Mach-O fileset as candidates, not verified ABI."""
        header = struct.pack("<8I", 0xFEEDFACF, 0x01000007, 0, 0xC, 0, 0, 0, 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.fileset"
            _ = path.write_bytes(header)
            digest, metadata, images = inspector.load_collection(path)
            assert digest == hashlib.sha256(header).hexdigest()
            assert metadata == {"collectionUUID": None}
            assert images == {}

    @staticmethod
    def test_fileset_symlink_is_not_followed() -> None:
        """Refuse an alias to an outside file at the final path component."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "original"
            _ = source.write_bytes(b"\0" * 32)
            link = root / "symlink"
            link.symlink_to(source)
            assert _rejects_collection(link, OSError)

    @staticmethod
    def test_fileset_fifo_fails_without_blocking() -> None:
        """Treat a FIFO as a nonregular input, never a device stream."""
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "named-pipe"
            os.mkfifo(fifo)
            assert _rejects_collection(fifo, ValueError)

    @staticmethod
    def test_oversized_sparse_fileset_rejected_before_mapping() -> None:
        """Reject a sparse input above the collector's size budget."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.fileset"
            with path.open("wb") as source:
                _ = source.truncate(inspector.COLLECTION_FILE_LIMIT + 1)
            assert _rejects_collection(path, ValueError)

    @staticmethod
    def test_empty_fileset_rejected_before_mmap() -> None:
        """Handle zero-length input without a host memory-mapping exception."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.fileset"
            _ = path.write_bytes(b"")
            assert _rejects_collection(path, ValueError)
