# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic offline KDK reader boundary regressions; no system images read."""

import os
from pathlib import Path
import plistlib
import tempfile
from typing import TYPE_CHECKING
from typing import cast
from unittest import TestCase
from unittest import mock

from tools import inspect_platform_abi as inspector

if TYPE_CHECKING:
    from collections.abc import Callable

EMPTY_PAYLOAD = b""


def _rejected_error(root: Path, relative: str) -> bool:
    """Report a failed symlink/nonregular KDK file open.

    Returns:
        True when the offline read fails at the filesystem boundary.

    """
    try:
        _ = inspector.read_kdk_file(root, relative)
    except OSError:
        return True
    return False


def _rejected_value(root: Path, relative: str) -> bool:
    """Report a failed KDK path/size/mutation contract.

    Returns:
        True when validation rejects the supplied offline input.

    """
    try:
        _ = inspector.read_kdk_file(root, relative)
    except ValueError:
        return True
    return False


def _rejected_plist(root: Path) -> bool:
    """Reject a KDK with non-dictionary plist metadata.

    Returns:
        True if the KDK input metadata is rejected by the inspector.

    """
    reader = cast("Callable[[Path], object]", inspector.load_kdk)
    try:
        _ = reader(root)
    except ValueError:
        return True
    return False


class KdkReaderBoundaryTests(TestCase):
    """Check that user-supplied offline roots cannot escape into other files."""

    @staticmethod
    def test_bounded_regular_nested_file_is_preserved() -> None:
        """Preserve bounded bytes read through already-open directories."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "offline"
            (root / "nested").mkdir(parents=True)
            payload = b"synthetic-static-abi\x00" * 64
            _ = (root / "nested/metadata.bin").write_bytes(payload)
            assert (
                inspector.read_kdk_file(root, "nested/metadata.bin") == payload
            )
            _ = (root / "empty.bin").write_bytes(EMPTY_PAYLOAD)
            assert inspector.read_kdk_file(root, "empty.bin") == EMPTY_PAYLOAD

    @staticmethod
    def test_nested_directory_and_leaf_symlinks_are_rejected() -> None:
        """Reject all symlink components under the selected root."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = workspace / "offline"
            (root / "nested").mkdir(parents=True)
            external = workspace / "outside.bin"
            original_external = b"must-stay-unread"
            _ = external.write_bytes(original_external)
            original = root / "nested/real.bin"
            _ = original.write_bytes(b"synthetic")
            (root / "nested/escape.bin").symlink_to(external)
            (root / "nested/internal.bin").symlink_to(original)
            (root / "external-dir").symlink_to(
                workspace, target_is_directory=True
            )
            for relative in (
                "nested/escape.bin",
                "nested/internal.bin",
                "external-dir/outside.bin",
            ):
                assert _rejected_error(root, relative)
            assert external.read_bytes() == original_external

    @staticmethod
    def test_absolute_and_parent_traversal_paths_are_rejected() -> None:
        """Never admit an absolute path or parent traversal from a KDK root."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "offline"
            root.mkdir()
            for relative in (
                "/etc/passwd",
                "../escape.bin",
                "nested/../escape.bin",
                "",
            ):
                assert _rejected_value(root, relative)

    @staticmethod
    def test_oversized_sparse_file_is_rejected_before_read() -> None:
        """Reject a >128-MiB sparse input without allocating its contents."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / "sparse.bin").open("wb") as source:
                _ = source.truncate(inspector.KDK_FILE_LIMIT + 1)
            assert _rejected_value(root, "sparse.bin")

    @staticmethod
    def test_fifo_is_rejected_without_blocking() -> None:
        """Do not block on a named pipe supplied in a fake KDK root."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "pipe")
            assert _rejected_value(root, "pipe")

    @staticmethod
    def test_version_plist_must_be_a_dictionary() -> None:
        """Reject a valid plist whose root is an unexpected list."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = root / "System/Library/CoreServices/SystemVersion.plist"
            version.parent.mkdir(parents=True)
            _ = version.write_bytes(
                plistlib.dumps(["synthetic-invalid-version"])
            )
            assert _rejected_plist(root)

    @staticmethod
    def test_family_plist_must_be_a_dictionary() -> None:
        """Reject malformed family metadata before reading a Mach-O image."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = root / "System/Library/CoreServices/SystemVersion.plist"
            version.parent.mkdir(parents=True)
            _ = version.write_bytes(
                plistlib.dumps({"ProductBuildVersion": "25G332"})
            )
            info = root / "System/Library/Extensions/IOPCIFamily.kext/Contents"
            info /= "Info.plist"
            info.parent.mkdir(parents=True)
            _ = info.write_bytes(plistlib.dumps(["synthetic-invalid-family"]))
            assert _rejected_plist(root)

    @staticmethod
    def test_changed_source_is_rejected_after_bounded_read() -> None:
        """A source modified during the read cannot create a trusted hash."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "changing.bin"
            _ = source.write_bytes(b"source-before-read")
            original_read = os.read
            changed = False

            def read_and_modify(descriptor: int, count: int) -> bytes:
                nonlocal changed
                data = original_read(descriptor, count)
                if data and not changed:
                    _ = source.write_bytes(b"source-after-read-is-different")
                    changed = True
                return data

            with mock.patch.object(os, "read", side_effect=read_and_modify):
                assert _rejected_value(root, "changing.bin")
            assert changed
