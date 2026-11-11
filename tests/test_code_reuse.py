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
#   - Offline regression cases for code reuse.
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
#   - Offline regression cases for code reuse.
# - Description:
#   - Implements or verifies the test_code_reuse source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for code reuse.
"""Offline source-acquisition, archive-boundary and ledger regressions."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
from typing import TYPE_CHECKING
from typing import cast
import unittest
from unittest import mock

if TYPE_CHECKING:
    from collections.abc import Generator

from tools.references import download as ref_download


@contextmanager
def expect_exception(
    error_type: type[Exception], pattern: str | None = None
) -> Generator[None]:
    """Verify an exception and optional message without a third-party runner.

    Raises:
        AssertionError: If the expected error or message does not occur.

    """
    try:
        yield
    except error_type as error:
        if pattern is not None and re.search(pattern, str(error)) is None:
            raise AssertionError from error
    else:
        raise AssertionError


EXPECTED_SPDX_LICENSE = "BSD-3-Clause"
SDK_EXPECTED_FILE_COUNT = 2
GIT_METADATA = b"local Git metadata"


def archive_bytes(name: str, payload: bytes) -> bytes:
    """Build a source-only archive fixture.

    Returns:
        Compressed bytes representing one archive entry.

    """
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


class ReferenceAcquisitionTests(unittest.TestCase):
    """Exercise pinned caches and immutable ledger history."""

    @staticmethod
    def test_complete_cache_and_preserved_assessment() -> None:
        """Retain verified source metadata and prior analyst assessments."""
        repository = ref_download.Repository(
            "fixture", "example/fixture", "a" * 40, 1
        )
        payload = (
            b"// SPDX-License-Identifier: BSD-3-Clause\nint source_only;\n"
        )
        archive = archive_bytes("fixture-revision/source.cpp", payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                ref_download,
                "_open_pinned_https",
                return_value=io.BytesIO(archive),
            ) as network:
                records = ref_download.download(repository, root)
                network.assert_called_once()
            assert records[0]["spdx_in_source"] == EXPECTED_SPDX_LICENSE
            ledger = root / "ledger.jsonl"
            assert ref_download.update_ledger(ledger, records) == 1
            row = cast("dict[str, object]", json.loads(ledger.read_text()))
            row["status"] = "partially-adapted"
            row["destinations"] = ["src/fixture.cpp"]
            _ = ledger.write_text(json.dumps(row) + "\n")
            reviewed = ledger.read_bytes()
            with mock.patch.object(
                ref_download,
                "_open_pinned_https",
                side_effect=AssertionError("offline means no network"),
            ):
                cached = ref_download.download(repository, root, offline=True)
            assert ref_download.update_ledger(ledger, cached) == 0
            assert ledger.read_bytes() == reviewed
            _ = (
                root / repository.name / repository.revision / "source.cpp"
            ).write_text("modified reference")
            with expect_exception(ValueError, "source changed"):
                _ = ref_download.download(repository, root, offline=True)

    @staticmethod
    def test_traversal_never_writes_outside_checkout() -> None:
        """Reject archive path traversal before creating outside files."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "malformed.tar.gz"
            _ = archive.write_bytes(
                archive_bytes("fixture/../outside.txt", b"must not escape")
            )
            checkout = root / "tree"
            checkout.mkdir()
            with expect_exception(ValueError, "Unsafe"):
                _ = ref_download.extract_sources(archive, checkout)
            assert not ((root / "outside.txt").exists())

    @staticmethod
    def test_https_endpoint_requires_pinned_hosts() -> None:
        """Reject schemes, authorities, ports and redirected host tricks."""
        valid_url = "https://codeload.github.com/example/repo/tar.gz/pin"
        assert ref_download.source_https_endpoint(valid_url) == (
            "codeload.github.com",
            "/example/repo/tar.gz/pin",
        )
        invalid_urls = (
            "http://codeload.github.com/example/repo",
            "https://untrusted.example.com/example/repo",
            "https://codeload.github.com:8443/example/repo",
            "https://user@codeload.github.com/example/repo",
            "https://codeload.github.com/example/repo#fragment",
        )
        for url in invalid_urls:
            with expect_exception(ValueError):
                _ = ref_download.source_https_endpoint(url)

    @staticmethod
    def test_archive_symlink_cannot_escape_checkout() -> None:
        """Reject tar symlinks pointing outside the extraction root."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "escape.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo("fixture/escape")
                entry.type = tarfile.SYMTYPE
                entry.linkname = "../../outside.txt"
                bundle.addfile(entry)
            checkout = root / "tree"
            checkout.mkdir()
            with expect_exception(ValueError, "Unsafe upstream symlink"):
                _ = ref_download.extract_sources(archive, checkout)
            assert not (checkout / "escape").exists()
            assert not (root / "outside.txt").exists()

    @staticmethod
    def test_missing_offline_cache_is_an_error() -> None:
        """Fail when required offline source bytes are unavailable."""
        with tempfile.TemporaryDirectory() as directory:
            repository = ref_download.Repository(
                "missing", "example/missing", "b" * 40, 1
            )
            with expect_exception(FileNotFoundError):
                _ = ref_download.download(
                    repository, Path(directory), offline=True
                )

    @staticmethod
    def test_linux_restore_preserves_mixed_ledger_and_assessments() -> None:
        """Restore Linux bytes without changing the provenance history."""
        payload = b"// Linux source, retained fixture\n"
        linux_source = "linux/drivers/bluetooth/ath3k.c"
        row = {
            "schema": 1,
            "source": linux_source,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "revision": "a" * 40,
            "upstream_path": "drivers/bluetooth/ath3k.c",
            "implementation": "partial",
            "destinations": ["src/bluetooth/Ath3kUsb.cpp"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "ledger.jsonl"
            _ = ledger.write_text(
                json.dumps(row)
                + "\n"
                + json.dumps({
                    "schema": "simpleath.reference.v1",
                    "repository": "other",
                    "revision": "pin",
                    "path": "source",
                    "sha256": "hash",
                })
                + "\n"
            )
            before = ledger.read_bytes()
            with mock.patch.object(
                ref_download,
                "_open_pinned_https",
                return_value=io.BytesIO(payload),
            ):
                assert ref_download.download_linux(root) == 1
            assert (root / linux_source).read_bytes() == payload
            with mock.patch.object(
                ref_download,
                "_open_pinned_https",
                side_effect=AssertionError("offline"),
            ):
                assert ref_download.download_linux(root, offline=True) == 1
            assert ledger.read_bytes() == before
            assert ref_download.update_ledger(ledger, []) == 0
            assert ledger.read_bytes() == before
            _ = (root / linux_source).write_bytes(b"changed")
            with expect_exception(ValueError, "Linux source changed"):
                _ = ref_download.download_linux(root, offline=True)

    @staticmethod
    def test_linux_bad_download_is_never_published() -> None:
        """Refuse mismatched Linux source content before publishing it."""
        linux_source = "linux/net/mac80211/scan.c"
        row = {
            "schema": 1,
            "source": linux_source,
            "revision": "b" * 40,
            "upstream_path": "net/mac80211/scan.c",
            "sha256": hashlib.sha256(b"correct").hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _ = (root / "ledger.jsonl").write_text(json.dumps(row) + "\n")
            with (
                mock.patch.object(
                    ref_download,
                    "_open_pinned_https",
                    return_value=io.BytesIO(b"incorrect"),
                ),
                expect_exception(ValueError, "hash mismatch"),
            ):
                _ = ref_download.download_linux(root)
            assert not ((root / linux_source).exists())

    @staticmethod
    def test_missing_custom_ledger_uses_canonical_history() -> None:
        """Seed a separate cache from the tracked canonical history."""
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            canonical = project / ".references/ledger.jsonl"
            canonical.parent.mkdir()
            _ = canonical.write_text(
                '{"schema":1,"source":"linux/source","implementation":"partial"}\n'
            )
            destination = project / "separate-cache"
            with mock.patch.object(ref_download, "ROOT", project):
                ref_download.seed_ledger(destination)
            assert (
                destination / "ledger.jsonl"
            ).read_bytes() == canonical.read_bytes()

    @staticmethod
    def test_sparse_sdk_adoption_checks_old_bytes_and_fills_missing_files() -> (
        None
    ):
        """Compare existing SDK bytes before adopting a complete archive."""
        repository = ref_download.Repository(
            "MacKernelSDK",
            "example/sdk",
            "c" * 40,
            SDK_EXPECTED_FILE_COUNT,
            flat=True,
        )
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
            for name, payload in (
                ("Headers/header.h", b"header"),
                ("LICENSE.txt", b"notice"),
            ):
                entry = tarfile.TarInfo("sdk-pin/" + name)
                entry.size = len(payload)
                bundle.addfile(entry, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "MacKernelSDK/Headers/header.h"
            old.parent.mkdir(parents=True)
            _ = old.write_bytes(b"header")
            metadata = root / "MacKernelSDK/.git/config"
            metadata.parent.mkdir()
            _ = metadata.write_bytes(GIT_METADATA)
            with mock.patch.object(
                ref_download,
                "_open_pinned_https",
                return_value=io.BytesIO(archive.getvalue()),
            ):
                records = ref_download.download(repository, root)
            assert len(records) == SDK_EXPECTED_FILE_COUNT
            assert (root / "MacKernelSDK/LICENSE.txt").is_file()
            assert metadata.read_bytes() == GIT_METADATA
            assert records == ref_download.download(
                repository, root, offline=True
            )

    @staticmethod
    def test_hash_conflict_preserves_existing_ledger() -> None:
        """Keep the previous ledger untouched when source identity conflicts."""
        original: ref_download.ReferenceRecord = {
            "schema": "simpleath.reference.v1",
            "repository": "upstream",
            "revision": "commit",
            "path": "file",
            "cache_path": "upstream/file",
            "sha256": "original",
            "bytes": 0,
            "kind": "file",
            "spdx_in_source": None,
            "license_review": "reviewed",
            "status": "reviewed",
            "destinations": [],
            "notes": "Synthetic ledger conflict fixture",
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            assert ref_download.update_ledger(ledger, [original]) == 1
            before = ledger.read_bytes()
            changed: ref_download.ReferenceRecord = {
                **original,
                "sha256": "different",
            }
            with expect_exception(ValueError, "differs from ledger"):
                _ = ref_download.update_ledger(ledger, [changed])
            assert before == ledger.read_bytes()


if __name__ == "__main__":
    _ = unittest.main()
