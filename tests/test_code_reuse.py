# Copyright (c) 2026 SimpleATH contributors.
"""Offline source-acquisition, archive-boundary and ledger regressions."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT = (
    Path(__file__).resolve().parents[1] / "tools" / "references" / "download.py"
)
SPEC = importlib.util.spec_from_file_location("simpleath_code_reuse", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REUSE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REUSE
SPEC.loader.exec_module(REUSE)


def archive_bytes(name: str, payload: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


class ReferenceAcquisitionTests(unittest.TestCase):
    def test_complete_cache_and_preserved_assessment(self) -> None:
        repository = REUSE.Repository("fixture", "example/fixture", "a" * 40, 1)
        payload = (
            b"// SPDX-License-Identifier: BSD-3-Clause\nint source_only;\n"
        )
        archive = archive_bytes("fixture-revision/source.cpp", payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                REUSE.urllib.request,
                "urlopen",
                return_value=io.BytesIO(archive),
            ) as network:
                records = REUSE.download(repository, root)
                network.assert_called_once()
            self.assertEqual(records[0]["spdx_in_source"], "BSD-3-Clause")
            ledger = root / "ledger.jsonl"
            self.assertEqual(REUSE.update_ledger(ledger, records), 1)
            row = json.loads(ledger.read_text())
            row["status"] = "partially-adapted"
            row["destinations"] = ["src/fixture.cpp"]
            ledger.write_text(json.dumps(row) + "\n")
            reviewed = ledger.read_bytes()
            with mock.patch.object(
                REUSE.urllib.request,
                "urlopen",
                side_effect=AssertionError("offline means no network"),
            ):
                cached = REUSE.download(repository, root, offline=True)
            self.assertEqual(REUSE.update_ledger(ledger, cached), 0)
            self.assertEqual(ledger.read_bytes(), reviewed)
            checkout = (
                root / repository.name / repository.revision / "source.cpp"
            )
            checkout.write_text("modified reference")
            with self.assertRaisesRegex(ValueError, "source changed"):
                REUSE.download(repository, root, offline=True)

    def test_traversal_never_writes_outside_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "malformed.tar.gz"
            archive.write_bytes(
                archive_bytes("fixture/../outside.txt", b"must not escape")
            )
            checkout = root / "tree"
            checkout.mkdir()
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                REUSE.extract_sources(archive, checkout)
            self.assertFalse((root / "outside.txt").exists())

    def test_missing_offline_cache_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = REUSE.Repository(
                "missing", "example/missing", "b" * 40, 1
            )
            with self.assertRaises(FileNotFoundError):
                REUSE.download(repository, Path(directory), offline=True)

    def test_linux_restore_preserves_mixed_ledger_and_assessments(self) -> None:
        payload = b"// Linux source, retained fixture\n"
        row = {
            "schema": 1,
            "source": "linux/drivers/bluetooth/ath3k.c",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "revision": "a" * 40,
            "upstream_path": "drivers/bluetooth/ath3k.c",
            "implementation": "partial",
            "destinations": ["src/bluetooth/Ath3kUsb.cpp"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "ledger.jsonl"
            ledger.write_text(
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
                REUSE.urllib.request,
                "urlopen",
                return_value=io.BytesIO(payload),
            ):
                self.assertEqual(REUSE.download_linux(root), 1)
            self.assertEqual((root / row["source"]).read_bytes(), payload)
            with mock.patch.object(
                REUSE.urllib.request,
                "urlopen",
                side_effect=AssertionError("offline"),
            ):
                self.assertEqual(REUSE.download_linux(root, offline=True), 1)
            self.assertEqual(ledger.read_bytes(), before)
            self.assertEqual(REUSE.update_ledger(ledger, []), 0)
            self.assertEqual(ledger.read_bytes(), before)
            (root / row["source"]).write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "Linux source changed"):
                REUSE.download_linux(root, offline=True)

    def test_linux_bad_download_is_never_published(self) -> None:
        row = {
            "schema": 1,
            "source": "linux/net/mac80211/scan.c",
            "revision": "b" * 40,
            "upstream_path": "net/mac80211/scan.c",
            "sha256": hashlib.sha256(b"correct").hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger.jsonl").write_text(json.dumps(row) + "\n")
            with mock.patch.object(
                REUSE.urllib.request,
                "urlopen",
                return_value=io.BytesIO(b"incorrect"),
            ):
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    REUSE.download_linux(root)
            self.assertFalse((root / row["source"]).exists())

    def test_missing_custom_ledger_uses_canonical_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            canonical = project / ".references/ledger.jsonl"
            canonical.parent.mkdir()
            canonical.write_text(
                '{"schema":1,"source":"linux/source","implementation":"partial"}\n'
            )
            destination = project / "separate-cache"
            with mock.patch.object(REUSE, "ROOT", project):
                REUSE.seed_ledger(destination)
            self.assertEqual(
                (destination / "ledger.jsonl").read_bytes(),
                canonical.read_bytes(),
            )

    def test_sparse_sdk_adoption_checks_old_bytes_and_fills_missing_files(
        self,
    ) -> None:
        repository = REUSE.Repository(
            "MacKernelSDK", "example/sdk", "c" * 40, 2, True
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
            old.write_bytes(b"header")
            metadata = root / "MacKernelSDK/.git/config"
            metadata.parent.mkdir()
            metadata.write_bytes(b"local Git metadata")
            with mock.patch.object(
                REUSE.urllib.request,
                "urlopen",
                return_value=io.BytesIO(archive.getvalue()),
            ):
                records = REUSE.download(repository, root)
            self.assertEqual(len(records), 2)
            self.assertTrue((root / "MacKernelSDK/LICENSE.txt").is_file())
            self.assertEqual(metadata.read_bytes(), b"local Git metadata")
            self.assertEqual(
                records, REUSE.download(repository, root, offline=True)
            )

    def test_hash_conflict_preserves_existing_ledger(self) -> None:
        original = {
            "repository": "upstream",
            "revision": "commit",
            "path": "file",
            "sha256": "original",
            "status": "reviewed",
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.jsonl"
            self.assertEqual(REUSE.update_ledger(ledger, [original]), 1)
            before = ledger.read_bytes()
            changed = dict(original, sha256="different")
            with self.assertRaisesRegex(ValueError, "differs from ledger"):
                REUSE.update_ledger(ledger, [changed])
            self.assertEqual(before, ledger.read_bytes())


if __name__ == "__main__":
    unittest.main()
