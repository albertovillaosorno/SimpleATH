# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Exercise pinned ABI snapshot integrity with synthetic offline JSON only."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import native_references as references
from tools.system_profiles import SYSTEMS

SYSTEM = "Tahoe"
IMAGE = references.SKYWALK
ADDRESS = 0x1000
FUNCTION = "_synthetic_method"
RAW = bytes.fromhex("12345678")
ERROR_HASH = "checksum mismatch"
ERROR_MISSING_SYSTEMS = "All three reference"
VERSION = "25.0.0"


def _document() -> dict[str, object]:
    image = {
        "uuid": "00000000000000000000000000000000",
        "symbols": {FUNCTION: ADDRESS},
        "exports": [FUNCTION],
        "tables": {"SyntheticInterface": [FUNCTION]},
        "functions": {FUNCTION: [ADDRESS, RAW.hex()]},
        "ranges": [[ADDRESS, RAW.hex()]],
    }
    library = {
        "uuid": "00000000000000000000000000000000",
        "symbols": {FUNCTION: ADDRESS},
        "exports": [FUNCTION],
    }
    return {
        "file": f"{SYSTEM}.json",
        "project": "SimpleATH",
        "createdBy": "synthetic-test",
        "createdOn": "2026/11/7",
        "copyright": "Synthetic test data",
        "schemaVersion": 1,
        "system": SYSTEM,
        "profile": SYSTEMS[SYSTEM],
        "collectionUUID": "00000000000000000000000000000000",
        "kernelVersion": VERSION,
        "images": {IMAGE: image},
        "libraries": {references.KERNEL: library},
        "pointers": {str(ADDRESS): ADDRESS + 8},
        "linkSearch": {"textSHA256": "a" * 64, "matches": [ADDRESS]},
    }


def _write_snapshot(folder: Path, document: object) -> Path:
    source = folder / f"{SYSTEM}.json"
    data = (json.dumps(document) + "\n").encode()
    _ = source.write_bytes(data)
    manifest = {"files": {source.name: hashlib.sha256(data).hexdigest()}}
    _ = (folder / "manifest.json").write_text(json.dumps(manifest))
    return source


def _load(folder: Path, document: object) -> object:
    source = _write_snapshot(folder, document)
    references.load_reference.cache_clear()
    with mock.patch.object(references, "DIRECTORY", folder):
        return references.load_reference(source)


def _rejects(folder: Path, document: object, error: type[Exception]) -> bool:
    try:
        _ = _load(folder, document)
    except error:
        return True
    return False


def _read_rejects(
    image: references.ReferenceImage, address: int, size: int
) -> bool:
    try:
        _ = image.read(address, size)
    except ValueError:
        return True
    return False


def _hash_rejects(source: Path) -> bool:
    try:
        _ = references.load_reference(source)
    except ValueError as error:
        return ERROR_HASH in str(error)
    return False


def _system_rejects() -> bool:
    try:
        _ = references.reference_paths()
    except ValueError as error:
        return ERROR_MISSING_SYSTEMS in str(error)
    return False


class SnapshotIntegrityTests(unittest.TestCase):
    """Type and checksum failures never become usable native ABI evidence."""

    @staticmethod
    def test_checked_snapshot_preserves_legacy_image_interfaces() -> None:
        """Synthetic image and collection names, reads and pointers agree."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = _write_snapshot(folder, _document())
            references.load_reference.cache_clear()
            with mock.patch.object(references, "DIRECTORY", folder):
                image = references.ReferenceImage(source, IMAGE)
                collection = references.ReferenceCollection(source)
                assert image.uuid == "0" * 32
                assert image.defined() == {FUNCTION}
                assert image.tables["SyntheticInterface"] == [FUNCTION]
                assert image.funcbytes(FUNCTION) == (ADDRESS, RAW)
                assert image.read(ADDRESS + 1, 2) == RAW[1:3]
                assert (
                    collection.images[references.KERNEL].symbols[FUNCTION]
                    == ADDRESS
                )
                assert collection.pointer(ADDRESS) == ADDRESS + 8
                assert collection.version() == VERSION
                assert collection.reference["linkSearch"]["matches"] == [
                    ADDRESS
                ]
                assert collection.reference["file"] == f"{SYSTEM}.json"
                assert collection.root.uuid == "0" * 32
                image.close()
                collection.close()

    @staticmethod
    def test_bad_checksum_is_fatal_even_for_valid_json() -> None:
        """Never read a snapshot not covered by its committed digest."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = _write_snapshot(folder, _document())
            _ = source.write_text("{}")
            references.load_reference.cache_clear()
            with mock.patch.object(references, "DIRECTORY", folder):
                assert _hash_rejects(source)

    @staticmethod
    def test_unknown_profile_and_wrong_schema_rejected() -> None:
        """A matching hash alone never authorizes a foreign profile."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            document = _document()
            document["system"] = "UnknownOS"
            assert _rejects(folder, document, ValueError)
            document = _document()
            document["profile"] = {}
            assert _rejects(folder, document, ValueError)
            document = _document()
            document["schemaVersion"] = False
            assert _rejects(folder, document, TypeError)

    @staticmethod
    def test_malformed_nested_values_rejected() -> None:
        """Disallow forged booleans, invalid pairs and non-object roots."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            assert _rejects(folder, [], ValueError)
            document = _document()
            document["pointers"] = {"123": True}
            assert _rejects(folder, document, TypeError)
            document = _document()
            document["images"] = {IMAGE: {"ranges": [[ADDRESS]]}}
            assert _rejects(folder, document, TypeError)

    @staticmethod
    def test_missing_ranges_fail_closed() -> None:
        """Snapshot range reads never pad, wrap or expose absent bytes."""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = _write_snapshot(folder, _document())
            references.load_reference.cache_clear()
            with mock.patch.object(references, "DIRECTORY", folder):
                image = references.ReferenceImage(source, IMAGE)
                for address, length in (
                    (ADDRESS - 1, 1),
                    (ADDRESS, -1),
                    (ADDRESS + 3, 2),
                ):
                    assert _read_rejects(image, address, length)

    @staticmethod
    def test_incomplete_system_mode_refuses_unpinned_references() -> None:
        """Missing mounted reference images cannot bypass mode selection."""
        with (
            mock.patch.dict(
                "os.environ", {"SIMPLEATH_NATIVE_SOURCE": "system"}
            ),
            mock.patch.object(references, "system_volumes", return_value={}),
        ):
            assert _system_rejects()
