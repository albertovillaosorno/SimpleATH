# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Bounded synthetic snapshot evidence tests; never inspect host/KDK data."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import TYPE_CHECKING
from typing import cast
from unittest import TestCase

from tools import inspect_platform_abi as inspector

if TYPE_CHECKING:
    from collections.abc import Callable

SNAPSHOT = "snapshot.json"
MANIFEST = "manifest.json"
IMAGE = "com.apple.kernel"
SYMBOL = "_symbol"
EVIDENCE = "snapshot_reported_export"


def _payload() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "profile": "synthetic-only",
        "images": {
            IMAGE: {
                "uuid": "synthetic-uuid",
                "symbols": {SYMBOL: "reported"},
                "exports": [SYMBOL],
                "tables": {"KDK_fake_table": {}},
                "functions": {},
            }
        },
    }


def _write(root: Path, value: object) -> Path:
    path = root / SNAPSHOT
    _ = path.write_text(json.dumps(value))
    return path


def _read(path: Path) -> tuple[str, dict[str, object], dict[str, object]]:
    reader = cast(
        "Callable[[Path], tuple[str, dict[str, object], dict[str, object]]]",
        inspector.load_reference,
    )
    return reader(path)


def _rejected(path: Path) -> bool:
    """Report fail-closed rejection of malformed/unsafe snapshot inputs.

    Returns:
        True if bounded reading or schema validation rejects the file.

    """
    try:
        _ = _read(path)
    except OSError, ValueError:
        return True
    return False


class OfflineReferenceReaderTests(TestCase):
    """Check that a selected snapshot cannot silently become ABI approval."""

    @staticmethod
    def test_valid_reference_without_manifest_is_not_verified() -> None:
        """Report candidate symbols but never assume manifest provenance."""
        with tempfile.TemporaryDirectory() as directory:
            path = _write(Path(directory), _payload())
            digest, metadata, images = _read(path)
            assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
            assert metadata["manifestHashMatched"] is False
            image_obj = images[IMAGE]
            assert isinstance(image_obj, dict)
            image = cast("dict[str, object]", image_obj)
            assert isinstance(image.get("symbols"), dict)
            symbols = cast("dict[str, str]", image["symbols"])
            assert symbols[SYMBOL] == EVIDENCE

    @staticmethod
    def test_valid_manifest_matches_exact_selected_bytes() -> None:
        """Accept only a matching recorded hash for the selected JSON file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write(root, _payload())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            _ = (root / MANIFEST).write_text(
                json.dumps({"files": {SNAPSHOT: digest}})
            )
            _, metadata, _ = _read(path)
            assert metadata["manifestHashMatched"] is True
            _ = path.write_text(path.read_text() + " ")
            assert _rejected(path)

    @staticmethod
    def test_reject_invalid_root_and_nested_image_shapes() -> None:
        """Reject lists, invalid image records and non-string export entries."""
        malformed: tuple[object, ...] = (
            [],
            {"schemaVersion": 1, "images": []},
            {"schemaVersion": 1, "images": {IMAGE: []}},
            {"schemaVersion": 1, "images": {IMAGE: {"symbols": {}}}},
            {
                "schemaVersion": 1,
                "images": {IMAGE: {"symbols": {}, "exports": [42]}},
            },
            {
                "schemaVersion": 1,
                "images": {IMAGE: {"symbols": {}, "exports": [], "tables": []}},
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in malformed:
                assert _rejected(_write(root, value))

    @staticmethod
    def test_reject_missing_manifest_map_and_invalid_hash_type() -> None:
        """Reject malformed manifest evidence before reporting a match."""
        manifests: tuple[object, ...] = (
            [],
            {"files": []},
            {"files": {SNAPSHOT: 1}},
            {"files": {SNAPSHOT: "invalid-sha256"}},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write(root, _payload())
            for manifest in manifests:
                _ = (root / MANIFEST).write_text(json.dumps(manifest))
                assert _rejected(path)

    @staticmethod
    def test_reject_duplicate_fields_and_nonfinite_json_constants() -> None:
        """Refuse ambiguous or non-JSON evidence before inventory parsing."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / SNAPSHOT
            for raw in (
                '{"schemaVersion":1,"schemaVersion":1,"images":{}}',
                '{"schemaVersion":1,"images":{"a":{},"a":{}}}',
                '{"schemaVersion":1,"images":{},"profile":NaN}',
            ):
                _ = path.write_text(raw)
                assert _rejected(path)

    @staticmethod
    def test_reject_symlink_and_oversized_sparse_snapshot() -> None:
        """Reject symlinks and oversized sparse files without reading them."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external.json"
            data = json.dumps(_payload()).encode()
            _ = external.write_bytes(data)
            path = root / SNAPSHOT
            path.symlink_to(external)
            assert _rejected(path)
            assert external.read_bytes() == data
            path.unlink()
            with path.open("wb") as stream:
                _ = stream.truncate(inspector.KDK_FILE_LIMIT + 1)
            assert _rejected(path)
