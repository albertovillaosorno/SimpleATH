# Copyright (c) 2026 SimpleATH contributors.
"""Guard exact ABI snapshot byte lineage across the project-label rename."""

from hashlib import sha256
from pathlib import Path
import unittest

from tools.abi_types import json_object
from tools.abi_types import mapping
from tools.abi_types import string
from tools.native_references import KERNEL
from tools.native_references import load_reference
from tools.system_profiles import SYSTEMS

ROOT = Path(__file__).resolve().parents[1] / "src/platform/abi"
PROJECT_LABEL = b'"project": "SimpleATH"'
LEGACY_LABEL = b'"project": "SimpleBCM"'
PROJECT = "SimpleATH"
REFERENCE_SHA256_BEFORE_LABEL_RENAME = {
    "Sonoma.json": (
        "7a8fe4b7b36ff67485eef3352cd13f6e2140f77ca65d48e8519543ac6db60877"
    ),
    "Sequoia.json": (
        "0e2311e735f1029a7f2957c8fcaa939561dc2ac14c58740be7ad552c4ba76ee1"
    ),
    "Tahoe.json": (
        "611b50f109954bb7eda873c40dccf7f6d3ff57a994a156ede9550d9ac9ce82cd"
    ),
}


def _manifest_files() -> dict[str, str]:
    document = json_object((ROOT / "manifest.json").read_bytes())
    entries = mapping(document.get("files"))
    return {name: string(value) for name, value in entries.items()}


class NativeReferenceManifestTests(unittest.TestCase):
    """Guard ABI payload byte lineage across metadata-only re-pins."""

    @staticmethod
    def test_all_manifest_hashes_cover_exact_checked_in_bytes() -> None:
        """Require a digest match for each pinned operating-system snapshot."""
        entries = _manifest_files()
        assert entries.keys() == REFERENCE_SHA256_BEFORE_LABEL_RENAME.keys()
        for name, recorded_hash in entries.items():
            assert (
                sha256((ROOT / name).read_bytes()).hexdigest() == recorded_hash
            )

    @staticmethod
    def test_pre_rename_abi_snapshot_bytes_are_recoverable_exactly() -> None:
        """Prove only the top-level project label changed since ABI capture."""
        for (
            name,
            historical_hash,
        ) in REFERENCE_SHA256_BEFORE_LABEL_RENAME.items():
            contents = (ROOT / name).read_bytes()
            assert contents.count(PROJECT_LABEL) == 1
            original = contents.replace(PROJECT_LABEL, LEGACY_LABEL, 1)
            assert sha256(original).hexdigest() == historical_hash

    @staticmethod
    def test_checked_reference_loader_accepts_only_pinned_os_profiles() -> None:
        """Exercise the checked loader without bypassing its hashes."""
        for name in REFERENCE_SHA256_BEFORE_LABEL_RENAME:
            system = name.removesuffix(".json")
            record = load_reference(ROOT / name)
            assert record["system"] == system
            assert record["project"] == PROJECT
            assert record["profile"] == SYSTEMS[system]
            assert KERNEL in record["libraries"]
