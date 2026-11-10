# Copyright (c) 2026 SimpleATH contributors.
"""Offline checks that the build fingerprint tracks actual source roots."""

import os
from pathlib import Path
import tempfile
from unittest import TestCase

from tools.source_fingerprint import MAX_FILE_BYTES
from tools.source_fingerprint import SOURCE_DIRECTORIES
from tools.source_fingerprint import SOURCE_FILES
from tools.source_fingerprint import source_fingerprint

SAMPLE_SOURCE = "source one"
CHANGED_SOURCE = "source two"
SAMPLE_FILE = "sample.txt"


def _fixture(root: Path) -> None:
    """Create all required paths within a disposable synthetic project."""
    for name in SOURCE_FILES:
        source = root / name
        source.parent.mkdir(parents=True, exist_ok=True)
        _ = source.write_text(name, encoding="utf-8")
    for name in SOURCE_DIRECTORIES:
        folder = root / name
        folder.mkdir(exist_ok=True)
        _ = (folder / SAMPLE_FILE).write_text(SAMPLE_SOURCE, encoding="utf-8")


def _rejects(root: Path) -> bool:
    """Check the strict source selection error path.

    Returns:
        True only if the fingerprint safely refused an invalid fixture.

    """
    try:
        _ = source_fingerprint(root)
    except ValueError, OSError:
        return True
    return False


class SourceFingerprintTests(TestCase):
    """A source change must invalidate the fingerprint before publication."""

    @staticmethod
    def test_source_roots_and_top_level_policies_are_included() -> None:
        """Cover source, tools, tests, docs, CI, and root-level metadata."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            baseline = source_fingerprint(root)
            assert source_fingerprint(root) == baseline
            for name in (*SOURCE_DIRECTORIES, "README.md", "ruff.toml"):
                path = root / name
                if path.is_dir():
                    path /= SAMPLE_FILE
                _ = path.write_text(CHANGED_SOURCE, encoding="utf-8")
                assert source_fingerprint(root) != baseline
                _ = path.write_text(
                    SAMPLE_SOURCE if name in SOURCE_DIRECTORIES else name,
                    encoding="utf-8",
                )
                assert source_fingerprint(root) == baseline

    @staticmethod
    def test_moved_linux_ledger_is_required_and_included() -> None:
        """Track the moved ledger without depending on its deleted old path."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            ledger = root / ".references/ledger.jsonl"
            baseline = source_fingerprint(root)
            _ = ledger.write_text(CHANGED_SOURCE, encoding="utf-8")
            assert source_fingerprint(root) != baseline
            ledger.unlink()
            assert _rejects(root)

    @staticmethod
    def test_runtime_state_caches_and_local_linux_tree_are_excluded() -> None:
        """Ignore only non-source cache, secret and Linux reference paths."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            baseline = source_fingerprint(root)
            (root / ".cache").mkdir()
            (root / ".references/linux").mkdir()
            (root / "tools" / "__pycache__").mkdir()
            _ = (root / ".env").write_text("synthetic-only")
            _ = (root / ".references/linux" / SAMPLE_FILE).write_text(CHANGED_SOURCE)
            _ = (root / ".cache" / SAMPLE_FILE).write_text(CHANGED_SOURCE)
            _ = (root / "tools" / "__pycache__" / "cached.pyc").write_bytes(
                b"not source"
            )
            _ = (root / "src" / ".DS_Store").write_bytes(b"ignored")
            assert source_fingerprint(root) == baseline

    @staticmethod
    def test_missing_root_file_and_symlink_fail_closed() -> None:
        """Reject missing source paths and linked external files."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            (root / "AGENTS.md").unlink()
            assert _rejects(root)
            _ = (root / "AGENTS.md").write_text("AGENTS.md")
            (root / "src" / "link.txt").symlink_to(SAMPLE_FILE)
            assert _rejects(root)

    @staticmethod
    def test_special_file_and_oversized_source_fail_closed() -> None:
        """Reject FIFOs and sparse oversized files without reading them."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            fifo = root / "docs" / "fifo"
            os.mkfifo(fifo)
            assert _rejects(root)
            fifo.unlink()
            file_path = root / "src" / SAMPLE_FILE
            os.truncate(file_path, MAX_FILE_BYTES + 1)
            assert _rejects(root)
