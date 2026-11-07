# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline source-tree contract checks for the opt-in legacy build helper."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase

# The opt-in legacy CLI imports helpers directly from tools/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from build import PROJECT
from build import copy_package_sources
from build import native_addresses

LICENSE_TEXT = "LICENSE"
README_TEXT = "README.md"
NOTICES_TEXT = "THIRD_PARTY_NOTICES.md"
COLLECT_TEXT = "collect"
DOC_TEXT = "docs"
OCLP_TEXT = "OCLP sample license"


class BuildSourceLayoutTests(TestCase):
    """Source-only fixtures cannot launch a compiler or packaging CLI."""

    @staticmethod
    def test_project_follows_current_platform_layout() -> None:
        """The source tree has one relocated project, not the root path."""
        assert PROJECT.parts[-3:] == (
            "src",
            "platform",
            "SimpleATH.xcodeproj",
        )
        assert PROJECT.is_dir()

    @staticmethod
    def test_native_imports_require_public_kernel_exports() -> None:
        """Private nlist definitions cannot masquerade as linkable imports."""
        kernel = SimpleNamespace(
            symbols={"_public": 0x1000, "_private": 0x2000},
            exports={"_public"},
        )
        wifi = SimpleNamespace(
            symbols={"_wifi": 0x3000, "_wifi_private": 0x4000},
            exports={"_wifi"},
        )
        collection = SimpleNamespace(
            kernel=kernel,
            images={"wifi": wifi},
        )
        assert native_addresses(collection, ["wifi", "missing"]) == {
            "_public": 0x1000,
            "_wifi": 0x3000,
        }

    @staticmethod
    def test_bundle_sources_use_current_repo_paths() -> None:
        """Copy real notices, tools and docs without legacy names."""
        with TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            stage = Path(directory) / "stage"
            (root / "tools").mkdir(parents=True)
            (root / "docs").mkdir()
            (stage / "Extra").mkdir(parents=True)
            for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
                _ = (root / name).write_text(name, encoding="utf-8")
            _ = (root / "tools/collect.py").write_text(
                "collect", encoding="utf-8"
            )
            _ = (root / "docs/Build.md").write_text("docs", encoding="utf-8")

            copy_package_sources(root, stage)
            assert (stage / "README.md").read_text() == README_TEXT
            assert (stage / "LICENSE").read_text() == LICENSE_TEXT
            assert (stage / "THIRD_PARTY_NOTICES.md").read_text() == (
                NOTICES_TEXT
            )
            assert (stage / "Extra/collect.py").read_text() == COLLECT_TEXT
            assert (stage / "Docs/Build.md").read_text() == DOC_TEXT
            assert not (stage / "Extra/OCLP-LICENSE.txt").exists()

    @staticmethod
    def test_optional_reference_notice_is_preserved_when_present() -> None:
        """Retain a checked-out OCLP license without fetching it."""
        with TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            stage = Path(directory) / "stage"
            (root / "tools").mkdir(parents=True)
            (root / "docs").mkdir()
            (stage / "Extra").mkdir(parents=True)
            for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
                _ = (root / name).write_text(name, encoding="utf-8")
            _ = (root / "tools/collect.py").write_text(
                "collect", encoding="utf-8"
            )
            notice = root / ".research/OpenCore-Legacy-Patcher/LICENSE.txt"
            notice.parent.mkdir(parents=True)
            _ = notice.write_text(OCLP_TEXT, encoding="utf-8")
            copy_package_sources(root, stage)
            assert (stage / "Extra/OCLP-LICENSE.txt").read_text() == (OCLP_TEXT)
