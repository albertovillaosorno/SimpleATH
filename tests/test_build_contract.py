# Copyright (c) 2026 SimpleATH contributors.
"""Offline source-tree contract checks for the opt-in legacy build helper."""

from dataclasses import dataclass
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

# The opt-in legacy CLI imports helpers directly from tools/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from build import PROJECT
from build import copy_package_sources
from build import fragment
from build import native_addresses
from build import package_name
from build import reference_relocations
from build import require_invariant
from build import vtable_rows

LICENSE_TEXT = "LICENSE"
README_TEXT = "README.md"
NOTICES_TEXT = "THIRD_PARTY_NOTICES.md"
COLLECT_TEXT = "collect"
DOC_TEXT = "docs"
OCLP_TEXT = "OCLP sample license"


@dataclass(frozen=True, slots=True)
class _FakeExportImage:
    """Synthetic public and private native symbol table."""

    symbols: dict[str, int]
    exports: set[str]


@dataclass(frozen=True, slots=True)
class _FakeExportCollection:
    """Kernel and library exports for a source-only import fixture."""

    kernel: _FakeExportImage
    images: dict[str, _FakeExportImage]


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
    def test_package_name_resolves_only_installed_git_command() -> None:
        """Require local git resolution before generating a prerelease name."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "mock-tool"
            _ = path.write_text(
                "synthetic executable fixture", encoding="utf-8"
            )
            commit = "a" * 40
            git_tool = "git"
            with (
                patch("build.os.environ.get", return_value=None),
                patch("build.shutil.which", return_value=str(path)),
                patch(
                    "build.subprocess.check_output", return_value=commit
                ) as run,
            ):
                name = package_name("Debug", "pre")
            assert name.endswith("-alpha-aaaaaaa")
            assert run.call_args.args[0][0] == str(path.resolve())
            with (
                patch("build.os.environ.get", return_value=None),
                patch("build.shutil.which", return_value=None),
            ):
                rejected = False
                try:
                    _ = package_name("Debug", "pre")
                except FileNotFoundError as error:
                    rejected = git_tool in str(error)
                assert rejected

    @staticmethod
    def test_native_imports_require_public_kernel_exports() -> None:
        """Private nlist definitions cannot masquerade as linkable imports."""
        kernel = _FakeExportImage(
            symbols={"_public": 0x1000, "_private": 0x2000},
            exports={"_public"},
        )
        wifi = _FakeExportImage(
            symbols={"_wifi": 0x3000, "_wifi_private": 0x4000},
            exports={"_wifi"},
        )
        collection = _FakeExportCollection(
            kernel=kernel,
            images={"wifi": wifi},
        )
        assert native_addresses(collection, ["wifi", "missing"]) == {
            "_public": 0x1000,
            "_wifi": 0x3000,
        }

    @staticmethod
    def test_fragments_preserve_required_and_optional_load_order() -> None:
        """Keep the original OpenCore load order for each packaging mode."""
        assert [row["BundlePath"] for row in fragment()["Kernel"]["Add"]] == [
            "SimpleATH.kext"
        ]
        assert [
            row["BundlePath"]
            for row in fragment(optional=True)["Kernel"]["Add"]
        ] == [
            "Lilu.kext",
            "AirportBrcmFixup.kext",
            "SimpleATH.kext",
            "AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext",
        ]

    @staticmethod
    def test_runtime_invariant_preserves_failure_only_diagnostics() -> None:
        """Evaluate diagnostic details only when an invariant fails."""
        evaluated: list[str] = []
        expected = "source invariant failed"

        def evidence() -> str:
            evaluated.append("failure")
            return expected

        require_invariant(len(evaluated) == 0, evidence)
        assert not evaluated
        failure_message = ""
        try:
            require_invariant(len(evaluated) > 0, evidence)
        except AssertionError as error:
            failure_message = str(error)
        assert failure_message == expected
        assert evaluated == ["failure"]

    @staticmethod
    def test_vtable_guards_refuse_malformed_manifest_rows() -> None:
        """Reject incomplete, oversized and incorrectly typed ABI guards."""
        assert vtable_rows([["_class", 24, "_method"]]) == [
            ("_class", 24, "_method")
        ]
        for malformed in (
            [["_class", 24]],
            [["_class", 24, "_method", "surplus"]],
            [["_class", "24", "_method"]],
            [["_class", True, "_method"]],
            [[0, 24, "_method"]],
        ):
            rejected = False
            try:
                _ = vtable_rows(malformed)
            except TypeError, ValueError:
                rejected = True
            assert rejected

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
            notice = root / ".references/OpenCore-Legacy-Patcher/LICENSE.txt"
            notice.parent.mkdir(parents=True)
            _ = notice.write_text(OCLP_TEXT, encoding="utf-8")
            copy_package_sources(root, stage)
            assert (stage / "Extra/OCLP-LICENSE.txt").read_text() == (OCLP_TEXT)


class RelocationVerifierPreflightTests(TestCase):
    """Synthetic Mach-O metadata validation does not execute build commands."""

    @staticmethod
    def test_checked_external_and_local_relocations() -> None:
        """Accept exactly two fully encoded relocations with stable order."""
        external = (3 << 25) | (1 << 27)
        local = 3 << 25
        data = struct.pack("<iIiI", 4, external, 12, local)
        fields = [0] * 18
        fields[14:18] = [0, 1, 8, 1]
        command = bytearray(struct.pack("<II18I", 11, 80, *fields))
        assert reference_relocations(data, [(11, command)], symbol_count=1) == [
            (True, 4, external),
            (False, 12, local),
        ]

    @staticmethod
    def test_reject_ambiguous_or_unsafe_reference_relocations() -> None:
        """Fail closed on absent, duplicate, truncated and corrupt records."""
        fields = [0] * 18
        fields[14:18] = [0, 1, 8, 1]
        command = bytearray(struct.pack("<II18I", 11, 80, *fields))
        external = (3 << 25) | (1 << 27)
        valid = struct.pack("<iIiI", 4, external, 12, 3 << 25)
        cases: tuple[tuple[bytes, list[tuple[int, bytearray]]], ...] = (
            (valid, []),
            (valid, [(11, command), (11, command)]),
            (valid, [(11, command[:-1])]),
            (valid[:8], [(11, command)]),
            (
                struct.pack("<iIiI", 4, external | 1, 12, 3 << 25),
                [(11, command)],
            ),
            (struct.pack("<iIiI", -4, external, 12, 3 << 25), [(11, command)]),
            (struct.pack("<iIiI", 4, 3 << 25, 12, 3 << 25), [(11, command)]),
        )
        for data, commands in cases:
            rejected = False
            try:
                _ = reference_relocations(data, commands, symbol_count=1)
            except ValueError:
                rejected = True
            assert rejected
