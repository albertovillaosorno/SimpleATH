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
#   - Offline regression cases for compile commands.
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
#   - Offline regression cases for compile commands.
# - Description:
#   - Implements or verifies the test_compile_commands source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for compile commands.
"""Synthetic source-only compilation database generation regressions."""

from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import mock

from tools import generate_compile_commands as generator

EXPECTED_FILE_ENTRY = b'"file": "src/portable.cpp"'


def _fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    """Create fake, local SDK metadata without downloading dependencies.

    Returns:
        SDK header root, libc++ include roots and a fake compiler path.

    """
    sdk = root / ".references/MacKernelSDK/Headers"
    library = root / "compiler/include/c++/v1"
    config = root / "compiler/include/x86_64-linux/c++/v1"
    compiler = root / "compiler/bin/clang++"
    for path in (
        sdk / "IOKit/IOLib.h",
        library / "placeholder",
        config / "__config_site",
        compiler,
        root / "src/SimpleATH.cpp",
        root / "src/platform/probe/main.mm",
        root / "tests/test_fixture.cpp",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_text("", encoding="utf-8")
    return sdk, library, config, compiler


class SourceOnlyCompileCommandsTests(TestCase):
    """Keep host Tidy commands distinct from native kext build commands."""

    @staticmethod
    def test_source_entries_are_explicit_and_portable_in_source_scope() -> None:
        """Keep parse flags aligned with source and host C++ dialects."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = (
                "src/hardware/board.cpp",
                "src/platform/probe/main.mm",
                "tests/test_fixture.cpp",
                "tools/host.cpp",
                "linux/ath9k/ignored.cpp",
            )
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                _ = path.write_text("// fixture\n", encoding="utf-8")
            commands = generator.source_commands(root)
            assert [entry["file"] for entry in commands] == sorted(names[:4])
            for command in commands:
                arguments = command["arguments"]
                assert command["directory"] == "."
                standard = (
                    "-std=c++17"
                    if command["file"].startswith(("tests/", "tools/"))
                    else "-std=c++14"
                )
                language = (
                    "objective-c++"
                    if command["file"].endswith(".mm")
                    else "c++"
                )
                assert arguments == [
                    "clang++",
                    standard,
                    "-I",
                    "src",
                    "-x",
                    language,
                    "-fsyntax-only",
                    command["file"],
                ]

    @staticmethod
    def test_installed_macos_kernel_sdk_enables_real_darwin_parse_flags() -> (
        None
    ):
        """Keep optional SDK headers out of portable tests and probe tools."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, _, _, compiler = _fixture(root)
            with (
                mock.patch.object(sys, "platform", "linux"),
                mock.patch.object(shutil, "which", return_value=str(compiler)),
            ):
                commands = {
                    entry["file"]: entry["arguments"]
                    for entry in generator.source_commands(root)
                }
            expected_flags = [
                "-DKERNEL=1",
                "-target",
                generator.DARWIN_TARGET,
                "-isystem",
                ".cache/clang-tidy/libcxx",
                "-isystem",
                ".cache/clang-tidy/libcxx-site",
                "-isystem",
                ".references/MacKernelSDK/Headers",
            ]
            assert commands["src/SimpleATH.cpp"][4:-4] == expected_flags
            assert commands["src/platform/probe/main.mm"][4:-4] == []
            assert commands["tests/test_fixture.cpp"][4:-4] == []
            native_sdk = root / "native-sdk"
            with (
                mock.patch.object(sys, "platform", "darwin"),
                mock.patch.dict("os.environ", {"SDKROOT": str(native_sdk)}),
            ):
                macos = {
                    entry["file"]: entry["arguments"]
                    for entry in generator.source_commands(root)
                }
            assert macos["src/SimpleATH.cpp"][4:-4] == [
                "-DKERNEL=1",
                "-isysroot",
                ".cache/clang-tidy/sdkroot",
                "-isystem",
                ".cache/clang-tidy/sdkroot/System/Library/Frameworks/Kernel.framework/Headers",
            ]
            assert str(sdk) not in macos["src/SimpleATH.cpp"]

    @staticmethod
    def test_regeneration_stays_below_root_and_is_deterministic() -> None:
        """Refresh absolute locations without invoking a compiler or build."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            _ = (root / "src/portable.cpp").write_text(
                "// fixture\n", encoding="utf-8"
            )
            target = generator.write_database(root)
            initial = target.read_bytes()
            assert generator.write_database(root) == target
            assert target.read_bytes() == initial
            assert EXPECTED_FILE_ENTRY in initial
            assert target.parent == root.resolve()
            assert sorted(file.name for file in root.iterdir()) == [
                "compile_commands.json",
                "src",
            ]

    @staticmethod
    def test_symlinked_sources_are_not_admitted() -> None:
        """An external source reached by symlink must not enter the database."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            outside = root / "reference.cpp"
            _ = outside.write_text("// external\n", encoding="utf-8")
            (root / "src/alias.cpp").symlink_to(outside)
            assert generator.source_commands(root) == []
