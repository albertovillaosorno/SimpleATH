# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic source-only compilation database generation regressions."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from tools import generate_compile_commands as generator

EXPECTED_FILE_ENTRY = b'"file": "src/portable.cpp"'


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
                assert command["directory"] == str(root.resolve())
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
