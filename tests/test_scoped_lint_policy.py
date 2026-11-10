# Copyright (c) 2026 SimpleATH contributors.
"""Guard meaningful lint isolation for production, fixtures and tooling."""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tempfile
import tomllib
from typing import cast
import unittest
from unittest import mock

from tools import validate

ROOT = Path(__file__).resolve().parent.parent
TIDY_TOOL = "clang-tidy"
SOURCE_POLICY = ".clang-tidy"
TEST_POLICY = "tests/.clang-tidy"
TOOL_POLICY = "tools/.clang-tidy"
SAFETY_CHECK = "bugprone-use-after-move"
ANALYZER_CHECK = "clang-analyzer-core.CallAndMessage"
COSMETIC_CHECK = "modernize-use-auto"
READABILITY_CHECK = "readability-magic-numbers"


class ScopedLintPolicy(unittest.TestCase):
    """Tests and tools can differ stylistically without hiding errors."""

    @staticmethod
    def test_tidy_resolves_per_directory_and_preserves_safety_rules() -> None:
        """Scoped C++ checks inherit safety gates and warnings-as-errors."""
        compiler = shutil.which(TIDY_TOOL)
        assert compiler is not None, "Clang-Tidy is mandatory"
        samples = (
            ("src/platform/Kernel.cpp", SOURCE_POLICY, True),
            ("tests/test_driver.cpp", TEST_POLICY, False),
            ("tools/checker.cpp", TOOL_POLICY, False),
        )
        for name, policy, is_source in samples:
            source = ROOT / name
            command = validate._command(  # pyright: ignore[reportPrivateUsage]
                TIDY_TOOL, source, ROOT
            )
            assert command is not None
            assert f"--config-file={ROOT / policy}" in command
            result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                [compiler, "-list-checks", f"--config-file={ROOT / policy}"],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=20,
            )
            assert result.returncode == 0, result.stderr
            rules = set(result.stdout.split())
            assert SAFETY_CHECK in rules
            assert ANALYZER_CHECK in rules
            assert (COSMETIC_CHECK in rules) is is_source
            assert (READABILITY_CHECK in rules) is is_source
            assert "WarningsAsErrors: '*'" in (ROOT / policy).read_text() or (
                is_source is False
                and "WarningsAsErrors: '*'"
                in (ROOT / SOURCE_POLICY).read_text()
            )

    @staticmethod
    def test_scoped_policy_change_invalidates_cached_tidy_checks() -> None:
        """Never reuse stale Clang-Tidy verdict after scoped policy edit."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for config in validate.CONFIGS[TIDY_TOOL]:
                path = root / config
                path.parent.mkdir(parents=True, exist_ok=True)
                _ = path.write_text("root policy", encoding="utf-8")
            source = root / "tests/check.cpp"
            source.parent.mkdir(exist_ok=True)
            _ = source.write_text("void check() {}", encoding="utf-8")
            policy = root / TEST_POLICY
            _ = policy.write_text(
                "InheritParentConfig: true\n", encoding="utf-8"
            )
            argv = ["clang-tidy", str(source)]
            with mock.patch.object(
                validate, "_version", return_value="fixture"
            ):
                previous = validate._signature(  # pyright: ignore[reportPrivateUsage]
                    argv, source, root, context=(TIDY_TOOL, b"headers")
                )
                _ = policy.write_text(
                    "InheritParentConfig: true\nChecks: '-readability-*'\n",
                    encoding="utf-8",
                )
                changed = validate._signature(  # pyright: ignore[reportPrivateUsage]
                    argv, source, root, context=(TIDY_TOOL, b"headers")
                )
            assert previous != changed

    @staticmethod
    def test_full_run_snapshot_changes_with_scoped_policy() -> None:
        """Concurrent validation never reuses an old test/tool rule snapshot."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/check.cpp"
            source.parent.mkdir()
            _ = source.write_text("void check() {}", encoding="utf-8")
            (root / "tests").mkdir()
            policy = root / TEST_POLICY
            _ = policy.write_text("Checks: '-readability-*'", encoding="utf-8")
            previous = validate.input_snapshot(root, [source])
            _ = policy.write_text("Checks: '-modernize-*'", encoding="utf-8")
            assert previous != validate.input_snapshot(root, [source])

    @staticmethod
    def test_ruff_enforces_safety_but_not_fixture_style() -> None:
        """Execute real Ruff on synthetic fixture and production snippets."""
        ruff = shutil.which("ruff")
        assert ruff is not None, "Ruff is required"
        source = "def fixture(value):\n    return value == 42\n"
        for target, passes in (
            ("tests/test_fixture.py", True),
            ("src/fixture.py", False),
        ):
            result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                [
                    ruff,
                    "check",
                    "--config",
                    str(ROOT / "ruff.toml"),
                    "--select",
                    "D,PLR2004",
                    "--stdin-filename",
                    target,
                    "-",
                ],
                input=source,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=20,
            )
            assert (result.returncode == 0) is passes, result.stdout
        bug = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            [
                ruff,
                "check",
                "--config",
                str(ROOT / "ruff.toml"),
                "--select",
                "F821",
                "--stdin-filename",
                "tests/test_fixture.py",
                "-",
            ],
            input="print(undefined_fixture_name)\n",
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=20,
        )
        assert bug.returncode != 0
        assert "Undefined name" in bug.stdout

    @staticmethod
    def test_missing_scope_uses_strict_root_tidy() -> None:
        """Absent scoped config must fall back to source policy."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _ = (root / SOURCE_POLICY).write_text("Checks: '*'\n")
            (root / "tests").mkdir()
            assert (
                validate._tidy_config(  # pyright: ignore[reportPrivateUsage]
                    root, root / "tests/test_driver.cpp"
                )
                == root / SOURCE_POLICY
            )

    @staticmethod
    def test_ruff_relaxes_style_only_outside_production() -> None:
        """Ruff syntax, bug and security rules stay active everywhere."""
        with (ROOT / "ruff.toml").open("rb") as stream:
            config = cast("dict[str, dict[str, object]]", tomllib.load(stream))
        lint = config["lint"]
        overrides = cast("dict[str, list[str]]", lint["per-file-ignores"])
        assert lint["select"] == ["ALL"]
        for path in ("tests/**/*.py", "tools/**/*.py"):
            ignored = set(overrides[path])
            assert "D" in ignored
            assert "PLR2004" in ignored
            for safety in ("F", "B", "S", "ARG", "ASYNC"):
                assert safety not in ignored
        assert "assert" in overrides["tests/**/*.py"]
        assert "assert" not in overrides["tools/**/*.py"]


if __name__ == "__main__":
    _ = unittest.main()
