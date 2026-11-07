# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Exercise real validator failure paths and offline language execution."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import TYPE_CHECKING
import unittest
from unittest import mock

from tools import validate as validator

if TYPE_CHECKING:
    from collections.abc import Callable

CHILD_FAILURE = 7
EXPECTED_SKIP = "skipped"
EXPECTED_FAIL = "fail"
EXPECTED_TIMEOUT = "timed out"
OUTSIDE = "Outside repository"
SHORT_TIMEOUT = 0.01
PYTHON_FAILURE = """\
import unittest
class Failure(unittest.TestCase):
    def test_failure(self):
        self.fail('intentional fixture failure')
"""


def _rejects(action: Callable[[], object], message: str) -> bool:
    try:
        _ = action()
    except ValueError as error:
        return message in str(error)
    return False


def _root(directory: str) -> Path:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir()
    (root / "tests").mkdir()
    _ = (root / "tests/__init__.py").write_text("", encoding="utf-8")
    return root


def _cache(root: Path, entry: object) -> None:
    path = root / ".cache/validate/cache.json"
    path.parent.mkdir(parents=True)
    payload = {"schema": validator.CACHE_VERSION, "entries": {"item": entry}}
    _ = path.write_text(json.dumps(payload), encoding="utf-8")


class CacheValidation(unittest.TestCase):
    """Reject malformed cache values while retaining actual failure results."""

    @staticmethod
    def test_unhashable_status_is_rejected() -> None:
        """Reject malformed status containers without a cache-reading crash."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _cache(root, {"fingerprint": "x", "status": [], "diagnostics": []})
            assert validator.read_cache(root) == {}

    @staticmethod
    def test_failed_result_remains_failed() -> None:
        """Keep failure state and diagnostics when loading a valid cache."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            entry = {
                "fingerprint": "x",
                "status": "fail",
                "diagnostics": ["bad"],
            }
            _cache(root, entry)
            assert validator.read_cache(root)["item"] == entry

    @staticmethod
    def test_invalid_json_is_ignored() -> None:
        """Recover safely from interrupted cache serialization."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _cache(root, None)
            path = root / ".cache/validate/cache.json"
            _ = path.write_text("{", encoding="utf-8")
            assert validator.read_cache(root) == {}


class SourceDiscovery(unittest.TestCase):
    """Protect source boundaries without hiding explicit unsupported inputs."""

    @staticmethod
    def test_path_outside_repository_is_rejected() -> None:
        """Reject traversal even when the requested path does not exist."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            assert _rejects(
                lambda: validator.source_files(root, ("../escape.py",)), OUTSIDE
            )

    @staticmethod
    def test_source_alias_outside_repository_is_rejected() -> None:
        """Resolve symlinks before admitting files to a check."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = _root(str(parent / "repo"))
            outside = parent / "outside.py"
            _ = outside.write_text("", encoding="utf-8")
            (root / "src/alias.py").symlink_to(outside)
            assert _rejects(
                lambda: validator.source_files(root, ("src/alias.py",)), OUTSIDE
            )

    @staticmethod
    def test_explicit_unknown_extension_is_rejected() -> None:
        """Avoid an apparently successful validation that checked no source."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "notes.txt").write_text("text", encoding="utf-8")
            assert _rejects(
                lambda: validator.source_files(root, ("notes.txt",)),
                "Unsupported",
            )


class HostProcesses(unittest.TestCase):
    """Propagate failure, terminate timeouts and bound diagnostic memory."""

    @staticmethod
    def test_nonzero_status_is_preserved() -> None:
        """Keep the real child exit status."""
        result = validator.run_process(
            [sys.executable, "-c", f"raise SystemExit({CHILD_FAILURE})"],
            cwd=Path.cwd(),
        )
        assert result.code == CHILD_FAILURE

    @staticmethod
    def test_timeout_is_failure() -> None:
        """Terminate a stalled child and return an explicit failure."""
        result = validator.run_process(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=Path.cwd(),
            seconds=SHORT_TIMEOUT,
        )
        assert result.code != 0
        assert EXPECTED_TIMEOUT in result.stderr

    @staticmethod
    def test_output_is_bounded() -> None:
        """Read only the configured output budget after the child exits."""
        length = validator.OUTPUT_LIMIT * 2
        result = validator.run_process(
            [
                sys.executable,
                "-c",
                f"import sys; sys.stdout.write('x'*{length})",
            ],
            cwd=Path.cwd(),
        )
        assert result.code == 0
        assert len(result.stdout) == validator.OUTPUT_LIMIT


class PythonExecution(unittest.TestCase):
    """Distinguish missing tests, empty modules and actual test failures."""

    @staticmethod
    def test_no_tests_is_skipped() -> None:
        """Report absence explicitly instead of claiming successful testing."""
        with tempfile.TemporaryDirectory() as directory:
            results = validator.run_tests(_root(directory))
            assert results[0]["status"] == EXPECTED_SKIP

    @staticmethod
    def test_empty_module_is_skipped() -> None:
        """Reject a zero-test unittest discovery as an executed pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_empty.py").write_text("", encoding="utf-8")
            assert validator.run_tests(root)[0]["status"] == EXPECTED_SKIP

    @staticmethod
    def test_python_failure_is_not_a_pass() -> None:
        """Propagate unittest assertions from the isolated test process."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_bad.py").write_text(
                PYTHON_FAILURE, encoding="utf-8"
            )
            assert validator.run_tests(root)[0]["status"] == EXPECTED_FAIL


class NativeExecution(unittest.TestCase):
    """Compile real host fixtures and check language/exit failure handling."""

    @staticmethod
    def test_missing_compiler_is_skipped() -> None:
        """Keep unavailable compiler support separate from a native pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_missing.cpp").write_text(
                "int main() {}", encoding="utf-8"
            )
            with mock.patch(
                f"{validator.__name__}.shutil.which", return_value=None
            ):
                assert validator.run_tests(root)[0]["status"] == EXPECTED_SKIP

    def test_cpp_runtime_failure_is_not_a_pass(self) -> None:
        """Propagate a nonzero exit from a successfully compiled host test."""
        if shutil.which("clang++") is None:
            self.skipTest("Installed clang++ required for host fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = f"int main() {{ return {CHILD_FAILURE}; }}"
            _ = (root / "tests/test_bad.cpp").write_text(
                source, encoding="utf-8"
            )
            assert validator.run_tests(root)[0]["status"] == EXPECTED_FAIL

    def test_cpp_compiler_failure_is_not_a_pass(self) -> None:
        """Keep compile diagnostics when a native test cannot be built."""
        if shutil.which("clang++") is None:
            self.skipTest("Installed clang++ required for host fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_bad.cpp").write_text(
                "#error intentional", encoding="utf-8"
            )
            assert validator.run_tests(root)[0]["status"] == EXPECTED_FAIL

    def test_companion_cannot_escape_repository(self) -> None:
        """Reject escaping additional source paths before compilation."""
        if shutil.which("clang++") is None:
            self.skipTest("Installed clang++ required for host fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_bad.cpp").write_text(
                "int main() {}", encoding="utf-8"
            )
            _ = (root / "tests/test_bad.sources").write_text(
                "../escape.cpp", encoding="utf-8"
            )
            results = validator.run_tests(root)
            assert results[0]["status"] == EXPECTED_FAIL
            assert OUTSIDE in results[0]["diagnostics"][0]


class DefaultCliOptions(unittest.TestCase):
    """Keep CLI defaults aligned with the configured validation policy."""

    @staticmethod
    def test_all_checks_and_json_are_enabled_without_flags() -> None:
        """The CLI must not override true Options defaults with false flags."""
        with mock.patch.object(sys, "argv", ["validate.py"]):
            options = validator.parse_options()
        assert options.tidy
        assert options.tests
        assert options.json_output
        assert options.files == ()
        assert not options.no_cache

    @staticmethod
    def test_opt_out_flags_are_explicit_and_independent() -> None:
        """Permit each opt-out without silently disabling another check."""
        for flag, field in (
            ("--no-tidy", "tidy"),
            ("--no-tests", "tests"),
            ("--no-json", "json_output"),
        ):
            with mock.patch.object(sys, "argv", ["validate.py", flag]):
                options = validator.parse_options()
            assert getattr(options, field) is False
            assert all(
                getattr(options, other)
                for other in ("tidy", "tests", "json_output")
                if other != field
            )
        with mock.patch.object(
            sys,
            "argv",
            ["validate.py", "--no-tidy", "--no-tests", "--no-json"],
        ):
            options = validator.parse_options()
        assert not options.tidy
        assert not options.tests
        assert not options.json_output

    @staticmethod
    def test_explicit_flags_and_files_preserve_cli_contract() -> None:
        """The previous positive flags remain accepted alongside file paths."""
        with mock.patch.object(
            sys,
            "argv",
            [
                "validate.py",
                "--tidy",
                "--tests",
                "--json",
                "--no-cache",
                "tools/validate.py",
            ],
        ):
            options = validator.parse_options()
        assert options.files == ("tools/validate.py",)
        assert options.tidy
        assert options.tests
        assert options.json_output
        assert options.no_cache


class LinuxReferenceExclusion(unittest.TestCase):
    """Exclude the local Linux source snapshot from all validator inputs."""

    @staticmethod
    def test_auto_discovery_does_not_lint_linux_reference_sources() -> None:
        """Never count vendor/reference Linux sources as validated files."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            linux = root / "linux"
            linux.mkdir()
            _ = (linux / "reference.py").write_text("not owned source")
            owned = root / "src" / "owned.py"
            _ = owned.write_text("import sys")
            with mock.patch.object(
                validator,
                "_inventory",
                return_value=["src/owned.py", "linux/reference.py"],
            ):
                assert validator.source_files(root, ()) == [owned]

    @staticmethod
    def test_explicit_linux_path_is_not_silent_success() -> None:
        """Reject even an explicit source path beneath ignored linux/."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            linux = root / "linux"
            linux.mkdir()
            _ = (linux / "reference.py").write_text("not owned source")
            assert _rejects(
                lambda: validator.source_files(root, ("linux/reference.py",)),
                "Ignored Linux reference directory",
            )
