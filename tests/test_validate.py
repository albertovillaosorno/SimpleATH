# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Exercise real validator failure paths and offline language execution."""

from contextlib import redirect_stderr
from contextlib import redirect_stdout
import fcntl
import io
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
SHARED_DIGEST = b"shared"
EXPECTED_TIMEOUT = "timed out"
FULL_SCOPE_FRAGMENT = '"scope": "repository"'
ONE_FAILURE_FRAGMENT = '"fail": 1'
SNAPSHOT_FAILURE_FRAGMENT = '"tool": "source-snapshot"'
MISSING_COMPILE_ENTRY = "No matching compile command"
OUTSIDE = "Outside repository"
SHORT_TIMEOUT = 0.01
ARGPARSE_FAILURE = 2
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
    def test_repository_dependency_digest_is_shared_within_one_run() -> None:
        """Avoid rehashing all sources for every source-level type check."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            files = (root / "src/first.py", root / "src/second.py")
            for source in files:
                _ = source.write_text("", encoding="utf-8")
            lint = validator.LintRun(root, validator.Options(), {})
            with (
                mock.patch.object(
                    validator, "_dependencies", return_value=SHARED_DIGEST
                ) as dependencies,
                mock.patch.object(
                    validator, "_signature", return_value="sig"
                ) as signature,
                mock.patch.dict(validator.CONFIGS, {"basedpyright": ()}),
                mock.patch.object(
                    validator, "_command", return_value=[sys.executable]
                ),
                mock.patch.object(
                    validator,
                    "run_process",
                    return_value=validator.Process(0, "", ""),
                ),
            ):
                for source in files:
                    result = lint.check(source, "basedpyright")
                    assert result["status"] == validator.STATUS_OK
            dependencies.assert_called_once_with(root)
            assert signature.call_count == len(files)
            assert all(
                call.kwargs["context"] == ("basedpyright", SHARED_DIGEST)
                for call in signature.call_args_list
            )

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
    def test_incomplete_git_inventory_fails_closed() -> None:
        """Do not count a truncated -z response as all repository sources."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            for output in ("src/example.py", "x" * validator.OUTPUT_LIMIT):
                with mock.patch.object(
                    validator,
                    "run_process",
                    return_value=validator.Process(0, output, ""),
                ):
                    assert _rejects(
                        lambda: validator.source_files(root, ()),
                        "Incomplete git source inventory",
                    )
            source = root / "src/example.py"
            _ = source.write_text("", encoding="utf-8")
            with mock.patch.object(
                validator,
                "run_process",
                return_value=validator.Process(0, "src/example.py\0", ""),
            ):
                assert validator.source_files(root, ()) == [source]

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


class ClangTidyDatabase(unittest.TestCase):
    """A present database must not turn a silent Tidy skip into a pass."""

    @staticmethod
    def test_usable_command_must_match_the_checked_source() -> None:
        """Reject stale, relative-workdir and commandless source entries."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            file = root / "src/radio.cpp"
            _ = file.write_text("int radio;", encoding="utf-8")
            database = root / "compile_commands.json"
            command = {
                "directory": str(root),
                "file": "src/radio.cpp",
                "arguments": ["clang++", "-fsyntax-only", "src/radio.cpp"],
            }
            _ = database.write_text(json.dumps([command]), encoding="utf-8")
            assert validator.tidy_command_exists(root, file)
            for replacement in (
                {**command, "directory": "."},
                {**command, "directory": str(root / "moved")},
                {**command, "arguments": []},
                {**command, "file": "src/other.cpp"},
            ):
                _ = database.write_text(
                    json.dumps([replacement]), encoding="utf-8"
                )
                assert not validator.tidy_command_exists(root, file)
            _ = database.write_text("{", encoding="utf-8")
            assert not validator.tidy_command_exists(root, file)

    @staticmethod
    def test_unmatched_command_is_skipped_without_running_tidy() -> None:
        """A Clang-Tidy exit zero cannot conceal a missing translation unit."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            file = root / "src/radio.cpp"
            _ = file.write_text("int radio;", encoding="utf-8")
            _ = (root / "compile_commands.json").write_text(
                "[]", encoding="utf-8"
            )
            for config in (".clang-tidy", ".editorconfig"):
                _ = (root / config).write_text("", encoding="utf-8")
            with (
                mock.patch.object(
                    validator, "_command", return_value=[sys.executable]
                ),
                mock.patch.object(validator.LintRun, "_check_ready") as ready,
            ):
                finding = validator.LintRun(
                    root, validator.Options(), {}
                ).check(file, "clang-tidy")
            assert finding["status"] == EXPECTED_SKIP
            assert MISSING_COMPILE_ENTRY in finding["diagnostics"][0]
            ready.assert_not_called()


def _sample_finding(
    file: str,
    tool: str,
    status: validator.Status,
    *,
    details: tuple[str, ...] = (),
) -> validator.Finding:
    """Construct a finding without invoking an installed tool.

    Returns:
        A synthetic check result.

    """
    return {
        "file": file,
        "tool": tool,
        "status": status,
        "cached": False,
        "diagnostics": list(details),
    }


class CompactReports(unittest.TestCase):
    """Only actionable findings are shown; summary retains pass counts."""

    @staticmethod
    def test_report_keeps_every_failure_and_skip_including_cache_hits() -> None:
        """Count checks while preserving each non-pass result."""
        passed = _sample_finding("src/clean.cpp", "clang-format", "pass")
        failed = _sample_finding(
            "src/bad.cpp",
            "clang-tidy",
            "fail",
            details=("bad header",),
        )
        failed["cached"] = True
        skipped = _sample_finding(
            "tools/missing.py",
            "basedpyright",
            "skipped",
            details=("tool absent",),
        )
        newer = _sample_finding(
            "tests/test_bad.py",
            "host-test",
            "fail",
            details=("assertion",),
        )
        report = validator.build_report(
            [passed, failed, skipped, newer],
            files=3,
            tests=True,
            tools={},
        )
        assert report["summary"] == {
            "files": 3,
            "checks": 4,
            "cached": 1,
            "executed": 2,
            "pass": 1,
            "fail": 2,
            "skipped": 1,
        }
        assert report["results"] == [failed, skipped, newer]
        assert failed["cached"]
        assert failed["diagnostics"] == ["bad header"]


class FullRepositoryRun(unittest.TestCase):
    """Ensure the shared report cannot omit checks or race between agents."""

    @staticmethod
    def test_snapshot_tracks_source_rules_and_native_manifests() -> None:
        """A source or test-build input change invalidates the same report."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/example.py"
            rule = root / ".clang-tidy"
            manifest = root / "tests/test_native.sources"
            _ = source.write_text("before", encoding="utf-8")
            _ = rule.write_text("rule-1", encoding="utf-8")
            _ = manifest.write_text("src/example.py", encoding="utf-8")
            initial = validator.input_snapshot(root, [source])
            _ = manifest.write_text("src/other.cpp", encoding="utf-8")
            manifest_changed = validator.input_snapshot(root, [source])
            assert initial != manifest_changed
            _ = rule.write_text("rule-2", encoding="utf-8")
            rules_changed = validator.input_snapshot(root, [source])
            assert manifest_changed != rules_changed
            _ = source.write_text("after", encoding="utf-8")
            assert rules_changed != validator.input_snapshot(root, [source])

    @staticmethod
    def test_source_edit_during_validation_fails_report() -> None:
        """Never publish an apparent clean pass from mixed source revisions."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/example.py"
            _ = source.write_text("before", encoding="utf-8")
            host = _sample_finding("tests/test_fake.py", "host-test", "pass")

            def edit_during_tests(
                working_root: Path,
            ) -> list[validator.Finding]:
                _ = (working_root / "src/example.py").write_text(
                    "after", encoding="utf-8"
                )
                return [host]

            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "src/example.py", "ruff", "pass"
                    ),
                ),
                mock.patch.object(
                    validator, "run_tests", side_effect=edit_during_tests
                ),
                mock.patch.object(validator, "_version", return_value="test"),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 1
            report = (root / ".cache/validate/report.json").read_text()
            assert FULL_SCOPE_FRAGMENT in report
            assert ONE_FAILURE_FRAGMENT in report
            assert SNAPSHOT_FAILURE_FRAGMENT in report

    @staticmethod
    def test_new_source_during_validation_fails_report() -> None:
        """Concurrent additions must not disappear from an apparent pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            first = root / "src/first.py"
            added = root / "src/second.py"
            _ = first.write_text("before", encoding="utf-8")

            def add_during_tests(working_root: Path) -> list[validator.Finding]:
                _ = (working_root / "src/second.py").write_text(
                    "added", encoding="utf-8"
                )
                return [
                    _sample_finding("tests/test_fake.py", "host-test", "pass")
                ]

            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator,
                    "source_files",
                    side_effect=[[first], [first, added]],
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "src/first.py", "ruff", "pass"
                    ),
                ),
                mock.patch.object(
                    validator, "run_tests", side_effect=add_during_tests
                ),
                mock.patch.object(validator, "_version", return_value="test"),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 1
            report = (root / ".cache/validate/report.json").read_text()
            assert ONE_FAILURE_FRAGMENT in report
            assert SNAPSHOT_FAILURE_FRAGMENT in report

    @staticmethod
    def test_multiline_tidy_version_is_not_the_llvm_heading() -> None:
        """Report the actual Clang-Tidy version in the tools manifest."""
        llvm_output = "LLVM (http://llvm.org/):\n LLVM version 23.1.2\n0"
        expected = "LLVM version 23.1.2"
        with mock.patch.object(validator, "_version", return_value=llvm_output):
            actual = validator.tool_version("clang-tidy", Path.cwd())
        assert actual == expected

    @staticmethod
    def test_file_arguments_do_not_narrow_scope_or_skip_tidy() -> None:
        """Legacy paths do not suppress discovered files, tools, or tests."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            native = root / "src/driver.cpp"
            python = root / "tools/check.py"
            seen: list[tuple[str, str]] = []

            def checked(file: Path, tool: str) -> validator.Finding:
                seen.append((file.name, tool))
                return _sample_finding(file.name, tool, "pass")

            host = _sample_finding("tests/test_fake.py", "host-test", "pass")
            output = io.StringIO()
            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[native, python]
                ) as discovered,
                mock.patch.object(
                    validator.LintRun, "check", side_effect=checked
                ),
                mock.patch.object(validator, "run_tests", return_value=[host]),
                mock.patch.object(
                    validator, "_version", return_value="fixture"
                ),
                mock.patch.object(
                    sys, "argv", ["validate.py", "src/driver.cpp"]
                ),
                redirect_stdout(output),
            ):
                assert validator.main() == 0
            assert discovered.call_args_list == [
                mock.call(root, ()),
                mock.call(root, ()),
            ]
            assert seen == [
                (native.name, "clang-format"),
                (native.name, "clang-tidy"),
                (python.name, "ruff-check"),
                (python.name, "ruff-format"),
                (python.name, "basedpyright"),
            ]
            report = (root / ".cache/validate/report.json").read_text()
            assert report == output.getvalue()
            expected_tidy = '"clang-tidy"'
            expected_scope = '"scope": "repository"'
            assert expected_tidy in report
            assert expected_scope in report
            expected_results = '"results": []'
            assert expected_results in report

    @staticmethod
    def test_exclusive_lock_covers_shared_cache_write() -> None:
        """A second writer must not hold the validator lock concurrently."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            locked = False

            def inspected(_: validator.Options) -> int:
                nonlocal locked
                path = root / ".cache/validate/run.lock"
                with path.open("a+b") as contender:
                    try:
                        fcntl.flock(
                            contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                    except BlockingIOError:
                        locked = True
                    else:
                        fcntl.flock(contender.fileno(), fcntl.LOCK_UN)
                return 0

            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "_validate", side_effect=inspected
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
            ):
                assert validator.main() == 0
            assert locked


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
    def test_disabled_mandatory_checks_are_rejected() -> None:
        """Do not mutate shared cache/report after reduced-scope flags."""
        for flag in ("--no-tidy", "--no-tests", "--no-json"):
            output = io.StringIO()
            code: int | None = None
            try:
                with (
                    mock.patch.object(sys, "argv", ["validate.py", flag]),
                    redirect_stderr(output),
                ):
                    _ = validator.parse_options()
            except SystemExit as error:
                if isinstance(error.code, int):
                    code = error.code
            assert code == ARGPARSE_FAILURE
            assert flag in output.getvalue()

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
