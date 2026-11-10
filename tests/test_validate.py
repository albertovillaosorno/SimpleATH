# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Exercise real validator failure paths and offline language execution."""

from contextlib import redirect_stderr
from contextlib import redirect_stdout
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from typing import TYPE_CHECKING
from typing import cast
from typing import final
import unittest
from unittest import mock

from tools import validate as validator

if TYPE_CHECKING:
    from collections.abc import Callable

CHILD_FAILURE = 7
EXPECTED_SKIP = "skipped"
EXPECTED_FAIL = "fail"
COMPILER_ERROR_MARKER = ": error:"
SHARED_DIGEST = b"shared"
EXPECTED_TIMEOUT = "timed out"
MISSING_PYTHON_COMPLETION = "without unittest"
INCOMPLETE_TEST_SUITE = "Incomplete unittest suite"
FULL_SCOPE_FRAGMENT = '"scope": "repository"'
ONE_FAILURE_FRAGMENT = '"fail": 1'
SNAPSHOT_FAILURE_FRAGMENT = '"tool": "source-snapshot"'
SOURCE_ONLY_FRAGMENT = '"source_only": true'
TESTS_REQUESTED_FRAGMENT = '"tests_requested": true'
FORBIDDEN_CHECK_OPTIONS = ("--no-tidy", "--no-tests", "--no-json")
MACOS_MISSING_FIXTURE = "'IOKit/IOLib.h' file not found"
MACOS_MODE = "macos"
UNKNOWN_FLAG_CODE = 2
UNKNOWN_LINUX_FLAG = "unrecognized arguments: --linux"
MISSING_COMPILE_ENTRY = "No matching compile command"
OUTSIDE = "Outside repository"
SHORT_TIMEOUT = 0.01
THREAD_TIMEOUT = 8.0
CONCURRENT_AGENTS = 5
PYTHON_SOURCE_AND_HOST_CHECKS = 4
COMPLETED_HOST_SCANS = 2
WAITING_AGENTS = CONCURRENT_AGENTS - 1
SEQUENTIAL_HOST_CALLS = 2
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
    (root / ".git").mkdir()
    (root / "src").mkdir()
    (root / "tests").mkdir()
    _ = (root / "tests/__init__.py").write_text("", encoding="utf-8")
    return root


def _cache(root: Path, entry: object) -> None:
    path = root / ".cache/validate/cache.json"
    path.parent.mkdir(parents=True)
    payload = {"schema": validator.CACHE_VERSION, "entries": {"item": entry}}
    _ = path.write_text(json.dumps(payload), encoding="utf-8")


def _lint_fingerprint(root: Path, file: Path, tool: str) -> str:
    """Get a real per-file cache key with synthetic offline tool success.

    Returns:
        Content-addressed cache key for the selected source/linter pair.

    """
    for config in validator.CONFIGS[tool]:
        _ = (root / config).write_text("fixture", encoding="utf-8")
    cache_key = file.relative_to(root).as_posix() + "::" + tool
    with (
        mock.patch.object(validator, "_command", return_value=[sys.executable]),
        mock.patch.object(validator, "_version", return_value="fixture"),
        mock.patch.object(validator, "tidy_command_exists", return_value=True),
        mock.patch.object(
            validator, "run_process", return_value=validator.Process(0, "", "")
        ),
    ):
        lint = validator.LintRun(root, validator.Options(), {})
        finding = lint.check(file, tool)
        assert finding["status"] == validator.STATUS_OK
        return lint.entries[cache_key]["fingerprint"]


def _lint_failure_diagnostics(text: str) -> list[str]:
    """Exercise native diagnostics through the public lint-check boundary.

    Returns:
        Bounded details from a synthetic Clang-Tidy failure.

    """
    with tempfile.TemporaryDirectory() as directory:
        root = _root(directory)
        source = root / "src/driver.cpp"
        _ = source.write_text("int driver;", encoding="utf-8")
        for config in validator.CONFIGS["clang-tidy"]:
            _ = (root / config).write_text("fixture", encoding="utf-8")
        with (
            mock.patch.object(
                validator, "_command", return_value=[sys.executable]
            ),
            mock.patch.object(validator, "_version", return_value="fixture"),
            mock.patch.object(
                validator, "tidy_command_exists", return_value=True
            ),
            mock.patch.object(
                validator, "_dependencies", return_value=SHARED_DIGEST
            ),
            mock.patch.object(
                validator,
                "run_process",
                return_value=validator.Process(1, text, ""),
            ),
        ):
            finding = validator.LintRun(root, validator.Options(), {}).check(
                source, "clang-tidy"
            )
        assert finding["status"] == EXPECTED_FAIL
        return finding["diagnostics"]


@final
class _FiveAgentFixture:
    """Synthetic locked full-repo validation with five overlapping callers."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "src/driver.py"
        _ = self.source.write_text("source", encoding="utf-8")
        self.started = threading.Event()
        self.release = threading.Event()
        self.blocked = threading.Condition()
        self.waiting: list[int] = []
        self.calls: list[int] = []
        self.results: list[int] = []
        self.output = io.StringIO()
        self.real_flock = fcntl.flock

    def host_tests(self, _: Path) -> list[validator.Finding]:
        """Block the leader until every other caller hits the lock.

        Returns:
            Synthetic successful host test results.

        Raises:
            TimeoutError: All test callers did not reach the shared lock.

        """
        self.calls.append(1)
        self.started.set()
        if not self.release.wait(THREAD_TIMEOUT):
            message = "Timed out waiting for the synthetic concurrent callers"
            raise TimeoutError(message)
        return [_sample_finding("tests/test_fake.py", "python-test", "pass")]

    def observe_lock(self, fd: int, operation: int) -> None:
        """Detect each concurrent nonblocking lock miss without sleeping.

        Raises:
            BlockingIOError: Another validator currently holds the lock.

        """
        try:
            self.real_flock(fd, operation)
        except BlockingIOError:
            with self.blocked:
                self.waiting.append(1)
                self.blocked.notify_all()
            raise

    def invoke(self) -> None:
        """Record each real validator exit code from a separate thread."""
        self.results.append(validator.main())

    def _launch(self, *, change_source: bool) -> None:
        leader = threading.Thread(target=self.invoke)
        followers = [
            threading.Thread(target=self.invoke) for _ in range(WAITING_AGENTS)
        ]
        try:
            leader.start()
            assert self.started.wait(THREAD_TIMEOUT)
            for follower in followers:
                follower.start()
            with self.blocked:
                assert self.blocked.wait_for(
                    lambda: len(self.waiting) == WAITING_AGENTS,
                    THREAD_TIMEOUT,
                )
                if change_source:
                    _ = self.source.write_text(
                        "edited in flight", encoding="utf-8"
                    )
        finally:
            self.release.set()
            leader.join(THREAD_TIMEOUT)
            for follower in followers:
                follower.join(THREAD_TIMEOUT)
        assert not leader.is_alive()
        assert all(not follower.is_alive() for follower in followers)

    def run(self, *, change_source: bool = False) -> None:
        """Verify run sharing, or rejection of changed in-flight sources."""
        with (
            mock.patch.object(validator, "ROOT", self.root),
            mock.patch.object(
                validator, "source_files", return_value=[self.source]
            ),
            mock.patch.object(
                validator.LintRun,
                "check",
                return_value=_sample_finding("src/driver.py", "ruff", "pass"),
            ),
            mock.patch.object(
                validator, "run_tests", side_effect=self.host_tests
            ),
            mock.patch.object(
                validator, "_tool_versions", return_value={"ruff": "fixture"}
            ),
            mock.patch.object(fcntl, "flock", side_effect=self.observe_lock),
            mock.patch.object(sys, "argv", ["validate.py"]),
            redirect_stdout(self.output),
        ):
            self._launch(change_source=change_source)
            report = (self.root / ".cache/validate/report.json").read_text()
            if change_source:
                # The first, mixed-snapshot report fails, then four waiting
                # callers share a new clean scan of the edited source.
                assert len(self.calls) == SEQUENTIAL_HOST_CALLS
                assert sorted(self.results) == [0] * WAITING_AGENTS + [1]
                assert SNAPSHOT_FAILURE_FRAGMENT in self.output.getvalue()
            else:
                assert len(self.calls) == 1
                assert self.results == [0] * CONCURRENT_AGENTS
                assert self.output.getvalue() == report * CONCURRENT_AGENTS
            # Later sequential requests must execute their own host tests.
            assert validator.main() == 0
            expected = SEQUENTIAL_HOST_CALLS + int(change_source)
            assert len(self.calls) == expected


class NativeFragmentCacheValidation(unittest.TestCase):
    """Ensure included native fragment bytes invalidate Tidy results."""

    @staticmethod
    def test_unusual_native_include_fragment_invalidates_tidy() -> None:
        """Literal in-tree includes must be tracked regardless of suffix."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            owner = root / "src/owner.cpp"
            fragment = root / "src/tables/limits.tbl"
            fragment.parent.mkdir()
            _ = owner.write_text(
                '#include "tables/limits.tbl"\nint owner;', encoding="utf-8"
            )
            _ = fragment.write_text("first", encoding="utf-8")
            initial = _lint_fingerprint(root, owner, "clang-tidy")
            unrelated = root / "src/unrelated.json"
            _ = unrelated.write_text("unrelated", encoding="utf-8")
            assert _lint_fingerprint(root, owner, "clang-tidy") == initial
            _ = fragment.write_text("changed", encoding="utf-8")
            changed = _lint_fingerprint(root, owner, "clang-tidy")
            assert changed != initial
            fragment.unlink()
            assert _lint_fingerprint(root, owner, "clang-tidy") != changed

    @staticmethod
    def test_macro_native_include_tracks_unknown_fragments() -> None:
        """Macro include targets cannot be resolved from literal syntax."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            owner = root / "src/owner.cpp"
            fragment = root / "src/limits.tbl"
            _ = owner.write_text(
                '#define FILE_NAME "limits.tbl"\n#include FILE_NAME\n',
                encoding="utf-8",
            )
            _ = fragment.write_text("before", encoding="utf-8")
            initial = _lint_fingerprint(root, owner, "clang-tidy")
            _ = fragment.write_text("after", encoding="utf-8")
            assert _lint_fingerprint(root, owner, "clang-tidy") != initial

    @staticmethod
    def test_transitive_unknown_extension_include_invalidates_tidy() -> None:
        """An unusual fragment may itself include another unusual fragment."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            owner = root / "src/owner.cpp"
            first = root / "src/outer.tbl"
            inner = root / "src/inner.tbl"
            _ = owner.write_text('#include "outer.tbl"\n', encoding="utf-8")
            _ = first.write_text('#include "inner.tbl"\n', encoding="utf-8")
            _ = inner.write_text("old", encoding="utf-8")
            original = _lint_fingerprint(root, owner, "clang-tidy")
            _ = inner.write_text("updated", encoding="utf-8")
            changed = _lint_fingerprint(root, owner, "clang-tidy")
            assert changed != original
            inner.unlink()
            assert _lint_fingerprint(root, owner, "clang-tidy") != changed

    @staticmethod
    def test_macro_include_inside_unknown_fragment_fails_open_cache() -> None:
        """A nested macro include must hash possible unusual targets."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            owner = root / "src/owner.cpp"
            first = root / "src/outer.tbl"
            fragment = root / "src/inner.tbl"
            _ = owner.write_text('#include "outer.tbl"\n', encoding="utf-8")
            _ = first.write_text(
                '#define FRAGMENT "inner.tbl"\n#include FRAGMENT\n',
                encoding="utf-8",
            )
            _ = fragment.write_text("old", encoding="utf-8")
            original = _lint_fingerprint(root, owner, "clang-tidy")
            _ = fragment.write_text("updated", encoding="utf-8")
            assert _lint_fingerprint(root, owner, "clang-tidy") != original


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
            dependencies.assert_called_once_with(root, "basedpyright")
            assert signature.call_count == len(files)
            assert all(
                call.kwargs["context"] == ("basedpyright", SHARED_DIGEST)
                for call in signature.call_args_list
            )

    @staticmethod
    def test_language_dependencies_do_not_invalidate_other_linters() -> None:
        """Python/stubs leave C++ signatures intact; headers still count."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            sources = {
                "python": root / "src/module.py",
                "stub": root / "src/module.pyi",
                "cpp": root / "src/radio.cpp",
                "header": root / "src/radio.hpp",
            }
            for source in sources.values():
                _ = source.write_text("first", encoding="utf-8")
            native_before = _lint_fingerprint(
                root, sources["cpp"], "clang-tidy"
            )
            python_before = _lint_fingerprint(
                root, sources["python"], "basedpyright"
            )
            for name in ("python", "stub"):
                _ = sources[name].write_text("changed", encoding="utf-8")
                assert (
                    _lint_fingerprint(root, sources["cpp"], "clang-tidy")
                    == native_before
                )
            python_now = _lint_fingerprint(
                root, sources["python"], "basedpyright"
            )
            assert python_before != python_now
            _ = sources["header"].write_text("changed", encoding="utf-8")
            assert (
                _lint_fingerprint(root, sources["cpp"], "clang-tidy")
                != native_before
            )
            assert (
                _lint_fingerprint(root, sources["python"], "basedpyright")
                == python_now
            )

    @staticmethod
    def test_unrelated_native_unit_keeps_tidy_cache_valid() -> None:
        """Editing one C++ unit must not recheck independent native units."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            first = root / "src/first.cpp"
            second = root / "src/second.cpp"
            header = root / "src/common.hpp"
            _ = first.write_text("int first;", encoding="utf-8")
            _ = second.write_text("int second;", encoding="utf-8")
            _ = header.write_text("#pragma once", encoding="utf-8")
            baseline = _lint_fingerprint(root, first, "clang-tidy")
            _ = second.write_text("int changed;", encoding="utf-8")
            assert _lint_fingerprint(root, first, "clang-tidy") == baseline
            _ = first.write_text("int altered;", encoding="utf-8")
            altered = _lint_fingerprint(root, first, "clang-tidy")
            assert altered != baseline
            _ = header.write_text("#pragma once\nint value;", encoding="utf-8")
            assert _lint_fingerprint(root, first, "clang-tidy") != altered

    @staticmethod
    def test_included_native_implementation_and_fragments_invalidate() -> None:
        """A translation unit including nonheaders still needs fresh lint."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            first = root / "src/first.cpp"
            second = root / "src/second.cpp"
            fragment = root / "src/shared.inc"
            _ = first.write_text(
                '#include "second.cpp"\n#include "shared.inc"',
                encoding="utf-8",
            )
            _ = second.write_text("int second;", encoding="utf-8")
            _ = fragment.write_text("int shared;", encoding="utf-8")
            baseline = _lint_fingerprint(root, first, "clang-tidy")
            _ = second.write_text("int changed;", encoding="utf-8")
            updated = _lint_fingerprint(root, first, "clang-tidy")
            assert updated != baseline
            _ = fragment.write_text("int changed_shared;", encoding="utf-8")
            assert _lint_fingerprint(root, first, "clang-tidy") != updated

    @staticmethod
    def test_objective_c_imported_unit_invalidates_tidy() -> None:
        """An Objective-C #import of a .mm file is a source dependency."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            owner = root / "src/owner.mm"
            imported = root / "src/imported.mm"
            _ = owner.write_text('#import "imported.mm"', encoding="utf-8")
            _ = imported.write_text("int before;", encoding="utf-8")
            initial = _lint_fingerprint(root, owner, "clang-tidy")
            _ = imported.write_text("int after;", encoding="utf-8")
            assert _lint_fingerprint(root, owner, "clang-tidy") != initial

    @staticmethod
    def test_lint_cache_tracks_language_search_environments() -> None:
        """Native include and Python import paths must invalidate own lint."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            native = root / "src/radio.cpp"
            python = root / "src/analysis.py"
            _ = native.write_text("int radio;", encoding="utf-8")
            _ = python.write_text("radio = True", encoding="utf-8")
            baseline = {"CPATH": "/fixture/a", "PYTHONPATH": "/fixture/a"}
            with mock.patch.dict(os.environ, baseline):
                native_before = _lint_fingerprint(root, native, "clang-tidy")
                python_before = _lint_fingerprint(root, python, "basedpyright")
            with mock.patch.dict(
                os.environ, {**baseline, "CPATH": "/fixture/b"}
            ):
                assert (
                    _lint_fingerprint(root, native, "clang-tidy")
                    != native_before
                )
                assert (
                    _lint_fingerprint(root, python, "basedpyright")
                    == python_before
                )
            with mock.patch.dict(
                os.environ, {**baseline, "PYTHONPATH": "/fixture/b"}
            ):
                assert (
                    _lint_fingerprint(root, native, "clang-tidy")
                    == native_before
                )
                assert (
                    _lint_fingerprint(root, python, "basedpyright")
                    != python_before
                )

    @staticmethod
    def test_python_stub_changes_complete_source_snapshot() -> None:
        """A type stub is an input even if it is not a separate lint target."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/module.py"
            stub = root / "src/module.pyi"
            _ = source.write_text("original", encoding="utf-8")
            before = validator.input_snapshot(root, [source])
            _ = stub.write_text("def foo() -> int: ...", encoding="utf-8")
            assert before != validator.input_snapshot(root, [source])

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
    def test_internal_source_symlink_cannot_disappear_from_inventory() -> None:
        """A linked source must not silently lose its original extension."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            target = root / "src/fixture.txt"
            _ = target.write_text("fixture", encoding="utf-8")
            (root / "src/driver.cpp").symlink_to(target)
            with mock.patch.object(
                validator, "_inventory", return_value=["src/driver.cpp"]
            ):
                assert _rejects(
                    lambda: validator.source_files(root, ()),
                    "Linked repository input",
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
    def test_tidy_diagnostics_keep_distinct_errors_within_limit() -> None:
        """Source snippets must not hide later independent Tidy findings."""
        output = "\n".join(
            "\n".join((
                f"src/driver.cpp:{index}:4: error: issue {index}",
                f"  {index} | broken syntax",
                "    | ^",
            ))
            for index in range(1, validator.DIAGNOSTIC_LIMIT + 4)
        )
        messages = _lint_failure_diagnostics(output)
        assert len(messages) == validator.DIAGNOSTIC_LIMIT
        assert messages[-1].endswith(f"issue {validator.DIAGNOSTIC_LIMIT}")
        assert all(COMPILER_ERROR_MARKER in message for message in messages)

    @staticmethod
    def test_non_compiler_errors_keep_traceback_context() -> None:
        """Fallback diagnostics preserve ordinary failures and tracebacks."""
        failure = "Traceback (most recent call last):\nValueError: example"
        assert _lint_failure_diagnostics(failure) == [
            "Traceback (most recent call last):",
            "ValueError: example",
        ]

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
    def test_premature_python_exit_zero_is_not_a_pass() -> None:
        """An import-time process exit must not masquerade as run tests."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_early_exit.py").write_text(
                "import os\nos._exit(0)\n", encoding="utf-8"
            )
            result = validator.run_tests(root)[0]
            assert result["status"] == EXPECTED_FAIL
            assert any(
                MISSING_PYTHON_COMPLETION in d for d in result["diagnostics"]
            )

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
    def test_missing_apple_sdk_headers_are_failures_on_every_host() -> None:
        """Never disguise a failed native parse as a successful lint result."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/SimpleATH.cpp"
            _ = source.write_text(
                "#include <IOKit/IOLib.h>\n", encoding="utf-8"
            )
            for config in validator.CONFIGS["clang-tidy"]:
                _ = (root / config).write_text("fixture", encoding="utf-8")
            missing = validator.Process(
                1,
                "",
                f"error: {MACOS_MISSING_FIXTURE} [clang-diagnostic-error]",
            )
            cache: dict[str, validator.CacheEntry] = {}
            with (
                mock.patch.object(
                    validator, "_command", return_value=[sys.executable]
                ),
                mock.patch.object(
                    validator, "tidy_command_exists", return_value=True
                ),
                mock.patch.object(
                    validator, "_version", return_value="fixture"
                ),
                mock.patch.object(
                    validator, "run_process", return_value=missing
                ) as process,
            ):
                lint = validator.LintRun(root, validator.Options(), cache)
                first = lint.check(source, "clang-tidy")
                second = lint.check(source, "clang-tidy")
                assert first["status"] == EXPECTED_FAIL
                assert second["status"] == EXPECTED_FAIL
                assert not first["cached"]
                assert second["cached"]
                assert first["diagnostics"] == second["diagnostics"]
                process.assert_called_once()

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


class NonSourceFixtureSnapshot(unittest.TestCase):
    """Verify the report identity includes every host-test input type."""

    @staticmethod
    def test_snapshot_tracks_non_source_host_test_fixtures() -> None:
        """Content, arrival and removal of host fixtures change run identity."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "tests/test_fixture.py"
            _ = source.write_text("import unittest", encoding="utf-8")
            fixture = root / "tests/fixtures/wpa2-eapol.bin"
            fixture.parent.mkdir()
            first = validator.input_snapshot(root, [source])
            _ = fixture.write_bytes(b"m1")
            created = validator.input_snapshot(root, [source])
            assert first != created
            _ = fixture.write_bytes(b"m3")
            changed = validator.input_snapshot(root, [source])
            assert created != changed
            fixture.unlink()
            assert validator.input_snapshot(root, [source]) == first

            # Interpreter bytecode caches are not test fixtures and may be
            # created by a test run itself; never report them as source drift.
            generated = root / "tests/__pycache__/test_fixture.cpython-314.pyc"
            generated.parent.mkdir()
            _ = generated.write_bytes(b"interpreter generated")
            assert validator.input_snapshot(root, [source]) == first

    @staticmethod
    def test_snapshot_tracks_input_permission_changes() -> None:
        """Host fixtures and scripts can behave differently after chmod."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/driver.py"
            fixture = root / "tests/fixture.sh"
            _ = source.write_text("print('ok')", encoding="utf-8")
            _ = fixture.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            source.chmod(0o600)
            fixture.chmod(0o600)
            baseline = validator.input_snapshot(root, [source])
            fixture.chmod(0o700)
            changed_fixture = validator.input_snapshot(root, [source])
            assert changed_fixture != baseline
            fixture.chmod(0o600)
            assert validator.input_snapshot(root, [source]) == baseline
            source.chmod(0o700)
            assert validator.input_snapshot(root, [source]) != baseline

    @staticmethod
    def test_snapshot_tracks_source_support_assets() -> None:
        """ABI JSON inputs and native ledgers invalidate completed reports."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/core.cpp"
            _ = source.write_text("int core;", encoding="utf-8")
            baseline = validator.input_snapshot(root, [source])
            for name in (
                "src/platform/abi/manifest.json",
                "tools/reference-data.json",
                "src/linux/linux-port-ledger.jsonl",
            ):
                asset = root / name
                asset.parent.mkdir(parents=True, exist_ok=True)
                _ = asset.write_bytes(b"one")
                first = validator.input_snapshot(root, [source])
                assert first != baseline, name
                _ = asset.write_bytes(b"two")
                assert validator.input_snapshot(root, [source]) != first, name
                asset.unlink()
                assert validator.input_snapshot(root, [source]) == baseline

            # Bulk checked-out Linux references are not live native inputs.
            linux = root / "src/linux/drivers/net/sample.conf"
            linux.parent.mkdir(parents=True)
            _ = linux.write_bytes(b"reference only")
            assert validator.input_snapshot(root, [source]) == baseline

    @staticmethod
    def test_snapshot_rejects_symlinked_source_support_asset() -> None:
        """Never allow ABI evidence to link outside the repository."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/core.cpp"
            _ = source.write_text("int core;", encoding="utf-8")
            asset = root / "src/platform/abi/manifest.json"
            asset.parent.mkdir(parents=True)
            asset.symlink_to(Path(directory).parent / "outside-abi.json")
            assert _rejects(
                lambda: validator.input_snapshot(root, [source]),
                "Linked support input",
            )

    @staticmethod
    def test_snapshot_streams_fixture_bytes() -> None:
        """Hash host fixture bytes without allocating the entire file."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/example.py"
            _ = source.write_text("pass", encoding="utf-8")
            fixture = root / "tests/large-vector.bin"
            _ = fixture.write_bytes(b"\x00\xff" * 65536)
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("unbounded source snapshot read"),
            ):
                streamed = validator.input_snapshot(root, [source])
            assert streamed == validator.input_snapshot(root, [source])

    @staticmethod
    def test_fixture_edit_during_validation_fails_report() -> None:
        """A mixed host fixture must not produce a reusable report."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/example.py"
            _ = source.write_text("print('ok')", encoding="utf-8")
            fixture = root / "tests/scan-record.json"
            _ = fixture.write_text('{"frame": "old"}', encoding="utf-8")

            def change_fixture(working_root: Path) -> list[validator.Finding]:
                assert working_root == root
                _ = fixture.write_text('{"frame": "new"}', encoding="utf-8")
                return [
                    _sample_finding("tests/test_fake.py", "python-test", "pass")
                ]

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
                    validator, "run_tests", side_effect=change_fixture
                ),
                mock.patch.object(
                    validator, "_version", return_value="fixture"
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 1
            report = (root / ".cache/validate/report.json").read_text()
            assert SNAPSHOT_FAILURE_FRAGMENT in report

    @staticmethod
    def test_snapshot_rejects_symlinked_test_fixture() -> None:
        """Never follow a test fixture link outside the source tree."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "tests/test_fixture.py"
            _ = source.write_text("import unittest", encoding="utf-8")
            fixture = root / "tests/fixture.bin"
            fixture.symlink_to(Path(directory).parent / "outside-fixture.bin")
            assert _rejects(
                lambda: validator.input_snapshot(root, [source]),
                "Linked test fixture",
            )


class PythonCompletionIntegrity(unittest.TestCase):
    """An early-stopped unittest suite is not a complete host test run."""

    @staticmethod
    def test_early_stop_cannot_hide_unexecuted_failing_test() -> None:
        """A partial successful unittest result must fail host validation."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            _ = (root / "tests/test_stopped.py").write_text(
                """import unittest
class Stopped(unittest.TestCase):
    def test_a_stop(self):
        self._outcome.result.stop()
    def test_z_unreached(self):
        self.fail('Must not be silently ignored')
""",
                encoding="utf-8",
            )
            result = validator.run_tests(root)[0]
            assert result["status"] == EXPECTED_FAIL
            assert any(
                INCOMPLETE_TEST_SUITE in detail
                for detail in result["diagnostics"]
            )


class DriftedLintCache(unittest.TestCase):
    """Mixed-snapshot lint results must never poison a future clean scan."""

    @staticmethod
    def test_source_drift_never_publishes_unverified_cache_entries() -> None:
        """An in-flight edit can make a cached pass refer to untested bytes."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/example.py"
            _ = source.write_text("original", encoding="utf-8")
            for config in (
                name for names in validator.CONFIGS.values() for name in names
            ):
                _ = (root / config).write_text("fixture", encoding="utf-8")
            _cache(
                root,
                {
                    "fingerprint": "existing",
                    "status": "pass",
                    "diagnostics": [],
                },
            )
            cache_path = root / ".cache/validate/cache.json"
            original_cache = cache_path.read_bytes()
            calls: list[list[str]] = []

            def lint_during_edit(
                argv: list[str],
                *,
                cwd: Path,
                seconds: float = validator.TIMEOUT_SECONDS,
            ) -> validator.Process:
                assert cwd == root
                assert seconds == validator.TIMEOUT_SECONDS
                calls.append(argv)
                if len(calls) == 1:
                    # The first lint key was computed for the original bytes,
                    # but the fake linter actually sees the changed source.
                    _ = source.write_text("modified", encoding="utf-8")
                return validator.Process(0, "", "")

            host = _sample_finding("tests/test_fake.py", "python-test", "pass")
            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator, "_command", return_value=[sys.executable]
                ),
                mock.patch.object(
                    validator, "_version", return_value="fixture"
                ),
                mock.patch.object(
                    validator, "run_process", side_effect=lint_during_edit
                ),
                mock.patch.object(validator, "run_tests", return_value=[host]),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 1
                assert (
                    SNAPSHOT_FAILURE_FRAGMENT
                    in (root / ".cache/validate/report.json").read_text()
                )
                assert cache_path.read_bytes() == original_cache
                _ = source.write_text("original", encoding="utf-8")
                before = len(calls)
                assert validator.main() == 0
                assert len(calls) - before == PYTHON_SOURCE_AND_HOST_CHECKS - 1


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
            assert SOURCE_ONLY_FRAGMENT in report
            assert TESTS_REQUESTED_FRAGMENT in report
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
    def test_source_change_while_five_agents_wait_prevents_stale_reuse() -> (
        None
    ):
        """A changed in-flight source requires a second complete host scan."""
        with tempfile.TemporaryDirectory() as directory:
            _FiveAgentFixture(_root(directory)).run(change_source=True)

    @staticmethod
    def test_five_simultaneous_callers_share_one_complete_scan() -> None:
        """Concurrent callers share a report; sequential callers rerun tests."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = _FiveAgentFixture(_root(directory))
            fixture.run()

    @staticmethod
    def test_host_compiler_version_changes_completed_run_identity() -> None:
        """Never reuse native test results from a replaced compiler binary."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "tests/test_native.cpp"
            _ = source.write_text("int main() { return 0; }", encoding="utf-8")
            host = _sample_finding(
                "tests/test_native.cpp", "native-test", "pass"
            )
            first_version = "clang version 23.1.2"
            second_version = "clang version 24.0.0"

            def installed(executable: str) -> str | None:
                host_compiler = "clang++"
                return (
                    "/opt/test/clang++" if executable == host_compiler else None
                )

            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "tests/test_native.cpp", "clang-format", "pass"
                    ),
                ),
                mock.patch.object(validator, "run_tests", return_value=[host]),
                mock.patch.object(shutil, "which", side_effect=installed),
                mock.patch.object(
                    validator,
                    "_version",
                    side_effect=[
                        "clang version 23.1.2",
                        "clang version 24.0.0",
                    ],
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 0
                marker = root / validator.COMPLETION_FILE
                before = cast(
                    "dict[str, object]", json.loads(marker.read_text())
                )
                report = (root / ".cache/validate/report.json").read_text()
                assert f'"native-test": "{first_version}"' in report
                assert validator.main() == 0
                after = cast(
                    "dict[str, object]", json.loads(marker.read_text())
                )
                report = (root / ".cache/validate/report.json").read_text()
                assert f'"native-test": "{second_version}"' in report
            assert before["identity"] != after["identity"]

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
    def test_cache_purge_cannot_replace_active_validator_lock() -> None:
        """Keep lock ownership when a cache directory is removed mid-scan."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            blocked = False

            def purge_during_validation(_: validator.Options) -> int:
                nonlocal blocked
                cache = root / ".cache/validate"
                cache.mkdir(parents=True, exist_ok=True)
                shutil.rmtree(cache)
                cache.mkdir()
                # A different validator opening the current lock path must
                # contend on the same inode even after the cache is purged.
                with (root / validator.RUN_LOCK_FILE).open("a+b") as contender:
                    try:
                        fcntl.flock(
                            contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                    except BlockingIOError:
                        blocked = True
                    else:
                        fcntl.flock(contender.fileno(), fcntl.LOCK_UN)
                return 0

            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "_validate", side_effect=purge_during_validation
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
            ):
                assert validator.main() == 0
            assert blocked

    @staticmethod
    def test_exclusive_lock_covers_shared_cache_write() -> None:
        """A second writer must not hold the validator lock concurrently."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            locked = False

            def inspected(_: validator.Options) -> int:
                nonlocal locked
                path = root / validator.RUN_LOCK_FILE
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


def _assert_host_environment_rechecks(
    name: str, root: Path, tests: mock.Mock
) -> None:
    """Emulate a waiter whose host test environment differs from its peer."""
    first = str(root / "scratch-first")
    second = str(root / "scratch-second")

    def contended(_: int, operation: int) -> None:
        if operation & fcntl.LOCK_NB:
            raise BlockingIOError

    with mock.patch.dict(os.environ, {name: first}):
        assert validator.main() == 0
        before = tests.call_count
        # A waiter read the previous completion token before the leader ran.
        with (
            mock.patch.object(
                validator, "_completion_token", return_value=None
            ),
            mock.patch.object(fcntl, "flock", side_effect=contended),
        ):
            assert validator.main() == 0
        assert tests.call_count == before

    with (
        mock.patch.dict(os.environ, {name: second}),
        mock.patch.object(validator, "_completion_token", return_value=None),
        mock.patch.object(fcntl, "flock", side_effect=contended),
    ):
        assert validator.main() == 0
    assert tests.call_count == before + 1, name


class CompletedRunEnvironment(unittest.TestCase):
    """Never share a completed host report across distinct environments."""

    @staticmethod
    def test_host_environment_changes_completed_run_identity() -> None:
        """Scratch, locale, time zone and hash seed affect host behavior."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/driver.py"
            _ = source.write_text("source", encoding="utf-8")
            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "src/driver.py", "ruff-check", "pass"
                    ),
                ),
                mock.patch.object(
                    validator,
                    "run_tests",
                    return_value=[
                        _sample_finding(
                            "tests/test_fake.py", "python-test", "pass"
                        )
                    ],
                ) as tests,
                mock.patch.object(
                    validator,
                    "_tool_versions",
                    return_value={"ruff": "fixture"},
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                for name in (
                    "TMPDIR",
                    "TMP",
                    "TEMP",
                    "LANG",
                    "LC_ALL",
                    "LC_CTYPE",
                    "TZ",
                    "PYTHONHASHSEED",
                ):
                    _assert_host_environment_rechecks(name, root, tests)


def _corrupt_completed_check_count(root: Path) -> None:
    """Write an internally consistent partial report and matching marker."""
    report_path = root / ".cache/validate/report.json"
    report = cast("dict[str, object]", json.loads(report_path.read_text()))
    summary = cast("dict[str, object]", report["summary"])
    assert summary["checks"] == PYTHON_SOURCE_AND_HOST_CHECKS
    summary.update({"checks": 1, "pass": 1, "cached": 0, "executed": 1})
    damaged = json.dumps(report, indent=2) + "\n"
    _ = report_path.write_text(damaged, encoding="utf-8")
    marker_path = root / validator.COMPLETION_FILE
    marker = cast("dict[str, object]", json.loads(marker_path.read_text()))
    marker["reportSHA256"] = hashlib.sha256(damaged.encode()).hexdigest()
    _ = marker_path.write_text(json.dumps(marker), encoding="utf-8")


class CompletedRunCountIntegrity(unittest.TestCase):
    """A shared full report must cover every required source and host check."""

    @staticmethod
    def test_waiter_rejects_checksum_matched_under_counted_report() -> None:
        """A tampered completion cannot turn partial checks into full green."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/driver.py"
            _ = source.write_text("source", encoding="utf-8")
            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "src/driver.py", "ruff-check", "pass"
                    ),
                ),
                mock.patch.object(
                    validator,
                    "run_tests",
                    return_value=[
                        _sample_finding(
                            "tests/test_fake.py", "python-test", "pass"
                        )
                    ],
                ) as tests,
                mock.patch.object(
                    validator,
                    "_tool_versions",
                    return_value={"ruff": "fixture"},
                ),
                mock.patch.object(sys, "argv", ["validate.py"]),
                redirect_stdout(io.StringIO()),
            ):
                assert validator.main() == 0
                _corrupt_completed_check_count(root)
                report_path = root / ".cache/validate/report.json"

                def contended(_: int, operation: int) -> None:
                    if operation & fcntl.LOCK_NB:
                        raise BlockingIOError

                with (
                    mock.patch.object(
                        validator, "_completion_token", return_value=None
                    ),
                    mock.patch.object(fcntl, "flock", side_effect=contended),
                ):
                    assert validator.main() == 0
                assert tests.call_count == COMPLETED_HOST_SCANS
                refreshed = cast(
                    "dict[str, object]", json.loads(report_path.read_text())
                )
                refreshed_summary = cast(
                    "dict[str, object]", refreshed["summary"]
                )
                assert (
                    refreshed_summary["checks"] == PYTHON_SOURCE_AND_HOST_CHECKS
                )


class CompletedReportIntegrity(unittest.TestCase):
    """Reused compact reports must agree with their own failure evidence."""

    @staticmethod
    def test_rejects_missing_or_relabelled_actionable_results() -> None:
        """A truncated failure list cannot be served as a completed scan."""
        passed = _sample_finding("src/ok.cpp", "clang-format", "pass")
        failed = _sample_finding("src/bad.cpp", "clang-tidy", "fail")
        skipped = _sample_finding(
            "tests/test_missing.py", "python-test", "skipped"
        )
        report = validator.build_report(
            [passed, failed, skipped], files=2, tests=True, tools={}
        )
        assert validator.report_exit_code(json.dumps(report), 2) == 1
        # The SHA-256 marker only authenticates the report bytes, not that
        # every required non-pass result survived serialization.
        report["results"] = [failed]
        assert validator.report_exit_code(json.dumps(report), 2) is None
        rows = [dict(failed), dict(skipped)]
        report["results"] = rows
        rows[0]["status"] = "pass"
        assert validator.report_exit_code(json.dumps(report), 2) is None
        rows[0]["status"] = "skipped"
        assert validator.report_exit_code(json.dumps(report), 2) is None

    @staticmethod
    def test_rejects_duplicate_or_malformed_failure_evidence() -> None:
        """Two distinct failures cannot be replaced by the same result."""
        first = _sample_finding("src/first.cpp", "clang-tidy", "fail")
        second = _sample_finding("src/second.cpp", "clang-tidy", "fail")
        report = validator.build_report(
            [first, second], files=2, tests=True, tools={}
        )
        assert validator.report_exit_code(json.dumps(report), 2) == 1
        report["results"] = [first, dict(first)]
        assert validator.report_exit_code(json.dumps(report), 2) is None
        damaged: dict[str, object] = dict(second)
        damaged["file"] = None
        report["results"] = [first, damaged]
        assert validator.report_exit_code(json.dumps(report), 2) is None
        damaged["file"] = second["file"]
        damaged["cached"] = "yes"
        assert validator.report_exit_code(json.dumps(report), 2) is None
        damaged["cached"] = False
        damaged["diagnostics"] = None
        assert validator.report_exit_code(json.dumps(report), 2) is None

    @staticmethod
    def test_rejects_impossible_cache_counts() -> None:
        """Run statistics must account for all executed or reused checks."""
        passed = _sample_finding("src/ok.cpp", "clang-format", "pass")
        report = validator.build_report([passed], files=1, tests=True, tools={})
        assert validator.report_exit_code(json.dumps(report), 1) == 0
        summary = cast("dict[str, object]", report["summary"])
        summary["cached"] = True
        assert validator.report_exit_code(json.dumps(report), 1) is None
        summary["cached"] = 1
        summary["executed"] = 1
        assert validator.report_exit_code(json.dumps(report), 1) is None
        summary["executed"] = 0
        summary["files"] = True
        assert validator.report_exit_code(json.dumps(report), 1) is None


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
    def test_linux_flag_is_rejected_on_every_host() -> None:
        """The CLI cannot turn missing Apple headers into skipped checks."""
        stderr = io.StringIO()
        exit_code: object = None
        with (
            mock.patch.object(sys, "argv", ["validate.py", "--linux"]),
            redirect_stderr(stderr),
        ):
            try:
                _ = validator.parse_options()
            except SystemExit as error:
                exit_code = error.code
        assert exit_code == UNKNOWN_FLAG_CODE
        assert UNKNOWN_LINUX_FLAG in stderr.getvalue()

    @staticmethod
    def test_completed_reports_reject_invalid_validation_modes() -> None:
        """The report labels its target and rejects unspecified modes."""
        report = validator.build_report([], files=0, tests=True, tools={})
        assert report["validation_mode"] == MACOS_MODE
        assert validator.report_exit_code(json.dumps(report), 0) == 0
        report["validation_mode"] = "unverified"
        assert validator.report_exit_code(json.dumps(report), 0) is None

    @staticmethod
    def test_full_reports_use_one_strict_macos_mode() -> None:
        """The full validator produces a single macOS-compatible report mode."""
        with tempfile.TemporaryDirectory() as directory:
            root = _root(directory)
            source = root / "src/driver.py"
            _ = source.write_text("pass", encoding="utf-8")
            with (
                mock.patch.object(validator, "ROOT", root),
                mock.patch.object(
                    validator, "source_files", return_value=[source]
                ),
                mock.patch.object(
                    validator.LintRun,
                    "check",
                    return_value=_sample_finding(
                        "src/driver.py", "ruff-check", "pass"
                    ),
                ),
                mock.patch.object(
                    validator,
                    "run_tests",
                    return_value=[
                        _sample_finding(
                            "tests/test_fake.py", "python-test", "pass"
                        )
                    ],
                ),
                mock.patch.object(
                    validator, "_tool_versions", return_value={"ruff": "test"}
                ),
                redirect_stdout(io.StringIO()),
                mock.patch.object(sys, "argv", ["validate.py"]),
            ):
                assert validator.main() == 0
                report = cast(
                    "dict[str, object]",
                    json.loads(
                        (root / ".cache/validate/report.json").read_text()
                    ),
                )
                assert report["validation_mode"] == MACOS_MODE

    @staticmethod
    def test_disabled_mandatory_checks_are_rejected() -> None:
        """Do not mutate shared cache/report after reduced-scope flags."""
        for flag in FORBIDDEN_CHECK_OPTIONS:
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
    def test_help_does_not_offer_unavailable_check_opt_outs() -> None:
        """Forbidden switches are errors, not listed feature controls."""
        output = io.StringIO()
        status: int | None = None
        try:
            with (
                mock.patch.object(sys, "argv", ["validate.py", "--help"]),
                redirect_stdout(output),
            ):
                _ = validator.parse_options()
        except SystemExit as error:
            if isinstance(error.code, int):
                status = error.code
        assert status == 0
        assert all(
            flag not in output.getvalue() for flag in FORBIDDEN_CHECK_OPTIONS
        )

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
