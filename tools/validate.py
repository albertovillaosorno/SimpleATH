#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Check source with installed linters and default-on offline host tests."""

import argparse
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field
import fcntl
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal

# Reviewed boundary: installed linters and opt-in host tests use argv only.
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import sys
import tempfile
from typing import Literal
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / ".git").exists()
)
CACHE_VERSION = "simpleath.validate.v2"
COMPLETION_FILE = ".cache/validate/last-run.json"
RUN_LOCK_FILE = ".git/simpleath-validate.lock"
COMPLETION_SCHEMA = "simpleath.validate.completed.v1"
CLANG_TIDY_TOOL = "clang-tidy"
PYRIGHT_TOOL = "basedpyright"
REPOSITORY_SCOPE = "repository"
VERSION_WORD = "version"
MISSING_TIDY_COMMAND = "No matching compile command in compile_commands.json"
NATIVE = frozenset({
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".m",
    ".mm",
})
UNITS = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm"})
NATIVE_TESTS = frozenset({".cpp", ".mm"})
SUPPORTED = NATIVE | {".py"}
TIMEOUT_SECONDS = 60.0
OUTPUT_LIMIT = 256 * 1024
DIAGNOSTIC_LIMIT = 12
EXIT_FAILURE = 1
EXIT_SKIPPED = 5
PYTHON_TEST_DRIVER = """\
import sys
import unittest
suite = unittest.TestLoader().discover(
    sys.argv[1], pattern=sys.argv[2], top_level_dir=sys.argv[3])
if not suite.countTestCases():
    raise SystemExit(5)
result = unittest.TextTestRunner(verbosity=2).run(suite)
counts = f"Tests run: {result.testsRun}; skipped: {len(result.skipped)}"
sys.stdout.write(counts + chr(10))
code = 1 if not result.wasSuccessful() else 0
if not code and result.skipped:
    code = 5
raise SystemExit(code)
"""
PYTHON_SUFFIX = ".py"
STATUS_OK: Literal["pass"] = "pass"
SKIPPED: Literal["skipped"] = "skipped"
type Status = Literal["pass", "fail", "skipped"]


class Finding(TypedDict):
    """Describe one actual check with bounded diagnostic output."""

    file: str
    tool: str
    status: Status
    cached: bool
    diagnostics: list[str]


class CacheEntry(TypedDict):
    """Store only a validated lint result and its input fingerprint."""

    fingerprint: str
    status: Status
    diagnostics: list[str]


@dataclass(frozen=True)
class Process:
    """Hold a subprocess outcome without untyped JSON or subprocess data."""

    code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Options:
    """Select mandatory full-repo checks and cache refresh behavior."""

    files: tuple[str, ...] = ()
    tidy: bool = True
    tests: bool = True
    json_output: bool = True
    no_cache: bool = False


CONFIGS = {
    "clang-format": (".clang-format", ".editorconfig"),
    "clang-tidy": (".clang-tidy", ".editorconfig", "compile_commands.json"),
    "ruff-check": ("ruff.toml", ".editorconfig"),
    "ruff-format": ("ruff.toml", ".editorconfig"),
    "basedpyright": ("pyrightconfig.json",),
}
EXECUTABLE = {
    "clang-format": "clang-format",
    "clang-tidy": "clang-tidy",
    "ruff-check": "ruff",
    "ruff-format": "ruff",
    "basedpyright": "basedpyright",
}


def _decode(text: str, decoder: Callable[[str], object] = json.loads) -> object:
    return decoder(text)


def _object_mapping(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _object_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _mapping(value: object) -> TypeIs[dict[str, object]]:
    return _object_mapping(value) and all(isinstance(k, str) for k in value)


def _strings(value: object) -> TypeIs[list[str]]:
    return _object_list(value) and all(isinstance(v, str) for v in value)


def _status(value: object) -> TypeIs[Status]:
    return isinstance(value, str) and value in {"pass", "fail", "skipped"}


def _entry(value: object) -> CacheEntry | None:
    result: CacheEntry | None = None
    if _mapping(value):
        result = _valid_entry(value)
    return result


def _valid_entry(value: dict[str, object]) -> CacheEntry | None:
    fingerprint, status = value.get("fingerprint"), value.get("status")
    diagnostics = value.get("diagnostics")
    if not isinstance(fingerprint, str) or not _strings(diagnostics):
        return None
    if not _status(status):
        return None
    return {
        "fingerprint": fingerprint,
        "status": status,
        "diagnostics": diagnostics[:DIAGNOSTIC_LIMIT],
    }


def read_cache(root: Path) -> dict[str, CacheEntry]:
    """Read validated cached lint results.

    Returns:
        Accepted records, or an empty mapping for absent/malformed data.

    """
    path = root / ".cache/validate/cache.json"
    try:
        value = _decode(path.read_text(encoding="utf-8"))
    except OSError, ValueError, RecursionError:
        return {}
    return _cache_entries(value)


def _cache_entries(value: object) -> dict[str, CacheEntry]:
    if not _mapping(value) or value.get("schema") != CACHE_VERSION:
        return {}
    entries = value.get("entries")
    if not _mapping(entries):
        return {}
    return {
        k: item for k, v in entries.items() if (item := _entry(v)) is not None
    }


def _stop(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    _ = process.wait()


def _wait(process: subprocess.Popen[bytes], seconds: float) -> int:
    try:
        return process.wait(timeout=seconds)
    except subprocess.TimeoutExpired, KeyboardInterrupt:
        _stop(process)
        raise


def run_process(
    argv: list[str], *, cwd: Path, seconds: float = TIMEOUT_SECONDS
) -> Process:
    """Run argv with bounded time/output and reap its process group on timeout.

    Returns:
        Exit code and bounded output, including explicit timeout errors.

    """
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            # Installed tools/test argv only; POSIX session isolates cleanup.
            with subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true]
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                start_new_session=True,
            ) as process:
                code = _wait(process, seconds)
        except (OSError, subprocess.TimeoutExpired) as error:
            return Process(EXIT_FAILURE, "", str(error))
        _ = output.seek(0)
        _ = errors.seek(0)
        return Process(
            code,
            output.read(OUTPUT_LIMIT).decode(errors="replace"),
            errors.read(OUTPUT_LIMIT).decode(errors="replace"),
        )


def _checked_path(root: Path, name: str) -> Path:
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        message = f"Outside repository: {name}"
        raise ValueError(message)
    if not path.is_file():
        message = f"Missing file: {name}"
        raise ValueError(message)
    return path


def _inventory(root: Path) -> list[str]:
    git = shutil.which("git")
    if git is None:
        message = "Missing installed git executable"
        raise ValueError(message)
    result = run_process(
        [
            git,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "src/",
            "tools/",
            "tests/",
        ],
        cwd=root,
    )
    if result.code:
        raise ValueError(result.stderr)
    # run_process bounds stdout. A truncated -z inventory silently drops files,
    # which could otherwise produce a false repository-wide success report.
    if len(result.stdout.encode("utf-8")) >= OUTPUT_LIMIT or (
        result.stdout and not result.stdout.endswith("\0")
    ):
        message = "Incomplete git source inventory"
        raise ValueError(message)
    return list(dict.fromkeys(p for p in result.stdout.split("\0") if p))


def source_files(root: Path, names: tuple[str, ...]) -> list[Path]:
    """Select canonical supported sources within the repository.

    Returns:
        Explicit or tracked/untracked project source paths.

    Raises:
        ValueError: If an explicit extension is unsupported.

    """
    if names and any(Path(n).suffix.lower() not in SUPPORTED for n in names):
        message = "Unsupported explicit source extension"
        raise ValueError(message)
    paths = (
        _checked_path(root, name) for name in (names or tuple(_inventory(root)))
    )
    ignored = (root / "linux").resolve()
    return sorted({
        path
        for path in paths
        if _source_candidate(path, ignored, explicit=bool(names))
    })


def _source_candidate(path: Path, ignored: Path, *, explicit: bool) -> bool:
    """Exclude local Linux references from source checks.

    Returns:
        True only for a supported, non-reference source file.

    Raises:
        ValueError: An explicitly requested Linux reference was ignored.

    """
    if path.is_relative_to(ignored):
        if explicit:
            message = "Ignored Linux reference directory: linux/"
            raise ValueError(message)
        return False
    return path.suffix.lower() in SUPPORTED


def _tools(file: Path, options: Options) -> list[str]:
    if file.suffix.lower() == PYTHON_SUFFIX:
        return ["ruff-check", "ruff-format", "basedpyright"]
    return ["clang-format"] + (
        ["clang-tidy"] if options.tidy and file.suffix.lower() in UNITS else []
    )


def _command(tool: str, file: Path, root: Path) -> list[str] | None:
    executable = shutil.which(EXECUTABLE[tool])
    if executable is None:
        return None
    flags = {
        "clang-format": [
            f"--style=file:{root / ".clang-format"}",
            "--dry-run",
            "--Werror",
            "--ferror-limit=1",
        ],
        "clang-tidy": [
            f"--config-file={root / ".clang-tidy"}",
            "-p",
            str(root),
            "--quiet",
        ],
        "ruff-check": [
            "check",
            "--config",
            str(root / "ruff.toml"),
            "--output-format",
            "concise",
        ],
        "ruff-format": [
            "format",
            "--check",
            "--config",
            str(root / "ruff.toml"),
        ],
        "basedpyright": [
            "-p",
            str(root / "pyrightconfig.json"),
            "--outputjson",
        ],
    }
    return [executable, *flags[tool], str(file)]


def _read_diagnostic(item: object) -> str:
    if not _mapping(item):
        return "Invalid diagnostic object"
    file = item.get("file")
    name = Path(file).name if isinstance(file, str) else "<unknown>"
    location = item.get("range")
    start = location.get("start") if _mapping(location) else None
    line = start.get("line") if _mapping(start) else None
    number = line + 1 if isinstance(line, int) else 1
    label = f"{name}:{number} {item.get("severity", "error")} "
    return f"{label}: {item.get("message", "")}"


def _diagnostics(process: Process) -> list[str]:
    try:
        payload = _decode(process.stdout)
    except ValueError, RecursionError:
        payload = None
    issues = payload.get("generalDiagnostics") if _mapping(payload) else None
    if _object_list(issues):
        return [_read_diagnostic(item) for item in issues[:DIAGNOSTIC_LIMIT]]
    text = process.stdout + "\n" + process.stderr
    lines = text.strip().splitlines()
    # Native diagnostics include source excerpts and caret lines. Truncating
    # raw lines can hide every independent issue after the first few. Retain
    # distinct compiler headlines when there are multiple errors, without
    # sacrificing context for a single error or ordinary process tracebacks.
    headlines = [
        line
        for line in lines
        if any(
            marker in line
            for marker in (": error:", ": fatal error:", ": warning:")
        )
    ]
    return (headlines if len(headlines) > 1 else lines)[:DIAGNOSTIC_LIMIT]


def _finding(
    file: str, tool: str, status: Status, *, details: list[str]
) -> Finding:
    return {
        "file": file,
        "tool": tool,
        "status": status,
        "cached": False,
        "diagnostics": details[:DIAGNOSTIC_LIMIT],
    }


@cache
def _version(executable: str, root: Path) -> str:
    result = run_process([executable, "--version"], cwd=root)
    return result.stdout + result.stderr + str(result.code)


def tool_version(executable: str, root: Path) -> str:
    """Retain version numbers when tools print a heading first.

    Returns:
        A recognizable version line, or an explicit unknown marker.

    """
    lines = _version(executable, root).splitlines()
    return next(
        (line.strip() for line in lines if VERSION_WORD in line.lower()),
        lines[0] if lines else "unknown",
    )


def _dependencies(root: Path, tool: str) -> bytes:
    """Digest only files a language-level analyzer could consume.

    Returns:
        A stable digest including relevant dependency paths and bytes.

    """
    suffixes = {".py", ".pyi"} if tool == PYRIGHT_TOOL else NATIVE
    digest = hashlib.sha256()
    files = sorted(
        p
        for d in ("src", "tools", "tests")
        for p in (root / d).rglob("*")
        if p.is_file() and p.suffix.lower() in suffixes
    )
    for path in files:
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.digest()


def _signature(
    command: list[str],
    file: Path,
    root: Path,
    *,
    context: tuple[str, bytes | None],
) -> str:
    tool, dependencies = context
    digest = hashlib.sha256(file.read_bytes())
    digest.update(Path(__file__).read_bytes())
    digest.update(json.dumps(command).encode())
    digest.update(_version(command[0], root).encode())
    for config in CONFIGS[tool]:
        digest.update((root / config).read_bytes())
    if tool in {"basedpyright", "clang-tidy"}:
        if dependencies is None:
            message = f"Missing {tool} source dependency fingerprint"
            raise ValueError(message)
        digest.update(dependencies)
    return digest.hexdigest()


def input_snapshot(root: Path, sources: list[Path]) -> bytes:
    """Fingerprint the complete selected source, rule, and test-manifest state.

    Returns:
        A digest suitable for rejecting reports assembled across live edits.

    Raises:
        ValueError: If a host fixture is a symlink, not a stable local file.

    """
    configurations = {
        root / config for names in CONFIGS.values() for config in names
    }
    manifests = set((root / "tests").rglob("*.sources"))
    # Host tests also read non-source fixture bytes (for example, captured
    # frames, JSON or binary vectors). Those inputs must invalidate a shared
    # completed report even though they are not standalone lint targets.
    # Ignore interpreter/linter caches created by tests during the scan.
    test_directory = root / "tests"
    generated_directories = frozenset({
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    })
    test_fixtures = {
        path
        for path in test_directory.rglob("*")
        if (path.is_file() or path.is_symlink())
        and path.suffix.lower() not in SUPPORTED
        and not any(
            part in generated_directories
            for part in path.relative_to(test_directory).parts[:-1]
        )
    }
    # Host fixture symlinks can escape the repository or change their target
    # without changing a tracked source. Fail closed rather than reading them.
    linked = next(
        (path for path in sorted(test_fixtures) if path.is_symlink()), None
    )
    if linked is not None:
        message = f"Linked test fixture: {linked.relative_to(root)}"
        raise ValueError(message)
    # Python stubs participate in type checking without being lint targets.
    stubs = {
        p
        for directory in ("src", "tools", "tests")
        for p in (root / directory).rglob("*.pyi")
        if p.is_file()
    }
    inputs = sorted(
        set(sources) | configurations | manifests | stubs | test_fixtures
    )
    digest = hashlib.sha256()
    for path in inputs:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        if not path.is_file():
            digest.update(b"absent\0")
            continue
        digest.update(b"present\0")
        # Binary host fixtures may be substantially larger than source
        # files. A bounded read avoids loading entire dumps into RAM.
        with path.open("rb") as source:
            while chunk := source.read(256 * 1024):
                digest.update(chunk)
    return digest.digest()


def _compile_entry_target(entry: object) -> Path | None:
    """Resolve only a usable, absolute-workdir compile command entry.

    Returns:
        The referenced source file, or None for an unusable entry.

    """
    target: Path | None = None
    if _mapping(entry):
        directory, filename = entry.get("directory"), entry.get("file")
        args, command = entry.get("arguments"), entry.get("command")
        usable = (_strings(args) and bool(args)) or (
            isinstance(command, str) and bool(command.strip())
        )
        if isinstance(directory, str) and isinstance(filename, str) and usable:
            base = Path(directory)
            if base.is_absolute():
                candidate = Path(filename)
                target = (
                    candidate if candidate.is_absolute() else base / candidate
                ).resolve()
    return target


def tidy_command_exists(root: Path, file: Path) -> bool:
    """Require a matching compile command before counting Tidy as executed.

    Returns:
        True only if the database contains a usable command for this file.

    """
    database = root / "compile_commands.json"
    try:
        # Prevent an unrelated or stale database from silently making Tidy
        # print "Compile command not found" with a SUCCESS exit status.
        if database.is_symlink() or database.stat().st_size > 32 * 1024 * 1024:
            return False
        entries = _decode(database.read_text(encoding="utf-8"))
    except OSError, ValueError, UnicodeError, RecursionError:
        return False
    return _object_list(entries) and any(
        _compile_entry_target(entry) == file.resolve() for entry in entries
    )


@dataclass
class LintRun:
    """Collect actual checks and validated lint cache entries."""

    root: Path
    options: Options
    entries: dict[str, CacheEntry]
    versions: dict[str, str] = field(default_factory=dict)
    dependency_digests: dict[str, bytes] = field(default_factory=dict)

    def check(self, file: Path, tool: str) -> Finding:
        """Run or reuse one lint check.

        Returns:
            An explicit pass, fail or skipped result.

        """
        relative = file.relative_to(self.root).as_posix()
        missing = [c for c in CONFIGS[tool] if not (self.root / c).is_file()]
        command = _command(tool, file, self.root)
        if missing or command is None:
            return _finding(
                relative,
                tool,
                "skipped",
                details=[
                    "Missing: " + ", ".join(missing or [EXECUTABLE[tool]])
                ],
            )
        if tool == CLANG_TIDY_TOOL and not tidy_command_exists(self.root, file):
            return _finding(
                relative,
                tool,
                "skipped",
                details=[MISSING_TIDY_COMMAND],
            )
        return self._check_ready(file, tool, command)

    def _check_ready(
        self, file: Path, tool: str, command: list[str]
    ) -> Finding:
        relative = file.relative_to(self.root).as_posix()
        if tool in {"basedpyright", "clang-tidy"} and (
            tool not in self.dependency_digests
        ):
            self.dependency_digests[tool] = _dependencies(self.root, tool)
        fingerprint = _signature(
            command,
            file,
            self.root,
            context=(tool, self.dependency_digests.get(tool)),
        )
        key = relative + "::" + tool
        old = self.entries.get(key)
        if (
            not self.options.no_cache
            and old is not None
            and old["fingerprint"] == fingerprint
        ):
            result = _finding(
                relative, tool, old["status"], details=old["diagnostics"]
            )
            result["cached"] = True
            return result
        process = run_process(command, cwd=self.root)
        status: Status = "pass" if process.code == 0 else "fail"
        details = _diagnostics(process)
        self.entries[key] = {
            "fingerprint": fingerprint,
            "status": status,
            "diagnostics": details,
        }
        return _finding(relative, tool, status, details=details)


def _test_files(root: Path) -> list[Path]:
    directory = root / "tests"
    if not directory.is_dir():
        return []
    names = sorted(p for p in directory.rglob("test_*.*") if p.is_file())
    files = [_checked_path(root, str(p.relative_to(root))) for p in names]
    return [p for p in files if p.suffix in NATIVE_TESTS | {".py"}]


def _native_sources(root: Path, test: Path) -> list[Path]:
    companion = test.with_suffix(".sources")
    if not companion.exists():
        return []
    paths = [
        _checked_path(root, line.strip())
        for line in _checked_path(root, str(companion.relative_to(root)))
        .read_text()
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if any(p.suffix not in UNITS for p in paths):
        message = f"Non-source path in {companion.relative_to(root)}"
        raise ValueError(message)
    return paths


def _native_test(root: Path, test: Path) -> Finding:
    relative = test.relative_to(root).as_posix()
    compiler = shutil.which("clang++")
    if compiler is None:
        return _finding(
            relative,
            "native-test",
            "skipped",
            details=["Missing installed clang++"],
        )
    sources = _native_sources(root, test)
    with tempfile.TemporaryDirectory(
        prefix="simpleath-host-test-"
    ) as directory:
        executable = Path(directory) / "test"
        command = [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(root / "src"),
            str(test),
            *map(str, sources),
            "-o",
            str(executable),
        ]
        build = run_process(command, cwd=root)
        if build.code:
            return _finding(
                relative,
                "native-test",
                "fail",
                details=["Host test compilation failed", *_diagnostics(build)],
            )
        result = run_process([str(executable)], cwd=root)
        return _finding(
            relative,
            "native-test",
            "pass" if result.code == 0 else "fail",
            details=[
                f"Host test exit status: {result.code}",
                *_diagnostics(result),
            ],
        )


def _python_test(root: Path, test: Path) -> Finding:
    relative = test.relative_to(root).as_posix()
    result = run_process(
        [
            sys.executable,
            "-E",
            "-B",
            "-c",
            PYTHON_TEST_DRIVER,
            str(test.parent),
            test.name,
            str(root),
        ],
        cwd=root,
    )
    status: Status = "pass" if result.code == 0 else "fail"
    if result.code == EXIT_SKIPPED:
        status = "skipped"
    return _finding(
        relative,
        "python-test",
        status,
        details=_diagnostics(result) or ["No runnable tests or tests skipped"],
    )


def _one_test(root: Path, path: Path) -> Finding:
    try:
        return (
            _python_test(root, path)
            if path.suffix == PYTHON_SUFFIX
            else _native_test(root, path)
        )
    except (OSError, ValueError) as error:
        return _finding(
            path.relative_to(root).as_posix(),
            "host-test",
            "fail",
            details=[str(error)],
        )


def run_tests(root: Path) -> list[Finding]:
    """Run discovered offline host tests without caching their outcomes.

    Returns:
        Separate findings for each Python or native test source.

    """
    files = _test_files(root)
    if not files:
        return [
            _finding(
                "tests/",
                "host-tests",
                "skipped",
                details=["No test_*.py/.cpp/.mm tests found"],
            )
        ]
    return [_one_test(root, p) for p in files]


def _save(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False, encoding="utf-8"
    ) as file:
        _ = file.write(json.dumps(payload, indent=2) + "\n")
        temporary = Path(file.name)
    _ = temporary.replace(path)


def build_report(
    results: list[Finding], *, files: int, tests: bool, tools: dict[str, str]
) -> dict[str, object]:
    """Summarize checks, retaining only non-passes in detail rows.

    Returns:
        All counts and only actionable results for the requested scope.

    """
    counts = {
        s: sum(r["status"] == s for r in results)
        for s in ("pass", "fail", "skipped")
    }
    return {
        "schema": CACHE_VERSION,
        "scope": REPOSITORY_SCOPE,
        # Offline host tests do not turn a source-only scan into hardware QA.
        "source_only": True,
        "tests_requested": tests,
        "tools": tools,
        "summary": {
            "files": files,
            "checks": len(results),
            "cached": sum(r["cached"] for r in results),
            "executed": sum(
                not r["cached"] and r["status"] != SKIPPED for r in results
            ),
            **counts,
        },
        # PASS checks remain in the full summary and lint cache, but all
        # cached/new failures and skips stay visible without noisy PASS rows.
        "results": [r for r in results if r["status"] != STATUS_OK],
    }


def parse_options() -> Options:
    """Parse full-repository validation without optional check omissions.

    Returns:
        Validated CLI choices for lint, host tests and JSON reports.

    """
    defaults = Options()
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "files",
        nargs="*",
        help="Legacy paths are accepted but ignored; the full repo is checked",
    )
    _ = parser.add_argument(
        "--tidy",
        action="store_true",
        default=defaults.tidy,
        help="Check Clang-Tidy with an existing compilation database",
    )
    _ = parser.add_argument(
        "--tests",
        action="store_true",
        default=defaults.tests,
        help="Run offline host tests under tests/; never build the kext",
    )
    _ = parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=defaults.json_output,
    )
    _ = parser.add_argument("--no-cache", action="store_true")
    namespace = parser.parse_args()
    values: dict[str, object] = vars(namespace)
    files = values.get("files")
    return Options(
        tuple(files) if _strings(files) else (),
        values.get("tidy") is True,
        values.get("tests") is True,
        values.get("json_output") is True,
        values.get("no_cache") is True,
    )


@dataclass(frozen=True)
class RunInputs:
    """Stable inventory, content fingerprint and tool versions for one run."""

    sources: list[Path]
    snapshot: bytes
    versions: dict[str, str]


def _completion_token(root: Path) -> str | None:
    """Read the last finished generation marker without trusting its type.

    Returns:
        The previous run token, if a well-formed marker exists.

    """
    try:
        value = _decode((root / COMPLETION_FILE).read_text(encoding="utf-8"))
    except OSError, ValueError, RecursionError:
        return None
    if not _mapping(value) or value.get("schema") != COMPLETION_SCHEMA:
        return None
    token = value.get("token")
    return token if isinstance(token, str) else None


def _run_identity(
    root: Path,
    options: Options,
    inputs: RunInputs,
) -> str:
    """Bind a complete result to its source, tool and host environment.

    Returns:
        SHA-256 identity for a precise full-repository validation request.

    """
    executables = {
        tool: shutil.which(name) for tool, name in EXECUTABLE.items()
    }
    executables["native-test"] = shutil.which("clang++")
    environment_names = (
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "CPATH",
        "CPLUS_INCLUDE_PATH",
        "C_INCLUDE_PATH",
        "SDKROOT",
        "DEVELOPER_DIR",
        "CC",
        "CXX",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    )
    environment = {name: os.environ.get(name) for name in environment_names}
    request: dict[str, object] = {
        "schema": CACHE_VERSION,
        "sourceFiles": [p.relative_to(root).as_posix() for p in inputs.sources],
        "snapshot": inputs.snapshot.hex(),
        "script": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": (sys.executable, sys.version),
        "options": (
            options.tidy,
            options.tests,
            options.json_output,
            options.no_cache,
        ),
        "executables": executables,
        "versions": inputs.versions,
        "environment": environment,
    }
    return hashlib.sha256(
        json.dumps(request, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _tool_versions(root: Path) -> dict[str, str]:
    """Resolve every linter and host compiler version for run deduplication.

    Returns:
        Version strings or unavailable markers for every source tool.

    """
    versions: dict[str, str] = {}
    # The offline native tests use clang++ too. A binary replacement at the
    # same path must invalidate a concurrent completed-run identity, even when
    # every source, test manifest, and linter version is unchanged.
    for tool, name in {**EXECUTABLE, "native-test": "clang++"}.items():
        executable = shutil.which(name)
        versions[tool] = (
            tool_version(executable, root)
            if executable is not None
            else "unavailable"
        )
    return versions


def _completed_pair(
    root: Path, previous: str | None
) -> tuple[dict[str, object], str] | None:
    """Read a newly finished generation and match its report checksum.

    Returns:
        The validated completion marker and exact report text, if present.

    """
    try:
        record = _decode((root / COMPLETION_FILE).read_text(encoding="utf-8"))
        report = (root / ".cache/validate/report.json").read_text(
            encoding="utf-8"
        )
    except OSError, ValueError, RecursionError:
        return None
    if not _mapping(record):
        return None
    token = record.get("token")
    digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
    valid = (
        record.get("schema") == COMPLETION_SCHEMA
        and isinstance(token, str)
        and token != previous
        and record.get("reportSHA256") == digest
    )
    return (record, report) if valid else None


def _report_counts(
    value: object, files: int
) -> tuple[int, int, int, int] | None:
    """Validate summary cardinality and disallow boolean impostor counts.

    Returns:
        Ordered pass/fail/skipped/check totals, or no trustworthy counts.

    """
    if not _mapping(value) or value.get("files") != files:
        return None
    values = [value.get(key) for key in ("pass", "fail", "skipped", "checks")]
    if not all(
        isinstance(number, int) and not isinstance(number, bool) and number >= 0
        for number in values
    ):
        return None
    passed, failed, skipped, checks = (
        int(number) for number in values if isinstance(number, int)
    )
    return (passed, failed, skipped, checks)


def _report_summary_code(value: object, source_count: int) -> int | None:
    if not _mapping(value):
        return None
    header = (
        value.get("schema"),
        value.get("scope"),
        value.get("source_only"),
        value.get("tests_requested"),
    )
    expected = (CACHE_VERSION, REPOSITORY_SCOPE, True, True)
    counts = _report_counts(value.get("summary"), source_count)
    if header != expected or counts is None:
        return None
    passed, failed, skipped, checks = counts
    return (
        (EXIT_FAILURE if failed or skipped else 0)
        if passed + failed + skipped == checks
        else None
    )


def _report_code(report_text: str, source_count: int) -> int | None:
    """Reject incomplete reports while preserving a real failing status.

    Returns:
        The report's real exit status or None for malformed information.

    """
    try:
        report = _decode(report_text)
    except ValueError, RecursionError:
        return None
    return _report_summary_code(report, source_count)


def _current_inputs(root: Path) -> RunInputs:
    sources = source_files(root, ())
    return RunInputs(
        sources, input_snapshot(root, sources), _tool_versions(root)
    )


def _completed_report(
    root: Path, options: Options, previous: str | None
) -> tuple[int, str] | None:
    """Reuse only a different completed generation with identical inputs.

    Returns:
        The earlier exit code and exact JSON report, or no reusable result.

    """
    candidate = _completed_pair(root, previous)
    if candidate is None:
        return None
    record, report_text = candidate
    try:
        inputs = _current_inputs(root)
        identity = _run_identity(root, options, inputs)
        code = _report_code(report_text, len(inputs.sources))
        # Recheck after reading every source; mixed versions cannot share.
        unchanged = inputs == _current_inputs(root)
    except OSError, ValueError, RecursionError:
        return None
    usable = (
        record.get("identity") == identity and code is not None and unchanged
    )
    return (code, report_text) if usable and code is not None else None


def _locked_run(options: Options) -> int:
    """Deduplicate identical overlapping requests after the full run lock.

    Returns:
        The real previous status for a shared run or a newly executed status.

    """
    # The cache may be removed by cleanup while a run is active. Keep the
    # advisory lock under .git so replacement cache directories cannot create
    # distinct lock inodes and allow simultaneous repository scans.
    with (ROOT / RUN_LOCK_FILE).open("a+b") as lock:
        previous = _completion_token(ROOT)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            reused = _completed_report(ROOT, options, previous)
            if reused is not None:
                code, report_text = reused
                _ = sys.stdout.write(report_text)
                return code
        return _validate(options)


def main() -> int:
    """Run selected lint checks and default-on offline host tests.

    Returns:
        Zero only when all requested checks pass; skipped checks fail closed.

    """
    options = parse_options()
    try:
        # Serialize the entire read/validate/write operation. Otherwise
        # parallel agents can overwrite a newer full report or lose cache
        # entries by reading and saving the same cache independently.
        return _locked_run(options)
    except (OSError, ValueError) as error:
        _ = sys.stderr.write(f"Validation error: {error}\n")
        return EXIT_FAILURE


def _validate(options: Options) -> int:
    if not options.tidy or not options.tests or not options.json_output:
        message = "All checks and JSON reporting are mandatory"
        raise ValueError(message)
    # File arguments are accepted for backwards compatibility, never as a
    # scope limiter: the owner requires every repository source in each run.
    sources = source_files(ROOT, ())
    initial_snapshot = input_snapshot(ROOT, sources)
    # Include the requested tools even if a missing prerequisite prevents a
    # tool from executing. An omitted clang-tidy key must never imply success.
    versions = _tool_versions(ROOT)
    lint = LintRun(ROOT, options, read_cache(ROOT), versions=versions)
    results = [
        lint.check(file, tool)
        for file in sources
        for tool in _tools(file, options)
    ]
    results.extend(run_tests(ROOT))
    # The run lock serializes validators, not other agents' source writes.
    # A changed source, rule, test manifest or inventory makes a mixed-revision
    # report unsafe even when every individual check happened to pass.
    stable = sources == source_files(
        ROOT, ()
    ) and initial_snapshot == input_snapshot(ROOT, sources)
    if not stable:
        results.append(
            _finding(
                "src/ tools/ tests/",
                "source-snapshot",
                "fail",
                details=["Inputs changed during scan; rerun on a stable tree"],
            )
        )
    report = build_report(
        results, files=len(sources), tests=options.tests, tools=lint.versions
    )
    _save(
        ROOT / ".cache/validate/cache.json",
        {"schema": CACHE_VERSION, "entries": lint.entries},
    )
    report_text = json.dumps(report, indent=2) + "\n"
    _save(ROOT / ".cache/validate/report.json", report)
    if stable:
        _save(
            ROOT / COMPLETION_FILE,
            {
                "schema": COMPLETION_SCHEMA,
                "token": os.urandom(16).hex(),
                "identity": _run_identity(
                    ROOT,
                    options,
                    RunInputs(sources, initial_snapshot, versions),
                ),
                "reportSHA256": hashlib.sha256(
                    report_text.encode()
                ).hexdigest(),
            },
        )
    _ = sys.stdout.write(report_text)
    return EXIT_FAILURE if any(r["status"] != STATUS_OK for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
