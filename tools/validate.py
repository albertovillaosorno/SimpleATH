#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Check source with installed linters and default-on offline host tests."""

import argparse
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field
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
DISPLAY_LIMIT = 2
DISPLAY_WIDTH = 240
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
    """Select lint checks, host tests and report presentation independently."""

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
    return text.strip().splitlines()[:DIAGNOSTIC_LIMIT]


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


def _dependencies(root: Path) -> bytes:
    digest = hashlib.sha256()
    files = sorted(
        p
        for d in ("src", "tools", "tests")
        for p in (root / d).rglob("*")
        if p.is_file() and p.suffix in SUPPORTED
    )
    for path in files:
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.digest()


def _signature(command: list[str], file: Path, root: Path, *, tool: str) -> str:
    digest = hashlib.sha256(file.read_bytes())
    digest.update(Path(__file__).read_bytes())
    digest.update(json.dumps(command).encode())
    digest.update(_version(command[0], root).encode())
    for config in CONFIGS[tool]:
        digest.update((root / config).read_bytes())
    if tool in {"basedpyright", "clang-tidy"}:
        digest.update(_dependencies(root))
    return digest.hexdigest()


@dataclass
class LintRun:
    """Collect actual checks and validated lint cache entries."""

    root: Path
    options: Options
    entries: dict[str, CacheEntry]
    versions: dict[str, str] = field(default_factory=dict)

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
        return self._check_ready(file, tool, command)

    def _check_ready(
        self, file: Path, tool: str, command: list[str]
    ) -> Finding:
        relative = file.relative_to(self.root).as_posix()
        self.versions[tool] = _version(command[0], self.root).splitlines()[0]
        fingerprint = _signature(command, file, self.root, tool=tool)
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


def _report(
    results: list[Finding], *, files: int, tests: bool, tools: dict[str, str]
) -> dict[str, object]:
    counts = {
        s: sum(r["status"] == s for r in results)
        for s in ("pass", "fail", "skipped")
    }
    return {
        "schema": CACHE_VERSION,
        "source_only": not tests,
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
        "results": results,
    }


def _display(results: list[Finding]) -> None:
    for item in results:
        cached = "CACHED " if item["cached"] else ""
        label = f"{item["status"].upper():7} {cached:7}{item["tool"]:14}"
        _ = sys.stdout.write(f"{label} {item["file"]}\n")
        if item["status"] != STATUS_OK:
            for line in item["diagnostics"][:DISPLAY_LIMIT]:
                _ = sys.stdout.write(f"  {line[:DISPLAY_WIDTH]}\n")


def parse_options() -> Options:
    """Parse the default-on CLI, preserving explicit check opt-outs.

    Returns:
        Validated CLI choices for lint, host tests and JSON reports.

    """
    defaults = Options()
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "files", nargs="*", help="Optional lint source paths"
    )
    _ = parser.add_argument(
        "--tidy",
        action=argparse.BooleanOptionalAction,
        default=defaults.tidy,
        help="Check Clang-Tidy with an existing compilation database",
    )
    _ = parser.add_argument(
        "--tests",
        action=argparse.BooleanOptionalAction,
        default=defaults.tests,
        help="Run offline host tests under tests/; never build the kext",
    )
    _ = parser.add_argument(
        "--json",
        dest="json_output",
        action=argparse.BooleanOptionalAction,
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


def main() -> int:
    """Run selected lint checks and default-on offline host tests.

    Returns:
        Zero only when all requested checks pass; skipped checks fail closed.

    """
    options = parse_options()
    try:
        return _validate(options)
    except (OSError, ValueError) as error:
        _ = sys.stderr.write(f"Validation error: {error}\n")
        return EXIT_FAILURE


def _validate(options: Options) -> int:
    sources = source_files(ROOT, options.files)
    lint = LintRun(ROOT, options, read_cache(ROOT))
    results = [
        lint.check(file, tool)
        for file in sources
        for tool in _tools(file, options)
    ]
    if options.tests:
        results.extend(run_tests(ROOT))
    report = _report(
        results, files=len(sources), tests=options.tests, tools=lint.versions
    )
    _save(
        ROOT / ".cache/validate/cache.json",
        {"schema": CACHE_VERSION, "entries": lint.entries},
    )
    _save(ROOT / ".cache/validate/report.json", report)
    if options.json_output:
        _ = sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        _display(results)
        _ = sys.stdout.write(json.dumps(report["summary"]) + "\n")
    return EXIT_FAILURE if any(r["status"] != STATUS_OK for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
