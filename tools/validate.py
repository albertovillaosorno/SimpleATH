#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Run cached source lint with installed tools; never build or run tests."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Fixed Git discovery and installed linters only, without a shell.
import sys
from typing import Literal
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "validate"
NATIVE = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm"}
UNITS = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
SUPPORTED = NATIVE | {".py"}
CLANG_FORMAT = "clang-format"
CLANG_TIDY = "clang-tidy"
RUFF_CHECK = "ruff-check"
RUFF_FORMAT = "ruff-format"
BASEDPYRIGHT = "basedpyright"
SUCCESS = "pass"
FAIL = "fail"
SKIPPED = "skipped"
MAX_DIAGNOSTICS = 12
JSON_SWITCH = "--outputjson"
TIMEOUT_SECONDS = 120
CONFIGS = {
    CLANG_FORMAT: (".clang-format", ".editorconfig"),
    CLANG_TIDY: (".clang-tidy", ".editorconfig", "compile_commands.json"),
    RUFF_CHECK: ("ruff.toml", ".editorconfig"),
    RUFF_FORMAT: ("ruff.toml", ".editorconfig"),
    BASEDPYRIGHT: ("pyrightconfig.json",),
}
EXECUTABLE = {
    CLANG_FORMAT: "clang-format",
    CLANG_TIDY: "clang-tidy",
    RUFF_CHECK: "ruff",
    RUFF_FORMAT: "ruff",
    BASEDPYRIGHT: "basedpyright",
}

type _Status = Literal["pass", "fail", "skipped"]
type _CacheStatus = Literal["pass", "fail"]


class _Options(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.files: list[str] = []
        self.tidy: bool = False
        self.json: bool = False
        self.no_cache: bool = False


class _CacheEntry(TypedDict):
    fingerprint: str
    status: _CacheStatus
    diagnostics: list[str]


class _Result(TypedDict):
    file: str
    tool: str
    status: _Status
    cached: bool
    diagnostics: list[str]


@dataclass
class _Context:
    """Mutable per-invocation cache and tool-version state."""

    options: _Options
    entries: dict[str, object]
    versions: dict[str, str]


def digest(data: bytes) -> str:
    """Return a source/configuration content hash.

    Returns:
        The SHA-256 digest encoded as hexadecimal text.

    """
    return hashlib.sha256(data).hexdigest()


def _is_sequence(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _is_strings(value: object) -> TypeIs[list[str]]:
    return _is_sequence(value) and all(isinstance(item, str) for item in value)


def _is_object_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_dict(value) and all(isinstance(key, str) for key in value)


def _decode_json(data: str, decoder: Callable[[str], object]) -> object:
    return decoder(data)


def read_json(path: Path) -> dict[str, object]:
    """Read a valid JSON object or return an empty cache.

    Returns:
        The decoded object, or an empty dictionary on read/parse failure.

    """
    try:
        value = _decode_json(path.read_text(encoding="utf-8"), json.loads)
    except OSError, ValueError:
        return {}
    return value if _is_mapping(value) else {}


def _git_paths() -> list[str]:
    git = shutil.which("git")
    if git is None:
        message = "Git executable is missing"
        raise ValueError(message)
    # Include untracked (but not gitignored) source, too. No Git mutations.
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - Fixed read-only Git enumeration.
        [
            git,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "src/",
            "tools/",
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return [item.decode() for item in result.stdout.split(b"\0") if item]


def _reject_explicit(message: str, *, explicit: bool) -> None:
    if explicit:
        raise ValueError(message)


def _source_path(name: str, *, explicit: bool) -> Path | None:
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT):
        message = f"Outside repository: {name}"
        raise ValueError(message)
    if not path.is_file():
        _reject_explicit(f"Missing file: {name}", explicit=explicit)
        return None
    if path.suffix.lower() in SUPPORTED:
        return path
    _reject_explicit(f"Unsupported extension: {name}", explicit=explicit)
    return None


def files_to_check(names: list[str]) -> list[Path]:
    """Resolve explicit paths or all tracked and new non-vendored source.

    Returns:
        The sorted unique source paths to validate.

    """
    explicit = bool(names)
    candidates = names if explicit else _git_paths()
    sources: set[Path] = set()
    for name in candidates:
        path = _source_path(name, explicit=explicit)
        if path is not None:
            sources.add(path)
    return sorted(sources)


def _read_diagnostic(item: object) -> str:
    if not _is_mapping(item):
        return "Invalid diagnostic object"
    file = item.get("file")
    name = Path(file).name if isinstance(file, str) else "<unknown>"
    location = item.get("range")
    start = location.get("start") if _is_mapping(location) else None
    line = start.get("line") if _is_mapping(start) else None
    number = (
        line + 1 if isinstance(line, int) and not isinstance(line, bool) else 1
    )
    severity = item.get("severity", "error")
    message = item.get("message", "")
    return f"{name}:{number} {severity}: {message}"


def _json_diagnostics(stdout: str, stderr: str) -> list[str] | None:
    try:
        payload = _decode_json(stdout, json.loads)
    except ValueError:
        return None
    issues = payload.get("generalDiagnostics") if _is_mapping(payload) else None
    if not _is_sequence(issues):
        return None
    details = [_read_diagnostic(item) for item in issues[:MAX_DIAGNOSTICS]]
    if stderr.strip() and _is_sequence(issues):
        details.append(stderr.strip().splitlines()[0])
    return details


def execute(command: list[str]) -> tuple[int, list[str]]:
    """Run one installed linter in a fixed cwd, never using shell execution.

    Returns:
        Its exit code and the first diagnostics, bounded by policy.

    """
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - Tool command vectors are constructed internally.
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        message = (
            "Linter exceeded 120 seconds (not a build)."
            if isinstance(error, subprocess.TimeoutExpired)
            else f"Linter could not start: {error}"
        )
        return 2, [message]
    details = (
        _json_diagnostics(result.stdout, result.stderr)
        if JSON_SWITCH in command
        else None
    )
    if details is not None:
        return result.returncode, details
    output = (result.stdout + "\n" + result.stderr).strip().splitlines()
    return result.returncode, output[:MAX_DIAGNOSTICS]


def save_json(path: Path, payload: object) -> None:
    """Write an ignored cache/report atomically without changing source."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    _ = temporary.write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    _ = temporary.replace(path)


def _args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("files", nargs="*", help="Optional source paths")
    _ = parser.add_argument(
        "--tidy",
        action="store_true",
        help="Clang-Tidy, only with existing compile_commands.json",
    )
    _ = parser.add_argument(
        "--json",
        action="store_true",
        help="Machine-readable report on stdout",
    )
    _ = parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Force fresh checks without changing source files",
    )
    return parser


def _toolset(file: Path, *, tidy: bool) -> list[str]:
    if file.suffix.lower() not in NATIVE:
        return [RUFF_CHECK, RUFF_FORMAT, BASEDPYRIGHT]
    tools = [CLANG_FORMAT]
    if tidy and file.suffix.lower() in UNITS:
        tools.append(CLANG_TIDY)
    return tools


def _command(
    tool: str, executable: str, configs: list[Path], *, file: Path
) -> list[str]:
    if tool == CLANG_FORMAT:
        command = [
            executable,
            f"--style=file:{configs[0]}",
            "--dry-run",
            "--Werror",
            "--ferror-limit=1",
            str(file),
        ]
    elif tool == CLANG_TIDY:
        command = [
            executable,
            f"--config-file={configs[0]}",
            "-p",
            str(ROOT),
            "--quiet",
            str(file),
        ]
    elif tool == RUFF_CHECK:
        command = [
            executable,
            "check",
            "--config",
            str(configs[0]),
            "--output-format",
            "concise",
            str(file),
        ]
    elif tool == RUFF_FORMAT:
        command = [
            executable,
            "format",
            "--check",
            "--config",
            str(configs[0]),
            str(file),
        ]
    else:
        command = [executable, "-p", str(configs[0]), JSON_SWITCH, str(file)]
    return command


def _fingerprint(
    file: Path, tool: str, version: str, *, configs: list[Path]
) -> str:
    signature = {
        "file_sha256": digest(file.read_bytes()),
        "tool": tool,
        "version": version,
        "rules": [(path.name, digest(path.read_bytes())) for path in configs],
    }
    return digest(json.dumps(signature, sort_keys=True).encode())


def _cache_entry(value: object) -> _CacheEntry | None:
    if not _is_mapping(value):
        return None
    fingerprint = value.get("fingerprint")
    status = value.get("status")
    diagnostics = value.get("diagnostics")
    if (
        isinstance(fingerprint, str)
        and _is_strings(diagnostics)
        and status in {SUCCESS, FAIL}
    ):
        return {
            "fingerprint": fingerprint,
            "status": SUCCESS if status == SUCCESS else FAIL,
            "diagnostics": diagnostics,
        }
    return None


def _version(ctx: _Context, tool: str, executable: str) -> str:
    if tool not in ctx.versions:
        code, lines = execute([executable, "--version"])
        ctx.versions[tool] = lines[0] if lines else f"unknown/{code}"
    return ctx.versions[tool]


def _result(
    relative: str,
    tool: str,
    outcome: tuple[_Status, list[str]],
    *,
    cached: bool,
) -> _Result:
    status, diagnostics = outcome
    return {
        "file": relative,
        "tool": tool,
        "status": status,
        "cached": cached,
        "diagnostics": diagnostics,
    }


def _check_one(ctx: _Context, file: Path, tool: str) -> _Result:
    configs = [ROOT / name for name in CONFIGS[tool]]
    executable = shutil.which(EXECUTABLE[tool])
    missing = [path.name for path in configs if not path.is_file()]
    if executable is None:
        missing.append(EXECUTABLE[tool])
    relative = file.relative_to(ROOT).as_posix()
    if missing or executable is None:
        return _result(
            relative,
            tool,
            (SKIPPED, ["Missing: " + ", ".join(missing)]),
            cached=False,
        )
    fingerprint = _fingerprint(
        file, tool, _version(ctx, tool, executable), configs=configs
    )
    key = f"{relative}::{tool}"
    old = _cache_entry(ctx.entries.get(key))
    if (
        not ctx.options.no_cache
        and old is not None
        and old["fingerprint"] == fingerprint
    ):
        return _result(
            relative, tool, (old["status"], old["diagnostics"]), cached=True
        )
    code, diagnostics = execute(_command(tool, executable, configs, file=file))
    status: _CacheStatus = SUCCESS if code == 0 else FAIL
    ctx.entries[key] = {
        "fingerprint": fingerprint,
        "status": status,
        "diagnostics": diagnostics,
    }
    return _result(relative, tool, (status, diagnostics), cached=False)


def _summary(sources: list[Path], results: list[_Result]) -> dict[str, int]:
    return {
        "files": len(sources),
        "checks": len(results),
        "executed": sum(
            not row["cached"] and row["status"] != SKIPPED for row in results
        ),
        "cached": sum(row["cached"] for row in results),
        SUCCESS: sum(row["status"] == SUCCESS for row in results),
        FAIL: sum(row["status"] == FAIL for row in results),
        SKIPPED: sum(row["status"] == SKIPPED for row in results),
    }


def _display(results: list[_Result], summary: dict[str, int]) -> None:
    for result in results:
        flag = "CACHED " if result["cached"] else ""
        prefix = f"{result["status"].upper():7} {flag:7}"
        _ = sys.stdout.write(f"{prefix} {result["tool"]:12} {result["file"]}\n")
        if result["status"] != SUCCESS:
            for line in result["diagnostics"][:2]:
                _ = sys.stdout.write(f"  {line[:240]}\n")
    count_lines = [
        f"\nSource-only: {summary["files"]} files, ",
        f"{summary["checks"]} checks, ",
        f"{summary["executed"]} executed, {summary["cached"]} cached, ",
        f"{summary[FAIL]} failures, {summary[SKIPPED]} skipped.\n",
    ]
    _ = sys.stdout.write("".join(count_lines))
    _ = sys.stdout.write("Agent report: .cache/validate/report.json\n")


def main() -> int:
    """Validate known source files and persist the structured report.

    Returns:
        Zero only if every requested check passed, or one on any failure.

    """
    parser = _args_parser()
    args = parser.parse_args(namespace=_Options())
    try:
        sources = files_to_check(args.files)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    previous = read_json(CACHE / "cache.json")
    existing = previous.get("entries")
    ctx = _Context(args, existing if _is_mapping(existing) else {}, {})
    results = [
        _check_one(ctx, file, tool)
        for file in sources
        for tool in _toolset(file, tidy=args.tidy)
    ]
    summary = _summary(sources, results)
    report = {
        "schema": "simpleath.validate.v1",
        "source_only": True,
        "tools": ctx.versions,
        "summary": summary,
        "results": results,
    }
    save_json(
        CACHE / "cache.json",
        {"schema": "simpleath.validate.v1", "entries": ctx.entries},
    )
    save_json(CACHE / "report.json", report)
    if args.json:
        _ = sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        _display(results, summary)
    return 1 if summary[FAIL] or summary[SKIPPED] else 0


if __name__ == "__main__":
    sys.exit(main())
