#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Incremental source lint: existing root rules, system tools, no build/tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "validate"
NATIVE = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
          ".m", ".mm"}
UNITS = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
SUPPORTED = NATIVE | {".py"}
CONFIGS = {
    "clang-format": [".clang-format", ".editorconfig"],
    "clang-tidy": [".clang-tidy", ".editorconfig", "compile_commands.json"],
    "ruff-check": ["ruff.toml", ".editorconfig"],
    "ruff-format": ["ruff.toml", ".editorconfig"],
    "basedpyright": ["pyrightconfig.json"],
}
EXECUTABLE = {
    "clang-format": "clang-format",
    "clang-tidy": "clang-tidy",
    "ruff-check": "ruff",
    "ruff-format": "ruff",
    "basedpyright": "basedpyright",
}


def digest(data: bytes) -> str:
    """Hash source/configuration bytes, independent of mtime."""
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    """Read optional cache without trusting malformed or outdated entries."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def files_to_check(names: list[str]) -> list[Path]:
    """Resolve explicit paths or tracked source files, excluding vendored code."""
    if not names:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", "src/", "tools/"],
            cwd=ROOT, capture_output=True, check=True,
        )
        names = [x.decode() for x in result.stdout.split(b"\0") if x]
    selected = set()
    for name in names:
        file = (ROOT / name).resolve()
        if not file.is_relative_to(ROOT):
            raise ValueError(f"Outside repository: {name}")
        if not file.is_file():
            if names:
                raise ValueError(f"Missing file: {name}")
            continue
        if file.suffix.lower() in SUPPORTED:
            selected.add(file)
        elif name not in (".", "") and len(names) == 1:
            raise ValueError(f"Unsupported extension: {name}")
    return sorted(selected)


def execute(command: list[str]) -> tuple[int, list[str]]:
    """Run an installed linter without file modifications or shell execution."""
    try:
        result = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True,
            check=False, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return 2, ["Linter exceeded 120 seconds (not a build)."]
    if "--outputjson" in command:
        try:
            payload = json.loads(result.stdout)
            issues = payload.get("generalDiagnostics", [])
            details = [
                f"{Path(d.get('file', '<unknown>')).name}:"
                f"{d.get('range', {}).get('start', {}).get('line', 0) + 1} "
                f"{d.get('severity', 'error')}: {d.get('message', '')}"
                for d in issues[:12]
            ]
            if result.stderr.strip():
                details.append(result.stderr.strip().splitlines()[0])
            return result.returncode, details
        except (ValueError, AttributeError, TypeError):
            pass
    output = (result.stdout + "\n" + result.stderr).strip().splitlines()
    return result.returncode, output[:12]


def save_json(path: Path, payload: dict) -> None:
    """Write cache/report atomically under the gitignored .cache directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    """Run formatting, lint and type checks with content-addressed caching."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="Optional source paths")
    parser.add_argument("--tidy", action="store_true",
                        help="Clang-Tidy, only with an existing compile_commands.json")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable report on stdout")
    parser.add_argument("--no-cache", action="store_true",
                        help="Force fresh checks without changing source files")
    args = parser.parse_args()
    try:
        sources = files_to_check(args.files)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))

    previous = read_json(CACHE / "cache.json")
    entries = previous.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    results = []
    versions: dict[str, str] = {}
    for file in sources:
        relative = file.relative_to(ROOT).as_posix()
        tools = (["clang-format"] + (["clang-tidy"] if args.tidy and
                 file.suffix.lower() in UNITS else [])
                 if file.suffix.lower() in NATIVE else
                 ["ruff-check", "ruff-format", "basedpyright"])
        for tool in tools:
            executable = shutil.which(EXECUTABLE[tool])
            needed = [ROOT / x for x in CONFIGS[tool]]
            # Clang-Tidy requires a preexisting compilation database; do
            # not generate one or attempt implicit compilation.
            missing = ([p.name for p in needed if not p.is_file()] +
                       ([] if executable else [EXECUTABLE[tool]]))
            if missing:
                results.append({"file": relative, "tool": tool,
                                "status": "skipped", "cached": False,
                                "diagnostics": ["Missing: " + ", ".join(missing)]})
                continue
            if tool not in versions:
                version_code, version_lines = execute([executable, "--version"])
                versions[tool] = (version_lines[0] if version_lines else
                                  f"unknown/{version_code}")
            signature = {
                "file_sha256": digest(file.read_bytes()),
                "tool": tool,
                "version": versions[tool],
                "rules": [(p.name, digest(p.read_bytes())) for p in needed],
            }
            fingerprint = digest(
                json.dumps(signature, sort_keys=True).encode()
            )
            key = relative + "::" + tool
            old = entries.get(key, {})
            if not args.no_cache and isinstance(old, dict) and old.get(
                    "fingerprint") == fingerprint:
                cached = True
                status = old.get("status", "fail")
                diagnostics = old.get("diagnostics", [])
            else:
                cached = False
                if tool == "clang-format":
                    command = [executable, f"--style=file:{needed[0]}",
                               "--dry-run", "--Werror", "--ferror-limit=1",
                               str(file)]
                elif tool == "clang-tidy":
                    command = [executable, f"--config-file={needed[0]}",
                               "-p", str(ROOT), "--quiet", str(file)]
                elif tool == "ruff-check":
                    command = [executable, "check", "--config",
                               str(needed[0]), "--output-format", "concise",
                               str(file)]
                elif tool == "ruff-format":
                    command = [executable, "format", "--check", "--config",
                               str(needed[0]), str(file)]
                else:
                    command = [executable, "-p", str(needed[0]),
                               "--outputjson", str(file)]
                code, diagnostics = execute(command)
                status = "pass" if code == 0 else "fail"
                entries[key] = {"fingerprint": fingerprint, "status": status,
                                "diagnostics": diagnostics}
            results.append({"file": relative, "tool": tool, "status": status,
                            "cached": cached, "diagnostics": diagnostics})

    counts = {name: sum(x["status"] == name for x in results)
              for name in ("pass", "fail", "skipped")}
    summary = {"files": len(sources), "checks": len(results),
               "executed": sum(not x["cached"] and x["status"] != "skipped"
                               for x in results),
               "cached": sum(x["cached"] for x in results), **counts}
    report = {"schema": "simpleath.validate.v1", "source_only": True,
              "tools": versions, "summary": summary, "results": results}
    save_json(CACHE / "cache.json", {"schema": "simpleath.validate.v1",
                                    "entries": entries})
    save_json(CACHE / "report.json", report)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for result in results:
            flag = "CACHED " if result["cached"] else ""
            print(f'{result["status"].upper():7} {flag:7} '
                  f'{result["tool"]:12} {result["file"]}')
            if result["status"] != "pass":
                for line in result["diagnostics"][:2]:
                    print(f"  {line[:240]}")
        print(f'\nSource-only: {summary["files"]} files, {summary["checks"]} '
              f'checks, {summary["executed"]} executed, '
              f'{summary["cached"]} cached, {summary["fail"]} failures, '
              f'{summary["skipped"]} skipped.')
        print("Agent report: .cache/validate/report.json")
    return 1 if summary["fail"] or summary["skipped"] else 0


if __name__ == "__main__":
    sys.exit(main())
