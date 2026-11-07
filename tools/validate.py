#!/usr/bin/env python3
"""Source-only Clang formatting/tidy runner for C, Objective-C and C++.

No builds, tests, downloads, file rewrites, Jig or hardware access.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUFFIXES = {".c", ".h", ".m", ".mm", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}
TRANSLATION_UNITS = {".c", ".m", ".mm", ".cc", ".cpp", ".cxx"}


def tracked_sources() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "src/", "tools/"],
        cwd=ROOT, capture_output=True, check=True,
    )
    return [ROOT / Path(name.decode()) for name in result.stdout.split(b"\0") if name]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="C/Objective-C/C++ source files (default: tracked src/ and tools/)")
    parser.add_argument("--tidy", action="store_true", help="Also run Clang-Tidy using an EXISTING compile_commands.json")
    args = parser.parse_args()

    files = [Path(name) for name in args.files] if args.files else tracked_sources()
    selected = sorted({p if p.is_absolute() else ROOT / p for p in files if p.suffix.lower() in SUFFIXES})
    selected = [p for p in selected if p.is_file()]
    if not selected:
        print("No C, Objective-C or C++ files to validate.")
        return 0

    formatter = shutil.which("clang-format")
    if formatter is None:
        print("clang-format not installed; no tools will be downloaded.", file=sys.stderr)
        return 2

    failed = False
    format_failures = 0
    for file in selected:
        path = str(file.relative_to(ROOT)) if file.is_relative_to(ROOT) else str(file)
        result = subprocess.run(
            [formatter, "--dry-run", "--Werror", "--ferror-limit=2", str(file)],
            cwd=ROOT, capture_output=True, text=True,
        )
        if result.returncode:
            format_failures += 1
            print(f"FAIL clang-format: {path}", file=sys.stderr)
            for line in result.stderr.splitlines()[:3]:
                print(f"  {line}", file=sys.stderr)
            failed = True

    if args.tidy:
        database = ROOT / "compile_commands.json"
        tidy = shutil.which("clang-tidy")
        if not database.is_file() or tidy is None:
            print("Clang-Tidy skipped: requires installed clang-tidy and existing compile_commands.json.", file=sys.stderr)
            return 2
        for file in selected:
            if file.suffix.lower() not in TRANSLATION_UNITS:
                continue
            if subprocess.run([tidy, "-p", str(ROOT), "--quiet", str(file)], cwd=ROOT).returncode:
                print(f"FAIL clang-tidy: {file.name}", file=sys.stderr)
                failed = True
    else:
        print("Clang-Tidy not requested (use --tidy with an existing compile_commands.json).")

    print(f"clang-format: {len(selected) - format_failures} passed, {format_failures} failed ({len(selected)} files). No build or tests.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
