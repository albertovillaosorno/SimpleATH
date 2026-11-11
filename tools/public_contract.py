#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno.
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - Original SimpleATH document or third-party license notice
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for public contract.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for public contract.
# - Description:
#   - Implements or verifies the public_contract source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for public contract.

"""Validate public source headers, provenance, Git history, and path hygiene."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CODE_EXTENSIONS = frozenset({
    ".cpp",
    ".hpp",
    ".c",
    ".h",
    ".cc",
    ".mm",
    ".py",
    ".inc",
    ".command",
    ".m",
})
FIELDS = (
    "Owns",
    "Must-Not",
    "Allows",
    "Split-When",
    "Merge-When",
    "Summary",
    "Description",
    "Usage",
    "Defaults",
)
CANONICAL_TRAILER = "Signed-off-by: Alberto Villa Osorno <300648727+albertovillaosorno@users.noreply.github.com>"
IDENTITY = "Alberto Villa Osorno"
EMAIL = "300648727+albertovillaosorno@users.noreply.github.com"
TYPES = frozenset({
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "release",
    "revert",
    "style",
    "test",
})
PERSONAL_PATH = re.compile(
    rb'/(?:home|Users)/[^/\r\n\s"\']+/(?:Developer|Downloads|Documents|Desktop)/'
)
SUBJECT = re.compile(r"^([a-z]+)\(([a-z0-9][a-z0-9-]*)\): (\S.*)$")
TRAILER = re.compile(
    r"^(?:Signed-off-by|Co-authored-by|Co-Authored-By|Reviewed-by):", re.I
)


def tracked(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
    )
    return sorted(
        name.decode("utf-8") for name in result.stdout.split(b"\0") if name
    )


def is_code(path: str) -> bool:
    return Path(path).suffix.lower() in CODE_EXTENSIONS or path.endswith(
        ".cpp.in"
    )


def verify_header(path: str, content: str, entry: dict[str, Any]) -> list[str]:
    """Check the ordered contract using the same syntax in both languages."""
    problems = []
    prefix = "#" if path.endswith((".py", ".command")) else "//"
    lines = content.splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if not lines or lines[0] != prefix + " Copyright:":
        return [f"{path}: missing uniform {prefix} Copyright header"]
    expected = (
        ("SPDX-License-Identifier:", entry["license"]),
        ("Confidential:", "false"),
        ("License-File:", entry["license_file"]),
        ("Provenance:", None),
    )
    head = "\n".join(lines[:100])
    for label, value in expected:
        if f"{prefix} {label}" not in head:
            problems.append(f"{path}: missing {label}")
        if value is not None and f"{prefix}   - {value}" not in head:
            problems.append(f"{path}: expected {label} = {value}")
    if f"{prefix} Boundary-Contract:" not in head:
        problems.append(f"{path}: missing Boundary-Contract")
    positions = [head.find(f"{prefix} - {field}:") for field in FIELDS]
    if -1 in positions or positions != sorted(positions):
        problems.append(f"{path}: missing or disordered boundary fields")
    for field in FIELDS:
        match = re.search(
            rf"(?m)^{re.escape(prefix)} - {field}:\n{re.escape(prefix)}   - \S",
            head,
        )
        if match is None:
            problems.append(f"{path}: empty {field} contract")
    if f"{prefix} Module:" not in head:
        problems.append(f"{path}: missing module summary")
    return problems


def check_source(root: Path = ROOT) -> list[str]:
    problems = []
    inventory_path = root / "docs/provenance/files.json"
    if not inventory_path.is_file():
        return ["Missing provenance/files.json"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory.get("schema") != "simpleath.file-provenance.v1":
        return ["Unrecognized provenance schema"]
    entries = {item["path"]: item for item in inventory["files"]}
    sources = tracked(root)
    missing = set(sources) - set(entries)
    surplus = set(entries) - set(sources)
    problems.extend(
        f"Missing file provenance: {name}" for name in sorted(missing)
    )
    problems.extend(
        f"Stale file provenance: {name}" for name in sorted(surplus)
    )
    for path in sources:
        if path not in entries:
            continue
        item = entries[path]
        if (
            not item.get("license")
            or not item.get("provenance")
            or not item.get("copyright")
        ):
            problems.append(f"{path}: incomplete provenance metadata")
        license_file = item.get("license_file")
        if not license_file or not all(
            (root / name.strip()).is_file()
            for name in str(license_file).split(";")
        ):
            problems.append(f"{path}: missing referenced license/notice")
        raw = (root / path).read_bytes()
        if PERSONAL_PATH.search(raw):
            problems.append(f"{path}: local user directory disclosed")
        if is_code(path):
            try:
                problems.extend(verify_header(path, raw.decode("utf-8"), item))
            except UnicodeDecodeError:
                problems.append(f"{path}: code is not valid UTF-8")
            if b"Copyright (c) " + b"2026 SimpleATH contributors." in raw:
                problems.append(f"{path}: redundant generic copyright banner")
        if path.startswith("src/firmware/ar3k/") and path.endswith(".dfu"):
            import hashlib

            if item.get("sha256") != hashlib.sha256(raw).hexdigest():
                problems.append(
                    f"{path}: firmware bytes differ from provenance digest"
                )
    if "compile_commands.json" in sources:
        compile_entries = json.loads((root / "compile_commands.json").read_text())
        for command in compile_entries:
            if Path(command["directory"]).is_absolute():
                problems.append("Absolute compile working directory")
            if any(str(value).startswith("/") for value in command["arguments"]):
                problems.append("Absolute compile argument path")
    if any(item.get("license") == "NOASSERTION" for item in entries.values()):
        problems.append("Unclassified license in file provenance")
    if "LICENSE" in sources:
        problems.append(
            "Generic LICENSE exists; public README must explain file licensing"
        )
    for name, pattern in (
        ("src", "HeaderFilterRegex: '(^|/)(src)/'"),
        ("support", "HeaderFilterRegex: '(^|/)(tests|tools)/'"),
    ):
        tidy = root / ".jig/lint" / name / ".clang-tidy"
        if not tidy.exists() or pattern not in tidy.read_text():
            problems.append(f"{tidy}: unexpected Clang-Tidy header scope")
    return problems


def inspect_commit(raw: bytes, root_commit: bool) -> list[str]:
    """Validate a full historical commit without erasing useful context."""
    result = []
    parts = raw.decode("utf-8", errors="replace").split("\n")
    subject = parts[0]
    matched = SUBJECT.fullmatch(subject)
    if len(subject) > 72 or matched is None or matched.group(1) not in TYPES:
        result.append("invalid type(scope): subject or subject length")
    if len(parts) < 4 or parts[1] != "":
        result.append("missing blank line after subject")
    if not raw.endswith(b"\n"):
        result.append("missing final newline")
    trailers = [line for line in parts[2:] if TRAILER.match(line)]
    if trailers.count(CANONICAL_TRAILER) != 1:
        result.append("wrong or missing signed-off-by trailer")
    if (
        any(
            line.startswith("Co-authored-by:")
            or line.startswith("Co-Authored-By:")
            for line in trailers
        )
        and not root_commit
    ):
        result.append("co-authorship outside root commit")
    if root_commit:
        coauthors = [
            line
            for line in trailers
            if line.lower().startswith("co-authored-by:")
        ]
        if any("ChatGPT" not in c and "Fable" not in c for c in coauthors):
            result.append("unexpected initial co-author")
    body = []
    for line in parts[2:]:
        if TRAILER.match(line):
            continue
        body.append(line)
        if len(line) > 80:
            result.append("body line exceeds 80 columns")
    if len(" ".join(body).strip()) < 80:
        result.append("descriptive commit body shorter than 80 characters")
    return result


def check_history(root: Path = ROOT) -> list[str]:
    hashes = subprocess.check_output(
        ["git", "rev-list", "--reverse", "HEAD"], cwd=root, text=True
    ).splitlines()
    problems = []
    if not hashes:
        return ["No reachable commits"]
    for position, sha in enumerate(hashes):
        header = (
            subprocess
            .check_output(
                ["git", "show", "-s", "--format=%an%n%ae%n%cn%n%ce", sha],
                cwd=root,
            )
            .decode()
            .splitlines()
        )
        if header != [IDENTITY, EMAIL, IDENTITY, EMAIL]:
            problems.append(
                f"{sha[:12]}: noncanonical author/committer identity"
            )
        body = subprocess.check_output(
            ["git", "show", "-s", "--format=%B", sha], cwd=root
        )
        problems.extend(
            f"{sha[:12]}: {problem}"
            for problem in inspect_commit(body, position == 0)
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("all", "headers", "history"), nargs="?", default="all"
    )
    args = parser.parse_args()
    errors = []
    if args.mode in {"all", "headers"}:
        errors.extend(check_source())
    if args.mode in {"all", "history"}:
        errors.extend(check_history())
    for error in errors[:100]:
        print("ERROR:", error, file=sys.stderr)
    if len(errors) > 100:
        print(f"... plus {len(errors) - 100} more findings", file=sys.stderr)
    print(
        f"Public contract: {"PASS" if not errors else "FAIL"} ({len(errors)} findings, mode={args.mode})"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
