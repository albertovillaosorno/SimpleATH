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
#   - Verify repository source and Markdown line widths.
# - Must-Not:
#   - Modify source bytes or silently exempt checked-in files.
# - Allows:
#   - Inputs: tracked source and Markdown paths.
#   - Outputs: precise filename, line, and width diagnostics.
#   - Side effects: read-only Git index and source inspection.
# - Split-When:
#   - Additional markup formats need independent width semantics.
# - Merge-When:
#   - Repository validation directly owns line-width enforcement.
# - Summary:
#   - Reject tracked Markdown and code comments over 80 columns.
# - Description:
#   - Inspects complete lines without rewriting executable expressions.
# - Usage:
#   - CI or unittest invokes the complete repository-wide check.
# - Defaults:
#   - Invalid UTF-8 and inaccessible tracked files fail closed.
#
# Module: Repository-wide source and Markdown line-width enforcement.

"""Limit Markdown and comments to 80 columns, without rejecting code."""

import io
import subprocess
import tokenize
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_COLUMNS = 80
CODE_SUFFIXES = frozenset({
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
    ".py",
    ".pyi",
    ".inc",
    ".command",
})
DOC_SUFFIXES = frozenset({".md", ".mdc", ".markdown"})
TEMPLATE_SUFFIXES = (".cpp.in", ".hpp.in")


def is_checked(path: str) -> bool:
    """Return whether a Git path is source code or Markdown."""
    return Path(
        path
    ).suffix.lower() in CODE_SUFFIXES | DOC_SUFFIXES or path.endswith(
        TEMPLATE_SUFFIXES
    )


def _c_comments(text: str) -> list[tuple[int, str, bool]]:
    """Extract C-family comments, ignoring quoted string and char literals."""
    found: list[tuple[int, str, bool]] = []
    block = False
    quoted = ""
    for number, line in enumerate(text.splitlines(), 1):
        i = 0
        segments: list[str] = []
        while i < len(line):
            if block:
                end = line.find("*/", i)
                if end < 0:
                    segments.append(line[i:])
                    i = len(line)
                else:
                    segments.append(line[i : end + 2])
                    i = end + 2
                    block = False
                continue
            if quoted:
                if line[i] == "\\":
                    i += 2
                elif line[i] == quoted:
                    quoted = ""
                    i += 1
                else:
                    i += 1
                continue
            if line[i] in ("'", '"'):
                quoted = line[i]
                i += 1
            elif line.startswith("//", i):
                segments.append(line[i:])
                break
            elif line.startswith("/*", i):
                block = True
                continue
            else:
                i += 1
        if segments:
            only_comment = line.lstrip().startswith(("//", "/*", "*"))
            # A comment embedded after code is assessed by its comment text,
            # never by the preceding expression length.
            length_text = line if only_comment else " ".join(segments)
            found.append((number, length_text, only_comment))
        elif block and line.lstrip().startswith("*"):
            found.append((number, line, True))
    return found


def _python_comments(text: str) -> list[tuple[int, str, bool]]:
    """Read only Python COMMENT tokens; ignore strings and declarations."""
    found: list[tuple[int, str, bool]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            line = token.line.rstrip("\r\n")
            only_comment = not line[: token.start[1]].strip()
            fragment = line if only_comment else token.string
            found.append((token.start[0], fragment, only_comment))
    except tokenize.TokenError, IndentationError:
        # The Python compiler and source linters separately reject malformed
        # programs; never treat their invalid literals as documentation.
        pass
    return found


def inspect_text(
    text: str,
    max_columns: int = MAX_COLUMNS,
    *,
    suffix: str = ".md",
) -> list[tuple[int, int]]:
    """Check Markdown lines or actual comment text, never executable code."""
    if suffix.lower() in DOC_SUFFIXES:
        entries = [
            (n, line, True) for n, line in enumerate(text.splitlines(), 1)
        ]
    elif suffix.lower() in {".py", ".pyi", ".command"}:
        entries = _python_comments(text)
    else:
        entries = _c_comments(text)
    return [
        (number, len(fragment.expandtabs(4)))
        for number, fragment, _ in entries
        if len(fragment.expandtabs(4)) > max_columns
    ]


def tracked_files(root: Path = ROOT) -> list[Path]:
    """Read tracked files from Git, excluding caches and untracked inputs."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = [
        part.decode("utf-8") for part in result.stdout.split(b"\0") if part
    ]
    return sorted(root / path for path in paths if is_checked(path))


def check_repository(root: Path = ROOT) -> list[str]:
    """Return actionable findings for every overlong tracked source line."""
    findings = []
    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(f"{relative}: unable to inspect: {exc}")
            continue
        findings.extend(
            f"{relative}:{line}: {width} columns (maximum {MAX_COLUMNS})"
            for line, width in inspect_text(text, suffix=path.suffix)
        )
    return findings


def main() -> int:
    """Report the complete set of line-width failures to CI."""
    findings = check_repository()
    for finding in findings:
        print(finding, file=sys.stderr)
    print(
        f"Checked tracked Markdown and code comments: {len(findings)} violations"
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
