# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - SimpleATH original; independently developed or locally authored
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for source fingerprint.
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
#   - Host-side tooling for source fingerprint.
# - Description:
#   - Implements or verifies the source_fingerprint source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for source fingerprint.
"""Deterministic fingerprint of the current tracked-source layout.

Only source, policies, tests, and checked-in documentation are inputs. Build
artifacts, .env, local dependencies, Linux references and temporary state must
never be read through this fingerprint.
"""

import hashlib
import json
import os
from pathlib import Path
import stat

SOURCE_DIRECTORIES = ("src", "tools", "docs", "tests", ".github")
SOURCE_FILES = (
    "AGENTS.md",
    "README.md",
    "TODO.md",
    "THIRD_PARTY_NOTICES.md",
    "licenses/GPL-2.0.txt",
    ".references/ledger.jsonl",
    ".jig/lint/.clang-format",
    ".jig/lint/src/.clang-tidy",
    ".jig/lint/support/.clang-tidy",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    ".jig/lint/src/pyrightconfig.json",
    ".jig/lint/support/pyrightconfig.json",
    ".jig/lint/ruff.toml",
)
IGNORED_NAMES = frozenset({"__pycache__", ".DS_Store"})
MAX_SOURCE_FILES = 10_000
MAX_FILE_BYTES = 32 * 1024 * 1024


def _regular_file(path: Path) -> bool:
    """Distinguish regular files from directories and special file types.

    Returns:
        True for a regular file and false for a directory.

    Raises:
        ValueError: A symlink or special source path was encountered.

    """
    if path.is_symlink():
        message = f"Symlink is not an allowed fingerprint input: {path}"
        raise ValueError(message)
    if path.is_dir():
        return False
    if not path.is_file():
        message = f"Unsupported source fingerprint input: {path}"
        raise ValueError(message)
    return True


def _root_files(root: Path) -> list[Path]:
    """Require every pinned policy file and the tracked Linux port ledger.

    Returns:
        Repository-relative file paths.

    Raises:
        ValueError: A required source file is missing or not regular.

    """
    result: list[Path] = []
    for name in SOURCE_FILES:
        relative = Path(name)
        if not _regular_file(root / relative):
            message = f"Required source fingerprint file missing: {name}"
            raise ValueError(message)
        result.append(relative)
    return result


def _directory_files(root: Path, name: str) -> list[Path]:
    """Enumerate one required source directory, omitting only local caches.

    Returns:
        Relative paths to regular files.

    Raises:
        ValueError: The directory is absent or contains special files.

    """
    directory = root / name
    if directory.is_symlink() or not directory.is_dir():
        message = f"Required source directory unavailable: {name}"
        raise ValueError(message)
    result: list[Path] = []
    for path in directory.rglob("*"):
        relative = path.relative_to(root)
        if any(part in IGNORED_NAMES for part in relative.parts):
            continue
        if _regular_file(path):
            result.append(relative)
    return result


def _inputs(root: Path) -> list[Path]:
    """Collect only actual source, policy, test and documentation paths.

    Returns:
        Sorted, root-relative paths inside the input allowlist.

    Raises:
        ValueError: The source root is invalid or inputs exceed the limit.

    """
    if root.is_symlink() or not root.is_dir():
        message = "Source fingerprint root must be a real directory"
        raise ValueError(message)
    inputs = set(_root_files(root))
    for name in SOURCE_DIRECTORIES:
        inputs.update(_directory_files(root, name))
        if len(inputs) > MAX_SOURCE_FILES:
            message = "Source fingerprint has too many inputs"
            raise ValueError(message)
    # Hash each source once; only the unified ledger is read from references.
    return sorted(inputs)


def _file_sha256(path: Path) -> str:
    """Hash one regular source file, refusing symlinks, FIFOs and oversize.

    Returns:
        Lowercase hex-encoded SHA-256 of the exact file bytes.

    Raises:
        ValueError: The input changed type or exceeded the source size limit.

    """
    if not _regular_file(path):
        message = f"Expected source file: {path}"
        raise ValueError(message)
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            message = f"Source file is not regular: {path}"
            raise ValueError(message)
        if metadata.st_size > MAX_FILE_BYTES:
            message = f"Source file exceeds fingerprint byte limit: {path}"
            raise ValueError(message)
        return hashlib.file_digest(handle, "sha256").hexdigest()


def source_fingerprint(root: Path) -> str:
    """Fingerprint every relevant SimpleATH source and policy path.

    Returns:
        Stable SHA-256 digest of relative paths and their byte digests.

    """
    hashes = {
        path.as_posix(): _file_sha256(root / path) for path in _inputs(root)
    }
    payload = json.dumps(hashes, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
