#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Copy existing OS ABI evidence, without installation or device access.

Run manually on the target Mac, or supply an already accessible offline root.
This tool is separate from collect.py: it never probes a live network driver.
It records observed files, not an attestation of what OpenCore actually loaded.
"""

import argparse
from datetime import UTC
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
from typing import NotRequired
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable
    from io import BufferedReader
    from io import BufferedWriter

VERSION = Path("System/Library/CoreServices/SystemVersion.plist")
FILES = (
    VERSION,
    Path("System/Library/KernelCollections/BootKernelExtensions.kc"),
    Path("System/Library/KernelCollections/SystemKernelExtensions.kc"),
    Path("System/Library/Kernels/kernel"),
)
FAMILIES = ("IOPCIFamily", "IO80211Family", "IOSkywalkFamily")
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
MAX_VERSION_BYTES = CHUNK_BYTES
STATUS_COPIED = "copied"
REJECTED_OUTPUT_PARTS = {"EFI", "System", "Library", "Preboot"}


class _Args(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.source_root: Path = Path("/")
        self.expected_build: str = "25G332"
        self.output: Path = Path()


class _Record(TypedDict):
    path: str
    status: str
    bytes: NotRequired[int]
    sha256: NotRequired[str]
    error: NotRequired[str]


def _is_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_dict(value) and all(isinstance(key, str) for key in value)


def _decode_plist(data: bytes, decoder: Callable[[bytes], object]) -> object:
    return decoder(data)


def _plist_dict(data: bytes) -> dict[str, object]:
    value = _decode_plist(data, plistlib.loads)
    if not _is_mapping(value):
        message = "Expected a dictionary in SystemVersion.plist"
        raise ValueError(message)
    return value


def _require_regular(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        message = "Source must be a bounded regular file"
        raise ValueError(message)


def open_source(
    root: Path, relative: Path
) -> tuple[BufferedReader, os.stat_result]:
    """Follow OS aliases only within the selected root, then open a file.

    Returns:
        A bounded regular binary file handle and its initial metadata.

    Raises:
        ValueError: The path escapes the OS root or exceeds the size limit.
        OSError: The source cannot be opened as an existing file.

    """
    source = (root / relative).resolve(strict=True)
    if root not in source.parents:
        message = "Source resolves outside the selected OS root"
        raise ValueError(message)
    handle = source.open("rb")
    try:
        info = os.fstat(handle.fileno())
        _require_regular(info)
    except OSError, ValueError:
        handle.close()
        raise
    return handle, info


def read_version(root: Path) -> dict[str, str | None]:
    """Decode a bounded source SystemVersion.plist and select version fields.

    Returns:
        The three observed OS version/build string fields, if present.

    Raises:
        ValueError: The plist is too large or cannot be decoded as a dict.

    """
    with open_source(root, VERSION)[0] as handle:
        data = handle.read(MAX_VERSION_BYTES + 1)
    if len(data) > MAX_VERSION_BYTES:
        message = "SystemVersion.plist exceeds limit"
        raise ValueError(message)
    info = _plist_dict(data)
    keys = ("ProductName", "ProductVersion", "ProductBuildVersion")
    return {
        key: value if isinstance(value := info.get(key), str) else None
        for key in keys
    }


def _copy_bytes(
    source: BufferedReader, target: BufferedWriter
) -> tuple[int, str]:
    digest = hashlib.sha256()
    length = 0
    for chunk in iter(lambda: source.read(CHUNK_BYTES), b""):
        length += len(chunk)
        if length > MAX_FILE_BYTES:
            message = "Source grew beyond size limit"
            raise ValueError(message)
        written = target.write(chunk)
        if written != len(chunk):
            message = "Destination accepted an incomplete evidence chunk"
            raise ValueError(message)
        digest.update(chunk)
    return length, digest.hexdigest()


def _verify_source(
    source: BufferedReader, before: os.stat_result, length: int
) -> None:
    after = os.fstat(source.fileno())
    old = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    new = (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if old != new or length != before.st_size:
        message = "Source changed during copy; copy discarded"
        raise ValueError(message)


def _copy_checked(
    root: Path, relative: Path, destination: Path
) -> tuple[int, str]:
    created = False
    completed = False
    try:
        with open_source(root, relative)[0] as source:
            before = os.fstat(source.fileno())
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as target:
                created = True
                length, digest = _copy_bytes(source, target)
            _verify_source(source, before, length)
        completed = True
        return length, digest
    finally:
        if created and not completed:
            # Only remove files created by this exclusive open, never a file
            # that already existed at the requested evidence destination.
            destination.unlink(missing_ok=True)


def copy_evidence(root: Path, output: Path, relative: Path) -> _Record:
    """Copy one bounded file, recording a failure without retaining partials.

    Returns:
        A path, byte-count and digest or the reason it was unavailable.

    """
    destination = output / relative
    try:
        length, digest = _copy_checked(root, relative, destination)
    except (OSError, ValueError) as error:
        return {
            "path": str(relative),
            "status": "unavailable",
            "error": str(error),
        }
    return {
        "path": str(relative),
        "status": STATUS_COPIED,
        "bytes": length,
        "sha256": digest,
    }


def _arguments() -> tuple[argparse.ArgumentParser, _Args]:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("/"),
        help="Already accessible installed OS root; never mounted by this tool",
    )
    _ = parser.add_argument("--expected-build", default="25G332")
    _ = parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New directory under your home or temporary directory",
    )
    return parser, parser.parse_args(namespace=_Args())


def _output_path(parser: argparse.ArgumentParser, output: Path) -> Path:
    selected = output.expanduser().resolve()
    allowed = (Path.home().resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(parent in selected.parents for parent in allowed):
        message = "Output must be a new directory under your home"
        message += " or temporary directory"
        parser.error(message)
    if any(part in REJECTED_OUTPUT_PARTS for part in selected.parts):
        parser.error(
            "Output must not be a system, library, preboot or EFI path"
        )
    return selected


def _source_version(
    parser: argparse.ArgumentParser, root: Path, expected: str
) -> dict[str, str | None]:
    try:
        version = read_version(root)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        parser.error("Cannot read source SystemVersion.plist: " + str(error))
    if version["ProductBuildVersion"] != expected:
        message = f"Source build is {version["ProductBuildVersion"]!r}; "
        message += f"expected {expected!r}. Nothing copied."
        parser.error(message)
    return version


def _family_files() -> list[Path]:
    files: list[Path] = []
    for family in FAMILIES:
        contents = (
            Path("System/Library/Extensions") / f"{family}.kext" / "Contents"
        )
        files.extend([contents / "Info.plist", contents / "MacOS" / family])
    return files


def _complete(output: Path, records: list[_Record], expected: str) -> bool:
    # Missing standalone kext executables can be normal; the KC is primary.
    complete = all(record["status"] == STATUS_COPIED for record in records[:2])
    copied_version = output / VERSION
    if copied_version.is_file():
        observed = _plist_dict(copied_version.read_bytes())
        complete &= observed.get("ProductBuildVersion") == expected
    return complete


def _manifest_payload(
    root: Path,
    version: dict[str, str | None],
    records: list[_Record],
    *,
    complete: bool,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "collectedUtc": datetime.now(UTC).isoformat(),
        "sourceRoot": str(root),
        "systemVersion": version,
        "requiredVersionAndBootCollectionCopied": complete,
        "provenance": (
            "Files observed under one root; loaded images not attested"
        ),
        "nativePciAbiVerified": False,
        "nativeWirelessAbiVerified": False,
        "files": records,
    }


def _write_manifest(output: Path, report: dict[str, object]) -> None:
    with (output / "manifest.json").open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        _ = target.write("\n")


def main() -> None:
    """Copy preexisting ABI evidence after strict source and output checks.

    Raises:
        SystemExit: Required evidence is incomplete; the manifest is retained.

    """
    parser, args = _arguments()
    root = args.source_root.expanduser().resolve(strict=True)
    output = _output_path(parser, args.output)
    version = _source_version(parser, root, args.expected_build)
    # Exclusive directory creation; never overwrite, resume or escalate.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = [copy_evidence(root, output, relative) for relative in FILES]
    records.extend(
        copy_evidence(root, output, path) for path in _family_files()
    )
    complete = _complete(output, records, args.expected_build)
    report = _manifest_payload(root, version, records, complete=complete)
    _write_manifest(output, report)
    _ = sys.stdout.write(f"{output}\n")
    if not complete:
        message = "Required evidence incomplete; inspect manifest.json."
        message += " No sudo retry performed."
        raise SystemExit(message)


if __name__ == "__main__":
    main()
