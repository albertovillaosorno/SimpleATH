#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Copy existing OS ABI evidence; no installer, build, kernel utility or PCI I/O.

Run manually on the target Mac, or supply an already accessible offline root.
This tool is separate from collect.py: it never probes a live network driver.
It records observed files, not an attestation of what OpenCore actually loaded.
"""

import argparse
import hashlib
import json
import os
import plistlib
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path


VERSION = Path("System/Library/CoreServices/SystemVersion.plist")
FILES = (
    VERSION,
    Path("System/Library/KernelCollections/BootKernelExtensions.kc"),
    Path("System/Library/KernelCollections/SystemKernelExtensions.kc"),
    Path("System/Library/Kernels/kernel"),
)
FAMILIES = ("IOPCIFamily", "IO80211Family", "IOSkywalkFamily")
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024


def open_source(root, relative):
    """Follow OS aliases only within the selected root, then open a regular file."""
    source = (root / relative).resolve(strict=True)
    if root not in source.parents:
        raise ValueError("Source resolves outside the selected OS root")
    handle = source.open("rb")
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        handle.close()
        raise ValueError("Source must be a bounded regular file")
    return handle, info


def read_version(root):
    with open_source(root, VERSION)[0] as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("SystemVersion.plist exceeds limit")
    info = plistlib.loads(data)
    return {key: info.get(key) for key in
            ("ProductName", "ProductVersion", "ProductBuildVersion")}


def copy_evidence(root, output, relative):
    record = {"path": str(relative)}
    destination = output / relative
    created = False
    try:
        with open_source(root, relative)[0] as source:
            before = os.fstat(source.fileno())
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            length = 0
            with destination.open("xb") as target:
                created = True
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > MAX_FILE_BYTES:
                        raise ValueError("Source grew beyond size limit")
                    target.write(chunk)
                    digest.update(chunk)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) or length != before.st_size:
                raise ValueError("Source changed during copy; copy discarded")
        record.update(status="copied", bytes=length, sha256=digest.hexdigest())
    except (OSError, ValueError) as error:
        if created:
            destination.unlink()
        record.update(status="unavailable", error=str(error))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("/"),
                        help="Already accessible installed OS root; never mounted by this tool")
    parser.add_argument("--expected-build", default="25G332")
    parser.add_argument("--output", type=Path, required=True,
                        help="New directory under your home or temporary directory")
    args = parser.parse_args()
    root = args.source_root.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve()
    allowed = (Path.home().resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(parent in output.parents for parent in allowed):
        parser.error("Output must be a new directory under your home or temporary directory")
    # Do not accept system/EFI paths, even when an offline root is under home.
    if any(part in ("EFI", "System", "Library", "Preboot") for part in output.parts):
        parser.error("Output must not be a system, library, preboot or EFI path")
    try:
        version = read_version(root)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        parser.error("Cannot read source SystemVersion.plist: " + str(error))
    if version["ProductBuildVersion"] != args.expected_build:
        parser.error("Source build is %r; expected %r. Nothing copied." % (
            version["ProductBuildVersion"], args.expected_build))
    # Exclusive directory creation: no overwrite, resume, deletion or privilege escalation.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = [copy_evidence(root, output, relative) for relative in FILES]
    for family in FAMILIES:
        contents = Path("System/Library/Extensions") / (family + ".kext") / "Contents"
        records.extend(copy_evidence(root, output, relative) for relative in (
            contents / "Info.plist", contents / "MacOS" / family))
    # Missing standalone kext executables can be normal; the KC is the primary evidence.
    complete = all(record["status"] == "copied" for record in records[:2])
    copied_version = output / VERSION
    if copied_version.is_file():
        observed = plistlib.loads(copied_version.read_bytes())
        complete &= observed.get("ProductBuildVersion") == args.expected_build
    report = {
        "schemaVersion": 1,
        "collectedUtc": datetime.now(timezone.utc).isoformat(),
        "sourceRoot": str(root),
        "systemVersion": version,
        "requiredVersionAndBootCollectionCopied": bool(complete),
        "provenance": "Files observed under one root; loaded images not attested",
        "nativePciAbiVerified": False,
        "nativeWirelessAbiVerified": False,
        "files": records,
    }
    with (output / "manifest.json").open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    print(output)
    if not complete:
        raise SystemExit("Required evidence incomplete; inspect manifest.json. No sudo retry performed.")


if __name__ == "__main__":
    main()
