#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 laobamac. All rights reserved.
# SPDX-License-Identifier:
#   - LicenseRef-SimpleBCM-All-Rights-Reserved
# Confidential:
#   - false
# License-File:
#   - LICENSE-SIMPLEBCM
# Provenance:
#   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
#   - Originally authored by laobamac on 2026/9/25.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for bootstrap.
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
#   - Host-side tooling for bootstrap.
# - Description:
#   - Implements or verifies the bootstrap source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for bootstrap.

"""Fetch pinned development references when explicitly invoked."""

import argparse
import hashlib
from pathlib import Path
import shutil

# Shell-free pinned Git operations only.
import subprocess
import sys
import zipfile

if __package__:
    from tools.references.download import REPOSITORIES as SOURCE_REPOSITORIES
    from tools.references.download import download
    from tools.references.download import update_ledger
else:
    from references.download import REPOSITORIES as SOURCE_REPOSITORIES
    from references.download import download
    from references.download import update_ledger

ROOT = Path(__file__).resolve().parent.parent
PARENT_COMPONENT = ".."
MAC_METADATA_COMPONENT = "__MACOSX"
MAC_KERNEL_SDK = "MacKernelSDK"
REPOSITORIES: dict[str, tuple[str, str, list[str]]] = {
    MAC_KERNEL_SDK: (
        "https://github.com/acidanthera/MacKernelSDK.git",
        "3f750085caa17ec3a7880f11c11bf4f48cd6a164",
        ["/Headers/", "/Library/x86_64/", "/LICENSE.txt"],
    ),
    "OpenCore-Legacy-Patcher": (
        "https://github.com/dortania/OpenCore-Legacy-Patcher.git",
        "8da38565fa1551a8e5ce8613ea835d04dd97e089",
        [
            "/payloads/Kexts/Wifi/IOSkywalkFamily-v1.2.0.zip",
            "/payloads/Kexts/Wifi/IO80211FamilyLegacy-v1.0.0.zip",
            "/payloads/Kexts/Wifi/AirPortBrcmNIC-Tahoe-v1.0.0.zip",
            "/LICENSE.txt",
        ],
    ),
}
ARCHIVES = {
    "Wifi/IOSkywalkFamily-v1.2.0.zip": (
        "1e12b7ef42f55b39ea54ada97b46331220668b2c48a28656e9875c5145fe2479"
    ),
    "Wifi/IO80211FamilyLegacy-v1.0.0.zip": (
        "e681dcc76a2cd2cea4b0ad5f27a3c816055fde3cdccd890dd10a3e2c84e96d93"
    ),
    "Wifi/AirPortBrcmNIC-Tahoe-v1.0.0.zip": (
        "04edd7127ce096f5de9f8112af6d06744f27e5bc659e3d6516408755cb9af032"
    ),
}


def git(folder: Path, *args: str) -> str:
    """Run Git with an argument vector.

    Returns:
        Captured standard output with surrounding whitespace removed.

    Raises:
        RuntimeError: Git is unavailable on the current path.

    """
    executable = shutil.which("git")
    if executable is None:
        message = "Git executable is missing"
        raise RuntimeError(message)
    # Git receives separate arguments; none are evaluated by a shell.
    return subprocess.check_output(
        [executable, "-C", str(folder), *args], text=True
    ).strip()


def _run_git(args: list[str], *, stdin: str | None = None) -> None:
    executable = shutil.which("git")
    if executable is None:
        message = "Git executable is missing"
        raise RuntimeError(message)
    # URLs/revisions come from the pinned constants above; shell stays disabled.
    _ = subprocess.run([executable, *args], input=stdin, text=True, check=True)


def _validate_item(
    bundle: zipfile.ZipFile,
    item: zipfile.ZipInfo,
    destination: Path,
    *,
    extract: bool,
) -> None:
    parts = Path(item.filename).parts
    if PARENT_COMPONENT in parts or item.filename.startswith("/"):
        message = "Unsafe archive entry path"
        raise RuntimeError(message)
    if item.is_dir() or MAC_METADATA_COMPONENT in parts:
        return
    target = destination / item.filename
    original = bundle.read(item)
    if extract and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_bytes(original)
    if not target.is_file() or target.read_bytes() != original:
        message = f"Extracted file differs from the pinned archive: {target}"
        raise RuntimeError(message)


def validate_payloads(*, extract: bool = False) -> None:
    """Compare payload archives and extracted bytes with pinned references.

    Raises:
        RuntimeError: A pinned archive checksum does not match.

    """
    for relative, digest in ARCHIVES.items():
        archive = (
            ROOT
            / ".references/OpenCore-Legacy-Patcher/payloads/Kexts"
            / relative
        )
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            message = f"Archive checksum verification failed: {archive}"
            raise RuntimeError(message)
        destination = ROOT / ".references/binaries" / archive.stem
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                _validate_item(bundle, item, destination, extract=extract)


def _sparse_checkout(path: Path, sparse: list[str]) -> None:
    _run_git(
        ["-C", str(path), "sparse-checkout", "set", "--no-cone", "--stdin"],
        stdin="\n".join(sparse),
    )


def _fetch_checkout(path: Path, repository: tuple[str, str, list[str]]) -> None:
    url, revision, sparse = repository
    _ = sys.stdout.write(
        f"Fetching pinned upstream build dependency: {url} @ {revision}\n"
    )
    _ = sys.stdout.flush()
    _run_git([
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        "--depth=1",
        url,
        str(path),
    ])
    _run_git(["-C", str(path), "fetch", "--depth=1", "origin", revision])
    _sparse_checkout(path, sparse)
    _run_git(["-C", str(path), "checkout", "--detach", revision])


def _validate_checkout(path: Path, revision: str) -> None:
    if git(path, "rev-parse", "HEAD") != revision:
        message = (
            "Upstream checkout revision does not match the pinned commit: "
            f"{path}"
        )
        raise RuntimeError(message)
    if git(path, "status", "--porcelain", "--untracked-files=no"):
        message = f"Upstream working tree contains modifications: {path}"
        raise RuntimeError(message)


def main() -> None:
    """Fetch and validate the explicitly pinned upstream build references."""
    parser = argparse.ArgumentParser()
    _ = parser.parse_args()
    research = ROOT / ".references"
    research.mkdir(exist_ok=True)
    for name, repository in REPOSITORIES.items():
        if name == MAC_KERNEL_SDK:
            sdk = next(
                item for item in SOURCE_REPOSITORIES if item.name == name
            )
            records = download(sdk, research)
            _ = update_ledger(research / "ledger.jsonl", records)
            continue
        path = research / name
        if not path.exists():
            _fetch_checkout(path, repository)
        _validate_checkout(path, repository[1])
        _sparse_checkout(path, repository[2])
    validate_payloads(extract=True)
    message = "All required upstream revisions, driver archives, and extracted"
    _ = sys.stdout.write(
        f"{message} files passed byte-for-byte verification.\n"
    )


if __name__ == "__main__":
    main()
