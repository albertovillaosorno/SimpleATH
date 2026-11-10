#!/usr/bin/env python3
# Copyright (c) 2026 SimpleATH contributors.
"""Cache pinned upstream source trees and preserve a per-file reuse ledger.

Downloads are source material only. No upstream build, installer or executable
is run. A cached file is not an implemented SimpleATH feature or a license grant.
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import NamedTuple
import urllib.request
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
SPDX = re.compile(rb"SPDX-License-Identifier:\s*([^\r\n]+)")


class Repository(NamedTuple):
    name: str
    project: str
    revision: str
    files: int
    flat: bool = False


REPOSITORIES = (
    Repository(
        "MacKernelSDK",
        "acidanthera/MacKernelSDK",
        "3f750085caa17ec3a7880f11c11bf4f48cd6a164",
        1232,
        True,
    ),
    Repository(
        "AirPort_RTW89",
        "FranciumOS-org/AirPort_RTW89",
        "90b6cfc5a69c271688fad188857cfaeb58053dc5",
        1584,
    ),
    Repository(
        "AirportItlwm-BE200",
        "Ersiter/AirportItlwm-BE200",
        "ff82f3e5647ce3885f5d48417b6356a6a23d2163",
        300,
    ),
    Repository(
        "nvidia-macos-driver",
        "nullmoth/nvidia-macos-driver",
        "7412cdde81447f78da0ebb64216dc258d8beaedb",
        1383,
    ),
)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(CHUNK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def member_path(name: str, prefix: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != prefix
    ):
        raise ValueError(f"Unsafe upstream archive member: {name}")
    return PurePosixPath(*path.parts[1:])


def extract_sources(archive: Path, destination: Path) -> int:
    """Extract ordinary source files and safe relative symlinks, never devices."""
    prefix = None
    count = 0
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if prefix is None:
                parts = PurePosixPath(member.name).parts
                if not parts:
                    raise ValueError("Archive has no repository prefix")
                prefix = parts[0]
            relative = member_path(member.name, prefix)
            if relative == PurePosixPath("."):
                if not member.isdir():
                    raise ValueError("Invalid repository root")
                continue
            target = destination.joinpath(*relative.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError(
                    f"Archive target escapes repository: {relative}"
                )
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ValueError(
                    f"Duplicate upstream archive member: {relative}"
                )
            if member.issym():
                link = Path(member.linkname)
                if link.is_absolute() or not (
                    target.parent / link
                ).resolve().is_relative_to(destination.resolve()):
                    raise ValueError(f"Unsafe upstream symlink: {relative}")
                target.symlink_to(member.linkname)
            elif member.isfile():
                total += member.size
                if member.size < 0 or total > MAX_SOURCE_BYTES:
                    raise ValueError("Upstream source size limit exceeded")
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError(f"Missing archive payload: {relative}")
                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output, CHUNK_BYTES)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise ValueError(f"Unsupported archive member type: {relative}")
            count += 1
    return count


def source_records(repository: Repository, checkout: Path) -> list[dict]:
    records = []
    prefix = (
        repository.name
        if repository.flat
        else f"{repository.name}/{repository.revision}"
    )
    for path in sorted(checkout.rglob("*")):
        if ".git" in path.relative_to(checkout).parts:
            continue
        if path.is_symlink():
            content = os.readlink(path).encode("utf-8")
            digest = hashlib.sha256(content).hexdigest()
            size = len(content)
            license_id = None
            kind = "symlink"
        elif path.is_file():
            digest = digest_file(path)
            size = path.stat().st_size
            with path.open("rb") as source:
                match = SPDX.search(source.read(16384))
            license_id = (
                match.group(1).decode("utf-8", errors="replace").strip()
                if match
                else None
            )
            kind = "file"
        else:
            continue
        records.append({
            "schema": "simpleath.reference.v1",
            "repository": f"https://github.com/{repository.project}",
            "revision": repository.revision,
            "path": path.relative_to(checkout).as_posix(),
            "cache_path": f"{prefix}/{path.relative_to(checkout).as_posix()}",
            "sha256": digest,
            "bytes": size,
            "kind": kind,
            "spdx_in_source": license_id,
            "license_review": "required-before-import; inspect file and upstream LICENSE/NOTICE",
            "status": "reference-only",
            "destinations": [],
            "notes": "Downloaded source, not implemented or runtime-verified.",
        })
    return records


def download(
    repository: Repository, references: Path, *, offline: bool = False
) -> list[dict]:
    checkout = references / repository.name
    if not repository.flat:
        checkout /= repository.revision
    receipt = references / f".{repository.name}-{repository.revision}.json"
    if checkout.exists() and receipt.is_file():
        saved = json.loads(receipt.read_text(encoding="utf-8"))
        records = source_records(repository, checkout)
        if (
            saved.get("repository") != repository.project
            or saved.get("revision") != repository.revision
            or saved.get("files") != records
        ):
            raise ValueError(f"Cached upstream source changed: {checkout}")
        return records
    if offline:
        raise FileNotFoundError(f"No verified cached checkout: {checkout}")
    if checkout.exists() and repository.name != "MacKernelSDK":
        raise ValueError(
            f"Existing source has no completed receipt: {checkout}"
        )
    with tempfile.TemporaryDirectory(
        prefix=".download-", dir=references
    ) as scratch:
        scratch_path = Path(scratch)
        archive = scratch_path / "source.tar.gz"
        request = urllib.request.Request(
            f"https://codeload.github.com/{repository.project}/tar.gz/{repository.revision}",
            headers={"User-Agent": "SimpleATH-reference-acquisition"},
        )
        downloaded = 0
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            archive.open("xb") as output,
        ):
            while True:
                block = response.read(CHUNK_BYTES)
                if not block:
                    break
                downloaded += len(block)
                if downloaded > MAX_ARCHIVE_BYTES:
                    raise ValueError("Upstream archive download limit exceeded")
                output.write(block)
        staging = scratch_path / "tree"
        staging.mkdir()
        count = extract_sources(archive, staging)
        if count != repository.files:
            raise ValueError(
                f"Expected {repository.files} tracked files for {repository.name}, got {count}"
            )
        records = source_records(repository, staging)
        if len(records) != count:
            raise ValueError("Extracted file inventory is incomplete")
        checkout.parent.mkdir(parents=True, exist_ok=True)
        # Publish only a complete immutable source tree. Never replace existing
        # owner modifications or execute material from a downloaded repository.
        if checkout.exists():
            # Adopt the earlier sparse SDK only after comparing every existing
            # source byte with this pinned complete archive. Never overwrite it.
            existing = source_records(repository, checkout)
            expected = {row["path"]: row for row in records}
            for row in existing:
                if row["path"] not in expected or row != expected[row["path"]]:
                    raise ValueError(
                        f"Existing SDK source changed: {row["path"]}"
                    )
            for row in records:
                target = checkout / row["path"]
                if not target.exists() and not target.is_symlink():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    (staging / row["path"]).rename(target)
        else:
            staging.rename(checkout)
        receipt.write_text(
            json.dumps(
                {
                    "repository": repository.project,
                    "revision": repository.revision,
                    "archive_sha256": digest_file(archive),
                    "files": records,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return records


def update_ledger(path: Path, records: list[dict]) -> int:
    """Add missing identities; retain existing assessment/destination records."""
    previous = path.read_text(encoding="utf-8") if path.exists() else ""
    latest = {}
    for line in previous.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "repository" in row and "source" not in row:
            identity = (row["repository"], row["revision"], row["path"])
            latest[identity] = row
    additions = []
    for row in records:
        identity = (row["repository"], row["revision"], row["path"])
        if identity in latest:
            if latest[identity]["sha256"] != row["sha256"]:
                raise ValueError(
                    f"Pinned source differs from ledger: {identity}"
                )
            continue
        additions.append(
            json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        latest[identity] = row
    if additions or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            try:
                output.write(previous)
                if previous and not previous.endswith("\n"):
                    output.write("\n")
                output.writelines(additions)
                output.flush()
                os.fsync(output.fileno())
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        temporary.chmod(0o644)
        temporary.replace(path)
    return len(additions)


def seed_ledger(references: Path) -> None:
    """Create a missing ledger from this checkout's tracked inventory/history."""
    ledger = references / "ledger.jsonl"
    if ledger.exists():
        return
    canonical = ROOT / ".references/ledger.jsonl"
    if canonical.is_file():
        content = canonical.read_bytes()
    else:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "show", "HEAD:.references/ledger.jsonl"],
            capture_output=True,
            check=True,
        )
        content = result.stdout
    # Check the restored inventory before publishing it; no Git index mutation.
    for line in content.splitlines():
        json.loads(line)
    references.mkdir(parents=True, exist_ok=True)
    with ledger.open("xb") as output:
        output.write(content)


def linux_records(ledger: Path) -> list[dict]:
    """Read current Linux download identities from the one tracked ledger."""
    latest = {}
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("schema") == 1 and row.get("source", "").startswith(
                "linux/"
            ):
                latest[row["source"]] = row
    if not latest:
        raise ValueError(
            "Linux download inventory is missing: restore the tracked "
            ".references/ledger.jsonl from this repository before downloading Linux"
        )
    return list(latest.values())


def download_linux(references: Path, *, offline: bool = False) -> int:
    """Restore exactly the Wi-Fi/Bluetooth files and hashes in the ledger.

    Existing assessment history is never replaced by download status. Different
    Linux revisions can supply individual retained files; each has its own pin.
    """
    seed_ledger(references)
    rows = linux_records(references / "ledger.jsonl")

    def acquire(row: dict) -> None:
        relative = PurePosixPath(row["source"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Unsafe Linux source path: {relative}")
        target = references.joinpath(*relative.parts)
        if not target.resolve().is_relative_to(references.resolve()):
            raise ValueError(
                f"Linux source path escapes references: {relative}"
            )
        if target.is_file():
            if target.is_symlink() or digest_file(target) != row["sha256"]:
                raise ValueError(f"Cached Linux source changed: {relative}")
            return
        if offline:
            raise FileNotFoundError(f"No cached Linux source: {relative}")
        revision = row.get("revision", "")
        upstream = row.get("upstream_path", "")
        if not re.fullmatch(r"[0-9a-f]{40}", revision) or not upstream:
            raise ValueError(
                f"Linux source has no verified upstream pin: {relative}"
            )
        url = f"https://raw.githubusercontent.com/torvalds/linux/{revision}/{upstream}"
        target.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(4):
            try:
                request = urllib.request.Request(
                    url,
                    headers={"User-Agent": "SimpleATH-reference-acquisition"},
                )
                try:
                    with urllib.request.urlopen(
                        request, timeout=30
                    ) as response:
                        content = response.read(MAX_ARCHIVE_BYTES + 1)
                except OSError:
                    # The kernel mirror serves identical Git blobs when raw
                    # GitHub requests are throttled. SHA-256 remains mandatory.
                    mirror = (
                        "https://kernel.googlesource.com/pub/scm/linux/kernel/"
                        f"git/torvalds/linux/+/{revision}/{upstream}?format=TEXT"
                    )
                    with urllib.request.urlopen(mirror, timeout=30) as response:
                        encoded = response.read(2 * MAX_ARCHIVE_BYTES + 1)
                    if len(encoded) > 2 * MAX_ARCHIVE_BYTES:
                        raise ValueError(
                            "Linux mirror response size limit exceeded"
                        )
                    content = base64.b64decode(encoded, validate=False)
                if len(content) > MAX_ARCHIVE_BYTES:
                    raise ValueError(
                        f"Linux source size limit exceeded: {relative}"
                    )
                if hashlib.sha256(content).hexdigest() != row["sha256"]:
                    raise ValueError(
                        f"Downloaded Linux source hash mismatch: {relative}"
                    )
                # Publish complete bytes only; interrupted downloads leave no
                # partial source, and a concurrent writer is never overwritten.
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(
                        dir=target.parent, delete=False
                    ) as output:
                        temporary = Path(output.name)
                        output.write(content)
                    temporary.chmod(0o644)
                    os.link(temporary, target)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                return
            except OSError:
                if attempt == 3:
                    raise
                time.sleep(attempt + 1)

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(acquire, rows))
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--references", type=Path, default=ROOT / ".references")
    parser.add_argument(
        "--repo",
        choices=[r.name for r in REPOSITORIES] + ["linux"],
        action="append",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Verify existing caches without downloading",
    )
    args = parser.parse_args()
    references = args.references.expanduser().resolve()
    references.mkdir(parents=True, exist_ok=True)
    seed_ledger(references)
    if not args.repo or "linux" in args.repo:
        count = download_linux(references, offline=args.offline)
        print(
            f"linux: {count} pinned Wi-Fi/Bluetooth reference files verified",
            flush=True,
        )
    for repository in REPOSITORIES:
        if args.repo and repository.name not in args.repo:
            continue
        records = download(repository, references, offline=args.offline)
        added = update_ledger(references / "ledger.jsonl", records)
        print(
            f"{repository.name} @ {repository.revision}: {len(records)} source files, {added} new ledger entries",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
