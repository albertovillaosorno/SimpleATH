#!/usr/bin/env python3
# Copyright (c) 2026 SimpleATH contributors.
"""Cache pinned upstream source trees and preserve a per-file reuse ledger.

Downloads are source material only. No upstream build, installer or executable
is run. A cached file is not an implemented SimpleATH feature or a license grant.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
from typing import NamedTuple
import urllib.request

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


REPOSITORIES = (
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
    for path in sorted(checkout.rglob("*")):
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
            "cache_path": f"{repository.name}/{repository.revision}/{path.relative_to(checkout).as_posix()}",
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
    checkout = references / repository.name / repository.revision
    receipt = references / f".{repository.name}-{repository.revision}.json"
    if checkout.exists():
        if not receipt.is_file():
            raise ValueError(
                f"Existing source has no completed receipt: {checkout}"
            )
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
        raise FileNotFoundError(f"No cached checkout: {checkout}")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--references", type=Path, default=ROOT / ".cache" / "references"
    )
    parser.add_argument(
        "--repo", choices=[r.name for r in REPOSITORIES], action="append"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Verify existing caches without downloading",
    )
    args = parser.parse_args()
    references = args.references.expanduser().resolve()
    references.mkdir(parents=True, exist_ok=True)
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
