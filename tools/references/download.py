#!/usr/bin/env python3
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
#   - Host-side tooling for download.
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
#   - Host-side tooling for download.
# - Description:
#   - Implements or verifies the download source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for download.
"""Cache pinned upstream source trees and preserve a per-file reuse ledger.

Downloads are source material only. No upstream build, installer or executable
is run. A cached file is not an implemented SimpleATH feature or a
license grant.
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
import hashlib
import http.client
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
from typing import NamedTuple
from typing import TYPE_CHECKING
from typing import TypedDict
from typing import cast

if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import Never
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
SPDX = re.compile(rb"SPDX-License-Identifier:\s*([^\r\n]+)")


# Source boundaries intentionally use one explicit error path so callers
# cannot accidentally publish partially verified archive or ledger material.
def _invalid(message: str) -> Never:
    raise ValueError(message)


def _missing(message: str) -> Never:
    raise FileNotFoundError(message)


def _network_failure(message: str) -> Never:
    raise OSError(message)


class Repository(NamedTuple):
    """A pinned upstream source repository and its expected inventory."""

    name: str
    project: str
    revision: str
    files: int
    flat: bool = False


class ReferenceRecord(TypedDict):
    """Retained, verified per-file upstream source inventory entry."""

    schema: str
    repository: str
    revision: str
    path: str
    cache_path: str
    sha256: str
    bytes: int
    kind: str
    spdx_in_source: str | None
    license_review: str
    status: str
    destinations: list[str]
    notes: str


class ReferenceReceipt(TypedDict):
    """Receipt proving an immutable downloaded reference inventory."""

    repository: str
    revision: str
    archive_sha256: str
    files: list[ReferenceRecord]


class LinuxLedgerRecord(TypedDict):
    """Pinned source identity required before an offline Linux restore."""

    schema: int
    source: str
    revision: str
    upstream_path: str
    sha256: str


ALLOWED_HTTPS_HOSTS = frozenset({
    "codeload.github.com",
    "raw.githubusercontent.com",
    "kernel.googlesource.com",
})
PARENT_COMPONENT = ".."
SDK_REPOSITORY = "MacKernelSDK"
GIT_METADATA_DIR = ".git"
LEDGER_REPOSITORY_KEY = "repository"
LEDGER_SOURCE_KEY = "source"
LINUX_RECORD_TAG = "linux"
RETRY_ATTEMPTS = 4
HTTP_STATUS_OK = 200
HTTPS_SCHEME = "https"
LICENSE_REVIEW_REQUIRED = (
    "required-before-import; inspect file and upstream LICENSE/NOTICE"
)


def source_https_endpoint(url: str) -> tuple[str, str]:
    """Accept only exact pinned HTTPS source hosts and safe URL forms.

    Returns:
        Validated host and request target without a redirect allowance.

    """
    parsed = urlsplit(url)
    if (
        parsed.scheme != HTTPS_SCHEME
        or parsed.hostname not in ALLOWED_HTTPS_HOSTS
    ):
        _invalid("Untrusted source download URL")
    if parsed.port is not None or parsed.username or parsed.password:
        _invalid("Source download URL includes forbidden authority fields")
    if parsed.fragment:
        _invalid("Source download URL includes a forbidden fragment")
    host = parsed.hostname
    return host, parsed.path + ("?" + parsed.query if parsed.query else "")


@contextmanager
def _open_pinned_https(url: str) -> Generator[http.client.HTTPResponse]:
    """Stream source bytes over validated TLS without following redirects.

    Yields:
        The certificate-validated HTTPS response.

    """
    host, path = source_https_endpoint(url)
    with closing(http.client.HTTPSConnection(host, timeout=30)) as connection:
        connection.request(
            "GET",
            path,
            headers={"User-Agent": "SimpleATH-reference-acquisition"},
        )
        response = connection.getresponse()
        if response.status != HTTP_STATUS_OK:
            _network_failure(f"Source download HTTP status: {response.status}")
        try:
            yield response
        finally:
            response.close()


REPOSITORIES = (
    Repository(
        "MacKernelSDK",
        "acidanthera/MacKernelSDK",
        "3f750085caa17ec3a7880f11c11bf4f48cd6a164",
        1232,
        flat=True,
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
    """Hash a local source file without loading the entire file into memory.

    Returns:
        Lowercase SHA-256 digest of the complete file bytes.

    """
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(CHUNK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def member_path(name: str, prefix: str) -> PurePosixPath:
    """Validate an archive member's path beneath its expected root.

    Returns:
        The member's relative path below the repository prefix.

    """
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts:
        _invalid(f"Unsafe upstream archive member: {name}")
    if PARENT_COMPONENT in path.parts or path.parts[0] != prefix:
        _invalid(f"Unsafe upstream archive member: {name}")
    return PurePosixPath(*path.parts[1:])


def _archive_prefix(member: tarfile.TarInfo) -> str:
    parts = PurePosixPath(member.name).parts
    if not parts:
        _invalid("Archive has no repository prefix")
    return parts[0]


def _verified_target(destination: Path, relative: PurePosixPath) -> Path:
    target = destination.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(destination.resolve()):
        _invalid(f"Archive target escapes repository: {relative}")
    return target


@dataclass
class _ExtractionState:
    """Archive extraction budget and destination shared across entries."""

    destination: Path
    prefix: str
    total_bytes: int = 0


def _extract_symlink(
    member: tarfile.TarInfo, target: Path, destination: Path
) -> None:
    link = Path(member.linkname)
    if link.is_absolute() or not (
        target.parent / link
    ).resolve().is_relative_to(destination.resolve()):
        _invalid(f"Unsafe upstream symlink: {member.name}")
    target.symlink_to(member.linkname)


def _extract_regular_file(
    source: tarfile.TarFile,
    member: tarfile.TarInfo,
    target: Path,
    *,
    previous_bytes: int,
) -> int:
    total = previous_bytes + member.size
    if member.size < 0 or total > MAX_SOURCE_BYTES:
        _invalid("Upstream source size limit exceeded")
    stream = source.extractfile(member)
    if stream is None:
        _invalid(f"Missing archive payload: {member.name}")
    with stream, target.open("xb") as output:
        shutil.copyfileobj(stream, output, CHUNK_BYTES)
    target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return total


def _materialize_member(
    source: tarfile.TarFile,
    member: tarfile.TarInfo,
    target: Path,
    *,
    state: _ExtractionState,
) -> None:
    if member.issym():
        _extract_symlink(member, target, state.destination)
    elif member.isfile():
        state.total_bytes = _extract_regular_file(
            source, member, target, previous_bytes=state.total_bytes
        )
    else:
        _invalid(f"Unsupported archive member type: {member.name}")


def _extract_member(
    source: tarfile.TarFile,
    member: tarfile.TarInfo,
    state: _ExtractionState,
) -> bool:
    relative = member_path(member.name, state.prefix)
    if relative == PurePosixPath():
        if not member.isdir():
            _invalid("Invalid repository root")
        return False
    target = _verified_target(state.destination, relative)
    if member.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        _invalid(f"Duplicate upstream archive member: {relative}")
    _materialize_member(source, member, target, state=state)
    return True


def extract_sources(archive: Path, destination: Path) -> int:
    """Extract validated files and symlinks without following outside paths.

    Returns:
        Number of extracted file or symlink entries.

    """
    state: _ExtractionState | None = None
    count = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if state is None:
                state = _ExtractionState(destination, _archive_prefix(member))
            count += int(_extract_member(source, member, state))
    return count


def source_records(
    repository: Repository, checkout: Path
) -> list[ReferenceRecord]:
    """Inventory verified bytes and SPDX tags for a pinned checkout.

    Returns:
        One immutable-source receipt entry per retained source file.

    """
    records: list[ReferenceRecord] = []
    prefix = (
        repository.name
        if repository.flat
        else f"{repository.name}/{repository.revision}"
    )
    for path in sorted(checkout.rglob("*")):
        if GIT_METADATA_DIR in path.relative_to(checkout).parts:
            continue
        if path.is_symlink():
            content = path.readlink().as_posix().encode("utf-8")
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
            "license_review": LICENSE_REVIEW_REQUIRED,
            "status": "reference-only",
            "destinations": [],
            "notes": "Downloaded source, not implemented or runtime-verified.",
        })
    return records


def _checked_receipt(
    repository: Repository, checkout: Path, receipt: Path
) -> list[ReferenceRecord]:
    saved = cast(
        "ReferenceReceipt", json.loads(receipt.read_text(encoding="utf-8"))
    )
    records = source_records(repository, checkout)
    if (
        saved.get("repository") != repository.project
        or saved.get("revision") != repository.revision
        or saved.get("files") != records
    ):
        _invalid(f"Cached upstream source changed: {checkout}")
    return records


def _receive_archive(repository: Repository, archive: Path) -> None:
    url = (
        f"https://codeload.github.com/{repository.project}"
        f"/tar.gz/{repository.revision}"
    )
    downloaded = 0
    with (
        _open_pinned_https(url) as response,
        archive.open("xb") as output,
    ):
        while block := response.read(CHUNK_BYTES):
            downloaded += len(block)
            if downloaded > MAX_ARCHIVE_BYTES:
                _invalid("Upstream archive download limit exceeded")
            _ = output.write(block)


def _checked_archive_records(
    repository: Repository, archive: Path, staging: Path
) -> list[ReferenceRecord]:
    staging.mkdir()
    count = extract_sources(archive, staging)
    if count != repository.files:
        context = f"Expected {repository.files} tracked files for "
        _invalid(f"{context}{repository.name}, got {count}")
    records = source_records(repository, staging)
    if len(records) != count:
        _invalid("Extracted file inventory is incomplete")
    return records


def _adopt_existing_sdk(
    repository: Repository,
    records: list[ReferenceRecord],
    staging: Path,
    *,
    checkout: Path,
) -> None:
    existing = source_records(repository, checkout)
    expected = {row["path"]: row for row in records}
    for row in existing:
        if row["path"] not in expected or row != expected[row["path"]]:
            _invalid(f"Existing SDK source changed: {row["path"]}")
    for row in records:
        target = checkout / row["path"]
        if not target.exists() and not target.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            _ = (staging / row["path"]).rename(target)


def _publish_source_checkout(
    repository: Repository,
    records: list[ReferenceRecord],
    staging: Path,
    *,
    checkout: Path,
) -> None:
    checkout.parent.mkdir(parents=True, exist_ok=True)
    if checkout.exists():
        # Retain exact pre-existing SDK bytes; never overwrite owner's files.
        _adopt_existing_sdk(repository, records, staging, checkout=checkout)
    else:
        _ = staging.rename(checkout)


def _write_source_receipt(
    repository: Repository,
    records: list[ReferenceRecord],
    receipt: Path,
    *,
    archive: Path,
) -> None:
    content: ReferenceReceipt = {
        "repository": repository.project,
        "revision": repository.revision,
        "archive_sha256": digest_file(archive),
        "files": records,
    }
    _ = receipt.write_text(
        json.dumps(content, indent=2) + "\n", encoding="utf-8"
    )


def download(
    repository: Repository, references: Path, *, offline: bool = False
) -> list[ReferenceRecord]:
    """Verify an existing pinned cache or acquire one without overwriting.

    Returns:
        Full source-file inventory after receipt and byte verification.

    """
    checkout = references / repository.name
    if not repository.flat:
        checkout /= repository.revision
    receipt = references / f".{repository.name}-{repository.revision}.json"
    if checkout.exists() and receipt.is_file():
        return _checked_receipt(repository, checkout, receipt)
    if offline:
        _missing(f"No verified cached checkout: {checkout}")
    if checkout.exists() and repository.name != SDK_REPOSITORY:
        _invalid(f"Existing source has no completed receipt: {checkout}")
    with tempfile.TemporaryDirectory(
        prefix=".download-", dir=references
    ) as scratch:
        scratch_path = Path(scratch)
        archive = scratch_path / "source.tar.gz"
        _receive_archive(repository, archive)
        staging = scratch_path / "tree"
        records = _checked_archive_records(repository, archive, staging)
        _publish_source_checkout(
            repository, records, staging, checkout=checkout
        )
        _write_source_receipt(repository, records, receipt, archive=archive)
        return records


def _previous_reference_identities(
    previous: str,
) -> dict[tuple[str, str, str], str]:
    latest: dict[tuple[str, str, str], str] = {}
    for line in previous.splitlines():
        if not line.strip():
            continue
        row = cast("dict[str, object]", json.loads(line))
        if LEDGER_REPOSITORY_KEY not in row or LEDGER_SOURCE_KEY in row:
            continue
        repository_name = row.get("repository")
        revision = row.get("revision")
        source_path = row.get("path")
        digest = row.get("sha256")
        if not all(
            isinstance(field, str)
            for field in (repository_name, revision, source_path, digest)
        ):
            _invalid("Malformed reference ledger identity")
        identity = (
            cast("str", repository_name),
            cast("str", revision),
            cast("str", source_path),
        )
        latest[identity] = cast("str", digest)
    return latest


def _new_reference_ledger_lines(
    records: list[ReferenceRecord], latest: dict[tuple[str, str, str], str]
) -> list[str]:
    additions: list[str] = []
    for row in records:
        identity = (row["repository"], row["revision"], row["path"])
        if identity in latest:
            if latest[identity] != row["sha256"]:
                _invalid(f"Pinned source differs from ledger: {identity}")
            continue
        additions.append(
            json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        latest[identity] = row["sha256"]
    return additions


def _atomic_write_ledger(
    path: Path, previous: str, additions: list[str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            separator = "\n" if previous and not previous.endswith("\n") else ""
            _ = output.write(previous + separator + "".join(additions))
            _ = output.flush()
            os.fsync(output.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    temporary.chmod(0o644)
    _ = temporary.replace(path)


def update_ledger(path: Path, records: list[ReferenceRecord]) -> int:
    """Append new source identities without replacing prior assessments.

    Returns:
        Number of newly appended ledger identities.

    """
    previous = path.read_text(encoding="utf-8") if path.exists() else ""
    latest = _previous_reference_identities(previous)
    additions = _new_reference_ledger_lines(records, latest)
    if additions or not path.exists():
        _atomic_write_ledger(path, previous, additions)
    return len(additions)


def seed_ledger(references: Path) -> None:
    """Seed a cache ledger from checked-in canonical source bytes."""
    ledger = references / "ledger.jsonl"
    if ledger.exists():
        return
    canonical = ROOT / ".references/ledger.jsonl"
    if not canonical.is_file():
        _missing(f"Missing tracked reference ledger: {canonical}")
    content = canonical.read_bytes()
    # Check the restored inventory before publishing it; no Git index mutation.
    for line in content.splitlines():
        json.loads(line)
    references.mkdir(parents=True, exist_ok=True)
    with ledger.open("xb") as output:
        _ = output.write(content)


def linux_records(ledger: Path) -> list[LinuxLedgerRecord]:
    """Read current Linux source identities from the tracked ledger.

    Returns:
        Last matching ledger entry for every pinned Linux source path.

    """
    latest: dict[str, LinuxLedgerRecord] = {}
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            row = cast("LinuxLedgerRecord", json.loads(line))
            if row.get("schema") == 1 and row.get("source", "").startswith(
                f"{LINUX_RECORD_TAG}/"
            ):
                latest[row["source"]] = row
    if not latest:
        _invalid("Linux inventory missing: restore .references/ledger.jsonl")
    return list(latest.values())


def _linux_source_target(
    row: LinuxLedgerRecord, references: Path
) -> tuple[PurePosixPath, Path]:
    relative = PurePosixPath(row["source"])
    if relative.is_absolute() or PARENT_COMPONENT in relative.parts:
        _invalid(f"Unsafe Linux source path: {relative}")
    target = references.joinpath(*relative.parts)
    if not target.resolve().is_relative_to(references.resolve()):
        _invalid(f"Linux source path escapes references: {relative}")
    return relative, target


def _cached_linux_source(
    row: LinuxLedgerRecord, relative: PurePosixPath, target: Path
) -> bool:
    if target.is_symlink():
        _invalid(f"Cached Linux source is a symlink: {relative}")
    if not target.is_file():
        return False
    if digest_file(target) != row["sha256"]:
        _invalid(f"Cached Linux source changed: {relative}")
    return True


def _read_https_bytes(url: str, *, maximum: int) -> bytes:
    with _open_pinned_https(url) as response:
        return response.read(maximum + 1)


def _linux_source_mirror(revision: str, upstream: str) -> bytes:
    mirror = (
        "https://kernel.googlesource.com/pub/scm/linux/kernel/"
        f"git/torvalds/linux/+/{revision}/{upstream}?format=TEXT"
    )
    encoded = _read_https_bytes(mirror, maximum=2 * MAX_ARCHIVE_BYTES)
    if len(encoded) > 2 * MAX_ARCHIVE_BYTES:
        _invalid("Linux mirror response size limit exceeded")
    return base64.b64decode(encoded, validate=False)


def _download_linux_bytes(row: LinuxLedgerRecord) -> bytes:
    revision = row.get("revision", "")
    upstream = row.get("upstream_path", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not upstream:
        _invalid(f"Linux source has no verified upstream pin: {row["source"]}")
    url = (
        f"https://raw.githubusercontent.com/torvalds/linux/{revision}/"
        f"{upstream}"
    )
    try:
        content = _read_https_bytes(url, maximum=MAX_ARCHIVE_BYTES)
    except OSError:
        # Same pinned Git blob, independent hosting; hash is checked below.
        content = _linux_source_mirror(revision, upstream)
    if len(content) > MAX_ARCHIVE_BYTES:
        _invalid(f"Linux source size limit exceeded: {row["source"]}")
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        _invalid(f"Downloaded Linux source hash mismatch: {row["source"]}")
    return content


def _publish_linux_bytes(content: bytes, target: Path) -> None:
    # Link a complete verified temporary inode into the cache without
    # replacing a concurrent writer's source file or its file identity.
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            _ = output.write(content)
        temporary.chmod(0o644)
        os.link(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _retry_linux_restore(row: LinuxLedgerRecord, target: Path) -> None:
    for attempt in range(RETRY_ATTEMPTS):
        try:
            _publish_linux_bytes(_download_linux_bytes(row), target)
        except OSError:
            if attempt == RETRY_ATTEMPTS - 1:
                raise
            time.sleep(attempt + 1)
        else:
            return


def _restore_linux_source(
    row: LinuxLedgerRecord, *, references: Path, offline: bool
) -> None:
    relative, target = _linux_source_target(row, references)
    if _cached_linux_source(row, relative, target):
        return
    if offline:
        _missing(f"No cached Linux source: {relative}")
    _retry_linux_restore(row, target)


def download_linux(references: Path, *, offline: bool = False) -> int:
    """Restore only pinned Linux files, preserving prior ledger history.

    Returns:
        Number of pinned Linux files verified or safely restored.

    """
    seed_ledger(references)
    rows = linux_records(references / "ledger.jsonl")
    restore = partial(
        _restore_linux_source, references=references, offline=offline
    )
    with ThreadPoolExecutor(max_workers=4) as workers:
        _ = list(workers.map(restore, rows))
    return len(rows)


class DownloadOptions(argparse.Namespace):
    """Strictly typed CLI fields populated by argparse."""

    references: Path = ROOT / ".references"
    repo: list[str] | None = None
    offline: bool = False


def main() -> int:
    """Run source acquisition in offline or pinned HTTPS mode.

    Returns:
        Zero if every requested source was verified successfully.

    """
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--references", type=Path, default=ROOT / ".references"
    )
    _ = parser.add_argument(
        "--repo",
        choices=[r.name for r in REPOSITORIES] + [LINUX_RECORD_TAG],
        action="append",
    )
    _ = parser.add_argument(
        "--offline",
        action="store_true",
        help="Verify existing caches without downloading",
    )
    args = cast("DownloadOptions", parser.parse_args())
    references = args.references.expanduser().resolve()
    references.mkdir(parents=True, exist_ok=True)
    seed_ledger(references)
    if not args.repo or LINUX_RECORD_TAG in args.repo:
        count = download_linux(references, offline=args.offline)
        _ = sys.stdout.write(
            f"linux: {count} pinned Wi-Fi/Bluetooth reference files verified\n"
        )
        _ = sys.stdout.flush()
    for repository in REPOSITORIES:
        if args.repo and repository.name not in args.repo:
            continue
        records = download(repository, references, offline=args.offline)
        added = update_ledger(references / "ledger.jsonl", records)
        label = f"{repository.name} @ {repository.revision}: "
        _ = sys.stdout.write(
            f"{label}{len(records)} source files, {added} new ledger entries\n"
        )
        _ = sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
