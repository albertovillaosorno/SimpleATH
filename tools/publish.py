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
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for publish.
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
#   - Host-side tooling for publish.
# - Description:
#   - Implements or verifies the publish source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for publish.
# Originally created by laobamac on 2026/9/28.
# Copyright © 2026 laobamac. All rights reserved.
"""Publish pre-existing, explicitly authorized release archives.

This legacy entrypoint is not part of the current tag-only SimpleATH CI.
Importing it must not fetch, build, upload, or alter a Git reference.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import TypeIs
import urllib.error
import urllib.parse
import urllib.request
import urllib.response

from build import CONFIGURATIONS
from build import package_name
from embed import VERSION
from release_guard import require_same_commit_tag

CHANNEL_PRE = "pre"
CHANNEL_REL = "rel"
HTTPS_SCHEME = "https"
SHA_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
NOT_FOUND = 404
PAGE_SIZE = 100
MAX_PAGES = 1000
REQUEST_TIMEOUT = 60
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _raw_mapping(value: object) -> TypeIs[dict[object, object]]:
    """Recognize a dict without inventing its key or value types.

    Returns:
        True only for a dictionary.

    """
    return isinstance(value, dict)


def _mapping(value: object) -> TypeIs[dict[str, object]]:
    """Narrow a decoded JSON object to string-keyed members.

    Returns:
        True for a dictionary with only string keys.

    """
    return _raw_mapping(value) and all(isinstance(key, str) for key in value)


def require_json_object(value: object) -> dict[str, object]:
    """Require an API object; reject malformed responses.

    Returns:
        The validated object.

    Raises:
        ValueError: The response is not a string-keyed object.

    """
    if not _mapping(value):
        message = "Expected an object with string keys"
        raise ValueError(message)
    return value


def _raw_sequence(value: object) -> TypeIs[list[object]]:
    """Recognize a JSON array with untrusted object elements.

    Returns:
        True only for a list.

    """
    return isinstance(value, list)


def require_json_array(value: object) -> list[object]:
    """Require a JSON array.

    Returns:
        An array whose element types remain untrusted.

    Raises:
        TypeError: The response is not an array.

    """
    if not _raw_sequence(value):
        message = "Expected an array"
        raise TypeError(message)
    return value


def _string(value: object) -> str:
    """Require a nonempty string.

    Returns:
        The validated string.

    Raises:
        ValueError: A required string is missing.

    """
    if not isinstance(value, str) or not value:
        message = "Expected a nonempty string"
        raise ValueError(message)
    return value


def require_release_id(value: object) -> int:
    """Validate GitHub's positive JSON identifier (not a bool).

    Returns:
        A positive numeric ID.

    Raises:
        ValueError: The response contains an invalid ID.

    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        message = "Invalid release or asset ID"
        raise ValueError(message)
    return value


def validate_identity(repository: str, sha: str) -> None:
    """Fail closed before using repository and revision in URLs or tags.

    Raises:
        ValueError: The repository or full commit identifier is invalid.

    """
    if REPOSITORY_RE.fullmatch(repository) is None:
        message = "Invalid repository name"
        raise ValueError(message)
    if SHA_RE.fullmatch(sha) is None:
        message = "Invalid lowercase full commit SHA"
        raise ValueError(message)


def validate_https_url(url: str, *, origin_only: bool) -> str:
    """Validate an HTTPS server without credentials, query or fragments.

    Returns:
        The validated URL without trailing slash.

    Raises:
        ValueError: The URL permits unsafe or ambiguous destinations.

    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != HTTPS_SCHEME or parsed.hostname is None:
        message = "Expected a secure HTTPS server"
        raise ValueError(message)
    if parsed.username is not None or parsed.password is not None:
        message = "Server URL must not include user information"
        raise ValueError(message)
    if parsed.query or parsed.fragment:
        message = "Server URL must not include query or fragment"
        raise ValueError(message)
    if origin_only and parsed.path not in {"", "/"}:
        message = "Server origin must not include a path"
        raise ValueError(message)
    return url.rstrip("/")


def _github_server_url() -> str:
    """Accept only an HTTPS GitHub server origin for Markdown links.

    Returns:
        Validated origin URL without a trailing slash.

    """
    url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return validate_https_url(url, origin_only=True)


def _render_commit(repository_url: str, value: object) -> str:
    """Escape a validated single GitHub commit into one Markdown row.

    Returns:
        Markdown with an exact SHA link and escaped subject.

    Raises:
        ValueError: A commit's SHA, metadata or message is invalid.

    """
    commit = require_json_object(value)
    commit_sha = _string(commit.get("sha")).lower()
    if SHA_RE.fullmatch(commit_sha) is None:
        message = "Invalid GitHub commit SHA in release notes"
        raise ValueError(message)
    details = require_json_object(commit.get("commit"))
    subject = _string(details.get("message")).splitlines()[0]
    escaped = re.sub(r"([\\`*_{}\[\]<>#|])", r"\\\1", subject)
    link = f"{repository_url}/commit/{commit_sha}"
    return f"- [`{commit_sha[:7]}`]({link}) {escaped}"


def prerelease_body(repository: str, commits: list[object]) -> str:
    """Render a release summary from validated GitHub commit metadata.

    Returns:
        Markdown with escaped subjects and exact commit URLs.

    """
    sha = os.environ["GITHUB_SHA"].lower()
    validate_identity(repository, sha)
    origin = _github_server_url()
    repository_url = f"{origin}/{repository}"
    changes = [_render_commit(repository_url, value) for value in commits]
    heading = "Experimental SimpleATH source; native Wi-Fi is unverified.\n\n"
    warning = "No physical driver behavior is established by a release.\n"
    readme_url = f"{repository_url}/blob/{sha}/README.md"
    return (
        heading
        + warning
        + f"Current limitations: [README]({readme_url}).\n\n"
        + "\n".join(changes)
        + "\n"
    )


def release_body() -> str:
    """Retain the historical upstream template as explicit reference only.

    Returns:
        A non-readiness statement for the legacy release workflow.

    """
    return """The original Broadcom design supported Sonoma, Sequoia and Tahoe.
Its old Skywalk and AirPort payload arrangements are not SimpleATH's
functional, physically verified native AR9565 Wi-Fi implementation.

**SimpleATH status:** Experimental AR9565 source only. Neither a kext build,
working Wi-Fi connectivity, Bluetooth coexistence nor AirDrop acceptance has
been established. The owner controls any future binary and device testing.
The tag-only SimpleATH CI workflow does not run this publishing script.
"""


def verify_archives(root: Path, channel: str, sha: str) -> list[Path]:
    """Require matching checksums for every prebuilt release archive.

    Returns:
        Validated archive and checksum paths.

    Raises:
        ValueError: A file is missing or its SHA-256 does not agree.

    """
    files: list[Path] = []
    for configuration in CONFIGURATIONS:
        name = package_name(configuration, channel, sha)
        archive = root / "dist" / f"{name}.zip"
        checksum = archive.with_name(f"{archive.name}.sha256")
        if not archive.is_file() or not checksum.is_file():
            message = f"Release archive or checksum is missing: {name}"
            raise ValueError(message)
        with archive.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        expected = [actual, archive.name]
        if checksum.read_text(encoding="utf-8").split() != expected:
            message = f"Release archive checksum differs: {name}"
            raise ValueError(message)
        files.extend((archive, checksum))
    return files


def formal_release_from_event() -> tuple[str, int]:
    """Read and validate an explicitly supplied formal release event.

    Returns:
        Exact tag and positive release identifier.

    Raises:
        ValueError: The release event is not eligible for publication.

    """
    event_path = Path(os.environ["GITHUB_EVENT_PATH"])
    event: object = json.loads(event_path.read_text(encoding="utf-8"))  # pyright: ignore[reportAny] - JSON is narrowed with require_json_object.
    release = require_json_object(require_json_object(event).get("release"))
    tag = _string(release.get("tag_name"))
    if (
        release.get("prerelease") is not False
        or release.get("draft") is not False
    ):
        message = "Formal release must not be draft or prerelease"
        raise ValueError(message)
    if tag not in {VERSION, f"v{VERSION}"}:
        message = f"Formal release tag must be {VERSION} or v{VERSION}"
        raise ValueError(message)
    return tag, require_release_id(release.get("id"))


def _api_origin() -> str:
    """Constrain the remote release API to a single HTTPS origin.

    Returns:
        A validated GitHub API URL.

    """
    url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    return validate_https_url(url, origin_only=False)


def read_json_response(raw: object) -> object | None:
    """Decode only HTTP response streams from the standard URL opener.

    Returns:
        Untrusted decoded JSON or None for an empty response.

    Raises:
        TypeError: The response transport is not a supported HTTP stream.
        ValueError: The response is too large to process safely.

    """
    if not isinstance(raw, urllib.response.addinfourl):
        message = "GitHub returned an unknown response transport"
        raise TypeError(message)
    with raw as response:
        content: bytes = response.read(MAX_RESPONSE_BYTES + 1)
    if len(content) > MAX_RESPONSE_BYTES:
        message = "GitHub response exceeds the bounded JSON size"
        raise ValueError(message)
    if not content:
        return None
    decoded: object = json.loads(content)  # pyright: ignore[reportAny] - JSON is structurally narrowed by the caller.
    return decoded


class _GitHub:
    """Narrow, authenticated release API boundary; never used by dry runs."""

    def __init__(self, token: str) -> None:
        """Capture the token without logging it or making any request."""
        self._api: str = _api_origin()
        self._token: str = token

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
        *,
        missing: bool = False,
    ) -> object | None:
        """Make the explicitly requested JSON HTTP operation.

        Returns:
            Decoded JSON data or None for empty/allowed 404 responses.

        Raises:
            ValueError: An unexpected HTTP error occurred.

        """
        encoded = None if data is None else json.dumps(data).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }
        query = urllib.request.Request(
            self._api + path, data=encoded, headers=headers, method=method
        )
        try:
            # S310 is reviewed: _api_origin enforces HTTPS; paths are local.
            raw: object = urllib.request.build_opener().open(  # pyright: ignore[reportAny] - Validate response shape before use.
                query, timeout=REQUEST_TIMEOUT
            )
            return read_json_response(raw)
        except urllib.error.HTTPError as error:
            if error.code == NOT_FOUND and missing:
                return None
            message = f"GitHub {method} {path} failed: HTTP {error.code}"
            raise ValueError(message) from None

    def object(
        self, method: str, path: str, data: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Require an API object response.

        Returns:
            A typed GitHub JSON object.

        """
        return require_json_object(self.request(method, path, data))

    def page(self, path: str) -> list[object]:
        """Require an API array response.

        Returns:
            Untrusted JSON array elements for validation.

        """
        return require_json_array(self.request("GET", path))


def _publish_formal(
    client: _GitHub, base: str, *, release_id: int, tag: str
) -> None:
    """Update only the matching existing, non-draft formal release.

    Raises:
        ValueError: The release identity or published state changed.

    """
    path = f"{base}/releases/{release_id}"
    current = client.object("GET", path)
    if (
        current.get("tag_name") != tag
        or current.get("prerelease") is not False
        or current.get("draft") is not False
    ):
        message = "Release state changed during publication"
        raise ValueError(message)
    _ = client.request("PATCH", path, {"body": release_body()})


def _ensure_alpha_ref(
    client: _GitHub, base: str, tag: str, *, sha: str
) -> None:
    """Never silently move an existing tag to another commit."""
    encoded = urllib.parse.quote(tag, safe="")
    ref = client.request("GET", f"{base}/git/ref/tags/{encoded}", missing=True)
    if ref is not None:
        require_same_commit_tag(ref, tag, sha)
    else:
        _ = client.request(
            "POST", f"{base}/git/refs", {"ref": f"refs/tags/{tag}", "sha": sha}
        )


def _publish_alpha(client: _GitHub, base: str, tag: str, *, sha: str) -> int:
    """Reuse an exact-commit alpha tag or create a new immutable ref.

    Returns:
        The positive release ID to be used for asset reconciliation.

    Raises:
        ValueError: An existing tag, release or commit data is unsafe.

    """
    encoded = urllib.parse.quote(tag, safe="")
    current_value = client.request(
        "GET", f"{base}/releases/tags/{encoded}", missing=True
    )
    current = (
        None if current_value is None else require_json_object(current_value)
    )
    if current is not None and (
        current.get("prerelease") is not True
        or current.get("draft") is not False
    ):
        message = "Alpha tag already belongs to a formal/draft release"
        raise ValueError(message)
    _ensure_alpha_ref(client, base, tag, sha=sha)
    commits = client.page(f"{base}/commits?sha={sha}&per_page=5")
    repository = base.removeprefix("/repos/")
    body = prerelease_body(repository, commits)
    values: dict[str, object] = {
        "tag_name": tag,
        "target_commitish": sha,
        "name": tag,
        "body": body,
        "draft": False,
        "prerelease": True,
        "make_latest": "false",
    }
    if current is not None:
        identifier = require_release_id(current.get("id"))
        release = client.object(
            "PATCH", f"{base}/releases/{identifier}", values
        )
    else:
        release = client.object("POST", f"{base}/releases", values)
    return require_release_id(release.get("id"))


def _pages(client: _GitHub, path: str) -> list[dict[str, object]]:
    """Collect only bounded, structurally checked GitHub JSON pages.

    Returns:
        Validated list of objects from up to MAX_PAGES pages.

    Raises:
        ValueError: GitHub returned malformed or unbounded pagination.

    """
    entries: list[dict[str, object]] = []
    for page in range(1, MAX_PAGES + 1):
        values = client.page(f"{path}?per_page={PAGE_SIZE}&page={page}")
        if len(values) > PAGE_SIZE:
            message = "GitHub returned an oversized page"
            raise ValueError(message)
        entries.extend(require_json_object(value) for value in values)
        if len(values) < PAGE_SIZE:
            return entries
    message = "GitHub pagination exceeded the bounded page limit"
    raise ValueError(message)


def _prune_alpha_assets(
    client: _GitHub, base: str, *, release_id: int, files: list[Path]
) -> None:
    """Remove only assets not present in the exact published file set."""
    keep = {path.name for path in files}
    for asset in _pages(client, f"{base}/releases/{release_id}/assets"):
        if _string(asset.get("name")) not in keep:
            identifier = require_release_id(asset.get("id"))
            _ = client.request("DELETE", f"{base}/releases/assets/{identifier}")


def _prune_old_alphas(client: _GitHub, base: str, *, release_id: int) -> None:
    """Remove only other prereleases, never drafts or formal releases."""
    for item in _pages(client, f"{base}/releases"):
        if item.get("prerelease") is not True or item.get("draft") is not False:
            continue
        identifier = require_release_id(item.get("id"))
        if identifier != release_id:
            _ = client.request("DELETE", f"{base}/releases/{identifier}")


def _upload(tag: str, repository: str, files: list[Path]) -> None:
    """Use a resolved GitHub CLI executable, never a shell command.

    Raises:
        ValueError: The release uploader executable is unavailable.

    """
    gh = shutil.which("gh")
    if gh is None:
        message = "GitHub release CLI is unavailable"
        raise ValueError(message)
    # S603 is reviewed: fixed argv, exact repository/tag, absolute executable.
    _ = subprocess.run(
        [
            gh,
            "release",
            "upload",
            tag,
            *(str(path) for path in files),
            "--repo",
            repository,
            "--clobber",
        ],
        check=True,
    )


@dataclass(frozen=True)
class _PublishPlan:
    """Validated release target and local prebuilt asset set."""

    tag: str
    repository: str
    sha: str
    files: list[Path]
    formal_id: int | None


def _publish(plan: _PublishPlan) -> None:
    """Publish only after local validations and non-dry-run approval."""
    client = _GitHub(os.environ["GH_TOKEN"])
    base = f"/repos/{plan.repository}"
    if plan.formal_id is None:
        release_id = _publish_alpha(client, base, plan.tag, sha=plan.sha)
    else:
        _publish_formal(client, base, release_id=plan.formal_id, tag=plan.tag)
        release_id = plan.formal_id
    _upload(plan.tag, plan.repository, plan.files)
    if plan.formal_id is None:
        _prune_alpha_assets(
            client, base, release_id=release_id, files=plan.files
        )
        _prune_old_alphas(client, base, release_id=release_id)
    _ = sys.stdout.write(
        f"Published {plan.tag}: " + ", ".join(p.name for p in plan.files) + "\n"
    )


class _ReleaseArgs(argparse.Namespace):
    """Typed command-line fields for the legacy release entrypoint."""

    channel: str = CHANNEL_PRE
    dry_run: bool = False


def main() -> None:
    """Validate pre-existing release artifacts before side-effecting actions."""
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--channel", choices=(CHANNEL_PRE, CHANNEL_REL), required=True
    )
    _ = parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(namespace=_ReleaseArgs())
    repository = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"].lower()
    validate_identity(repository, sha)
    channel: str = args.channel
    files = verify_archives(
        Path(__file__).resolve().parent.parent, channel, sha
    )
    tag, formal_id = (
        formal_release_from_event()
        if channel == CHANNEL_REL
        else (f"v{VERSION}-alpha", None)
    )
    if args.dry_run:
        output = {
            "repository": repository,
            "tag": tag,
            "channel": channel,
            "body": release_body() if channel == CHANNEL_REL else None,
            "assets": [file.name for file in files],
        }
        _ = sys.stdout.write(json.dumps(output, indent=2) + "\n")
        return
    _publish(_PublishPlan(tag, repository, sha, files, formal_id))


if __name__ == "__main__":
    main()
