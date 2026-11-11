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
#   - Host-side tooling for release guard.
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
#   - Host-side tooling for release guard.
# - Description:
#   - Implements or verifies the release_guard source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for release guard.
"""Require immutable, exact-commit GitHub tag references before publishing."""

import re
from typing import TypeIs

TAG_SEPARATOR = "/"
COMMIT_TARGET_TYPE = "commit"


def _is_dict(value: object) -> TypeIs[dict[object, object]]:
    """Narrow arbitrary parsed data to an object-keyed dictionary.

    Returns:
        True only for a dictionary.

    """
    return isinstance(value, dict)


def _text_keyed_object(value: object) -> TypeIs[dict[str, object]]:
    """Narrow an untrusted response to a dictionary with string keys.

    Returns:
        True only for a dictionary whose keys are all strings.

    """
    if not _is_dict(value):
        return False
    return all(isinstance(key, str) for key in value)


def _validate_tag_identity(tag: str, sha: str) -> None:
    """Reject an ambiguous tag name or non-canonical commit SHA.

    Raises:
        ValueError: The supplied tag or SHA is invalid.

    """
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        message = "Expected a lowercase, full commit SHA"
        raise ValueError(message)
    if not tag or TAG_SEPARATOR in tag:
        message = "Invalid release tag name"
        raise ValueError(message)


def require_same_commit_tag(response: object, tag: str, sha: str) -> None:
    """Reject rewritten, annotated or malformed existing release tags.

    An existing lightweight Git tag is safe to reuse only if it still
    targets the exact requested commit. Never move an existing tag.

    Raises:
        ValueError: The requested commit or returned Git reference is invalid.

    """
    _validate_tag_identity(tag, sha)
    if not _text_keyed_object(response):
        message = "GitHub tag response is not an object"
        raise ValueError(message)
    if response.get("ref") != f"refs/tags/{tag}":
        message = "GitHub tag response does not match the requested reference"
        raise ValueError(message)
    target = response.get("object")
    if not _text_keyed_object(target):
        message = "GitHub tag target is not an object"
        raise ValueError(message)
    if target.get("type") != COMMIT_TARGET_TYPE or target.get("sha") != sha:
        message = "Existing Git tag does not point to the requested commit"
        raise ValueError(message)
