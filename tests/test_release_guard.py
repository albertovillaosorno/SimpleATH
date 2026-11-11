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
#   - Offline regression cases for release guard.
# - Must-Not:
#   - Require physical hardware, mutate installed drivers, or suppress failures.
# - Allows:
#   - Inputs: isolated fixtures and reproducible source-under-test inputs.
#   - Outputs: assertions and observable regression verdicts.
#   - Side effects: test-local temporary files and bounded subprocesses only.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Offline regression cases for release guard.
# - Description:
#   - Implements or verifies the test_release_guard source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for release guard.
"""No-network regression for immutable release tag selection."""

from unittest import TestCase

from tools.release_guard import require_same_commit_tag

TAG = "v1.2.0-alpha"
SHA = "a" * 40
OTHER_SHA = "b" * 40


def _reference(
    *, sha: str = SHA, target_type: str = "commit"
) -> dict[str, object]:
    """Create a synthetic GitHub lightweight/annotated ref.

    Returns:
        A JSON-shaped response without contacting GitHub.

    """
    return {
        "ref": f"refs/tags/{TAG}",
        "object": {"type": target_type, "sha": sha},
    }


def _rejects(response: object, *, tag: str = TAG, sha: str = SHA) -> bool:
    """Check that malformed release metadata is refused.

    Returns:
        True if the checked tag contract rejects the response.

    """
    try:
        require_same_commit_tag(response, tag, sha)
    except ValueError:
        return True
    return False


class ReleaseTagIntegrity(TestCase):
    """No existing Git reference is implicitly authorized to move."""

    @staticmethod
    def test_exact_lightweight_commit_can_be_reused() -> None:
        """Accept the same commit without producing a tag write."""
        assert require_same_commit_tag(_reference(), TAG, SHA) is None

    @staticmethod
    def test_different_commit_refuses_implicit_rewrite() -> None:
        """A changed tag never authorizes forced history rewrites."""
        assert _rejects(_reference(sha=OTHER_SHA))

    @staticmethod
    def test_annotated_tag_is_not_assumed_to_be_a_commit() -> None:
        """Avoid confusing annotated-tag object SHAs with commit SHAs."""
        assert _rejects(_reference(target_type="tag"))

    @staticmethod
    def test_missing_or_malformed_target_is_rejected() -> None:
        """Require the full GitHub response shape before reusing a ref."""
        assert _rejects(None)
        assert _rejects({"ref": f"refs/tags/{TAG}"})
        assert _rejects({"ref": f"refs/tags/{TAG}", "object": []})

    @staticmethod
    def test_wrong_ref_or_invalid_sha_is_rejected() -> None:
        """The requested exact ref and full commit SHA must agree."""
        response = _reference()
        response["ref"] = "refs/tags/unrelated"
        assert _rejects(response)
        assert _rejects(_reference(), sha="not-a-sha")
        assert _rejects(_reference(), tag="invalid/nested")
