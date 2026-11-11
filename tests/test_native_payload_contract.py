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
#   - Offline regression cases for native payload contract.
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
#   - Offline regression cases for native payload contract.
# - Description:
#   - Implements or verifies the test_native_payload_contract source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native payload contract.
"""Synthetic legacy payload string-renaming safety regressions."""

from unittest import TestCase

from tools.native_payload_strings import rename_class_cstrings


def _rejects(
    image: bytearray,
    sections: tuple[tuple[int, int], ...],
    replacements: dict[str, str],
    *,
    require_all: bool,
) -> str | None:
    """Return the error from a rejected but unchanged image.

    Returns:
        Its rejection text, or None for success/partial mutation.

    """
    before = bytes(image)
    try:
        _ = rename_class_cstrings(
            image, sections, replacements, require_all=require_all
        )
    except ValueError as error:
        return str(error) if bytes(image) == before else None
    return None


class CStringRewriteTests(TestCase):
    """Class renaming is bounded, exact and all-or-nothing on rejection."""

    @staticmethod
    def test_replaces_exact_names_without_resizing_image() -> None:
        """Preserve image size and original offsets of repeated classes."""
        image = bytearray(b"LongName\0other\0LongName\0")
        found = rename_class_cstrings(
            image,
            ((0, 9), (9, len(image) - 9)),
            {"LongName": "NewName"},
            require_all=True,
        )
        assert found == {"LongName": [0, 15]}
        expected = b"NewName\0\0other\0NewName\0\0"
        assert image == expected

    @staticmethod
    def test_missing_required_class_does_not_modify_earlier_match() -> None:
        """Reject missing names without exposing partial replacements."""
        image = bytearray(b"LongName\0other\0")
        error = _rejects(
            image,
            ((0, len(image)),),
            {"LongName": "NewName", "Absent": "Short"},
            require_all=True,
        )
        assert error is not None
        expected = "Class strings missing"
        assert expected in error

    @staticmethod
    def test_overlong_class_name_rolls_back_all_candidates() -> None:
        """Reject expansion without modifying an earlier valid match."""
        image = bytearray(b"LongName\0Tiny\0")
        error = _rejects(
            image,
            ((0, len(image)),),
            {"LongName": "NewName", "Tiny": "TooLong"},
            require_all=False,
        )
        assert error is not None
        expected = "Invalid replacement"
        assert expected in error

    @staticmethod
    def test_unterminated_section_never_changes_image() -> None:
        """Reject trailing class data without a CString terminator."""
        image = bytearray(b"LongName\0other")
        error = _rejects(
            image,
            ((0, len(image)),),
            {"LongName": "NewName"},
            require_all=False,
        )
        assert error is not None
        expected = "Unterminated CString"
        assert expected in error

    @staticmethod
    def test_sections_outside_image_are_rejected() -> None:
        """Reject negative or overlarge mapped section spans."""
        for span in ((-1, 1), (0, -1), (3, 3), (5, 0)):
            image = bytearray(b"A\0BC")
            error = _rejects(
                image,
                (span,),
                {"A": "B"},
                require_all=False,
            )
            assert error is not None
            expected = "outside the image"
            assert expected in error

    @staticmethod
    def test_overlapping_sections_rejected_before_mutation() -> None:
        """Prevent duplicate writes and order-dependent class rejection."""
        image = bytearray(b"LongName\0")
        error = _rejects(
            image,
            ((0, 9), (2, 7)),
            {"LongName": "NewName"},
            require_all=False,
        )
        assert error is not None
        expected = "Overlapping CString"
        assert expected in error

    @staticmethod
    def test_optional_unrecognized_strings_are_unchanged() -> None:
        """Leave unrelated CString names intact in nonlegacy payloads."""
        image = bytearray(b"\xff\0other\0")
        found = rename_class_cstrings(
            image, ((0, len(image)),), {"Absent": "Next"}, require_all=False
        )
        assert found == {}
        expected = b"\xff\0other\0"
        assert image == expected

    @staticmethod
    def test_nonascii_or_embedded_nul_replacement_rejected() -> None:
        """Reject malformed replacement names before mutating any strings."""
        for replacement, diagnostic in (
            ("N\0me", "Invalid replacement"),
            ("Námé", "Non-ASCII replacement"),
        ):
            image = bytearray(b"LongName\0")
            error = _rejects(
                image,
                ((0, len(image)),),
                {"LongName": replacement},
                require_all=True,
            )
            assert error is not None
            assert diagnostic in error
