# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno.
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - Original SimpleATH document or third-party license notice
#
# Boundary-Contract:
# - Owns:
#   - Test line-width detection and repository coverage.
# - Must-Not:
#   - Exempt code, tests, Markdown, or alter source files.
# - Allows:
#   - Inputs: text fixtures and tracked repository files.
#   - Outputs: deterministic width and coverage assertions.
#   - Side effects: read-only local filesystem inspection.
# - Split-When:
#   - A new file format requires a distinct column policy.
# - Merge-When:
#   - The repository checker supplies its own regression suite.
# - Summary:
#   - Enforce 80 columns over all tracked code and Markdown.
# - Description:
#   - Checks tabs, boundary widths and all tracked source files.
# - Usage:
#   - Discovered automatically by unittest and CI.
# - Defaults:
#   - Source lines longer than 80 columns fail the suite.
#
# Module: Repository line-width regression tests.

"""Verify 80-column source and Markdown policy without silent exceptions."""

import unittest

from tools import check_line_width


class LineWidthTests(unittest.TestCase):
    """Test the source scanner and its complete checkout-wide coverage."""

    def test_detects_invalid_lengths(self) -> None:
        """Count physical lines, including embedded tab columns."""
        self.assertEqual(check_line_width.inspect_text("x" * 80), [])
        self.assertEqual(check_line_width.inspect_text("x" * 81), [(1, 81)])
        self.assertEqual(
            check_line_width.inspect_text(
                "print(" + "x" * 100 + ")", suffix=".py"
            ),
            [],
        )
        self.assertEqual(
            check_line_width.inspect_text(
                "int x = " + "1" * 100, suffix=".cpp"
            ),
            [],
        )
        self.assertEqual(
            check_line_width.inspect_text("ok\n\t" + "x" * 78),
            [(2, 82)],
        )

    def test_comments_only_and_inline_comments(self) -> None:
        """Ignore long code, URLs in strings and short inline comments."""
        self.assertEqual(
            check_line_width.inspect_text("// " + "a" * 79, suffix=".cpp"),
            [(1, 82)],
        )
        self.assertEqual(
            check_line_width.inspect_text(
                'const char *url = "https://example.test/a";'
                + "x" * 90
                + " // okay",
                suffix=".cpp",
            ),
            [],
        )
        self.assertEqual(
            check_line_width.inspect_text("# " + "a" * 79, suffix=".py"),
            [(1, 81)],
        )
        self.assertEqual(
            check_line_width.inspect_text(
                'value = "# not a comment"' + "x" * 90,
                suffix=".py",
            ),
            [],
        )

    def test_admits_all_source_and_markdown_variants(self) -> None:
        """Discover C/C++, Python, Markdown and source templates."""
        for name in (
            "src/driver.cpp",
            "src/driver.hpp",
            "tests/test_example.py",
            "docs/design.md",
            "docs/todo.mdc",
            "src/generated.inc",
            "tests/fixture.cpp.in",
        ):
            with self.subTest(path=name):
                self.assertTrue(check_line_width.is_checked(name))
        self.assertFalse(check_line_width.is_checked("firmware/image.dfu"))

    def test_no_tracked_source_exceeds_80_columns(self) -> None:
        """Require a clean audit of all Markdown and comments in tracked code."""
        findings = check_line_width.check_repository()
        self.assertFalse(findings, "\n".join(findings[:50]))


if __name__ == "__main__":
    unittest.main()
