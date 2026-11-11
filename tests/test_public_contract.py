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
#   - Offline regression cases for public contract.
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
#   - Offline regression cases for public contract.
# - Description:
#   - Implements or verifies the test_public_contract source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for public contract.

"""Offline regression checks for public code header and history contracts."""

import unittest
from tools import public_contract


class PublicContractTests(unittest.TestCase):
    def test_header_rejects_unlicensed_code(self) -> None:
        entry = {"license": "MIT", "license_file": "LICENSE-MIT"}
        findings = public_contract.verify_header(
            "tools/new.py", "# private\n", entry
        )
        self.assertTrue(findings)

    def test_history_rejects_subject_without_scope(self) -> None:
        findings = public_contract.inspect_commit(
            b"Add something\n\nNothing.\n", False
        )
        self.assertTrue(findings)

    def test_history_accepts_complete_example(self) -> None:
        body = b"feat(wifi): validate the staged station input\n\nReject malformed station input before device state is touched. Preserve\nrepeatable source-only validation and return an explicit error to callers.\n\nSigned-off-by: Alberto Villa Osorno <300648727+albertovillaosorno@users.noreply.github.com>\n"
        self.assertEqual(public_contract.inspect_commit(body, False), [])

    def test_path_hygiene_detects_user_home(self) -> None:
        value = ("/" + "home/someone/Developer/experimental/driver").encode()
        self.assertIsNotNone(public_contract.PERSONAL_PATH.search(value))


if __name__ == "__main__":
    unittest.main()
