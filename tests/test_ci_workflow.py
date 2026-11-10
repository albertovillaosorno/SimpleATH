# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Alberto Villa Osorno.
"""Guard explicit-tag GitHub Actions entrypoints and validation-before-build."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github/workflows"
CI = WORKFLOWS / "ci.yml"
BUILD = WORKFLOWS / "build.yml"
CI_TAG = "- 'ci'"
CI_PREFIX_TAG = "- 'ci-*'"
CI_TRIGGER_PATTERN = (
    r"(?m)^on:\n  push:\n    tags:\n"
    r"      - 'ci'\n      - 'ci-\*'\n  workflow_call:"
)
BUILD_TAG = "- 'build-v*'"
REQUIRED_VALIDATOR = "python3 -B tools/validate.py --no-cache"
REUSABLE_CI = "uses: ./.github/workflows/ci.yml"
VALIDATE_JOB = "  validate:"
LOG_UPLOAD_CONDITION = "if: always()"
FORBIDDEN_EVENTS = ("pull_request:", "workflow_dispatch:", "schedule:")
CI_REQUIREMENTS = (
    "runs-on: macos-26-intel",
    "python-version: '3.15'",
    "actions/checkout@v7",
    "actions/setup-python@v7",
    "actions/upload-artifact@v7",
    "brew install llvm ruff basedpyright",
    "tools/bootstrap_sdk.py",
    "tools/generate_compile_commands.py",
    REQUIRED_VALIDATOR,
)
CI_FORBIDDEN = (
    "tools/validate.py --linux",
    "-target SimpleATH",
    "CODE_SIGNING_ALLOWED",
)
BUILD_REQUIREMENTS = (
    "needs: validate",
    "needs.validate.result == 'success'",
    "startsWith(github.ref, 'refs/tags/build-v')",
    "runs-on: macos-26-intel",
    "xcodebuild",
    "CODE_SIGNING_ALLOWED=NO",
    "actions/checkout@v7",
    "actions/upload-artifact@v7",
)


class TagGatedCI(unittest.TestCase):
    """Prevent accidental builds on ordinary pushes or failed validation."""

    @staticmethod
    def test_only_explicit_ci_and_release_tags_trigger_workflows() -> None:
        """Keep CI-only tags separate from owner-authorized build tags."""
        ci = CI.read_text(encoding="utf-8")
        build = BUILD.read_text(encoding="utf-8")
        assert re.search(
            CI_TRIGGER_PATTERN,
            ci,
        )
        assert re.search(
            r"(?m)^on:\n  push:\n    tags:\n      - 'build-v\*'\n",
            build,
        )
        for content in (ci, build):
            for event in FORBIDDEN_EVENTS:
                assert event not in content
        assert CI_TAG in ci
        assert CI_PREFIX_TAG in ci
        assert BUILD_TAG in build
        assert BUILD_TAG not in ci
        assert CI_TAG not in build
        assert CI_PREFIX_TAG not in build

    @staticmethod
    def test_ci_has_mandatory_full_macos_validation_without_build() -> None:
        """No CI-only tag may compile a kernel extension."""
        ci = CI.read_text(encoding="utf-8")
        for required in CI_REQUIREMENTS:
            assert required in ci
        for forbidden in CI_FORBIDDEN:
            assert forbidden not in ci

    @staticmethod
    def test_build_requires_completed_reusable_validation_job() -> None:
        """A failed, canceled or skipped validator blocks Xcode builds."""
        build = BUILD.read_text(encoding="utf-8")
        jobs = build.split("\njobs:\n", maxsplit=1)[1]
        validation, kernel_build = jobs.split("\n  build:\n", maxsplit=1)
        assert VALIDATE_JOB in validation
        assert REUSABLE_CI in validation
        for required in BUILD_REQUIREMENTS:
            assert required in kernel_build
        assert (
            LOG_UPLOAD_CONDITION
            in kernel_build.split(
                "- name: Preserve kernel build artifacts", maxsplit=1
            )[1]
        )
