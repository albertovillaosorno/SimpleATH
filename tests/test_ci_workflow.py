# Copyright (c) 2026 Alberto Villa Osorno.
"""Guard owner-tagged builds and advisory versus strict CI validation."""

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
REQUIRED_VALIDATOR = "python3 -B tools/validate.py --no-cache --stdout-only"
REUSABLE_CI = "uses: ./.github/workflows/ci.yml"
VALIDATE_JOB = "  validate:"
LOG_UPLOAD_CONDITION = "if: always()"
ADVISORY_INPUT = "advisory: true"
ADVISORY_CONTINUE = "continue-on-error: ${{ inputs.advisory == true }}"
STRICT_STANDALONE_DEFAULT = "default: false"
SOURCE_OUTCOME = "steps.source_validation.outcome"
CANCEL_GUARD = "!cancelled()"
VALIDATOR_STDOUT_MODE = "--stdout-only"
VALIDATE_DEPENDENCY = "needs: validate"
REFERENCED_NEEDS = "needs.validate"
HOMEBREW_COMMAND = "brew "
CI_ADVISORY_WARNING_GUARD = "inputs.advisory &&"
CI_ADVISORY_WARNING = "::warning title=Source validation failed::"
PUBLIC_RUNNER_GUARD = "github.event.repository.private == false"
FORBIDDEN_EVENTS = ("pull_request:", "workflow_dispatch:", "schedule:")
CI_REQUIREMENTS = (
    "runs-on: macos-26-intel",
    "python-version: '3.15'",
    "actions/checkout@v7",
    "actions/setup-python@v7",
    "astral-sh/setup-uv@v7",
    "enable-cache: false",
    "uv pip install --system --python python3 --no-cache",
    "--only-binary :all:",
    "clang-format==22.1.8",
    "clang-tidy==22.1.8",
    "ruff==0.17.4",
    "basedpyright==1.40.2",
    "nodejs-wheel-binaries==24.19.0",
    "RUFF_NO_CACHE: '1'",
    "tools/bootstrap_sdk.py",
    "tools/generate_compile_commands.py",
    REQUIRED_VALIDATOR,
)
CI_FORBIDDEN = (
    "tools/validate.py --linux",
    "-target SimpleATH",
    "CODE_SIGNING_ALLOWED",
    "brew update",
    "brew install",
    "report.json",
    "actions/upload-artifact",
)
BUILD_REQUIREMENTS = (
    "startsWith(github.ref, 'refs/tags/build-v')",
    CANCEL_GUARD,
    "runs-on: macos-26-intel",
    "xcodebuild",
    "CODE_SIGNING_ALLOWED=NO",
    "actions/checkout@v7",
    "actions/upload-artifact@v7",
)


class TagGatedCI(unittest.TestCase):
    """Prevent unauthorized builds and silent failed validation."""

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
        assert PUBLIC_RUNNER_GUARD in ci
        # A standalone CI tag fails on strict validator errors, while a
        # reusable owner-tagged build requests advisory status explicitly.
        assert ADVISORY_CONTINUE in ci
        assert STRICT_STANDALONE_DEFAULT in ci
        assert SOURCE_OUTCOME in ci
        assert VALIDATOR_STDOUT_MODE in ci
        assert CI_ADVISORY_WARNING_GUARD in ci
        assert CI_ADVISORY_WARNING in ci
        for forbidden in CI_FORBIDDEN:
            assert forbidden not in ci

    @staticmethod
    def test_build_reports_advisory_validation_without_blocking_xcode() -> None:
        """Keep validation visible, but honor authorized build-v tags."""
        build = BUILD.read_text(encoding="utf-8")
        jobs = build.split("\njobs:\n", maxsplit=1)[1]
        validation, kernel_build = jobs.split("\n  build:\n", maxsplit=1)
        assert VALIDATE_JOB in validation
        assert REUSABLE_CI in validation
        assert ADVISORY_INPUT in validation
        assert PUBLIC_RUNNER_GUARD in validation
        assert PUBLIC_RUNNER_GUARD in kernel_build
        for required in BUILD_REQUIREMENTS:
            assert required in kernel_build
        # CI runs concurrently, not as a dependency of the authorized build.
        assert VALIDATE_DEPENDENCY not in kernel_build
        assert REFERENCED_NEEDS not in kernel_build
        assert HOMEBREW_COMMAND not in kernel_build
        assert (
            LOG_UPLOAD_CONDITION
            in kernel_build.split(
                "- name: Preserve kernel build artifacts", maxsplit=1
            )[1]
        )
