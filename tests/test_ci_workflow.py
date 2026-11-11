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
#   - Offline regression cases for ci workflow.
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
#   - Offline regression cases for ci workflow.
# - Description:
#   - Implements or verifies the test_ci_workflow source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for ci workflow.
"""Guard disjoint tag events, strict CI and native Apple kernel headers."""

from pathlib import Path
import re
import unittest

from tools.build_tag import validate_tag

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github/workflows"
CI = WORKFLOWS / "ci.yml"
BUILD = WORKFLOWS / "build.yml"
RELEASE = WORKFLOWS / "release.yml"
KERNEL_CONFIG = ROOT / "src/platform/Kernel.xcconfig"
CI_CALL = "uses: ./.github/workflows/ci.yml"
RELEASE_GATE = "needs.validate.result == 'success'"
OLD_BUILD_TAG_PATTERN = "build-vYYYY.MM.DD.HH.mm"
FORBIDDEN_EVENTS = ("pull_request:", "workflow_dispatch:", "schedule:")
FORBIDDEN_REFERENCE = (".references/MacKernelSDK", "bootstrap_sdk.py")
TRIGGER_TAG = re.compile(r"(?m)^      - '([^']+)'$")
CI_REQUIREMENTS = (
    "workflow_call:",
    "runs-on: macos-26-intel",
    "astral-sh/setup-uv@v7",
    "enable-cache: false",
    "--only-binary :all:",
    "python3 -B tools/validate.py --no-cache --stdout-only",
    "tools/generate_compile_commands.py",
    "python3 -B -m unittest discover",
    "-s tests -t . -p 'test_*.py' -v",
    "python3 -B tools/check_line_width.py",
    "RUFF_NO_CACHE: '1'",
    "xcrun --sdk macosx --show-sdk-path",
)
CI_FORBIDDEN = (
    "continue-on-error:",
    "advisory:",
    "-target SimpleATH",
    "gh release create",
    "actions/upload-artifact",
    "brew install",
    "brew update",
    "report.json",
    *FORBIDDEN_REFERENCE,
)
BUILD_REQUIREMENTS = (
    "tools/build_tag.py",
    "xcodebuild",
    "CODE_SIGNING_ALLOWED=NO",
    "ARCHS=x86_64",
    "Verify native Apple kernel and C++ headers before Xcode",
    "#include <stddef.h>",
    "#include <stdint.h>",
    "SYSTEM_HEADER_SEARCH_PATHS",
    "KERNEL_FRAMEWORK_HEADERS",
    "python3 -B -m unittest -q tests.test_tahoe_native_sdk_abi",
    "python3 -B -m unittest -q tests.test_tahoe_apple80211_sdk_headers",
    "python3 -B -m unittest -q tests.test_native_metaclass_allocation",
    "actions/upload-artifact@v7",
)
# The Apple kernel header tree must take precedence over macOS usr/include.
BUILD_KERNEL_FIRST_SYNTAX = '-isystem "$builtin" -isystem "$kernel"'
BUILD_KERNEL_FIRST_XCODE = (
    'SYSTEM_HEADER_SEARCH_PATHS="$builtin $kernel $sdk/usr/include"'
)
BUILD_FORBIDDEN = (
    CI_CALL,
    "needs: validate",
    "tools/validate.py",
    "continue-on-error:",
    "gh release create",
    "cxx/cstddef",
    "cxx/cstdint",
    *FORBIDDEN_REFERENCE,
)
RELEASE_REQUIREMENTS = (
    CI_CALL,
    "needs: validate",
    RELEASE_GATE,
    "gh release create",
    "--verify-tag",
    "contents: write",
    "runs-on: ubuntu-latest",
)
RELEASE_FORBIDDEN = (
    "continue-on-error:",
    "xcodebuild",
    "-target SimpleATH",
    *FORBIDDEN_REFERENCE,
)


class WorkflowContract(unittest.TestCase):
    """Never conflate CI, a kext build, and a publishable release."""

    @staticmethod
    def test_only_intended_tag_events_trigger_workflows() -> None:
        """Three disjoint tag families have three disjoint entrypoints."""
        expected = (
            (CI, ("ci", "ci-*")),
            (BUILD, ("build-v*",)),
            (RELEASE, ("release-v*",)),
        )
        for workflow, tags in expected:
            content = workflow.read_text(encoding="utf-8")
            trigger = content.split("\njobs:\n", maxsplit=1)[0]
            assert set(TRIGGER_TAG.findall(trigger)) == set(tags)
            assert not any(event in trigger for event in FORBIDDEN_EVENTS)

    @staticmethod
    def test_ci_is_strict_and_never_builds_or_publishes() -> None:
        """Fail on one finding, missing tool or skipped check."""
        content = CI.read_text(encoding="utf-8")
        for required in CI_REQUIREMENTS:
            assert required in content
        for forbidden in CI_FORBIDDEN:
            assert forbidden not in content

    @staticmethod
    def test_build_never_invokes_ci_or_publishes_release() -> None:
        """Only x86_64 Xcode compilation may follow a CalVer build tag."""
        content = BUILD.read_text(encoding="utf-8")
        for required in BUILD_REQUIREMENTS:
            assert required in content
        for forbidden in BUILD_FORBIDDEN:
            assert forbidden not in content
        first = content.index("Checkout exact authorized commit")
        second = content.index("Enforce authorized CalVer tag")
        preflight = content.index(
            "Test Tahoe ABI inheritance against native Apple SDK"
        )
        private_headers = content.index(
            "Reject unavailable Apple80211 private SDK headers"
        )
        metaclass = content.index(
            "Verify native metaclass allocator signatures and SDK syntax"
        )
        compilation = content.index("Build unsigned x86_64 kernel extension")
        assert (
            first
            < second
            < preflight
            < private_headers
            < metaclass
            < compilation
        )

    @staticmethod
    def test_build_kernel_header_search_never_selects_userspace_first() -> None:
        """Ensure Apple libkern declarations win over SDK _strings.h."""
        content = BUILD.read_text(encoding="utf-8")
        assert BUILD_KERNEL_FIRST_SYNTAX in content
        assert BUILD_KERNEL_FIRST_XCODE in content

    @staticmethod
    def test_release_requires_a_successful_strict_ci_result() -> None:
        """Only a green check on the same tag may publish a release."""
        content = RELEASE.read_text(encoding="utf-8")
        for required in RELEASE_REQUIREMENTS:
            assert required in content
        for forbidden in RELEASE_FORBIDDEN:
            assert forbidden not in content
        assert content.index("  validate:") < content.index("  publish:")

    @staticmethod
    def test_native_config_cannot_include_downloaded_reference_sdk() -> None:
        """Compile only against Apple kernel headers; no copied SDK."""
        config = KERNEL_CONFIG.read_text(encoding="utf-8")
        for required in (
            "KERNEL_EXTENSION_HEADER_SEARCH_PATHS",
            "KERNEL_FRAMEWORK_HEADERS",
            "$(SDKROOT)",
            "-nostdlib",
        ):
            assert required in config
        for forbidden in (".references", "libc++", "c++/v1"):
            assert forbidden not in config


class CalVerBuildTags(unittest.TestCase):
    """Reject old dotted tags and impossible calendar dates."""

    @staticmethod
    def test_only_canonical_timestamp_passes() -> None:
        """Date/time must use YYYY.MMDD.HHmm with numeric zero-padding."""
        assert validate_tag("build-v2026.1110.1555")
        assert validate_tag("build-v2024.0229.2359")
        for invalid in (
            "build-v2026.11.10.15.55",
            "build-v2026.1110.155",
            "build-v2026.1110.15550",
            "build-v2026.1331.1245",
            "build-v2025.0229.1245",
            "build-v2026.1131.0000",
            "build-v2026.1110.2400",
            "build-v2026.1110.2360",
            "build-v2026.1110.1555-extra",
            "release-v2026.1110.1555",
        ):
            assert not validate_tag(invalid)

    @staticmethod
    def test_build_job_does_not_reintroduce_old_tag_contract() -> None:
        """The compiled workflow must refer to the strict parser only."""
        content = BUILD.read_text(encoding="utf-8")
        assert re.search(r"run: python3 -B tools/build_tag.py", content)
        assert OLD_BUILD_TAG_PATTERN not in content
