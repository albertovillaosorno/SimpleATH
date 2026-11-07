# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Fake-only forwarding ABI fixture tests; never invoke a Darwin compiler."""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tempfile
from typing import TYPE_CHECKING
from unittest import TestCase
from unittest import mock

from tools import native_forwarding_probe as probe

if TYPE_CHECKING:
    from collections.abc import Callable

FAKE_XCRUN = "/offline-fixture/xcrun"
ASSEMBLY = ".globl _athSkyForward0\n"
EXPECTED_CALLS = 12
EXPECT_FORWARD0 = 'extern "C" void athSkyForward0();'
EXPECT_CALLBACK1 = 'extern "C" void athSkyCallback1();'
EXPECT_FORWARD_PTR = "reinterpret_cast<uintptr_t>(athSkyForward1)"
GOOD_OUTPUT = (
    '{"forwardingCalls":12,"retainedReceivers":4,"releasedReceivers":4}'
)


def _reject(action: Callable[[], object]) -> bool:
    try:
        _ = action()
    except ValueError, FileNotFoundError:
        return True
    return False


class NativeForwardingProbeTests(TestCase):
    """Keep template generation deterministic and compiler dispatch opt-in."""

    @staticmethod
    def test_checked_template_replaces_every_exact_placeholder() -> None:
        """Render two methods with their expected forwarding symbols."""
        source = probe.render_fixture(2)
        assert EXPECT_FORWARD0 in source
        assert EXPECT_CALLBACK1 in source
        assert EXPECT_FORWARD_PTR in source
        for token in (probe.DECLARATIONS, probe.FORWARDERS, probe.CALLBACKS):
            assert token not in source

    @staticmethod
    def test_missing_duplicate_or_changed_template_rejects() -> None:
        """Never silently compile partial fixture placeholders."""
        with mock.patch.object(
            Path, "read_text", return_value="bad @FORWARDERS@"
        ):
            assert _reject(lambda: probe.render_fixture(2))
        with mock.patch.object(
            Path,
            "read_text",
            return_value="@DECLARATIONS@@DECLARATIONS@@FORWARDERS@@CALLBACKS@",
        ):
            assert _reject(lambda: probe.render_fixture(2))
        for count in (0, -1, probe.MAX_FORWARDERS + 1):
            assert _reject(lambda count=count: probe.render_fixture(count))

    @staticmethod
    def test_missing_toolchain_never_launches_or_writes() -> None:
        """A missing local macOS tool is not misreported as a pass."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=None),
            mock.patch.object(subprocess, "run") as launch,
            mock.patch.object(subprocess, "check_output") as executable,
        ):
            root = Path(directory)
            assert _reject(lambda: probe.run_probe(root, ASSEMBLY, 2))
            assert list(root.iterdir()) == []
            launch.assert_not_called()
            executable.assert_not_called()

    @staticmethod
    def test_compiler_dispatch_is_fixed_and_bounded() -> None:
        """Check fixed argv and bounded timeouts without a shell."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=FAKE_XCRUN),
            mock.patch.object(subprocess, "run") as launch,
            mock.patch.object(
                subprocess, "check_output", return_value=GOOD_OUTPUT
            ) as executable,
        ):
            root = Path(directory)
            assert (
                probe.run_probe(root, ASSEMBLY, 2)["forwardingCalls"]
                == EXPECTED_CALLS
            )
            assert (root / "Forwarding.S").read_text() == (
                ".section __TEXT,__text\n" + ASSEMBLY
            )
            assert (root / "ForwardingValidation.cpp").read_text() == (
                probe.render_fixture(2)
            )
            launch.assert_called_once_with(
                [
                    FAKE_XCRUN,
                    "clang++",
                    "-std=c++14",
                    "-O1",
                    "-UNDEBUG",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    str(root / "ForwardingValidation.cpp"),
                    str(root / "Forwarding.S"),
                    "-o",
                    str(root / "forwarding"),
                ],
                check=True,
                shell=False,
                timeout=120,
            )
            executable.assert_called_once_with(
                [str(root / "forwarding")],
                text=True,
                shell=False,
                timeout=60,
            )

    @staticmethod
    def test_malformed_or_inconsistent_reports_fail_closed() -> None:
        """Reject missing calls, bogus JSON, boolean counts and leaked refs."""
        for output in (
            "[]",
            "{",
            "{}",
            '{"forwardingCalls":true,"retainedReceivers":4,"releasedReceivers":4}',
            '{"forwardingCalls":11,"retainedReceivers":4,"releasedReceivers":4}',
            '{"forwardingCalls":12,"retainedReceivers":4,"releasedReceivers":3}',
            '{"forwardingCalls":12,"retainedReceivers":3,"releasedReceivers":3}',
        ):
            assert _reject(
                lambda output=output: probe.checked_counts(output, 2)
            )
        assert probe.checked_counts(GOOD_OUTPUT, 2) == {
            "forwardingCalls": 12,
            "retainedReceivers": 4,
            "releasedReceivers": 4,
        }

    @staticmethod
    def test_missing_folder_or_source_rejects_prelaunch() -> None:
        """Reject absent assembly/folder and excessive method bounds early."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assert _reject(
                lambda: probe.run_probe(root / "absent", ASSEMBLY, 2)
            )
            assert _reject(lambda: probe.run_probe(root, "", 2))
            assert _reject(
                lambda: probe.run_probe(
                    root, ASSEMBLY, probe.MAX_FORWARDERS + 1
                )
            )
