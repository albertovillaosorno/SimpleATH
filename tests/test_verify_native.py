# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Fake-only forwarding ABI fixture tests; never invoke a Darwin compiler."""

import ast
import os
from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tempfile
from typing import TYPE_CHECKING
from unittest import TestCase
from unittest import mock

from tools import native_forwarding_probe as probe
from tools.native_invariants import MAX_NATIVE_ARTIFACT_BYTES
from tools.native_invariants import read_native_artifact
from tools.native_invariants import reconstruct_payload_image
from tools.native_invariants import require

if TYPE_CHECKING:
    from collections.abc import Callable

FAKE_XCRUN = "/offline-fixture/xcrun"
ASSEMBLY = ".globl _athSkyForward0\n"
EXPECTED_CALLS = 12
EXPECT_FORWARD0 = 'extern "C" void athSkyForward0();'
EXPECT_CALLBACK1 = 'extern "C" void athSkyCallback1();'
EXPECT_FORWARD_PTR = "reinterpret_cast<uintptr_t>(athSkyForward1)"
EXPECTED_ABI_GUARDS = 52
EXPECTED_RECONSTRUCTED_PAYLOAD = b"\x00ab\x00cd\x00"
REQUIRE_FUNCTION = "require"
RAW_READ_METHOD = "read_bytes"
CHECKED_READ_FUNCTION = "read_native_artifact"
RECONSTRUCT_FUNCTION = "reconstruct_payload_image"
MIN_BOUNDED_READS = 5
FAILURE_MARKER = "synthetic failed"
GOOD_OUTPUT = (
    '{"forwardingCalls":12,"retainedReceivers":4,"releasedReceivers":4}'
)


def _reject(action: Callable[[], object]) -> bool:
    try:
        _ = action()
    except ValueError, OSError:
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


class NativeAbiInvariantTests(TestCase):
    """Prevent Python optimization from silently disabling ABI validation."""

    @staticmethod
    def test_all_verifier_asserts_are_explicit_guards() -> None:
        """Keep every native verification check active under Python -O."""
        source = Path(__file__).parent.parent / "tools/verify_native.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        assert not any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        guards = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == REQUIRE_FUNCTION
        ]
        assert len(guards) == EXPECTED_ABI_GUARDS

    @staticmethod
    def test_all_generated_binary_reads_have_bounded_preflight() -> None:
        """Keep generated payload reads on the nofollow artifact boundary."""
        source = Path(__file__).parent.parent / "tools/verify_native.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        calls = [
            node.func for node in ast.walk(tree) if isinstance(node, ast.Call)
        ]
        assert not any(
            isinstance(callee, ast.Attribute) and callee.attr == RAW_READ_METHOD
            for callee in calls
        )
        assert (
            sum(
                isinstance(callee, ast.Name)
                and callee.id == CHECKED_READ_FUNCTION
                for callee in calls
            )
            >= MIN_BOUNDED_READS
        )
        assert any(
            isinstance(callee, ast.Name) and callee.id == RECONSTRUCT_FUNCTION
            for callee in calls
        )

    @staticmethod
    def test_invariant_guard_rejects_false_or_nonboolean_truthy() -> None:
        """Reject false checks and malformed truthy manifest metadata."""
        verified = True
        assert require(verified, "synthetic verified") is None
        invalid: tuple[object, ...] = (
            False,
            None,
            1,
            "true",
            [0],
            {"fake": True},
            0,
        )
        errors: list[str] = []
        for condition in invalid:
            try:
                require(condition, FAILURE_MARKER)
            except ValueError as error:
                errors.append(str(error))
            else:
                errors.append("Accepted malformed native ABI condition")
        assert len(errors) == len(invalid)
        assert all(FAILURE_MARKER in error for error in errors)


class NativePayloadReconstructionTests(TestCase):
    """Rebuild binary regions only after bounded segment validation."""

    @staticmethod
    def test_in_bounds_segments_reconstruct_with_zero_gaps() -> None:
        """Preserve file bytes and zero-fill gaps in an exact-length image."""
        payload = reconstruct_payload_image(
            7, [(1, 0, 2), (4, 3, 2)], b"Xab0cd", base=1
        )
        assert payload == EXPECTED_RECONSTRUCTED_PAYLOAD

    @staticmethod
    def test_invalid_manifest_sizes_rejected_before_allocation() -> None:
        """Reject bool, missing, zero, negative, and oversized dimensions."""
        values: tuple[object, ...] = (
            None,
            True,
            "4",
            0,
            -1,
            MAX_NATIVE_ARTIFACT_BYTES + 1,
        )
        for size in values:
            assert _reject(
                lambda size=size: reconstruct_payload_image(size, [], b"abcd")
            )

    @staticmethod
    def test_source_and_target_span_errors_are_fatal() -> None:
        """Reject underflow, length overflow, truncated data and bad bases."""
        bad_segments = (
            (-1, 0, 1),
            (0, -1, 1),
            (0, 0, -1),
            (6, 0, 1),
            (0, 4, 1),
            (5, 0, 2),
        )
        for segment in bad_segments:
            assert _reject(
                lambda segment=segment: reconstruct_payload_image(
                    6, [segment], b"abcd"
                )
            )
        assert _reject(
            lambda: reconstruct_payload_image(6, [], b"abcd", base=-1)
        )
        assert _reject(
            lambda: reconstruct_payload_image(6, [], b"abcd", base=5)
        )
        assert _reject(
            lambda: reconstruct_payload_image(6, [(0, -1, 1)], b"abcd", base=2)
        )


class NativeArtifactReadTests(TestCase):
    """Artifact verification refuses unsafe disk input before binary checks."""

    @staticmethod
    def test_regular_product_is_read_exactly() -> None:
        """Preserve all bytes of a synthetic native product."""
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "product.bin"
            source = b"\x00\x01\xfe\xffnative"
            _ = product.write_bytes(source)
            assert read_native_artifact(product) == source

    @staticmethod
    def test_symlink_fifo_and_empty_source_are_refused() -> None:
        """Never follow a link or block on a named pipe."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "real.bin"
            _ = source.write_bytes(b"real")
            (root / "link.bin").symlink_to(source)
            fifo = root / "fifo.bin"
            os.mkfifo(fifo)
            empty = root / "empty.bin"
            _ = empty.write_bytes(b"")
            for path in (root / "link.bin", fifo, empty):
                assert _reject(lambda path=path: read_native_artifact(path))

    @staticmethod
    def test_oversize_sparse_artifact_is_refused_without_reading() -> None:
        """Reject a huge synthetic artifact from its metadata alone."""
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "oversized.bin"
            _ = product.write_bytes(b"a")
            os.truncate(product, MAX_NATIVE_ARTIFACT_BYTES + 1)
            assert _reject(lambda: read_native_artifact(product))
