# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic ABI verifier entrypoint tests without invoking a compiler."""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tempfile
from unittest import TestCase
from unittest import mock

from tools import abi_types
from tools import verify

XCRUN_NAME = "xcrun"
FAKE_XCRUN = "/test-only/xcrun"
FAKE_REPORT = '{"ringRecords": 42, "nativeUUID": "synthetic"}'
VALID_NESTED_REPORT = '{"nested": {"bad": [null, {}]}}'


def _rejects_xcrun(root: Path) -> bool:
    try:
        _ = verify.verify_abi(root)
    except FileNotFoundError as error:
        return XCRUN_NAME in str(error)
    return False


def _rejects_report(root: Path, output: str) -> bool:
    with (
        mock.patch.object(shutil, "which", return_value=FAKE_XCRUN),
        mock.patch.object(subprocess, "run"),
        mock.patch.object(subprocess, "check_output", return_value=output),
    ):
        try:
            _ = verify.verify_abi(root)
        except ValueError:
            return True
        return False


def _rejects_mapping(value: object) -> bool:
    try:
        _ = abi_types.mapping(value)
    except ValueError:
        return True
    return False


def _rejects_json(value: str) -> bool:
    try:
        _ = abi_types.json_object(value)
    except ValueError:
        return True
    return False


class AbiVerifierBoundaryTests(TestCase):
    """Keep source materialization and process dispatch explicitly scoped."""

    @staticmethod
    def test_missing_xcrun_rejects_before_dispatch() -> None:
        """No compiler or fixture process runs when xcrun is unavailable."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=None),
            mock.patch.object(subprocess, "run") as run,
            mock.patch.object(subprocess, "check_output") as output,
        ):
            assert _rejects_xcrun(Path(directory))
            run.assert_not_called()
            output.assert_not_called()

    @staticmethod
    def test_compiler_and_fixture_dispatch_uses_fixed_argv() -> None:
        """Check the exact local fixture, compile argv and structured report."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=FAKE_XCRUN),
            mock.patch.object(subprocess, "run") as run,
            mock.patch.object(
                subprocess, "check_output", return_value=FAKE_REPORT
            ) as output,
        ):
            root = Path(directory).resolve()
            assert verify.verify_abi(root) == {
                "ringRecords": 42,
                "nativeUUID": "synthetic",
            }
            assert (root / "ABIValidation.cpp").read_text(encoding="utf-8") == (
                verify.HOST_SOURCE_FILE.read_text(encoding="utf-8")
            )
            run.assert_called_once_with(
                [
                    FAKE_XCRUN,
                    "clang++",
                    "-std=c++14",
                    "-O1",
                    "-g",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    "-mmacosx-version-min=14.0",
                    "-I",
                    str(verify.ROOT / "SimpleATH"),
                    str(root / "ABIValidation.cpp"),
                    "-framework",
                    "IOKit",
                    "-framework",
                    "CoreFoundation",
                    "-lobjc",
                    "-o",
                    str(root / "ABIValidation"),
                ],
                check=True,
                shell=False,
            )
            output.assert_called_once_with(
                [str(root / "ABIValidation")],
                text=True,
                timeout=60,
                shell=False,
            )

    @staticmethod
    def test_nonobject_and_malformed_reports_fail_closed() -> None:
        """Never treat arbitrary fixture stdout as an ABI report."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assert _rejects_report(root, "[1, 2]")
            assert _rejects_report(root, "{")
            assert not _rejects_report(root, VALID_NESTED_REPORT)

    @staticmethod
    def test_json_decoder_rejects_nonstring_keys_and_too_deep() -> None:
        """Validate the shared typed boundary against Python-only objects."""
        for value in ({1: "value"}, [None], {"data": b"invalid"}):
            assert _rejects_mapping(value)
        deep = '{"depth":' * 66 + "null" + "}" * 66
        assert _rejects_json(deep)
