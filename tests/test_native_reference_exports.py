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
#   - Offline regression cases for native reference exports.
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
#   - Offline regression cases for native reference exports.
# - Description:
#   - Implements or verifies the test_native_reference_exports source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native reference exports.
"""Pure export-reader factory checks; do not generate native ABI snapshots."""

from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest import mock

from tools import native_references as references

SYNTHETIC_COLLECTION = Path("/synthetic/collection.kc")


def _factory_rejected(module: SimpleNamespace) -> bool:
    """Exercise only factory dispatch with a fake imported module.

    Returns:
        True when an absent or malformed export reader fails closed.

    """
    with mock.patch("importlib.import_module", return_value=module):
        try:
            _ = references.open_export_collection(SYNTHETIC_COLLECTION)
        except TypeError:
            return True
    return False


class NativeReferenceExportTests(TestCase):
    """Require typed, duck-checked reader operations at the export boundary."""

    @staticmethod
    def test_valid_reader_is_selected_without_opening_native_binaries() -> None:
        """Dispatch to a fake checked collection without any file access."""
        reader = SimpleNamespace(
            root=SimpleNamespace(uuid="synthetic"),
            images={},
            pointer=mock.Mock(return_value=0),
            version=mock.Mock(return_value="synthetic"),
            close=mock.Mock(),
        )
        factory = mock.Mock(return_value=reader)
        module = SimpleNamespace(KernelCollection=factory)
        with mock.patch(
            "importlib.import_module", return_value=module
        ) as loader:
            result = references.open_export_collection(SYNTHETIC_COLLECTION)
        assert result is reader
        factory.assert_called_once_with(SYNTHETIC_COLLECTION)
        loader.assert_called_once_with("tools.kernel_collection")

    @staticmethod
    def test_missing_factory_or_unchecked_interface_is_rejected() -> None:
        """Never trust an import that lacks the required reader methods."""
        assert _factory_rejected(SimpleNamespace(KernelCollection=None))
        bad = SimpleNamespace(KernelCollection=mock.Mock(return_value=object()))
        assert _factory_rejected(bad)
