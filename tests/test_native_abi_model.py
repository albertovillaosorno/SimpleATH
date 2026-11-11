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
#   - Offline regression cases for native abi model.
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
#   - Offline regression cases for native abi model.
# - Description:
#   - Implements or verifies the test_native_abi_model source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native abi model.
"""Synthetic ABI view mapping regressions, without real image dependencies."""

from typing import final
from unittest import TestCase
from unittest import mock

from tools import native_abi

PARENT = "SyntheticParent"
CHILD = "SyntheticChild"
OLD_METHODS = ["first", "removed", "second"]
NATIVE_METHODS = ["first", "second"]
CHILD_METHODS = ["first", "second", "second", "extra"]
VIRTUAL_SLOT_BYTES = native_abi.VTABLE_SLOT_BYTES


@final
class _Image:
    """Provide just the labels and exported names used by the ABI mapper."""

    def __init__(self, label: str, exported: dict[str, int]) -> None:
        """Capture an immutable synthetic symbol inventory."""
        self.label: str = label
        self.names: dict[str, tuple[str, int, int, int, int]] = {
            name: (name, 15, 1, 0, address)
            for name, address in exported.items()
        }

    def defined(self) -> set[str]:
        """Return the synthetic export catalog.

        Returns:
            Exported name set from this fake image.

        """
        return set(self.names)


def _model() -> native_abi.NativeModel:
    """Construct an uninitialized model with explicit in-memory catalogs.

    Returns:
        A source-free model with all mapping outputs set to empty.

    """
    model = object.__new__(native_abi.NativeModel)
    # These synthetic sources intentionally omit Mach's real mmap contract.
    for label in ("old", "native", "kernel"):
        setattr(model, label, _Image(label, {}))
    image_catalog_attribute = "images"
    setattr(
        model,
        image_catalog_attribute,
        {
            "Legacy": _Image("Legacy", {"second": 0x1234, "extra": 0x4567}),
            "BrcmTahoe": _Image("BrcmTahoe", {}),
        },
    )
    model.old_tables = {}
    model.new_tables = {}
    model.old_views = {}
    model.tables = {}
    model.holes = []
    return model


class NativeModelSlotMappingTests(TestCase):
    """Preserve the original physical/legacy slot mapping algorithm."""

    @staticmethod
    def test_native_holes_and_inherited_overrides() -> None:
        """Keep missing, inherited and new legacy slots distinct."""
        model = _model()
        catalogs = {
            ("old", PARENT): OLD_METHODS,
            ("native", PARENT): NATIVE_METHODS,
            ("BrcmTahoe", CHILD): CHILD_METHODS,
        }

        def fake_table(
            image: _Image, cls: str, _kernel: object = None
        ) -> list[str]:
            """Return named synthetic slots without opening a Mach-O image.

            Returns:
                A fixed list of method names for each synthetic image.

            """
            _ = _kernel
            return catalogs[image.label, cls]

        with (
            mock.patch.object(native_abi, "table", side_effect=fake_table),
            mock.patch.object(native_abi, "method_key", side_effect=str),
        ):
            model._map_native_class(PARENT)  # ruff: ignore[private-member-access]  # pyright: ignore[reportPrivateUsage]
            model._map_legacy_class("BrcmTahoe", CHILD, PARENT)  # ruff: ignore[private-member-access]  # pyright: ignore[reportPrivateUsage]
        assert model.holes == [(PARENT, VIRTUAL_SLOT_BYTES, "removed")]
        assert model.old_views[PARENT] == [
            ("native", PARENT, 0),
            ("absent", "removed", 0),
            ("native", PARENT, VIRTUAL_SLOT_BYTES),
        ]
        assert model.new_tables[CHILD] == ["first", "second", "extra"]
        assert model.tables[CHILD] == [
            ("native", PARENT, 0),
            ("Legacy", "second", 0x1234),
            ("Legacy", "extra", 0x4567),
        ]
        assert model.old_views[CHILD] == [
            model.old_views[PARENT][0],
            ("Legacy", "second", 0x1234),
            model.old_views[PARENT][2],
            ("Legacy", "extra", 0x4567),
        ]

    def test_unmappable_legacy_override_rejects(self) -> None:
        """Do not silently rewrite an older superclass slot without a match."""
        model = _model()
        catalogs = {
            ("old", PARENT): OLD_METHODS,
            ("native", PARENT): NATIVE_METHODS,
            ("BrcmTahoe", CHILD): ["first", "unmapped", "second"],
        }
        image_symbols = "names"
        setattr(
            model.images["BrcmTahoe"],
            image_symbols,
            {"unmapped": ("unmapped", 15, 1, 0, 0x8888)},
        )

        def fake_table(
            image: _Image, cls: str, _kernel: object = None
        ) -> list[str]:
            """Return synthetic slots for the negative override case.

            Returns:
                Method names for the requested image and class.

            """
            _ = _kernel
            return catalogs[image.label, cls]

        with (
            mock.patch.object(native_abi, "table", side_effect=fake_table),
            mock.patch.object(native_abi, "method_key", side_effect=str),
        ):
            model._map_native_class(PARENT)  # ruff: ignore[private-member-access]  # pyright: ignore[reportPrivateUsage]
            # Keep this regression in the standard-library unittest suite.
            with self.assertRaisesRegex(  # ruff: ignore[pytest-unittest-raises-assertion]
                ValueError, "Unmapped override"
            ):
                model._map_legacy_class("BrcmTahoe", CHILD, PARENT)  # ruff: ignore[private-member-access]  # pyright: ignore[reportPrivateUsage]
        assert CHILD not in model.tables
