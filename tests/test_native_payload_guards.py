# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline native profile catalog checks without loading Mach-O images."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING
from unittest import TestCase

if TYPE_CHECKING:
    from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from native_payload import checked_client_profile_rows
from native_payload import checked_system_profile_names
from native_payload import emit_system_profiles
from native_payload import prepare_native_guards
from system_profiles import SYSTEMS

MISSING_PROFILE = "Incomplete native user-client profile catalog"
EMPTY_PROFILES = "Incomplete or reordered native system profile catalog"


def _error(action: Callable[[], object]) -> Exception | None:
    """Return expected input errors from a pure offline operation.

    Returns:
        A caught catalog error, or None on unexpected success.

    """
    try:
        _ = action()
    except (KeyError, ValueError) as error:
        return error
    return None


class NativeProfileCatalogContracts(TestCase):
    """Missing records must never produce a truncated generated C++ table."""

    @staticmethod
    def test_complete_catalog_retains_every_import_and_vtable_size() -> None:
        """Preserve known table order and generated row representation."""
        symbols = [["ctor", "dtor"], ["other"]]
        tables = [["slot0", "slot1"], ["slot0"]]
        indices = {"ctor": 9, "dtor": 10, "other": 11}
        assert checked_client_profile_rows(symbols, tables, indices) == [
            (9, 10, 2),
            (11, 1),
        ]

    def test_missing_parallel_profile_is_rejected(self) -> None:
        """Do not silently truncate a two-class native user-client list."""
        for symbols, tables in (
            ([["ctor"], ["other"]], [["slot0"]]),
            ([["ctor"]], [["slot0"], ["slot1"]]),
            ([], []),
        ):
            with self.subTest(symbols=symbols, tables=tables):
                error = _error(
                    lambda current_symbols=symbols, current_tables=tables: (
                        checked_client_profile_rows(
                            current_symbols,
                            current_tables,
                            {"ctor": 1, "other": 2},
                        )
                    )
                )
                assert isinstance(error, ValueError)
                assert MISSING_PROFILE in str(error)

    @staticmethod
    def test_missing_required_native_index_is_rejected() -> None:
        """Never generate a placeholder for a mandatory class import."""
        error = _error(
            lambda: checked_client_profile_rows(
                [["ctor"], ["other"]], [["slot"], ["slot"]], {"ctor": 1}
            )
        )
        assert isinstance(error, KeyError)
        assert error.args == ("other",)

    @staticmethod
    def test_native_profile_coverage_is_exact_and_ordered() -> None:
        """Prevent missing, duplicated or reordered source profile records."""
        systems = tuple(SYSTEMS)
        checked_system_profile_names(systems)
        for names in (
            [],
            list(systems[:-1]),
            [*systems, systems[0]],
            [*reversed(systems)],
            [*systems[:-1], "Unrecognized"],
        ):
            error = _error(
                lambda current=names: checked_system_profile_names(current)
            )
            assert isinstance(error, ValueError)
            assert EMPTY_PROFILES in str(error)

    @staticmethod
    def test_empty_native_profile_set_is_rejected() -> None:
        """Reject absent sources rather than write a misleading empty table."""
        for action in (
            lambda: prepare_native_guards([]),
            lambda: emit_system_profiles([], {}),
        ):
            error = _error(action)
            assert isinstance(error, ValueError)
            assert EMPTY_PROFILES in str(error)
