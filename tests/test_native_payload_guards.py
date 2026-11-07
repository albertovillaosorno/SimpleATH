# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline native profile catalog checks without loading Mach-O images."""

from __future__ import annotations

from functools import partial
from pathlib import Path
import sys
from typing import TYPE_CHECKING
from unittest import TestCase

if TYPE_CHECKING:
    from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from native_payload import CLIENT_CLASSES
from native_payload import SkywalkPlan
from native_payload import checked_client_profile_rows
from native_payload import checked_system_profile_names
from native_payload import emit_system_profiles
from native_payload import native_client_symbols
from native_payload import prepare_native_guards
from system_profiles import SYSTEMS

MISSING_PROFILE = "Incomplete native user-client profile catalog"
EMPTY_PROFILES = "Incomplete or reordered native system profile catalog"
MISSING_GUARDS = "Native ABI guards were not prepared"
MALFORMED_CATALOG = "Malformed native user-client symbol or vtable catalog"


def _valid_clients() -> tuple[list[list[str]], list[list[str]], dict[str, int]]:
    """Build complete and ordered fake client exports without source images.

    Returns:
        Mangled client symbols, synthetic vtables and native import indices.

    """
    symbols = [native_client_symbols(cls) for cls in CLIENT_CLASSES]
    tables = [["slot0", "slot1"], ["slot0"]]
    indices = {
        name: index + 9
        for index, name in enumerate(
            name for group in symbols for name in group
        )
    }
    return symbols, tables, indices


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
        symbols, tables, indices = _valid_clients()
        assert checked_client_profile_rows(symbols, tables, indices) == [
            (9, 10, 11, 12, 13, 2),
            (14, 15, 16, 17, 18, 1),
        ]

    def test_missing_parallel_profile_is_rejected(self) -> None:
        """Do not silently truncate a two-class native user-client list."""
        valid_symbols, valid_tables, indices = _valid_clients()
        for symbols, tables in (
            (valid_symbols, valid_tables[:-1]),
            (valid_symbols[:-1], valid_tables),
            ([], []),
        ):
            with self.subTest(symbols=symbols, tables=tables):
                error = _error(
                    lambda current_symbols=symbols, current_tables=tables: (
                        checked_client_profile_rows(
                            current_symbols,
                            current_tables,
                            indices,
                        )
                    )
                )
                assert isinstance(error, ValueError)
                assert MISSING_PROFILE in str(error)

    @staticmethod
    def test_missing_required_native_index_is_rejected() -> None:
        """Never generate a placeholder for a mandatory class import."""
        symbols, tables, indices = _valid_clients()
        missing = symbols[1][-1]
        del indices[missing]
        error = _error(
            lambda: checked_client_profile_rows(symbols, tables, indices)
        )
        assert isinstance(error, KeyError)
        assert error.args == (missing,)

    @staticmethod
    def test_incomplete_native_class_symbols_and_vtable_are_rejected() -> None:
        """Refuse malformed rows even when both profile counts match."""
        symbols, tables, indices = _valid_clients()
        for altered_symbols, altered_tables in (
            ([symbols[0][:-1], symbols[1]], tables),
            ([list(reversed(symbols[0])), symbols[1]], tables),
            (symbols, [[], tables[1]]),
        ):
            error = _error(
                partial(
                    checked_client_profile_rows,
                    altered_symbols,
                    altered_tables,
                    indices,
                )
            )
            assert isinstance(error, ValueError)
            assert MALFORMED_CATALOG in str(error)

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
    def test_unprepared_guard_tables_cannot_be_emitted() -> None:
        """No C++ metadata may be written before all source guards pass."""
        plans: list[SkywalkPlan] = []
        for system in SYSTEMS:
            # Skip image loading; the preflight must reject before using it.
            plan = object.__new__(SkywalkPlan)
            plan.system = system
            plan.guards_ready = False
            plans.append(plan)
        error = _error(lambda: emit_system_profiles(plans, {}))
        assert isinstance(error, ValueError)
        assert MISSING_GUARDS in str(error)
        error = _error(lambda: plans[0].emit({}))
        assert isinstance(error, ValueError)
        assert MISSING_GUARDS in str(error)

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
