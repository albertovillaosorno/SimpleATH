# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic payload generation without an SDK, device or kext build."""

from __future__ import annotations

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import final
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from abi_types import json_object
import embed
from embed import LABELS
from embed import LABEL_AIRPORT
from embed import LABEL_AIRPORT_ORIGINAL

if TYPE_CHECKING:
    from embed import CommandLayout

MAPPED_SIZE = 512
MAPPED_KMOD = 4
EXPECTED_PAYLOADS = 3
EXPECTED_NATIVE_IMPORTS = 2
STORAGE_DELTA = "delta"
SOURCE_PLIST = b"SYNTHETIC"


@final
class _FakePlan:
    """Synthetic native adapter that emits no executable kernel code."""

    def __init__(self, system: str) -> None:
        self.system = system
        self.vtable_guards = {"vtable": 8}
        self.class_guards = {"class": 12}
        self.unchecked_overrides: list[str] = []
        self.link_bytes = b"\x01\x02"
        self.link_mask = b"\xff\x00"
        self.link_references = ["reference"]

    @staticmethod
    def manifest() -> dict[str, object]:
        """Return the same required adapter keys as a real profile.

        Returns:
            Fake profile metadata, including a retained custom key.

        """
        return dict.fromkeys(
            (
                "system",
                "kernel",
                "build",
                "nativeUUID",
                "wirelessUUID",
                "ethernetSize",
                "poolSize",
                "nativeSlotCount",
                "ethernetLinkSymbol",
                "ethernetLinkSlot",
                "airPortPayloadIndex",
                "customEvidence",
            ),
            "synthetic",
        )

    @staticmethod
    def namespace_payload(label: str, data: bytearray) -> dict[str, list[int]]:
        """Mark test image bytes and return class-string evidence.

        Returns:
            Deterministic fake class-string offsets.

        """
        data[2] = 42 if label == LABEL_AIRPORT else 18
        return {"SyntheticClass": [2, 4]}

    @staticmethod
    def emit(native: dict[str, int]) -> tuple[list[str], list[str]]:
        """Provide inert source declarations for the generator.

        Returns:
            One C++ comment and one assembly directive.

        """
        return [f"// synthetic Skywalk imports {len(native)}"], [
            ".quad _synthetic"
        ]


@final
class _FakeImage:
    """A source-backed image with synthetic, non-Mach-O byte contents."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segments: list[tuple[str, int, int, int, int]] = []
        self.symbols = {"_kmod_info": MAPPED_KMOD, "_entry": 40, "_version": 52}


def _synthetic_plist(
    data: bytes,
) -> tuple[dict[str, object], str, dict[str, str]]:
    """Supply checked bundle dependencies, retaining a binary value.

    Returns:
        Separate metadata for each source image.

    """
    assert data == SOURCE_PLIST
    return (
        {"CFBundleIdentifier": "test.native", "BinaryData": b"\x00\xff"},
        "test.native",
        {"system.library": "1"},
    )


def _synthetic_expanded(layout: CommandLayout) -> tuple[bytearray, list[int]]:
    """Map synthetic bytes without examining or invoking native payloads.

    Returns:
        Complete fake VM image and defined symbol-value locations.

    """
    data = bytearray(MAPPED_SIZE)
    data[0] = layout.image.data[0]
    data[4] = 11
    return data, [8, 24]


def _synthetic_images(root: Path) -> dict[str, Path]:
    """Create non-executable source files used only by patched generator.

    Returns:
        Label-to-path lookup for synthetic bundle source files.

    """
    images: dict[str, Path] = {}
    for label in LABELS:
        binary = root / label / "Contents" / "MacOS" / "dummy"
        binary.parent.mkdir(parents=True)
        _ = binary.write_bytes(label.encode())
        _ = (binary.parent.parent / "Info.plist").write_bytes(SOURCE_PLIST)
        images[label] = binary
    return images


class EmbeddedSourceGenerationTests(TestCase):
    """Source emission must preserve the exact ordering and delta metadata."""

    @staticmethod
    def test_synthetic_full_delta_output_without_native_build() -> None:
        """Emit three fake payloads without touching actual native inputs."""
        with TemporaryDirectory(prefix="simpleath-embed-test-") as name:
            root = Path(name)
            output = root / "output"
            with patch.multiple(
                embed,
                OUTPUT=output,
                IMAGES=_synthetic_images(root),
                SYSTEMS=["first", "last"],
                SYMBOLS={label: {"_entry"} for label in LABELS},
                HARDWARE_VERSION_SYMBOL="_version",
                SkywalkPlan=_FakePlan,
                Image=_FakeImage,
                validate_payloads=Mock(),
                _require_shared_profiles=Mock(),
                parse=Mock(return_value=([], [])),
                checked_dysymtab_fields=Mock(return_value=(0,) * 18),
                checked_payload_size=Mock(return_value=MAPPED_SIZE),
                _native_import_catalog=Mock(
                    return_value=(
                        ["_method", "_vtable"],
                        {("_vtable", 8, "_method")},
                    )
                ),
                checked_info_plist=Mock(side_effect=_synthetic_plist),
                image_relocations=Mock(
                    return_value=(
                        [(20, 4, 0, 0, 8)],
                        0,
                    )
                ),
                expanded_legacy_image=Mock(side_effect=_synthetic_expanded),
                route_prefixes=Mock(return_value=[(24, 16)]),
                emit_system_profiles=Mock(
                    return_value=["// synthetic profiles"]
                ),
            ):
                embed.generate()
            EmbeddedSourceGenerationTests._check_generated(output)

    @staticmethod
    def _check_generated(output: Path) -> None:
        """Assert generated manifest and source contain all fake records."""
        raw_manifest = json_object((output / "manifest.json").read_text())
        assert _is_string_dictionary(raw_manifest)
        payloads = raw_manifest["payloads"]
        assert _is_dictionary_list(payloads)
        imports = raw_manifest["nativeImports"]
        assert _is_object_list(imports)
        assert len(payloads) == EXPECTED_PAYLOADS
        assert len(imports) == EXPECTED_NATIVE_IMPORTS
        storage_summary = raw_manifest["payloadStorage"]
        assert _is_string_dictionary(storage_summary)
        assert (
            storage_summary["expandedBytes"] == EXPECTED_PAYLOADS * MAPPED_SIZE
        )
        EmbeddedSourceGenerationTests._check_payloads(output, payloads)
        EmbeddedSourceGenerationTests._check_source(output)

    @staticmethod
    def _check_payloads(
        output: Path, payloads: list[dict[str, object]]
    ) -> None:
        """Ensure a shared base is reported for the synthetic AirPort delta."""
        storage = [entry["storage"] for entry in payloads]
        assert all(_is_string_dictionary(entry) for entry in storage)
        base, original, derived = storage
        assert _is_string_dictionary(base)
        assert _is_string_dictionary(original)
        assert _is_string_dictionary(derived)
        assert derived["kind"] == STORAGE_DELTA
        assert derived["base"] == LABEL_AIRPORT_ORIGINAL
        assert (output / "AirPort.delta").read_bytes()
        base_tables, original_tables = base["tables"], original["tables"]
        assert _is_object_list(base_tables)
        assert _is_object_list(original_tables)
        assert base_tables[0] == original_tables[0]

    @staticmethod
    def _check_source(output: Path) -> None:
        """Check once-only table interning and native symbol source records."""
        cpp = (output / "Payloads.cpp").read_text()
        assembly = (output / "Payloads.S").read_text()
        assert cpp.count("static const Relocation relocs0[]") == 1
        payload_marker = "const Payload payloads[3]"
        guards_marker = "const NativeVtableGuard nativeVtableGuards[]"
        imports_marker = "_athNativeImports:"
        assert payload_marker in cpp
        assert guards_marker in cpp
        assert imports_marker in assembly


def _is_object_dictionary(value: object) -> TypeIs[dict[object, object]]:
    """Check mapping shape without assuming key or value types.

    Returns:
        True for dictionary values.

    """
    return isinstance(value, dict)


def _is_string_dictionary(value: object) -> TypeIs[dict[str, object]]:
    """Check keys before inspecting decoded JSON dictionaries.

    Returns:
        True only for dictionaries with string keys.

    """
    return _is_object_dictionary(value) and all(
        isinstance(key, str) for key in value
    )


def _is_object_list(value: object) -> TypeIs[list[object]]:
    """Verify that an untyped JSON value is an array.

    Returns:
        True only for list values.

    """
    return isinstance(value, list)


def _is_dictionary_list(value: object) -> TypeIs[list[dict[str, object]]]:
    """Reject non-object payload records in the synthetic output.

    Returns:
        True only for lists of dictionaries with string keys.

    """
    return _is_object_list(value) and all(
        _is_string_dictionary(entry) for entry in value
    )
