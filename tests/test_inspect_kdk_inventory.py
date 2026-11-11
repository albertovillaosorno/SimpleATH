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
#   - Offline regression cases for inspect kdk inventory.
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
#   - Offline regression cases for inspect kdk inventory.
# - Description:
#   - Implements or verifies the test_inspect_kdk_inventory source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for inspect kdk inventory.
"""In-memory synthetic KDK family evidence; no production OS images."""

from __future__ import annotations

from pathlib import Path
import plistlib
import struct
import tempfile
from typing import cast
from unittest import TestCase

from tools import inspect_platform_abi as inspector

MAC_MAGIC = 0xFEEDFACF
CPU_X86_64 = 0x01000007
KEXT_FILETYPE = 0xB
SYMTAB_COMMAND = 2
SYMTAB_SIZE = 24
HEADER_SIZE = 32
NLIST_SIZE = 16
GLOBAL_SECTION_TYPE = 0x0F
PCI_FAMILY = "IOPCIFamily"
WIFI_FAMILY = "IO80211Family"
SKYWALK_FAMILY = "IOSkywalkFamily"
FAMILIES = (PCI_FAMILY, WIFI_FAMILY, SKYWALK_FAMILY)
PCI_SYMBOL = "_IOPCIDevicePublic"
WIFI_SYMBOL = "_IO80211Controller"
SKYWALK_SYMBOL = "_IOSkywalkNetworkInterface"
KERNEL_SYMBOL = "_IODMACommand"
KERNEL_IMAGE = "com.apple.kernel"
MISSING_IMAGE = "image_not_in_supplied_evidence"
EXPORT_COUNT = 2


def _thin_image(symbol: str) -> bytes:
    """Encode one self-contained candidate-only thin Mach-O nlist.

    Returns:
        A minimal synthetic Mach-O image with one defined public symbol.

    """
    table_offset = HEADER_SIZE + SYMTAB_SIZE
    strings_offset = table_offset + NLIST_SIZE
    names = b"\0" + symbol.encode("utf-8") + b"\0"
    return b"".join((
        struct.pack(
            "<8I", MAC_MAGIC, CPU_X86_64, 0, KEXT_FILETYPE, 1, SYMTAB_SIZE, 0, 0
        ),
        struct.pack(
            "<6I",
            SYMTAB_COMMAND,
            SYMTAB_SIZE,
            table_offset,
            1,
            strings_offset,
            len(names),
        ),
        struct.pack("<IBBHQ", 1, GLOBAL_SECTION_TYPE, 1, 0, 0),
        names,
    ))


def _write(root: Path, relative: str, contents: bytes) -> None:
    """Create a synthetic bounded KDK input inside the selected root."""
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    _ = target.write_bytes(contents)


def _fixture(root: Path, *, with_kernel: bool = False) -> None:
    """Create three package families and optionally the packaged kernel."""
    _write(
        root,
        "System/Library/CoreServices/SystemVersion.plist",
        plistlib.dumps({
            "ProductVersion": "26.7.2",
            "ProductBuildVersion": "25G332",
        }),
    )
    for family, symbol in zip(
        FAMILIES, (PCI_SYMBOL, WIFI_SYMBOL, SKYWALK_SYMBOL), strict=True
    ):
        contents = f"System/Library/Extensions/{family}.kext/Contents/"
        _write(
            root,
            contents + "Info.plist",
            plistlib.dumps({
                "CFBundleIdentifier": "com.apple.iokit." + family,
                "CFBundleVersion": "synthetic",
            }),
        )
        _write(root, contents + "MacOS/" + family, _thin_image(symbol))
    pci_contents = f"System/Library/Extensions/{PCI_FAMILY}.kext/Contents/"
    _write(
        root,
        pci_contents + "Resources/config/IOPCIFamily.exports",
        (PCI_SYMBOL + "\n_AbsentSymbol\n").encode("utf-8"),
    )
    if with_kernel:
        _write(
            root, "System/Library/Kernels/kernel", _thin_image(KERNEL_SYMBOL)
        )


class OfflineKdkInventoryTests(TestCase):
    """Never confuse KDK package evidence with loaded native interfaces."""

    @staticmethod
    def test_family_export_intersection_is_candidate_only() -> None:
        """Intersect PCI export metadata without granting ABI approval."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            report = inspector.inventory(
                root, reference_mode=False, kdk_mode=True
            )
            groups = report["groups"]
            assert isinstance(groups, dict)
            assert groups["pci"]["symbols"] == {
                PCI_SYMBOL: "kdk_config_export_and_defined_global_nlist"
            }
            assert groups["wireless"]["symbols"] == {
                WIFI_SYMBOL: "global_definition_candidate"
            }
            assert groups["skywalk"]["symbols"] == {
                SKYWALK_SYMBOL: "global_definition_candidate"
            }
            assert groups["dma"]["state"] == MISSING_IMAGE
            assert report["nativePciAbiVerified"] is False
            assert report["nativeWirelessAbiVerified"] is False
            metadata = report["metadata"]
            assert isinstance(metadata, dict)
            assert metadata["loadedImageProvenanceVerified"] is False
            images = cast("dict[str, dict[str, object]]", metadata["images"])
            assert (
                images["com.apple.iokit.IOPCIFamily"]["configExportListEntries"]
                == EXPORT_COUNT
            )

    @staticmethod
    def test_optional_packaged_kernel_remains_candidate_only() -> None:
        """Adding an optional kernel expands evidence but not verification."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, with_kernel=True)
            report = inspector.inventory(
                root, reference_mode=False, kdk_mode=True
            )
            names = report["imageNames"]
            assert isinstance(names, list)
            assert KERNEL_IMAGE in names
            groups = report["groups"]
            assert isinstance(groups, dict)
            assert groups["dma"]["symbols"] == {
                KERNEL_SYMBOL: "global_definition_candidate"
            }
            assert report["nativePciAbiVerified"] is False
            assert report["nativeWirelessAbiVerified"] is False
