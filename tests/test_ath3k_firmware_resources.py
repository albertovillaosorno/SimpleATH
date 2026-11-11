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
#   - Offline regression cases for ath3k firmware resources.
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
#   - Offline regression cases for ath3k firmware resources.
# - Description:
#   - Implements or verifies the test_ath3k_firmware_resources source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for ath3k firmware resources.
"""Source-only regression tests for exact licensed AR3012 DFU resources."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import plistlib
from tempfile import TemporaryDirectory
from typing import cast
from unittest import TestCase
from unittest.mock import patch

from tools.firmware import embed_ar3k

ROOT = Path(__file__).resolve().parents[1]
PLIST = ROOT / "src/Info.plist"
MANIFEST = ROOT / "src/firmware/manifest.json"
BOOT_CLASS = "SimpleATHUsbBluetooth"
HCI_CLASS = "SimpleATHUsbHciTransport"
BOOT_VENDOR_IDS = {0x0CF3, 0x13D3}
HCI_VENDOR_IDS = {0x0CF3, 0x13D3, 0x0489, 0x04C5, 0x04CA, 0x0930, 0x0B05}
EXPECTED_IMAGES = 18
LICENSE_FRAGMENT = "license"
RESOURCE_NAME_FRAGMENT = "resource name"


class Ath3kFirmwareTests(TestCase):
    """Verify reproducible DFU bytes, USB boot matching and failure paths."""

    @staticmethod
    def test_plist_has_verified_vendor_scoped_boot_images() -> None:
        """Keep both Wi-Fi personalities and exact USB payload bytes."""
        info = cast("dict[str, object]", plistlib.loads(PLIST.read_bytes()))
        personalities = cast(
            "dict[str, dict[str, object]]", info["IOKitPersonalities"]
        )
        boot = [
            entry
            for entry in personalities.values()
            if entry.get("IOClass") == BOOT_CLASS
        ]
        assert len(boot) == len(BOOT_VENDOR_IDS)
        assert {
            cast("int", entry["idVendor"]) for entry in boot
        } == BOOT_VENDOR_IDS
        catalog = embed_ar3k.images()
        assert len(catalog) == EXPECTED_IMAGES
        for entry in boot:
            assert entry["SimpleATHAth3kFirmware"] == catalog
        assert {entry["IOClass"] for entry in personalities.values()} == {
            "SimpleATH",
            "SimpleATHTahoeController",
            BOOT_CLASS,
            HCI_CLASS,
        }

    @staticmethod
    def test_normal_hci_matches_separate_apple_host_transport() -> None:
        """Only class-correct post-firmware USB may invoke the HCI probe."""
        info = cast("dict[str, object]", plistlib.loads(PLIST.read_bytes()))
        personalities = cast(
            "dict[str, dict[str, object]]", info["IOKitPersonalities"]
        )
        hci = [
            entry for entry in personalities.values()
            if entry.get("IOClass") == HCI_CLASS
        ]
        assert len(hci) == len(HCI_VENDOR_IDS)
        observed_vendors = {
            cast("int", entry["idVendor"]) for entry in hci
        }
        assert observed_vendors == HCI_VENDOR_IDS
        for entry in hci:
            assert entry["IOProviderClass"] == "IOUSBHostInterface"
            assert entry["bInterfaceNumber"] == 0
            assert entry["bInterfaceClass"] == 0xE0
            assert entry["bInterfaceSubClass"] == 1
            assert entry["bInterfaceProtocol"] == 1
            assert "SimpleATHAth3kFirmware" not in entry
        libraries = cast("dict[str, str]", info["OSBundleLibraries"])
        assert libraries["com.apple.iokit.IOBluetoothFamily"] == "1.0.0"

        native = (
            ROOT / "src/platform/bluetooth/SimpleATHUsbBluetooth.cpp"
        ).read_text()
        assert "isSupportedAth3kHciIdentity(out)" in native
        native_superclass = "IOBluetoothHostControllerUSBTransport"
        assert f"{native_superclass}::start(provider)" in native
        assert f"{native_superclass}::stop(provider)" in native

    @staticmethod
    def test_plist_round_trip_never_changes_bytes() -> None:
        """An already embedded plist must be byte-for-byte idempotent."""
        before = PLIST.read_bytes()
        assert embed_ar3k.bundled_info(before) == before

    @staticmethod
    def test_firmware_sha256_and_licenses_match_manifest() -> None:
        """Verify each resource using independent pinned image files."""
        manifest = cast("dict[str, object]", json.loads(MANIFEST.read_text()))
        assets = cast("list[dict[str, object]]", manifest["assets"])
        assert len(assets) == EXPECTED_IMAGES
        contents = embed_ar3k.images()
        for asset in assets:
            file_name = cast("str", asset["file"])
            data = contents["ar3k/" + file_name]
            assert len(data) == asset["bytes"]
            assert hashlib.sha256(data).hexdigest() == asset["sha256"]
            license_name = cast("str", asset["license"])
            assert (ROOT / "src/firmware" / license_name).is_file()

    @staticmethod
    def test_missing_license_is_rejected() -> None:
        """Do not package firmware without its original licensing text."""
        rejected = False
        with (
            TemporaryDirectory() as directory,
            patch.object(embed_ar3k, "ROOT_FIRMWARE", Path(directory)),
        ):
            try:
                _ = embed_ar3k.images()
            except ValueError as error:
                rejected = LICENSE_FRAGMENT in str(error)
        assert rejected

    @staticmethod
    def test_invalid_catalog_path_is_rejected() -> None:
        """A malicious manifest must not read outside the firmware store."""
        manifest = cast("dict[str, object]", json.loads(MANIFEST.read_text()))
        assets = cast("list[dict[str, object]]", manifest["assets"])
        assets[0]["file"] = "../invalid.dfu"
        rejected = False
        with TemporaryDirectory() as directory:
            altered = Path(directory) / "manifest.json"
            _ = altered.write_text(json.dumps(manifest))
            with patch.object(embed_ar3k, "MANIFEST", altered):
                try:
                    _ = embed_ar3k.images()
                except ValueError as error:
                    rejected = RESOURCE_NAME_FRAGMENT in str(error)
        assert rejected
