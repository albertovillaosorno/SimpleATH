# Copyright (c) 2026 SimpleATH contributors.
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
MANIFEST = ROOT / "firmware/manifest.json"
BOOT_CLASS = "SimpleATHUsbBluetooth"
BOOT_VENDOR_IDS = {0x0CF3, 0x13D3}
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
        }

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
            assert (ROOT / "firmware" / license_name).is_file()

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
