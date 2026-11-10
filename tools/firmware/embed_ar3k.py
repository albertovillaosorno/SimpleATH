#!/usr/bin/env python3
# Copyright (c) 2026 SimpleATH contributors.
"""Embed unchanged, licensed AR3012 DFU images as IOService OSData.

This deterministic source-only transform embeds byte-preserved firmware in
USB boot personalities. No hardware access, kext build, or firmware execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from pathlib import PureWindowsPath
import plistlib
import sys
from typing import TypedDict
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
PLIST = ROOT / "src/Info.plist"
ROOT_FIRMWARE = ROOT / "firmware"
MANIFEST = ROOT_FIRMWARE / "manifest.json"
SCHEMA = "simpleath.ath3k.firmware.v1"
BLUETOOTH_CLASS = "SimpleATHUsbBluetooth"
MAX_FIRMWARE_BYTES = 1024 * 1024
MIN_FIRMWARE_BYTES = 20
ASSET_COUNT = 18
LICENSE_NAMES = frozenset((
    "LICENCE.atheros_firmware",
    "LICENSE.QualcommAtheros_ar3k",
))


class _Asset(TypedDict):
    """One pinned unmodified DFU image and its original license."""

    file: str
    bytes: int
    sha256: str
    license: str


class _Manifest(TypedDict):
    """Auditable immutable AR3012 firmware inventory."""

    schema: str
    source: str
    upstream: str
    assets: list[_Asset]


def _valid_name(name: str) -> bool:
    """Reject invented paths, non-DFU formats, and path traversals.

    Returns:
        Whether this resource has a simple valid filename.

    """
    if not name.isascii() or not name.endswith(".dfu"):
        return False
    if Path(name).name != name or PureWindowsPath(name).name != name:
        return False
    return name.startswith(("AthrBT_0x", "ramps_0x"))


def _require_license(license_name: str) -> None:
    """Require the original upstream redistribution notice to be present.

    Raises:
        ValueError: The referenced license text is absent.

    """
    if not (ROOT_FIRMWARE / license_name).is_file():
        message = "Missing original AR3012 firmware license"
        raise ValueError(message)


def _read_asset(asset: _Asset) -> bytes:
    """Verify license presence, image shape, and complete SHA-256.

    Returns:
        Unmodified bytes from the pinned firmware asset.

    Raises:
        ValueError: Invalid firmware resource, licensing, or content.

    """
    name = asset["file"]
    license_name = asset["license"]
    if license_name not in LICENSE_NAMES:
        message = "Unsupported AR3012 firmware license"
        raise ValueError(message)
    _require_license(license_name)
    path = ROOT_FIRMWARE / "ar3k" / name
    if path.is_symlink() or not path.is_file():
        message = "Missing or linked AR3012 firmware image"
        raise ValueError(message)
    data = path.read_bytes()
    expected = asset["bytes"]
    if not MIN_FIRMWARE_BYTES <= expected <= MAX_FIRMWARE_BYTES:
        message = "AR3012 firmware has invalid size"
        raise ValueError(message)
    if (
        len(data) != expected
        or hashlib.sha256(data).hexdigest() != asset["sha256"]
    ):
        message = "AR3012 firmware image mismatch"
        raise ValueError(message)
    return data


def images() -> dict[str, bytes]:
    """Verify complete DFU catalog and all published source bytes.

    Returns:
        Resource names mapped to exact unmodified DFU contents.

    Raises:
        ValueError: Manifest, licensing, image or inventory is invalid.

    """
    manifest = cast("_Manifest", json.loads(MANIFEST.read_text()))
    if manifest["schema"] != SCHEMA:
        message = "Unexpected AR3012 manifest schema"
        raise ValueError(message)
    output: dict[str, bytes] = {}
    for asset in manifest["assets"]:
        name = asset["file"]
        if not _valid_name(name) or name in output:
            message = "Unsupported or duplicate AR3012 resource name"
            raise ValueError(message)
        output[name] = _read_asset(asset)
    if len(output) != ASSET_COUNT:
        message = "Incomplete pinned AR3012 firmware catalog"
        raise ValueError(message)
    return {"ar3k/" + key: value for key, value in output.items()}


def bundled_info(source: bytes) -> bytes:
    """Rebuild full Info.plist preserving PCI and AirPort personalities.

    Returns:
        A stable plist with two vendor-scoped USB bootstrap personalities.

    """
    info = cast("dict[str, object]", plistlib.loads(source))
    existing = cast("dict[str, dict[str, object]]", info["IOKitPersonalities"])
    keep = {
        key: value
        for key, value in existing.items()
        if value.get("IOClass") != BLUETOOTH_CLASS
    }
    payloads = images()
    for vendor, label in ((0x0CF3, "Atheros"), (0x13D3, "AzureWave")):
        keep[f"SimpleATH USB AR3012 {label} firmware"] = {
            "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
            "IOClass": BLUETOOTH_CLASS,
            "IOProviderClass": "IOUSBHostInterface",
            "idVendor": vendor,
            "bConfigurationValue": "*",
            "bInterfaceNumber": 0,
            "IOProbeScore": 100,
            # Vendor-only personality reduces duplicate firmware blobs.
            # Actual product AND revision are checked in the native probe.
            "SimpleATHAth3kFirmware": payloads,
        }
    info["IOKitPersonalities"] = keep
    return plistlib.dumps(info, sort_keys=False)


def main() -> None:
    """Regenerate the embedded resources or verify a committed plist.

    Raises:
        SystemExit: The checked-in resource payload has changed.

    """
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--check", action="store_true", help="verify committed plist"
    )
    arguments = parser.parse_args()
    current = PLIST.read_bytes()
    expected = bundled_info(current)
    check_requested = cast("bool", arguments.check)
    if check_requested:
        if current != expected:
            message = "AR3012 firmware resources are not synchronized"
            raise SystemExit(message)
        _ = sys.stdout.write("Verified AR3012 firmware in USB personalities\n")
    else:
        _ = PLIST.write_bytes(expected)
        _ = sys.stdout.write("Embedded pinned AR3012 firmware for USB\n")


if __name__ == "__main__":
    main()
