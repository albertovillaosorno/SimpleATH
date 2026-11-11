#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 laobamac. All rights reserved.
# SPDX-License-Identifier:
#   - LicenseRef-SimpleBCM-All-Rights-Reserved
# Confidential:
#   - false
# License-File:
#   - LICENSE-SIMPLEBCM
# Provenance:
#   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
#   - Originally authored by laobamac on 2026/11/2.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for check.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for check.
# - Description:
#   - Implements or verifies the check source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for check.

"""Verify legacy package metadata without compiling, signing, or packaging."""

from __future__ import annotations

import ast
import json
import plistlib
import re
import sys
from typing import TYPE_CHECKING
from typing import TypeIs
# Parse only local Xcode scheme metadata.
import xml.etree.ElementTree as ET  # ruff: ignore[suspicious-xml-etree-import]

from bootstrap import ROOT
from build import fragment
from build import package_name
from embed import VERSION
from native_references import DIRECTORY
from native_references import load_reference
from system_profiles import SYSTEMS

if TYPE_CHECKING:
    from collections.abc import Callable

PROJECT_NAME = "SimpleATH.xcodeproj"
PROJECT_REFERENCE = f"container:{PROJECT_NAME}"
BUNDLE_IDENTIFIER = "$(PRODUCT_BUNDLE_IDENTIFIER)"
LILU_ID = "as.vit9696.Lilu"
NATIVE_NAMESPACE = "ath::"
TIMER_CLASS = "IOTimerEventSource"
RESOURCE_NAME = "IOResources"
LEGACY_WIRELESS_FRAMEWORK = "com.apple.iokit.IO80211FamilyLegacy"
INTEL_ARCH = "x86_64"
EXPECTED_NATIVE_FRAMEWORKS = frozenset({
    "com.apple.iokit.IOSkywalkFamily",
    "com.apple.iokit.IO80211Family",
})
STAGE1_FRAMEWORKS = frozenset({
    "com.apple.kpi.iokit",
    "com.apple.kpi.libkern",
    "com.apple.kpi.mach",
    "com.apple.kpi.private",
})


def _ensure(*, condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _is_object_mapping(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_mapping(value) and all(
        isinstance(key, str) for key in value
    )


def _mapping(value: object, description: str) -> dict[str, object]:
    if not _is_mapping(value):
        message = f"Expected dictionary of string keys: {description}"
        raise ValueError(message)
    return value


def _is_object_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _decode_json(
    text: str, decoder: Callable[[str], object] = json.loads
) -> object:
    return decoder(text)


def _decode_plist(
    data: bytes, decoder: Callable[[bytes], object] = plistlib.loads
) -> object:
    return decoder(data)


def _check_source_references() -> None:
    for path in (ROOT / "Tools").glob("*.py"):
        _ = ast.parse(path.read_text(), filename=str(path))
    for path in (ROOT / "Docs").glob("*.json"):
        _ = _decode_json(path.read_text())
    for system in SYSTEMS:
        _ = load_reference(DIRECTORY / f"{system}.json")


def _check_project() -> None:
    _ensure(
        condition={p.name for p in ROOT.glob("*.xcodeproj")} == {PROJECT_NAME},
        message="Unexpected Xcode project layout",
    )
    project = ROOT / PROJECT_NAME
    for path in project.rglob("*.xcscheme"):
        # Schemes are local source-controlled build metadata, not network XML.
        # Parse local Xcode scheme source only.
        for reference in ET.parse(path).iter(  # ruff: ignore[suspicious-xml-element-tree-usage]
            "BuildableReference"
        ):
            _ensure(
                condition=reference.attrib["ReferencedContainer"]
                == PROJECT_REFERENCE,
                message=f"Unexpected Xcode scheme reference: {path}",
            )


def _check_info_plist() -> None:
    kernel_config = (ROOT / "Config/Kernel.xcconfig").read_text()
    version_match = re.search(
        r"^MODULE_VERSION\s*=\s*(\S+)", kernel_config, re.MULTILINE
    )
    if version_match is None:
        message = "Missing MODULE_VERSION in Kernel.xcconfig"
        raise AssertionError(message)
    _ensure(
        condition=version_match.group(1) == VERSION,
        message="Driver and package versions differ",
    )
    info = _mapping(
        _decode_plist((ROOT / "SimpleATH/Info.plist").read_bytes()),
        "SimpleATH/Info.plist",
    )
    _ensure(
        condition=info.get("OSBundleCompatibleVersion") == VERSION,
        message="Incompatible bundle version",
    )
    _ensure(
        condition=info.get("CFBundleIdentifier") == BUNDLE_IDENTIFIER,
        message="Unexpected bundle identifier",
    )
    libraries = _mapping(info.get("OSBundleLibraries"), "OSBundleLibraries")
    _ensure(
        condition=LILU_ID not in libraries,
        message="Unexpected Lilu dependency",
    )
    if (ROOT / "BOOTFIX-SIMPLEATH.md").exists():
        _ensure(
            condition=frozenset(libraries) == STAGE1_FRAMEWORKS,
            message="Unexpected Stage-1 frameworks",
        )
        stage1 = (ROOT / "SimpleATH/SimpleATH.cpp").read_text()
        _ensure(
            condition=NATIVE_NAMESPACE not in stage1,
            message="Unexpected native code in Stage-1",
        )
        _ensure(
            condition=TIMER_CLASS not in stage1,
            message="Unexpected timer in Stage-1",
        )
        _ensure(
            condition=RESOURCE_NAME in plistlib.dumps(info).decode(),
            message="Missing IOResources",
        )
    else:
        _ensure(
            condition=libraries.keys() >= EXPECTED_NATIVE_FRAMEWORKS,
            message="Missing native Wi-Fi frameworks",
        )
    _ensure(
        condition=LEGACY_WIRELESS_FRAMEWORK not in libraries,
        message="Unexpected legacy Wi-Fi framework",
    )


def _check_docs() -> None:
    for name in ("README.md", "README.en.md"):
        document = (ROOT / name).read_text()
        _ensure(
            condition=f"version-{VERSION}-" in document,
            message=f"Missing release version in {name}",
        )
        for system in SYSTEMS:
            _ensure(
                condition=system in document,
                message=f"Missing {system} in {name}",
            )


def _check_fragments() -> None:
    for optional in (False, True):
        config = _mapping(fragment(optional=optional), "fragment")
        kernel = _mapping(config.get("Kernel"), "fragment Kernel")
        raw_add = kernel.get("Add")
        if not _is_object_list(raw_add):
            message = "Expected list: fragment Kernel/Add"
            raise ValueError(message)
        entries = [_mapping(entry, "Kernel/Add entry") for entry in raw_add]
        expected = ["SimpleATH.kext"]
        if optional:
            expected = [
                "Lilu.kext",
                "AirportBrcmFixup.kext",
                *expected,
                "AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext",
            ]
        _ensure(
            condition=[entry.get("BundlePath") for entry in entries]
            == expected,
            message="Unexpected kext bundle paths",
        )
        _ensure(
            condition=kernel.get("Block") == [],
            message="Native frameworks must remain enabled",
        )
        _check_kext_entries(entries)
        _ensure(
            condition=_decode_plist(plistlib.dumps(config)) == config,
            message="Kernel fragment did not round-trip through plist",
        )


def _check_kext_entries(entries: list[dict[str, object]]) -> None:
    for entry in entries:
        _ensure(
            condition=entry.get("Enabled") is True,
            message="Kext must be enabled",
        )
        _ensure(
            condition=entry.get("Arch") == INTEL_ARCH,
            message="Unexpected kext architecture",
        )
        _ensure(
            condition=(entry.get("MinKernel"), entry.get("MaxKernel"))
            == ("23.0.0", "25.99.99"),
            message="Unexpected kernel range",
        )


def _check_package_names() -> None:
    for configuration in ("Debug", "Release"):
        _ensure(
            condition=package_name(configuration)
            == f"SimpleATH-v{VERSION}-{configuration.upper()}",
            message="Unexpected package name",
        )
        _ensure(
            condition=package_name(configuration, "pre", "a" * 40).endswith(
                "-alpha-aaaaaaa"
            ),
            message="Unexpected prerelease package name",
        )


def main() -> None:
    """Check local metadata contracts without invoking any build workflows."""
    _check_source_references()
    _check_project()
    _check_info_plist()
    _check_docs()
    _check_fragments()
    _check_package_names()
    _ = sys.stdout.write(
        "Source metadata, native configuration and version checks passed.\n"
    )


if __name__ == "__main__":
    main()
