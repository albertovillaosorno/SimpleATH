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
#   - Offline regression cases for native bundle dependencies.
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
#   - Offline regression cases for native bundle dependencies.
# - Description:
#   - Implements or verifies the test_native_bundle_dependencies source
#     boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native bundle dependencies.
"""Validate native networking imports against pinned Tahoe KDK metadata.

The Xcode linker can produce a Mach-O with unresolved kernel superclass
imports. OpenCore needs the provider kexts declared explicitly in the
consumer's OSBundleLibraries, not merely in a transitive family dependency.
"""

import json
from pathlib import Path
import plistlib
from typing import cast
import unittest

ROOT = Path(__file__).resolve().parent.parent
INFO = ROOT / "src/Info.plist"
KDK = ROOT / "docs/evidence/TAHOE-25G332-KDK-SYMBOLS.json"
IO80211 = "com.apple.iokit.IO80211Family"
SKYWALK = "com.apple.iokit.IOSkywalkFamily"
NETWORK = "com.apple.iokit.IONetworkingFamily"
# The six superclass groups from the authorized artifact's OpenCore failure.
# Each source anchor is part of the native production Tahoe implementation.
PRELINK_SUPERCLASSES = (
    ("IONetworkController", "TahoeControllerABI.hpp", NETWORK),
    ("IOEthernetController", "TahoeControllerABI.hpp", NETWORK),
    ("IOSkywalkInterface", "TahoeInterfaceABI.hpp", SKYWALK),
    ("IOSkywalkNetworkInterface", "TahoeInterfaceABI.hpp", SKYWALK),
    ("IOSkywalkEthernetInterface", "TahoeInterfaceABI.hpp", SKYWALK),
    ("IOSkywalkPacket", "TahoeInterfaceABI.hpp", SKYWALK),
)


class NativeBundleDependencies(unittest.TestCase):
    """Every independently imported superclass has a direct bundle owner."""

    @staticmethod
    def test_pinned_kdk_requires_both_networking_families() -> None:
        """Catch unsupported assumptions about transitive family ownership."""
        with KDK.open(encoding="utf-8") as source:
            images = cast(
                "dict[str, dict[str, dict[str, str]]]",
                json.load(source)["metadata"]["images"],
            )
        wifi = images[IO80211]["dependencies"]
        skywalk = images[SKYWALK]["dependencies"]
        assert wifi[SKYWALK] == "1.0"
        assert wifi[NETWORK] == "3.0"
        assert skywalk[NETWORK] == "3.2"

    @staticmethod
    def test_kext_directly_imports_wireless_and_skywalk_superclasses() -> None:
        """Stop native prelinked injection with absent provider libraries."""
        with INFO.open("rb") as source:
            libraries = cast(
                "dict[str, str]", plistlib.load(source)["OSBundleLibraries"]
            )
        assert libraries[IO80211] == "1200.13.1"
        assert libraries[SKYWALK] == "1.0"
        # 3.2 covers IO80211Family's 3.0 and SkywalkFamily's 3.2 floors.
        assert libraries[NETWORK] == "3.2"

    @staticmethod
    def test_open_core_prelink_superclass_groups_have_direct_owners() -> None:
        """Guard every failed import group, not only its parent family."""
        with INFO.open("rb") as source:
            libraries = cast(
                "dict[str, str]", plistlib.load(source)["OSBundleLibraries"]
            )
        for classname, source_name, family in PRELINK_SUPERCLASSES:
            native_source = ROOT / "src/platform/tahoe" / source_name
            assert classname in native_source.read_text(encoding="utf-8")
            assert family in libraries, f"{classname} needs {family}"


if __name__ == "__main__":
    _ = unittest.main()
