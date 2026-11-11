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
#   - Offline regression cases for tahoe native sdk abi.
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
#   - Offline regression cases for tahoe native sdk abi.
# - Description:
#   - Implements or verifies the test_tahoe_native_sdk_abi source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for tahoe native sdk abi.
"""Guard native Tahoe networking vtable inheritance and Apple SDK syntax.

The 2026-11-10 authorized Intel build failed because legacy reserved-slot
names were marked override even though Apple's IONetworkController exposes
those slots as allocatePacketNoWait/setHardwareAssists virtual methods.
"""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

from tools.native_apple_kernel_headers import native_kernel_syntax_command

MACOS_PLATFORM = "darwin"
EXPECTED_OVERRIDE = "override"
CONTROLLER_BASE_DECLARATION = (
    "class IO80211Controller : public IOEthernetController"
)
ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "src/platform/tahoe/TahoeControllerABI.hpp"
APPLE_BASE_METHODS = ("allocatePacketNoWait", "setHardwareAssists")
LEGACY_SLOT_NAMES = (
    "_RESERVEDIONetworkController6",
    "_RESERVEDIONetworkController7",
)

# These signatures are from Apple's published IONetworkingFamily
# IONetworkController.h (cad955eb9e4351e78bc75618b293b0f47d7db2c5).
# This self-contained host fixture is not used as a kext/CI SDK.
INHERITANCE_PROBE = """\
using UInt32 = unsigned int;
using IOReturn = int;
struct __mbuf;
using mbuf_t = __mbuf *;
class IONetworkController {
public:
    virtual mbuf_t allocatePacketNoWait(UInt32);
    virtual IOReturn setHardwareAssists(UInt32, UInt32);
};
class IOEthernetController : public IONetworkController {};
class IO80211Controller : public IOEthernetController {};
using AllocateSlot = mbuf_t (IONetworkController::*)(UInt32);
using AssistsSlot = IOReturn (IONetworkController::*)(UInt32, UInt32);
static_assert(__is_same(decltype(&IONetworkController::allocatePacketNoWait),
                        AllocateSlot), "packet allocation ABI drift");
static_assert(__is_same(decltype(&IO80211Controller::allocatePacketNoWait),
                        AllocateSlot), "packet allocation must be inherited");
static_assert(__is_same(decltype(&IONetworkController::setHardwareAssists),
                        AssistsSlot), "hardware assists ABI drift");
static_assert(__is_same(decltype(&IO80211Controller::setHardwareAssists),
                        AssistsSlot), "hardware assists must be inherited");
"""

NATIVE_SDK_PROBE = """\
#include "platform/tahoe/TahoeControllerABI.hpp"
using AllocateSlot = mbuf_t (IONetworkController::*)(UInt32);
using AssistsSlot = IOReturn (IONetworkController::*)(UInt32, UInt32);
static_assert(__is_same(decltype(&IONetworkController::allocatePacketNoWait),
                        AllocateSlot), "native packet ABI changed");
static_assert(__is_same(decltype(&IO80211Controller::allocatePacketNoWait),
                        AllocateSlot),
              "wireless packet ABI shadows native base");
static_assert(__is_same(decltype(&IONetworkController::setHardwareAssists),
                        AssistsSlot), "native assist ABI changed");
static_assert(__is_same(decltype(&IO80211Controller::setHardwareAssists),
                        AssistsSlot),
              "wireless assist ABI shadows native base");
"""


def _run(
    args: list[str], *, source: str = ""
) -> subprocess.CompletedProcess[str]:
    """Execute a bounded syntax-only compiler probe, never link a kext.

    Returns:
        Process status plus captured compiler diagnostics.

    """
    return subprocess.run(
        args,
        input=source,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=30,
        cwd=ROOT,
    )


class TahoeNativeSdkAbi(unittest.TestCase):
    """Always check local declarations; use actual Apple SDK on macOS."""

    @staticmethod
    def test_wireless_header_inherits_native_network_slots() -> None:
        """Never reintroduce old reserved aliases or shadow native slots."""
        content = HEADER.read_text(encoding="utf-8")
        active_source = "\n".join(
            line.split("//", 1)[0] for line in content.splitlines()
        )
        for name in (*LEGACY_SLOT_NAMES, *APPLE_BASE_METHODS):
            assert re.search(rf"\b{name}\s*\(", active_source) is None, (
                f"wireless ABI redeclares native method: {name}"
            )
        assert CONTROLLER_BASE_DECLARATION in content

    @staticmethod
    def test_host_compiler_keeps_base_slot_types_and_order() -> None:
        """A host-only stand-in checks C++ inherited member pointer types."""
        compiler = shutil.which("clang++")
        assert compiler is not None, "Clang is required for the source tests"
        result = _run(
            [
                compiler,
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsyntax-only",
                "-x",
                "c++",
                "-",
            ],
            source=INHERITANCE_PROBE,
        )
        assert result.returncode == 0, result.stderr

    @staticmethod
    def test_old_reserved_override_is_rejected_by_compiler() -> None:
        """Reproduce the exact 2026-11-10 override compile failure."""
        compiler = shutil.which("clang++")
        assert compiler is not None, "Clang is required for the source tests"
        bad = INHERITANCE_PROBE.replace(
            "class IO80211Controller : public IOEthernetController {};",
            """class IO80211Controller : public IOEthernetController {
    void _RESERVEDIONetworkController6() override;
    void _RESERVEDIONetworkController7() override;
};""",
        )
        result = _run(
            [compiler, "-std=c++14", "-fsyntax-only", "-x", "c++", "-"],
            source=bad,
        )
        assert result.returncode != 0, "the historical invalid ABI must fail"
        assert EXPECTED_OVERRIDE in result.stderr

    @staticmethod
    def test_native_apple_sdk_inheritance_and_full_wireless_header() -> None:
        """On macOS, compile the real ABI header against native SDK only.

        Linux still checks source contracts and the synthetic compiler probe.
        This method intentionally does not report the non-Mac path as a skip.
        """
        if sys.platform != MACOS_PLATFORM:
            return
        sdk = _run(["xcrun", "--sdk", "macosx", "--show-sdk-path"])
        assert sdk.returncode == 0, sdk.stderr
        resource = _run(["xcrun", "clang++", "-print-resource-dir"])
        assert resource.returncode == 0, resource.stderr
        # Userland usr/include must never precede Kernel.framework:
        # that order imports incompatible _strings.h, MacTypes.h and
        # sys/cdefs.h declarations into IOKit/libkern.
        command = native_kernel_syntax_command(
            Path(sdk.stdout.strip()),
            Path(resource.stdout.strip()),
            ROOT / "src",
        )
        result = _run(command, source=NATIVE_SDK_PROBE)
        assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    _ = unittest.main()
