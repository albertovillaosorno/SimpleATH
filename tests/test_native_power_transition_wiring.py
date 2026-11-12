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
#   - Offline native power-off status propagation source regression.
# - Must-Not:
#   - Claim a macOS power transition or real DMA shutdown occurred.
# - Allows:
#   - Inputs: current SimpleATH source and transport implementation.
#   - Outputs: deterministic source-wiring assertions.
#   - Side effects: none.
# - Split-When:
#   - An authorized native lifecycle harness replaces source-only evidence.
# - Merge-When:
#   - The lifecycle wiring checks directly own this contract.
# - Summary:
#   - Verify that explicit native radio-off reports failed queue release.
# - Description:
#   - Checks release/status order without invoking a kernel service.
# - Usage:
#   - Executed by offline Python unit test discovery.
# - Defaults:
#   - Missing source evidence is a test failure.
#
# Module: native radio power transition source regression.
"""Verify explicit native radio-off returns actual shutdown status."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
OWNER = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
TRANSPORT = (ROOT / "src/platform/tahoe/TahoeWirelessTransport.cpp").read_text(
    encoding="utf-8"
)


class NativePowerTransitionWiring(unittest.TestCase):
    @staticmethod
    def test_owner_reports_real_gated_shutdown_result() -> None:
        owner = OWNER.split("static IOReturn ownerSetPower(", 1)[1].split(
            "static IOReturn ownerSetMacAction(", 1
        )[0]
        assert "return self.startClient();" in owner
        assert "return self.stopClient(ClientStopMode::Suspend);" in owner
        assert "self.setPowerState(0, nullptr);" not in owner

    @staticmethod
    def test_release_failure_cannot_be_turned_into_success() -> None:
        stop = OWNER.split("IOReturn stopClient(ClientStopMode mode)", 1)[
            1
        ].split("static IOReturn adoptQueuesAction(", 1)[0]
        assert "return kIOReturnNotReady;" in stop
        assert "IOReturn gated = kIOReturnNotReady;" in stop
        assert "gated = gate_->runAction(sleepAction);" in stop
        assert "gated = gate_->runAction(terminateAction);" in stop
        assert "gated = gate_->runAction(stopAction);" in stop
        assert "const IOReturn released = queues_.releaseClient();" in stop
        assert (
            stop.index("queues_.releaseClient()")
            < stop.index("IOLockUnlock(lifecycle_);")
            < stop.index("return gated != kIOReturnSuccess ? gated : released;")
        )
        assert "if (released != kIOReturnSuccess)" in stop

    @staticmethod
    def test_transport_retains_mailbox_if_provider_rejects_power_off() -> None:
        power = TRANSPORT.split(
            "IOReturn TahoeWirelessTransport::setPower(bool on)", 1
        )[1].split("TahoeWirelessTransport::setMac(", 1)[0]
        assert "owner_.setPower(owner_.context, on);" in power
        assert "if (result == kIOReturnSuccess && !on)" in power
        assert power.index("owner_.setPower(owner_.context, on)") < power.index(
            "invalidateMailboxes();"
        )
        assert "return result;" in power


if __name__ == "__main__":
    unittest.main()
