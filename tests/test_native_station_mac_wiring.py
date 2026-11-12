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
#   - Source-level native station MAC program and identity-propagation checks.
# - Must-Not:
#   - Claim real PCI register write, native AirPort operation, or RF readiness.
# - Allows:
#   - Inputs: native owner source and exact production method boundaries.
#   - Outputs: independently reproducible wiring assertions.
#   - Side effects: no hardware, RF, PCI, kernel or network operations.
# - Split-When:
#   - A kernel harness can test owner callbacks under an actual command gate.
# - Merge-When:
#   - Hardware MAC register behavior is tested in test_station_mac.cpp.
# - Summary:
#   - Ensure OS MAC changes reach real quiesced PCU identity and native users.
# - Description:
#   - Checks copied requests, physical readback, restart and error retirement.
# - Usage:
#   - Executed through ordinary Python unit test discovery.
# - Defaults:
#   - Missing or bypassed native identity gates fail closed.
#
# Module: Native source-only station MAC readdressing integration checks.
"""Verify source wiring of physical native MAC changes without running PCI."""

import unittest
from pathlib import Path

SOURCE = (
    Path(__file__).resolve().parent.parent / "src/SimpleATH.cpp"
).read_text(encoding="utf-8")


def method(start: str, end: str) -> str:
    assert SOURCE.count(start) == 1, start
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class NativeStationMacWiring(unittest.TestCase):
    @staticmethod
    def test_os_request_copied_before_hardware_gate() -> None:
        wrapper = method(
            "static IOReturn\n        ownerSetMac(",
            "// The platform scan contract uses bridge generations",
        )
        assert wrapper.index("memcpy(&stable[0], address, sizeof(stable));") < (
            wrapper.index("gate_->runAction(ownerSetMacAction, &stable[0])")
        )
        assert "self.gate_ == nullptr" in wrapper
        assert "ownerSnapshot(context" not in wrapper

    @staticmethod
    def test_only_quiesced_prepared_hardware_changes_mac() -> None:
        change = method(
            "static IOReturn ownerSetMacAction(",
            "static IOReturn\n        ownerSetMac(",
        )
        assert change.index("memcmp(requested, &self.stationMac_[0]") < (
            change.index("!self.enginesQuiesced_")
        )
        for required in (
            "self.queues_.phase() != simpleath::NativeQueuePhase::Prepared",
            "!self.queues_.initialStartEligibleGated()",
            "self.radioOperational_",
            "self.channelAuthorized_",
            "self.joinWatchRequestId_ != 0",
            "self.programmedBssidEpoch_ != 0",
            "self.nativePairwiseTx_.installed()",
            "self.nativePairwiseRx_.installed()",
            "self.nativeGroupInstalled()",
            "self.scanBridge_.status().radioScanRunning",
            "self.queues_.epoch() != self.epoch_",
            "simpleath::validatePermanentMac(requested)",
            "(requested[0] & 0x02U) == 0U",
        ):
            assert required in change, required
        permit = method(
            "static bool stationMacPermit(", "// This permit is valid only"
        )
        assert "canReset(context, epoch)" in permit
        assert "NativeQueuePhase::Prepared" in permit
        assert "initialStartEligibleGated()" in permit
        assert "!self.radioOperational_ && !self.channelAuthorized_" in permit
        assert "self.board_.view(epoch) != nullptr" in permit

    @staticmethod
    def test_only_verified_identity_published_and_propagated() -> None:
        change = method(
            "static IOReturn ownerSetMacAction(",
            "static IOReturn\n        ownerSetMac(",
        )
        assert (
            change.index("programAr9565StationMac(")
            < change.index(
                "progress.result != simpleath::MacIdentityResult::Ok"
            )
            < change.index("memcpy(&self.stationMac_[0], requested")
            < change.index("self.notifyWirelessChange(false);")
        )
        failure = change.split(
            "if (progress.result != simpleath::MacIdentityResult::Ok)", 1
        )[1].split("memcpy(&self.stationMac_[0], requested", 1)[0]
        assert "self.retireNativeLink(kIOReturnNotReady);" in failure
        assert "self.stationMacProgrammed_ = false;" in failure
        assert "self.keyCache_.requiresReset = true;" in failure
        snapshot = method(
            "static IOReturn ownerSnapshotAction(",
            "static IOReturn ownerSnapshot(",
        )
        assert "&board->summary.mac[0]" in snapshot
        assert "&self.stationMac_[0]" in snapshot
        assert "if (!self.stationMacProgrammed_)" in snapshot
        connection = method(
            "static IOReturn ownerConnectAction(",
            "static IOReturn\n        ownerConnect(",
        )
        assert "&self.stationMac_[0]" in connection
        awdl = method("void receiveNativeAwdl(", "void retireNativeLink(")
        assert "&stationMac_[0]" in awdl

    @staticmethod
    def test_real_pcu_identity_reapplied_at_every_new_epoch() -> None:
        start = method("IOReturn startHardware()", "void stopHardware(")
        assert "requestedStationMacValid_" in start
        assert "&requestedStationMac_[0]" in start
        assert "programAr9565StationMac(" in start
        assert (
            start.index("programAr9565StationMac(")
            < start.index("memcpy(&stationMac_[0], selected")
            < start.index("stationMacProgrammed_ = true;")
        )
        stop = method(
            "void stopHardware(", "static IOReturn prepareFreshStartAction("
        )
        assert "memset(&stationMac_[0], 0, sizeof(stationMac_));" in stop
        assert "requestedStationMacValid_ = false" not in stop
        assert "memset(&requestedStationMac_" not in stop


if __name__ == "__main__":
    unittest.main()
