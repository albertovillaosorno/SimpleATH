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
#   - Offline integration checks for native link-loss hardware retirement.
# - Must-Not:
#   - Claim runtime key erasure, test physical DMA, or replace kernel tests.
# - Allows:
#   - Inputs: repository-native implementation source and fixed call anchors.
#   - Outputs: source wiring assertions for terminal WPA2 failures and faults.
#   - Side effects: no hardware, network, or filesystem mutation.
# - Split-When:
#   - A real kernel harness can exercise these callbacks with device evidence.
# - Merge-When:
#   - The existing native owner can absorb the trace checks directly.
# - Summary:
#   - Terminal protected TX failures must use the native retire path.
# - Description:
#   - Source-only checks compensate for unavailable Tahoe kernel headers.
# - Usage:
#   - Run through the default offline host test discovery.
# - Defaults:
#   - A missing call site or unexpected fallback fails the trace.
#
# Module: Source-only native link-loss/CCMP retirement wiring regressions.
"""Check guarded source call paths; never substitute for physical tests."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWNER = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
QUEUE = (ROOT / "src/platform/Ar9565NativeQueues.cpp").read_text(
    encoding="utf-8"
)
POLICY = (ROOT / "src/platform/NativeLinkRetirement.hpp").read_text(
    encoding="utf-8"
)


def body(source: str, before: str, after: str) -> str:
    """Bound a source-only call chain by unique, checked function anchors."""
    assert source.count(before) == 1, before
    tail = source.split(before, 1)[1]
    assert tail.count(after) >= 1, after
    return tail.split(after, 1)[0]


class NativeLinkRetirementWiring(unittest.TestCase):
    """Prevent software-only teardown from returning to terminal TX paths."""

    @staticmethod
    def test_protected_completion_failure_retires_hardware() -> None:
        completion = body(
            OWNER,
            "static void\n        queueTransmitted(",
            "static void queueFault(",
        )
        assert completion.count("self.retireNativeLink(kIOReturnIOError);") == 2
        assert "self.failNativeJoin(" not in completion
        assert "self.queues_.phase() ==" in completion
        assert "simpleath::NativeQueuePhase::Running" in completion
        assert (
            "simpleath::tahoe::WirelessEvent::TransmitAvailable" in completion
        )

    @staticmethod
    def test_early_management_tx_denial_retires_hardware() -> None:
        # M2/M4 denial must isolate live DMA after WPA2 state advances.
        response = body(
            OWNER,
            "bool sendNativeManagementResponse(",
            "static void queueReceived(",
        )
        assert (
            "simpleath::ieee80211::ActionKind::TransmitAssociation" in response
        )
        assert "simpleath::ieee80211::ActionKind::TransmitEapol" in response
        failed_submit = body(
            response,
            "if (submitted != kIOReturnSuccess)",
            "else if (action.kind ==",
        )
        assert "self.retireNativeLink(submitted);" in failed_submit
        assert "self.engine_.radioStopped(" not in failed_submit
        assert "self.failNativeJoin(" not in failed_submit

    @staticmethod
    def test_rekey_failure_and_deferred_reply_revoke_hardware() -> None:
        rekey = body(
            OWNER,
            "void finishNativeDriverGroup1(",
            "void receiveNativeDriverMsdu(",
        )
        assert "retireNativeLink(kIOReturnNotReady);" in rekey
        lease = body(
            OWNER,
            "finishNativeRxKeyLease(simpleath::ieee80211::EngineResult result,",
            "observeNativeAssociatedBeacon(",
        )
        assert "self.retireNativeLink(leaseEnd);" in lease
        deferred = body(
            OWNER,
            "static void queueKeyUpdateResumed(",
            "static void queueInterrupt(",
        )
        assert "self.retireNativeLink(result);" in deferred

    @staticmethod
    def test_key_update_failure_quarantines_isolated_dma() -> None:
        queue = body(
            QUEUE,
            "bool NativeQueues::retireLinkGated()",
            "bool NativeQueues::linkRetirementIsolatedGated()",
        )
        # After M3 key installation DMA is Prepared, not Running.
        assert "phase_ == NativeQueuePhase::Prepared &&" in queue
        assert "keyUpdateIsolated_" in queue
        assert "phase_ = NativeQueuePhase::Quarantined;" in queue
        lease = body(
            OWNER,
            "finishNativeRxKeyLease(simpleath::ieee80211::EngineResult result,",
            "observeNativeAssociatedBeacon(",
        )
        assert "self.retireNativeLink(kIOReturnNotReady);" in lease
        assert lease.index(
            "self.retireNativeLink(kIOReturnNotReady);"
        ) < lease.index("self.queues_.endKeyUpdateGated();")

    @staticmethod
    def test_driver_m4_requires_deferred_completion_tracking() -> None:
        immediate = body(
            OWNER,
            "bool sendNativeManagementResponse(",
            "static void queueReceived(",
        )
        assert "self.retireNativeLink(kIOReturnNotReady);" in immediate
        assert "HardwareKeysInstalled" in immediate
        deferred = body(
            OWNER,
            "static void queueKeyUpdateResumed(",
            "static void queueInterrupt(",
        )
        assert "self.nativePairwiseTx_.installed()" in deferred
        assert "self.nativePairwiseRx_.installed()" in deferred
        assert "self.nativeGroupInstalled()" in deferred
        assert deferred.index("self.nativeGroupInstalled()") < deferred.index(
            "self.submitPreparedTransmit("
        )

    @staticmethod
    def test_device_fault_latches_reset_before_software_cleanup() -> None:
        fault = body(
            OWNER,
            "static void queueFault(",
            "static void queueKeyUpdateResumed(",
        )
        assert "self.keyCache_.requiresReset = true;" in fault
        assert (
            'self.setProperty("SimpleATHKeyCacheResetRequired", true);' in fault
        )
        assert fault.index("self.queues_.stopGated(") < fault.index(
            "self.engine_.radioStopped("
        )

    @staticmethod
    def test_explicit_power_on_requires_fresh_epoch_after_retirement() -> None:
        # The child power-on request goes through the serialized PCI owner.
        power = body(OWNER, "static IOReturn ownerSetPower(",
                     "static IOReturn\n        ownerSetMac(")
        assert "return self.startClient();" in power
        start = body(OWNER, "IOReturn startClient()",
                     "void releaseQueuesClient()")
        assert start.index("prepareFreshStartAction") < start.index(
            "queues_.releaseClient();"
        ) < start.index("gate_->runAction(startAction)")
        assert "result == kIOReturnSuccess && releaseRetiredQueues" in start
        assert "if (result == kIOReturnSuccess)" in start
        assert "IOReturn result = gate_->runAction(startAction);" not in start
        recovery = body(OWNER, "static IOReturn prepareFreshStartAction(",
                        "static IOReturn startAction(")
        assert "simpleath::NativeQueuePhase::Quarantined" in recovery
        assert "self.keyCache_.requiresReset" in recovery
        assert "mapped && !self.queuesAdopted_" in recovery
        assert "self.stopHardware(simpleath::ProviderAccess::Available);" in recovery
        assert recovery.index("self.stopHardware(") < recovery.index(
            "release = mapped;"
        )
        assert "if (!self.powered_ &&" in recovery
        assert "return kIOReturnNotReady;" in recovery

    @staticmethod
    def test_fault_detached_queue_retries_isolation_before_release() -> None:
        # A fault already detached IRQ ownership; stopping must still try
        # physical isolation before allowing releaseClient to free DMA.
        stop = body(OWNER, "void stopHardware(simpleath::ProviderAccess access)",
                    "static IOReturn prepareFreshStartAction(")
        assert "queues_.phase() == simpleath::NativeQueuePhase::Quarantined" in stop
        assert "queues_.stopGated(access ==" in stop
        assert stop.index("queues_.stopGated(") < stop.index("session_.stop(access);")
        queue = body(QUEUE, "bool NativeQueues::stopGated(bool available)",
                     "IOReturn NativeQueues::releaseClient()")
        assert "phase_ = isolated ? NativeQueuePhase::Prepared" in queue
        assert "NativeQueuePhase::Quarantined" in queue
        released = body(QUEUE, "IOReturn NativeQueues::releaseClient()",
                        "} // namespace simpleath")
        assert "phase_ == NativeQueuePhase::Quarantined" in released
        assert "return kIOReturnBusy;" in released

    @staticmethod
    def test_terminal_queue_cannot_erase_with_pending_transmit() -> None:
        retire = body(
            QUEUE,
            "bool NativeQueues::retireLinkGated()",
            "bool NativeQueues::linkRetirementIsolatedGated()",
        )
        assert "const bool noOutstandingTransmit = !txPending_;" in retire
        assert "const bool isolated = isolateHardwareGated();" in retire
        assert "phase_ = NativeQueuePhase::Quarantined;" in retire
        assert (
            "linkRetirementIsolated_ = isolated && noOutstandingTransmit;"
            in retire
        )
        assert POLICY.index(
            "out.queueIsolated = backend.isolate("
        ) < POLICY.index("out.hardwareKeysErased =")


if __name__ == "__main__":
    _ = unittest.main()
