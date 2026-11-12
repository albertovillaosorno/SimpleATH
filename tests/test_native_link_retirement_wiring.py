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


class NativeLocalLeaveWiring(unittest.TestCase):
    """Trace terminal local-leave TX and bounded retirement contracts."""

    @staticmethod
    def test_local_disassociation_defers_retirement_until_edma_completion() -> (
        None
    ):
        leave = body(
            OWNER,
            "static IOReturn ownerDisconnectAction(",
            "static IOReturn ownerDisconnect(",
        )
        assert leave.index(
            "if (self.pendingLocalLeaveToken_ != 0)"
        ) < leave.index("simpleath::ieee80211::makeDisassociationRequest(")
        assert leave.index(
            "if (!self.queues_.hasTransmitSpace())"
        ) < leave.index("const uint64_t token = self.nextTransmitToken_;")
        assert (
            leave.index("const uint64_t token = self.nextTransmitToken_;")
            < leave.index("self.submitPreparedTransmit(")
            < leave.index("if (sent != kIOReturnSuccess)")
            < leave.index("self.pendingLocalLeaveToken_ = token;")
        )
        assert (
            leave.index("self.pendingLocalLeaveToken_ = token;")
            < leave.index("self.controlledPortAuthorized_ = false;")
            < leave.index("self.joinStatus_ = kIOReturnAborted;")
        )
        assert "self.pendingLocalLeaveEpoch_ = self.epoch_;" in leave
        assert "self.linkTimer_->setTimeoutMS(kNativeLinkWatchdogMs)" in leave
        # An unsuccessful timer arm is a terminal fallback. No unconditional
        # retirement may cancel the just-submitted on-air management frame.
        assert leave.count("self.retireNativeLink(") == 1
        assert leave.index("if (self.linkTimer_ == nullptr") < leave.index(
            "self.retireNativeLink(kIOReturnNotReady);"
        )

    @staticmethod
    def test_local_leave_completion_owns_terminal_hardware_retirement() -> None:
        queue = body(
            QUEUE,
            "void NativeQueues::transmitCompleted()",
            "void NativeQueues::serviceInterruptGated()",
        )
        assert queue.index("txPending_ = false;") < queue.index(
            "callbacks_.transmitted(callbacks_.context, token, status);"
        )
        completion = body(
            OWNER,
            "static void\n        queueTransmitted(",
            "static void queueFault(",
        )
        leave = body(
            completion,
            "if (token != 0 && token == self.pendingLocalLeaveToken_",
            "if (token != 0 && token == self.pendingWpa2Group2Token_)",
        )
        assert "self.pendingLocalLeaveEpoch_ == self.epoch_" in leave
        assert "self.retireNativeLink(" in leave
        assert "status.frameTransmitOk" in leave
        assert "!status.excessiveRetries" in leave
        assert "!status.filtered" in leave
        assert "kIOReturnIOError" in leave
        assert "kIOReturnAborted" in leave

    @staticmethod
    def test_local_leave_watchdog_and_reset_have_bounded_ownership() -> None:
        watchdog = body(
            OWNER, "static void linkTimerFired(", "static void scanTimerFired("
        )
        assert watchdog.index(
            "self.pendingLocalLeaveToken_ != 0"
        ) < watchdog.index("self.engine_.checkBeaconTimeout(")
        assert "self.retireNativeLink(kIOReturnTimeout);" in watchdog
        reset = body(
            OWNER,
            "void failNativeJoin(IOReturn status)",
            "static IOReturn ownerConnectAction(",
        )
        assert "pendingLocalLeaveToken_ = 0;" in reset
        assert "pendingLocalLeaveEpoch_ = 0;" in reset
        assert "linkTimer_->cancelTimeout();" in reset
        terminal = body(
            OWNER,
            "void retireNativeLink(IOReturn reason)",
            "void recordNativeAssociation()",
        )
        assert "failNativeJoin(reason);" in terminal
        fault = body(
            OWNER,
            "static void queueFault(",
            "static void queueKeyUpdateResumed(",
        )
        assert "self.failNativeJoin(result);" in fault
        stop = body(
            OWNER,
            "void stopHardware(simpleath::ProviderAccess access)",
            "static IOReturn prepareFreshStartAction(",
        )
        assert "failNativeJoin(kIOReturnNotReady);" in stop

    @staticmethod
    def test_pending_local_leave_closes_all_software_radio_admission() -> None:
        snapshot = body(
            OWNER,
            "static IOReturn ownerSnapshotAction(",
            "static IOReturn ownerSnapshot(",
        )
        assert "self.pendingLocalLeaveToken_ == 0 && liveRfKill" in snapshot
        scan = body(
            OWNER,
            "static IOReturn ownerBeginScanAction(",
            "static IOReturn ownerBeginScan(",
        )
        assert "self.pendingLocalLeaveToken_ != 0" in scan
        transmit = body(
            OWNER,
            "bool canSubmitTransmit()",
            "IOReturn submitPreparedTransmit(",
        )
        assert "pendingLocalLeaveToken_ == 0" in transmit
        keys = body(
            OWNER,
            "static IOReturn ownerInstallKeyAction(",
            "static IOReturn\n        ownerInstallKey(",
        )
        assert "self.pendingLocalLeaveToken_ != 0" in keys
        port = body(
            OWNER,
            "static IOReturn ownerAuthorizePortAction(",
            "static IOReturn ownerAuthorizePortScopedAction(",
        )
        assert "self.pendingLocalLeaveToken_ != 0" in port
        receive = body(
            OWNER,
            "static void queueReceived(",
            "static void\n        queueTransmitted(",
        )
        assert "self.pendingLocalLeaveToken_ != 0" in receive


class NativeReceiveDeadlineWiring(unittest.TestCase):
    """Trace native RX clock admission before packet and key routing."""

    @staticmethod
    def test_rx_deadlines_before_protected_or_aggregate_delivery() -> None:
        receive = body(
            OWNER,
            "static void queueReceived(",
            "static void\n        queueTransmitted(",
        )
        assert (
            receive.index("const uint64_t receiveNowMs =")
            < receive.index("if (self.portReadyPending_ &&")
            < receive.index("self.engine_.checkBeaconTimeout(")
            < receive.index("self.receiveNativeAwdl(")
            < receive.index("self.routeNativeSecurityRx(")
            < receive.index("self.routeNativeOpenAmsdu(")
            < receive.index("self.engine_.acceptRx(")
        )
        assert "kNativePortOpenTimeoutMs" in receive
        assert "simpleath::ieee80211::ActionKind::LinkLost" in receive
        assert "self.retireNativeLink(kIOReturnTimeout);" in receive
        assert "self.retireNativeLink(kIOReturnNotReady);" in receive


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
    def test_shutdown_serializes_gate_stop_and_dma_release() -> None:
        # A wake/start cannot steal a previous power-off DMA mapping.
        # All three teardown entrypoints use the startup lock.
        power = body(OWNER, "IOReturn setPowerState(", "bool willTerminate(")
        assert "stopClient(ClientStopMode::Suspend);" in power
        assert "startClient();" in power
        terminate = body(
            OWNER,
            "bool willTerminate(",
            "void stop(IOService *provider) override",
        )
        assert "stopClient(ClientStopMode::Terminate);" in terminate
        stop = body(
            OWNER,
            "void stop(IOService *provider) override",
            "void free() override",
        )
        assert "stopClient(ClientStopMode::FinalStop);" in stop
        shutdown = body(
            OWNER,
            "void stopClient(ClientStopMode mode)",
            "static IOReturn adoptQueuesAction(",
        )
        assert (
            shutdown.index("IOLockLock(lifecycle_);")
            < shutdown.index("gate_->runAction(sleepAction)")
            < shutdown.index("queues_.releaseClient();")
            < shutdown.index("IOLockUnlock(lifecycle_);")
        )
        assert "gate_->runAction(terminateAction)" in shutdown
        assert "gate_->runAction(stopAction)" in shutdown
        start = body(
            OWNER, "IOReturn startClient()", "enum class ClientStopMode"
        )
        assert "IOLockLock(lifecycle_);" in start
        assert "IOLockUnlock(lifecycle_);" in start

    @staticmethod
    def test_explicit_power_on_requires_fresh_epoch_after_retirement() -> None:
        # The child power-on request goes through the serialized PCI owner.
        power = body(
            OWNER,
            "static IOReturn ownerSetPower(",
            "static IOReturn\n        ownerSetMac(",
        )
        assert "return self.startClient();" in power
        start = body(
            OWNER, "IOReturn startClient()", "enum class ClientStopMode"
        )
        assert (
            start.index("prepareFreshStartAction")
            < start.index("queues_.releaseClient();")
            < start.index("gate_->runAction(startAction)")
        )
        assert "result == kIOReturnSuccess && releaseRetiredQueues" in start
        assert "if (result == kIOReturnSuccess)" in start
        assert "IOReturn result = gate_->runAction(startAction);" not in start
        recovery = body(
            OWNER,
            "static IOReturn prepareFreshStartAction(",
            "static IOReturn startAction(",
        )
        assert "simpleath::NativeQueuePhase::Quarantined" in recovery
        assert "self.keyCache_.requiresReset" in recovery
        assert "mapped && !self.queuesAdopted_" in recovery
        assert (
            "self.stopHardware(simpleath::ProviderAccess::Available);"
            in recovery
        )
        assert recovery.index("self.stopHardware(") < recovery.index(
            "release = mapped;"
        )
        assert "if (!self.powered_ &&" in recovery
        assert "return kIOReturnNotReady;" in recovery

    @staticmethod
    def test_fault_detached_queue_retries_isolation_before_release() -> None:
        # A fault already detached IRQ ownership; stopping must still try
        # physical isolation before allowing releaseClient to free DMA.
        stop = body(
            OWNER,
            "void stopHardware(simpleath::ProviderAccess access)",
            "static IOReturn prepareFreshStartAction(",
        )
        assert (
            "queues_.phase() == simpleath::NativeQueuePhase::Quarantined"
            in stop
        )
        assert "queues_.stopGated(access ==" in stop
        assert stop.index("queues_.stopGated(") < stop.index(
            "session_.stop(access);"
        )
        queue = body(
            QUEUE,
            "bool NativeQueues::stopGated(bool available)",
            "IOReturn NativeQueues::releaseClient()",
        )
        assert "phase_ = isolated ? NativeQueuePhase::Prepared" in queue
        assert "NativeQueuePhase::Quarantined" in queue
        released = body(
            QUEUE,
            "IOReturn NativeQueues::releaseClient()",
            "} // namespace simpleath",
        )
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
