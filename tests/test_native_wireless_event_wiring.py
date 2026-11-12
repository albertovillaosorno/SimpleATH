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
#   - Offline source wiring assertions for Tahoe native radio notifications.
# - Must-Not:
#   - Claim device RF scans, native events, or a verified macOS ABI.
# - Allows:
#   - Inputs: current Tahoe production source and portable event policy.
#   - Outputs: deterministic integration assertions.
#   - Side effects: no hardware, kernel, or network operations.
# - Split-When:
#   - A native IOKit mailbox harness can run under an authorized SDK.
# - Merge-When:
#   - The portable host regression covers the event ring policy directly.
# - Summary:
#   - Verify that the native event mailbox never drops terminal scan notices.
# - Description:
#   - Checks event retention and physical scan completion source boundaries.
# - Usage:
#   - Executed through Python unit test discovery.
# - Defaults:
#   - Missing policy or stale event checks fail closed.
#
# Module: Tahoe native wireless event wiring source regression.
"""Check production event callbacks invoke the portable completion policy."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
TRANSPORT = (ROOT / "src/platform/tahoe/TahoeWirelessTransport.cpp").read_text(
    encoding="utf-8"
)
INFRA = (ROOT / "src/platform/tahoe/SimpleATHInfraProtocol.cpp").read_text(
    encoding="utf-8"
)
OWNER = (ROOT / "src/platform/tahoe/NativeWirelessOwner.hpp").read_text(
    encoding="utf-8"
)
EPOCH = (ROOT / "src/platform/tahoe/NativeWirelessEpoch.hpp").read_text(
    encoding="utf-8"
)


class NativeSnapshotFailureWiring(unittest.TestCase):
    @staticmethod
    def test_failed_provider_snapshot_revokes_cached_receive_admission() -> (
        None
    ):
        sample = TRANSPORT.split(
            "IOReturn TahoeWirelessTransport::snapshot(WirelessSnapshot &out)",
            1,
        )[1].split("IOReturn TahoeWirelessTransport::setPower(bool on)", 1)[0]
        failed = sample.split(
            "if (result != kIOReturnSuccess || (current.epoch == 0U))", 1
        )[1].split("const uint64_t currentAssociation", 1)[0]
        for required in (
            "IOLockLock(mailboxLock_);",
            "receiveAuthorized_ = false;",
            "eapolReceiveAuthorized_ = false;",
            "associationGeneration_ = 0;",
            "receiveHead_ = receiveCount_ = 0;",
            "memset(&frames_[0], 0, sizeof(frames_));",
            "IOLockUnlock(mailboxLock_);",
        ):
            assert required in failed, required
        assert failed.index("receiveAuthorized_ = false;") < failed.index(
            "IOLockUnlock(mailboxLock_);"
        )
        assert failed.index("memset(&frames_[0]") < failed.index(
            "return result == kIOReturnSuccess"
        )
        # A transient lost snapshot must not throw away outstanding scan
        # completions or mailbox event notifications.
        assert "invalidateMailboxes();" not in failed


class NativePowerOffAdmissionWiring(unittest.TestCase):
    @staticmethod
    def test_failed_power_off_keeps_receive_and_snapshot_revoked() -> None:
        header = (
            ROOT / "src/platform/tahoe/TahoeWirelessTransport.hpp"
        ).read_text(encoding="utf-8")
        assert "bool powerOffRequested_ {false};" in header
        power = TRANSPORT.split(
            "IOReturn TahoeWirelessTransport::setPower(bool on)", 1
        )[1].split("TahoeWirelessTransport::setMac(", 1)[0]
        before = power.split("owner_.setPower(owner_.context, on);", 1)[0]
        for required in (
            "if (!on)",
            "IOLockLock(mailboxLock_);",
            "powerOffRequested_ = true;",
            "receiveAuthorized_ = false;",
            "eapolReceiveAuthorized_ = false;",
            "associationGeneration_ = 0;",
            "receiveHead_ = receiveCount_ = 0;",
            "memset(&frames_[0], 0, sizeof(frames_));",
            "IOLockUnlock(mailboxLock_);",
        ):
            assert required in before, required
        assert before.index("powerOffRequested_ = true;") < before.index(
            "memset(&frames_[0]"
        )
        assert "invalidateMailboxes();" not in before
        # A failed stop does not lift the power-off latch, and the existing
        # successful-stop branch still retires all old scan/receive tickets.
        assert "if (result == kIOReturnSuccess && !on)" in power
        success_on = power.split(
            "else if (result == kIOReturnSuccess && on)", 1
        )[1].split("return result;", 1)[0]
        assert "powerOffRequested_ = false;" in success_on
        assert "powerOffRequested_ = false;" not in before
        assert (
            "powerOffRequested_ = false;"
            not in power.split("if (result == kIOReturnSuccess && !on)", 1)[
                1
            ].split("else if (result == kIOReturnSuccess && on)", 1)[0]
        )
        snapshot = TRANSPORT.split(
            "IOReturn TahoeWirelessTransport::snapshot(WirelessSnapshot &out)",
            1,
        )[1].split("IOReturn TahoeWirelessTransport::setPower(bool on)", 1)[0]
        assert (
            "if (powerOffRequested_ ||\n"
            "                !acceptWirelessSnapshot("
        ) in snapshot
        assert snapshot.index(
            "IOLockLock(mailboxLock_);",
            snapshot.index("const IOReturn result = owner_.snapshot"),
        ) < snapshot.index("if (powerOffRequested_ ||")
        bind = TRANSPORT.split("IOReturn TahoeWirelessTransport::bind(", 1)[1]
        bind = bind.split("void TahoeWirelessTransport::unbind()", 1)[0]
        assert "powerOffRequested_ = false;" in bind


class NativePollEventSequencingWiring(unittest.TestCase):
    @staticmethod
    def test_state_changes_refresh_before_wcl_notices_or_skywalk() -> None:
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        drain = poll.index(
            "controller_->nextRadioEvent(event, epoch, generation)"
        )
        refresh = poll.index("if (stateChanged)")
        project = poll.index("const bool available =")
        join = poll.index("pollJoin(state, live);")
        link = poll.index("const bool link = available")
        packets = poll.index("nativePacketAdmission(state,")
        assert drain < refresh < project < join < link < packets
        assert "wirelessEventInvalidatesSnapshot(event)" in poll[:refresh]
        assert (
            "live = controller_->radioSnapshot(state) == kIOReturnSuccess;"
            in (poll[refresh:project])
        )
        assert "state = {};" in poll[refresh:project]
        assert "event == WirelessEvent::ScanFinished" in poll[:refresh]
        assert "completedEpoch = epoch;" in poll[:refresh]
        assert "completedGeneration = generation;" in poll[:refresh]
        assert "WirelessEvent::ProviderStopped;" in EPOCH
        assert "event == WirelessEvent::ProviderStopped" in EPOCH
        assert "event == WirelessEvent::TransmitAvailable" not in poll
        # The physical retry may enqueue SCAN_DONE on the same poll, and the
        # completion is accepted only after the refreshed scan-running check.
        assert poll.index("retryScanCompletion();") < drain
        assert refresh < poll.index("acceptWirelessScanCompletion(")
        assert "scanEpoch_, scanGeneration_," in poll
        assert "scanEpoch_,scanGeneration_,live,state.scanning)" in "".join(
            poll.split()
        )

    @staticmethod
    def test_radio_unavailable_aborts_same_epoch_scan() -> None:
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        offline = poll.split("if (!available || state.epoch != lastEpoch_)", 1)[
            1
        ]
        offline = offline.split("// Revocation is sticky", 1)[0]
        assert (
            "scanGeneration_ != 0 && (!available || scanEpoch_ != state.epoch)"
            in (offline)
        )
        assert offline.index("controller_->scanCancel(scanGeneration_);") < (
            offline.index("finishScan(true);")
        )
        assert offline.index("finishScan(true);") < (
            offline.index("lastEpoch_ = live ? state.epoch : 0;")
        )
        assert poll.index("if (stateChanged)") < poll.index(
            "if (!available || state.epoch != lastEpoch_)"
        )
        assert poll.index("finishScan(true);") < poll.index(
            "acceptWirelessScanCompletion("
        )


class NativeWirelessEventWiring(unittest.TestCase):
    @staticmethod
    def test_event_abi_remains_shared_and_ordered() -> None:
        assert '#include "NativeWirelessEpoch.hpp"' in OWNER
        assert EPOCH.count("enum class WirelessEvent : uint32_t") == 1
        declarations = EPOCH.split("enum class WirelessEvent : uint32_t", 1)[1]
        declarations = declarations.split("};", 1)[0]
        expected = (
            "RadioChanged",
            "ScanFinished",
            "AssociationChanged",
            "LinkChanged",
            "TransmitAvailable",
            "ProviderStopped",
        )
        assert [
            line.strip().rstrip(",")
            for line in declarations.splitlines()
            if line.strip().endswith(",")
        ] == list(expected)

    @staticmethod
    def test_terminal_event_clears_saturated_mailbox() -> None:
        notify = TRANSPORT.split("IOReturn TahoeWirelessTransport::notify(", 1)[
            1
        ]
        notify = notify.split("void TahoeWirelessTransport::receive(", 1)[0]
        terminal = notify.split(
            "if (event == WirelessEvent::ProviderStopped)", 1
        )[1]
        terminal = terminal.split(
            "if (event == WirelessEvent::ScanFinished", 1
        )[0]
        assert "self.providerStopped_ = true;" in terminal
        assert "self.epoch_ = 0;" in terminal
        assert "self.invalidateMailboxes();" in terminal
        assert notify.index(
            "self.invalidateMailboxes();",
            notify.index("if (event == WirelessEvent::ProviderStopped)"),
        ) < notify.index("if (self.eventCount_ == kEventCapacity)")

    @staticmethod
    def test_scan_completion_preempts_noise_not_other_completions() -> None:
        notify = TRANSPORT.split("IOReturn TahoeWirelessTransport::notify(", 1)[
            1
        ]
        notify = notify.split("void TahoeWirelessTransport::receive(", 1)[0]
        assert (
            "evictWirelessNoncriticalEvent(self.events_, self.eventHead_,"
            in notify
        )
        assert notify.index("--self.eventCount_;") < notify.index(
            "if (self.eventCount_ == kEventCapacity)"
        )
        assert "ring[index].event == WirelessEvent::ScanFinished" in EPOCH
        assert "ring[index].event == WirelessEvent::ProviderStopped" in EPOCH

    @staticmethod
    def test_saturated_terminal_events_retire_only_older_generation() -> None:
        notify = TRANSPORT.split("IOReturn TahoeWirelessTransport::notify(", 1)[
            1
        ]
        notify = notify.split("void TahoeWirelessTransport::receive(", 1)[0]
        assert "evictWirelessSupersededScanEvent(" in notify
        assert "self.eventCount_, epoch," in notify
        assert "evictWirelessSupersededScanEvent(self.events_," in notify
        assert "generation)))" in notify
        assert "evictWirelessNoncriticalEvent(" in notify
        assert notify.index("evictWirelessNoncriticalEvent(") < notify.index(
            "evictWirelessSupersededScanEvent("
        )
        assert "ring[index].event != WirelessEvent::ScanFinished" in EPOCH
        assert "ring[index].generation >= currentGeneration" in EPOCH

    @staticmethod
    def test_generation_qualified_scan_completion_on_native_consumer() -> None:
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        assert "nextRadioEvent(event, epoch, generation)" in poll
        assert "acceptWirelessScanCompletion(" in poll
        compact = "".join(poll.split())
        assert (
            "acceptWirelessScanCompletion(completedEpoch,completedGeneration,"
            "scanEpoch_,scanGeneration_,live,state.scanning)"
        ) in compact
        assert "finishScan(false);" in poll
        assert "eventGeneration == activeScanGeneration" in EPOCH
        assert "eventEpoch == activeScanEpoch" in EPOCH
        assert "!physicalScanRunning" in EPOCH

    @staticmethod
    def test_provider_and_mailbox_carry_original_scan_generation() -> None:
        native = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        transport_header = (
            ROOT / "src/platform/tahoe/TahoeWirelessTransport.hpp"
        ).read_text(encoding="utf-8")
        controller = (
            ROOT / "src/platform/tahoe/SimpleATHTahoeController.cpp"
        ).read_text(encoding="utf-8")
        assert '"SimpleATHWirelessOwnerV7"' in OWNER
        assert "kWirelessOwnerAbi = 7;" in OWNER
        assert "WirelessOwnerV7 callbacks" in native
        assert (
            "done.ticket.generation"
            in native.split("IOReturn notifyWirelessScanFinished()", 1)[
                1
            ].split("bool abortActiveNativeScan()", 1)[0]
        )
        assert "*slot = {event, epoch, generation};" in TRANSPORT
        assert "generation = record.generation;" in TRANSPORT
        assert "uint64_t generation;" in transport_header
        assert "takeEvent(event, epoch, generation)" in controller
        assert "(generation != 0U)" in TRANSPORT

    @staticmethod
    def test_rejected_mailbox_notice_remains_retryable() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        body = provider.split("IOReturn notifyWirelessScanFinished()", 1)[1]
        body = body.split("static IOReturn ownerRetryScanCompletionAction", 1)[
            0
        ]
        native = TRANSPORT.split("IOReturn TahoeWirelessTransport::notify(", 1)[
            1
        ]
        native = native.split("void TahoeWirelessTransport::receive(", 1)[0]
        assert "IOReturn (*notify)(void *, WirelessEvent," in OWNER
        assert "IOReturn (*retryScanCompletion)(void *);" in OWNER
        assert (
            "IOReturn (*acknowledgeScanCompletion)(void *, uint64_t epoch,"
            in OWNER
        )
        assert "return kIOReturnNoResources;" in native
        assert "return kIOReturnSuccess;" in native
        assert "result = wirelessNotify_(" in body
        assert "if (result == kIOReturnSuccess)" in body
        assert "notifiedScanGeneration_ = done.ticket.generation;" in body
        assert "acknowledgeCompletion" not in body
        assert "if (notifiedScanGeneration_ == done.ticket.generation)" in body
        assert "return self.notifyWirelessScanFinished();" in provider
        assert "retryScanCompletion(owner_.context)" in TRANSPORT
        assert "self.scanBridge_.acknowledgeCompletion(done.ticket)" in provider
        assert "done.ticket.generation != identity.generation" in provider
        assert "identity.epoch != self.epoch_" in provider

    @staticmethod
    def test_scan_start_pairs_epoch_with_accepted_generation() -> None:
        controller = (
            ROOT / "src/platform/tahoe/SimpleATHTahoeController.cpp"
        ).read_text(encoding="utf-8")
        transport_header = (
            ROOT / "src/platform/tahoe/TahoeWirelessTransport.hpp"
        ).read_text(encoding="utf-8")
        start = TRANSPORT.split(
            "IOReturn TahoeWirelessTransport::startScan(", 1
        )[1]
        start = start.split("IOReturn TahoeWirelessTransport::cancelScan(", 1)[
            0
        ]
        infra_start = INFRA.split("SimpleATHInfraProtocol::beginScan(", 1)[1]
        infra_start = infra_start.split("SimpleATHInfraProtocol::emit(", 1)[0]
        assert "generation = 0;" in start
        assert "epoch = 0;" in start
        assert "NativeScanStartRequest accepted {state.epoch, 0, 0};" in start
        assert "owner_.beginScan(owner_.context, &accepted)" in start
        assert "acceptWirelessScanStart(" in start
        assert (
            "state.epoch, accepted.acceptedEpoch, accepted.generation," in start
        )
        assert "epoch_, providerStopped_" in start
        assert start.index("acceptWirelessScanStart(") < start.index(
            "scanGeneration_ = accepted.generation;"
        )
        assert "generation = accepted.generation;" in start
        assert "epoch = accepted.acceptedEpoch;" in start
        assert "sampledEpoch == acceptedEpoch" in EPOCH
        assert "acceptedEpoch == mailboxEpoch" in EPOCH
        native = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        gate = native.split("static IOReturn ownerBeginScanAction(", 1)[1]
        gate = gate.split("ownerBeginScan(void *context,", 1)[0]
        assert "NativeScanStartRequest" in gate
        assert gate.index("request.requestedEpoch != self.epoch_") < (
            gate.index("self.scanBridge_.beginScan(serial, ticket)")
        )
        assert gate.index("request.acceptedEpoch = self.epoch_;") < (
            gate.index("request.generation = ticket.generation;")
        )
        callback = native.split("ownerBeginScan(void *context,", 1)[1]
        callback = callback.split("static IOReturn ownerCancelScanAction(", 1)[
            0
        ]
        assert "request->acceptedEpoch = 0;" in callback
        assert "request->generation = 0;" in callback
        assert (
            "self.gate_->runAction(ownerBeginScanAction, request)" in callback
        )
        assert (
            "startScan(uint64_t &generation, uint64_t &epoch)"
            in transport_header
        )
        assert "return transport_.startScan(generation, epoch);" in controller
        assert "controller_->scanStart(generation, epoch);" in infra_start
        assert "scanEpoch_ = epoch;" in infra_start
        assert "scanEpoch_ = state.epoch;" not in infra_start

    @staticmethod
    def test_consumer_acks_only_after_os_completion_dispatch() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        controller = (
            ROOT / "src/platform/tahoe/SimpleATHTahoeController.cpp"
        ).read_text(encoding="utf-8")
        finish = INFRA.split("void SimpleATHInfraProtocol::finishScan(", 1)[1]
        finish = finish.split("void SimpleATHInfraProtocol::tick(", 1)[0]
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        assert "const uint64_t completedGeneration = scanGeneration_;" in finish
        assert "const uint64_t completedEpoch = scanEpoch_;" in finish
        assert finish.index(
            "emit(kScanDoneEvent, &status, sizeof(status));"
        ) < (finish.index("controller_->acknowledgeScanCompletion("))
        assert "controller_->retryScanCompletion();" in poll
        assert "scanEpoch_ == state.epoch" in poll
        assert "!state.scanning" in poll
        assert (
            "return transport_.acknowledgeScanCompletion(epoch, generation);"
            in controller
        )
        assert "return transport_.retryScanCompletion();" in controller
        assert "ownerAcknowledgeScanCompletion" in provider
        assert "ownerRetryScanCompletion" in provider
        assert "owner.unsubscribe != nullptr" in TRANSPORT
        assert "owner.retryScanCompletion != nullptr" in TRANSPORT
        assert "owner.acknowledgeScanCompletion != nullptr" in TRANSPORT
        assert "if (!stopping_ && acknowledged != kIOReturnSuccess)" in finish
        assert "pendingScanAckEpoch_ = completedEpoch;" in finish
        assert "pendingScanAckGeneration_ = completedGeneration;" in finish
        assert "controller_->scanCancel(scanGeneration_);" in poll
        assert "pendingScanAckEpoch_," in poll
        assert "pendingScanAckGeneration_)" in poll
        assert "(live && state.epoch != pendingScanAckEpoch_)" in poll

    @staticmethod
    def test_normal_scan_handoff_retries_rejected_provider_ack() -> None:
        finish = INFRA.split("void SimpleATHInfraProtocol::finishScan(", 1)[1]
        finish = finish.split("void SimpleATHInfraProtocol::tick(", 1)[0]
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        normal = finish.split("if (!canceled)", 1)[1]
        assert "emit(kScanDoneEvent, &status, sizeof(status));" in normal
        assert "controller_->acknowledgeScanCompletion(" in normal
        assert "if (!stopping_ && acknowledged != kIOReturnSuccess)" in normal
        assert "if (canceled &&" not in normal
        assert "pendingScanAckEpoch_ = completedEpoch;" in normal
        assert "pendingScanAckGeneration_ = completedGeneration;" in normal
        assert "if (pendingScanAckGeneration_ != 0U)" in poll
        assert "controller_->acknowledgeScanCompletion(" in poll
        assert "pendingScanAckEpoch_," in poll
        assert "pendingScanAckGeneration_)" in poll
        assert "pendingScanAckGeneration_ = 0;" in poll


class NativeWirelessInterruptedScanWiring(unittest.TestCase):
    """An RF interruption must not erase its native completion before ack."""

    @staticmethod
    def test_scan_timer_retains_failed_intent_until_native_ack() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        timer = provider.split("static void scanTimerFired(", 1)[1]
        timer = timer.split("IOReturn notifyWirelessScanFinished()", 1)[0]
        radio_loss = timer.split("if (self.scanEpoch_ != self.epoch_", 1)[1]
        radio_loss = radio_loss.split("const uint64_t now =", 1)[0]
        assert "const bool interrupted = self.abortActiveNativeScan();" in (
            radio_loss
        )
        assert "self.notifyWirelessScanFinished();" in radio_loss
        assert "self.completedScanTicket_ = {};" in radio_loss
        assert "self.scanBridge_.clear();" not in radio_loss
        assert "self.notifiedScanGeneration_ = 0;" not in radio_loss
        assert radio_loss.index("self.notifyWirelessScanFinished();") < (
            radio_loss.index("self.completedScanTicket_ = {};")
        )
        # A failed handoff can still be retried on the same owner epoch.
        retry = provider.split(
            "static IOReturn ownerRetryScanCompletionAction", 1
        )[1]
        retry = retry.split(
            "static IOReturn ownerAcknowledgeScanCompletion", 1
        )[0]
        assert "return self.notifyWirelessScanFinished();" in retry


class NativeWirelessRfLossWiring(unittest.TestCase):
    """Same-epoch radio failures must retain tickets and revoke old BSSes."""

    @staticmethod
    def test_link_retirement_and_dma_fault_keep_pending_scan_identity() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        link = provider.split("void retireNativeLink(IOReturn reason)", 1)[1]
        link = link.split("void recordNativeAssociation()", 1)[0]
        fault = provider.split("static void queueFault(", 1)[1]
        fault = fault.split("static void queueKeyUpdateResumed(", 1)[0]
        for body in (link, fault):
            assert "abortActiveNativeScan();" in body
            assert "notifyWirelessScanFinished();" in body
            assert "completedScanTicket_ = {};" in body
            assert "scanBridge_.clear();" not in body
            assert "notifiedScanGeneration_ = 0;" not in body
            assert body.index("notifyWirelessScanFinished();") < body.index(
                "completedScanTicket_ = {};"
            )

    @staticmethod
    def test_bss_enumeration_rechecks_live_rf_and_queue_lease() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        result = provider.split("static IOReturn ownerNextBssAction(", 1)[1]
        result = result.split("static IOReturn ownerNextBss(", 1)[0]
        assert "!self.radioOperational_" in result
        assert "!self.channelAuthorized_" in result
        assert "!self.liveRfKillUnblocked()" in result
        assert (
            "self.queues_.phase() != simpleath::NativeQueuePhase::Running"
            in (result)
        )
        assert result.index("!self.radioOperational_") < result.index(
            "self.scanBridge_.next(ticket, *request.result)"
        )


class NativeWirelessObserverRebindWiring(unittest.TestCase):
    """Check that a new native listener inherits no orphan scan intent."""

    @staticmethod
    def test_new_observer_retires_orphan_scan_before_registration() -> None:
        provider = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")
        subscribe = provider.split("static IOReturn ownerSubscribeAction(", 1)[
            1
        ]
        subscribe = subscribe.split("static IOReturn ownerSubscribe(", 1)[0]
        assert "const bool vacant = self.wirelessObserver_ == nullptr;" in (
            subscribe
        )
        assert "if (!vacant)" in subscribe
        assert "self.abortActiveNativeScan();" in subscribe
        assert "self.scanBridge_.clear();" in subscribe
        assert "self.completedScanTicket_ = {};" in subscribe
        assert "self.notifiedScanGeneration_ = 0;" in subscribe
        assert subscribe.index("self.abortActiveNativeScan();") < (
            subscribe.index("self.wirelessObserver_ = request.observer;")
        )
        assert subscribe.index("self.scanBridge_.clear();") < (
            subscribe.index("self.wirelessObserver_ = request.observer;")
        )
        unsubscribe = provider.split("static void ownerUnsubscribe(", 1)[1]
        unsubscribe = unsubscribe.split("void notifyWirelessChange(", 1)[0]
        assert "IOLockLock(self.observerLock_);" in unsubscribe
        assert "self.wirelessObserver_ = nullptr;" in unsubscribe
        assert "self.scanBridge_.clear();" not in unsubscribe
        assert "owner_.unsubscribe(owner_.context, this);" in TRANSPORT


if __name__ == "__main__":
    unittest.main()
