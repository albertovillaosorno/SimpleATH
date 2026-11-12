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
#   - Source-level native join deadline and link transition checks.
# - Must-Not:
#   - Claim an actual Tahoe timer, association or physical radio test.
# - Allows:
#   - Inputs: native owner source and bounded, unique method anchors.
#   - Outputs: assertions for timed failure and same-epoch cleanup.
#   - Side effects: no hardware, USB, Wi-Fi or kernel operations.
# - Split-When:
#   - A kernel integration harness can exercise these exact call sites.
# - Merge-When:
#   - A native lifecycle harness can provide stronger behavioral evidence.
# - Summary:
#   - Expire submitted joins without fabricating association success.
# - Description:
#   - Checks native authentication deadline and associated watchdog handoff.
# - Usage:
#   - Run via ordinary offline Python test discovery.
# - Defaults:
#   - Missing or reordered native call paths fail these checks.
#
# Module: Native source-only pending join deadline regressions.
"""Verify native join timeout wiring without running physical radio."""

import unittest
from pathlib import Path

SOURCE = (
    Path(__file__).resolve().parent.parent / "src/SimpleATH.cpp"
).read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    assert SOURCE.count(start) == 1, start
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class NativeJoinDeadlineWiring(unittest.TestCase):
    @staticmethod
    def test_only_physical_authentication_submission_starts_deadline() -> None:
        connect = body(
            "static IOReturn ownerConnectAction(",
            "static IOReturn\n        ownerConnect(",
        )
        assert (
            connect.index("self.submitPreparedTransmit(")
            < connect.index("if (sent != kIOReturnSuccess)")
            < connect.index("self.joinWatchRequestId_ = self.joinRequestId_;")
            < connect.index("self.linkTimer_->setTimeoutMS(")
        )
        assert "kNativeJoinTimeoutMs" in connect
        assert "self.linkWatchEpoch_ = self.epoch_;" in connect
        assert "self.linkWatchAssociationGeneration_ = 0;" in connect
        assert "self.retireNativeLink(kIOReturnNotReady);" in connect
        assert "self.failNativeJoin(sent);" in connect

    @staticmethod
    def test_late_association_cannot_bypass_join_deadline() -> None:
        connect = body(
            "static IOReturn ownerConnectAction(",
            "static IOReturn\n        ownerConnect(",
        )
        assert connect.index("self.submitPreparedTransmit(") < connect.index(
            "self.joinWatchStartedMs_ ="
        )
        association = body(
            "void recordNativeAssociation()", "void receiveNativeAwdl("
        )
        assert (
            association.index("nowMs < joinWatchStartedMs_")
            < association.index("nowMs - joinWatchStartedMs_ >=")
            < association.index("retireNativeLink(kIOReturnTimeout);")
            < association.index("++associationGeneration_;")
            < association.index("joinWatchStartedMs_ = 0;")
        )
        assert "joinWatchRequestId_ != joinRequestId_" in association

    @staticmethod
    def test_pending_deadline_closes_hardware_before_beacon_liveness() -> None:
        fired = body(
            "static void linkTimerFired(", "static void scanTimerFired("
        )
        assert (
            fired.index("self.linkWatchEpoch_ != self.epoch_")
            < fired.index("if (self.joinWatchRequestId_ != 0)")
            < fired.index("self.linkWatchAssociationGeneration_ == 0")
            < fired.index("if (self.pendingLocalLeaveToken_ != 0)")
            < fired.index("self.engine_.checkBeaconTimeout(")
        )
        assert "self.joinEpoch_ != self.epoch_" in fired
        assert "self.joinRequestId_ != self.joinWatchRequestId_" in fired
        assert "self.joinStatus_ != kIOReturnSuccess" in fired
        assert "self.retireNativeLink(kIOReturnTimeout);" in fired
        assert "self.retireNativeLink(kIOReturnNotReady);" in fired

    @staticmethod
    def test_association_switches_same_timer_to_beacon_watchdog() -> None:
        association = body(
            "void recordNativeAssociation()", "void receiveNativeAwdl("
        )
        assert (
            association.index("++associationGeneration_;")
            < association.index("joinWatchRequestId_ = 0;")
            < association.index("linkWatchAssociationGeneration_")
            < association.index("linkTimer_->setTimeoutMS(")
        )
        assert "kNativeLinkWatchdogMs" in association
        assert "retireNativeLink(kIOReturnNotReady);" in association

    @staticmethod
    def test_initial_port_open_has_independent_bounded_deadline() -> None:
        fired = body(
            "static void linkTimerFired(", "static void scanTimerFired("
        )
        assert fired.index("if (self.portReadyPending_ &&") < fired.index(
            "self.engine_.checkBeaconTimeout("
        )
        assert "now < self.portReadyStartedMs_" in fired
        assert (
            "now - self.portReadyStartedMs_ >= kNativePortOpenTimeoutMs"
            in fired
        )
        assert "self.retireNativeLink(kIOReturnTimeout);" in fired
        association = body(
            "void recordNativeAssociation()", "void receiveNativeAwdl("
        )
        assert (
            association.index("portReadyStartedMs_ =")
            < association.index("portReadyPending_ = true;")
            < association.index("linkTimer_->setTimeoutMS(")
        )
        assert "kNativePortOpenTimeoutMs = 15000U;" in SOURCE

    @staticmethod
    def test_late_port_open_does_not_bypass_watchdog() -> None:
        open_port = body(
            "static IOReturn ownerAuthorizePortAction(",
            "static IOReturn ownerAuthorizePortScopedAction(",
        )
        assert (
            open_port.index("nativeControlledPortSecurityReady(")
            < open_port.index("self.verifyNativeAssociationLease(")
            < open_port.index("self.portReadyPending_ = false;")
            < open_port.index("self.controlledPortAuthorized_ = true;")
        )
        verifier = body(
            "IOReturn verifyNativeAssociationLease(uint64_t nowMs)",
            "IOReturn submitPreparedTransmit(",
        )
        # A previously opened port can later be closed during key rotation.
        # Only the initial unopened association has the finite deadline.
        assert "if (portReadyPending_ &&" in verifier
        assert (
            "nowMs - portReadyStartedMs_ >= kNativePortOpenTimeoutMs"
            in verifier
        )
        assert "if (!portReadyPending_ ||" not in verifier
        assert "engine_.checkBeaconTimeout(nowMs, action)" in verifier

    @staticmethod
    def test_failed_join_and_terminal_paths_invalidate_deadline() -> None:
        failed = body(
            "void failNativeJoin(IOReturn status)",
            "static IOReturn ownerConnectAction(",
        )
        assert "linkWatchEpoch_ = 0;" in failed
        assert "linkWatchAssociationGeneration_ = 0;" in failed
        assert "joinWatchRequestId_ = 0;" in failed
        assert "joinWatchStartedMs_ = 0;" in failed
        assert "portReadyStartedMs_ = 0;" in failed
        assert "portReadyPending_ = false;" in failed
        assert "linkTimer_->cancelTimeout();" in failed
        terminal = body(
            "void retireNativeLink(IOReturn reason)",
            "void recordNativeAssociation()",
        )
        assert "failNativeJoin(reason);" in terminal
        fault = body(
            "static void queueFault(", "static void queueKeyUpdateResumed("
        )
        assert "self.failNativeJoin(result);" in fault
        stop = body(
            "void stopHardware(simpleath::ProviderAccess access)",
            "static IOReturn prepareFreshStartAction(",
        )
        assert "failNativeJoin(kIOReturnNotReady);" in stop


if __name__ == "__main__":
    unittest.main()
