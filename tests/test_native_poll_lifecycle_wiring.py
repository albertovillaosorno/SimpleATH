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
#   - Native InfraProtocol poll timer failure source regression.
# - Must-Not:
#   - Claim hardware RF, actual OS event receipt or kernel timer execution.
# - Allows:
#   - Inputs: current native InfraProtocol translation unit.
#   - Outputs: offline assertions for bounded control-plane failure handling.
#   - Side effects: none.
# - Split-When:
#   - A native Tahoe harness can inject actual IOTimerEventSource failures.
# - Merge-When:
#   - A portable lifecycle fixture covers this behavior without IOKit.
# - Summary:
#   - Verify that a lost native poll scheduler retires OS-visible state.
# - Description:
#   - Checks start/rearm failure, down notification and service retirement.
# - Usage:
#   - Discovered by the repository's offline unittest runner.
# - Defaults:
#   - Missing fail-closed wiring is a regression failure.
#
# Module: native poll lifecycle source-only checks.
"""Verify failed native WCL poll scheduling does not strand a live session."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "src/platform/tahoe/SimpleATHInfraProtocol.cpp").read_text(
    encoding="utf-8"
)


def section(start: str, end: str) -> str:
    assert SOURCE.count(start) == 1, start
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class NativePollLifecycleWiring(unittest.TestCase):
    @staticmethod
    def test_failed_initial_timer_arm_rejects_interface_start() -> None:
        start = section(
            "bool SimpleATHInfraProtocol::start(IOService *provider)",
            "void SimpleATHInfraProtocol::stop(IOService *provider)",
        )
        assert (
            "timer_->setTimeoutMS(kPollMilliseconds) != kIOReturnSuccess"
            in start
        )
        assert start.index("packets_.start(this, controller_)") < start.index(
            "timer_->setTimeoutMS(kPollMilliseconds)"
        )
        assert "shutdown();" in start
        assert start.index("shutdown();") < start.rindex("return false;")

    @staticmethod
    def test_lost_periodic_poll_scheduler_retires_native_session() -> None:
        poll = SOURCE.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        assert (
            "timer_->setTimeoutMS(kPollMilliseconds) != kIOReturnSuccess"
            in poll
        )
        assert "shutdown();" in poll
        assert (
            poll.index("packets_.poll();")
            < poll.index("timer_->setTimeoutMS(kPollMilliseconds)")
            < poll.index("shutdown();")
        )

    @staticmethod
    def test_shutdown_revokes_link_and_radio_availability_before_packets() -> (
        None
    ):
        stop = section(
            "void SimpleATHInfraProtocol::shutdown()",
            "IOReturn SimpleATHInfraProtocol::stopAction(",
        )
        assert "linked_ = false;" in stop
        assert "available_ = false;" in stop
        assert "setLinkState(" in stop
        assert (
            "emit(kDriverAvailableEvent, availability, sizeof(availability))"
            in stop
        )
        assert stop.index("linked_ = false;") < stop.index("packets_.stop();")
        assert stop.index("available_ = false;") < stop.index(
            "packets_.stop();"
        )
        assert "controller_->scanCancel(scanGeneration_);" in stop
        assert "finishScan(true);" in stop
        assert "retireJoin(kIOReturnAborted, 3);" in stop


if __name__ == "__main__":
    unittest.main()
