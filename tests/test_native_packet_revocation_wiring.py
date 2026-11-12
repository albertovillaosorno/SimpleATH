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
#   - Source-only native packet enable lease retirement regressions.
# - Must-Not:
#   - Claim OS network access, hardware receive or physical join behavior.
# - Allows:
#   - Inputs: existing InfraProtocol native WCL source.
#   - Outputs: bounded source-wiring assertions for explicit packet revocation.
#   - Side effects: none.
# - Split-When:
#   - A native Skywalk harness can inject a failed station leave.
# - Merge-When:
#   - Shared native request lifecycle tests cover this source contract.
# - Summary:
#   - Reject stale Skywalk enable across leave and same-epoch AP retirement.
# - Description:
#   - Verify data-request intent is revoked before the next poll admission.
# - Usage:
#   - Run through offline Python unittest discovery.
# - Defaults:
#   - Stale packet-intent retention is a test failure.
#
# Module: WCL packet intent revocation regression.
"""Verify old OS packet enables cannot revive a retired association."""

from pathlib import Path
import unittest

SOURCE = (
    Path(__file__).resolve().parent.parent
    / "src/platform/tahoe/SimpleATHInfraProtocol.cpp"
).read_text(encoding="utf-8")


def section(start: str, end: str) -> str:
    assert SOURCE.count(start) == 1, start
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class NativePacketRevocationWiring(unittest.TestCase):
    @staticmethod
    def test_explicit_leave_revokes_data_request_before_provider_call() -> None:
        leave = section(
            "IOReturn SimpleATHInfraProtocol::leaveJoin(bool abort)",
            "void SimpleATHInfraProtocol::pollJoin(",
        )
        assert (
            leave.index("dataRequested_ = false;")
            < leave.index("dataRequestEpoch_ = 0;")
            < leave.index("controller_->stationLeave(3);")
        )
        assert "if (result != kIOReturnSuccess)" in leave
        assert "return result;" in leave

    @staticmethod
    def test_terminal_join_state_revokes_old_packet_intent() -> None:
        terminal = section(
            "void SimpleATHInfraProtocol::retireJoin(",
            "IOReturn SimpleATHInfraProtocol::leaveJoin(",
        )
        assert "dataRequested_ = false;" in terminal
        assert "dataRequestEpoch_ = 0;" in terminal
        observed = section(
            "void SimpleATHInfraProtocol::pollJoin(",
            "IOReturn SimpleATHInfraProtocol::beginScan(",
        )
        failed = observed.split(
            "if ((notices & (FailureNotice | DisconnectionNotice)) != 0)", 1
        )[1]
        assert "dataRequested_ = false;" in failed
        assert "dataRequestEpoch_ = 0;" in failed
        assert failed.index("dataRequested_ = false;") < failed.index(
            "packets_.disable();"
        )

    @staticmethod
    def test_new_join_preserves_preassociation_packet_demand() -> None:
        join = section(
            "IOReturn SimpleATHInfraProtocol::beginJoin(",
            "void SimpleATHInfraProtocol::emitJoin(",
        )
        assert "packets_.disable();" in join
        # A fresh join may consume an early WCL enable request; only a
        # retired join/explicit leave revokes the old OS authorization.
        assert "dataRequested_ = false;" not in join
        poll = SOURCE.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        assert (
            "nativePacketAdmission(state, dataRequested_, dataRequestEpoch_)"
            in poll
        )


if __name__ == "__main__":
    unittest.main()
