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
        notify = TRANSPORT.split("void TahoeWirelessTransport::notify(", 1)[1]
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
        notify = TRANSPORT.split("void TahoeWirelessTransport::notify(", 1)[1]
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
    def test_stale_scan_event_requires_finished_physical_dwell() -> None:
        poll = INFRA.split("void SimpleATHInfraProtocol::poll()", 1)[1]
        assert "acceptWirelessScanCompletion(" in poll
        assert "epoch, scanEpoch_, live, state.scanning" in poll
        assert "finishScan(false);" in poll
        assert "eventEpoch == activeScanEpoch && !physicalScanRunning" in EPOCH


if __name__ == "__main__":
    unittest.main()
