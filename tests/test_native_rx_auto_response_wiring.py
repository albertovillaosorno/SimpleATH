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
#   - Source-level receive-only EDMA automatic-response guard tests.
# - Must-Not:
#   - Claim macOS execution, physical ACK suppression or RF readiness.
# - Allows:
#   - Inputs: stable native queue and portable MAC source boundaries.
#   - Outputs: fail-closed callback and MMIO admission ordering assertions.
#   - Side effects: no hardware, kernel or filesystem mutation.
# - Split-When:
#   - A real kernel harness can exercise automatic-response registers.
# - Merge-When:
#   - Native queue integration has direct reproducible hardware tests.
# - Summary:
#   - Prevent receive-only startup from bypassing self-generated TX checks.
# - Description:
#   - Verifies two MMIO readback guards before bus/IRQ enable.
# - Usage:
#   - Run through the default offline Python unittest discovery.
# - Defaults:
#   - Missing or reordered guards fail the source-level check.
#
# Module: Native receive-only EDMA automatic-response admission regression.
"""Check native receive-only MMIO guard ordering without a real radio."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUEUE = (ROOT / "src/platform/Ar9565NativeQueues.cpp").read_text(
    encoding="utf-8"
)
MAC = (ROOT / "src/hardware/Ar9565MacControl.cpp").read_text(encoding="utf-8")


class ReceiveOnlyAutomaticResponseWiring(unittest.TestCase):
    @staticmethod
    def test_two_live_checks_before_dma_and_interrupt_enable() -> None:
        start = QUEUE.split("IOReturn NativeQueues::startGated()", 1)[1].split(
            "bool NativeQueues::isolateHardwareGated()", 1
        )[0]
        check = "!receiveOnlyAutoResponsesBlockedGated()"
        assert start.count(check) == 2
        assert start.index("!callbacks_.radioReady(") < start.index(
            "!callbacks_.setBusMaster"
        )
        assert (
            start.index(check)
            < start.index("callbacks_.setBusMaster(callbacks_.context, true)")
            < start.rindex(check)
            < start.index("interrupt_->enable();")
            < start.index("write(kIer, 1)")
        )
        # Both denials quarantine an in-progress hardware startup.
        assert start.count("fault(kIOReturnNotReady);") == 2
        assert "return kIOReturnNotReady;" in start

    @staticmethod
    def test_physical_readback_revalidates_epoch_and_requires_zero() -> None:
        guard = QUEUE.split(
            "bool NativeQueues::receiveOnlyAutoResponsesBlockedGated() const", 1
        )[1].split("IOReturn NativeQueues::startGated()", 1)[0]
        assert "if (!gated() || callbacks_.radioReady == nullptr)" in guard
        assert "verifyAr9565ReceiveOnlyAutoResponsesDisabled(" in guard
        assert "bus, epoch_, callbacks_.radioReady" in guard

        helper = MAC.split(
            "MacReceiveOnlyResult verifyAr9565ReceiveOnlyAutoResponsesDisabled(",
            1,
        )[1].split("MacIdentityProgress", 1)[0]
        assert "0x832c" in helper
        assert (
            "bus.barLengthBytes < kSelfGeneratedMask + sizeof(uint32_t)"
            in helper
        )
        assert helper.count("!permit(bus.context, epoch)") == 2
        assert (
            helper.index("!permit(bus.context, epoch)")
            < helper.index("bus.read32(bus.context, kSelfGeneratedMask, &mask)")
            < helper.rindex("!permit(bus.context, epoch)")
            < helper.index("return mask == 0 ? MacReceiveOnlyResult::Ok")
        )
        assert "mask == UINT32_MAX" in helper
        assert "MacReceiveOnlyResult::AutoResponsesEnabled" in helper
