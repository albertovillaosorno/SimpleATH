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
#   - Source regression for native key-update queue admission and unwind.
# - Must-Not:
#   - Claim physical DMA isolation or real WPA2/RF operation.
# - Allows:
#   - Inputs: reviewed native queue and controller implementation source.
#   - Outputs: deterministic key-update admission ordering assertions.
#   - Side effects: none beyond reading repository source.
# - Split-When:
#   - A native kernel harness can exercise the actual work-loop transitions.
# - Merge-When:
#   - Queue admission is covered by an equivalent kernel regression.
# - Summary:
#   - Keep public queue startup from bypassing a borrowed WPA2 key lease.
# - Description:
#   - Guard an isolated queue until its exclusive restart has finished.
# - Usage:
#   - Run via offline unittest discovery and tools/validate.py.
# - Defaults:
#   - Missing guards or cleanup paths fail the source regression.
#
# Module: Native key-update queue admission regression.
"""Assert a WPA2 key-write lease cannot be bypassed by public RX start."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
QUEUE = (ROOT / "src/platform/Ar9565NativeQueues.cpp").read_text(
    encoding="utf-8"
)
OWNER = (ROOT / "src/SimpleATH.cpp").read_text(encoding="utf-8")


def body(start: str, stop: str) -> str:
    """Select a single native method without neighboring method guards."""
    return QUEUE.split(start, 1)[1].split(stop, 1)[0]


class NativeKeyUpdateQueueWiring(unittest.TestCase):
    """Prevent reentrant queue activation across protected RX key writes."""

    def test_public_start_refuses_isolated_and_borrowed_queues(self) -> None:
        start = body(
            "IOReturn NativeQueues::startGated()",
            "bool NativeQueues::isolateHardwareGated()",
        )
        preflight = start.split("phase_ = NativeQueuePhase::Running", 1)[0]
        self.assertIn("keyUpdateIsolated_", preflight)
        self.assertIn("keyUpdateRestartPending_", preflight)
        self.assertIn("inReceiveCallback_", preflight)
        self.assertIn("inInterruptService_", preflight)
        self.assertNotIn("keyUpdateIsolated_ = false", preflight)
        self.assertNotIn("keyUpdateRestartPending_ = false", preflight)

    def test_private_restart_releases_lease_only_after_borrowers_exit(
        self,
    ) -> None:
        restart = body(
            "IOReturn NativeQueues::restartAfterKeyUpdateGated()",
            "IOReturn NativeQueues::endKeyUpdateGated()",
        )
        self.assertIn("inReceiveCallback_ || inInterruptService_", restart)
        success = restart.split("clearQuiescedBuffers();", 1)[1]
        self.assertLess(
            success.index("keyUpdateIsolated_ = false;"),
            success.index("startGated();"),
        )
        self.assertLess(
            success.index("keyUpdateRestartPending_ = false;"),
            success.index("startGated();"),
        )
        self.assertIn("phase_ == NativeQueuePhase::Prepared", restart)
        self.assertIn("phase_ = NativeQueuePhase::Quarantined;", restart)
        self.assertIn("callbacks_.fault(", restart)

    def test_native_owner_preserves_initial_start_lease_gate(self) -> None:
        owner = OWNER.split("static IOReturn activatePreparedQueuesAction(", 1)[
            1
        ]
        owner = owner.split("static IOReturn failedQueueStartAction(", 1)[0]
        self.assertLess(
            owner.index("!self.queues_.initialStartEligibleGated()"),
            owner.index("self.queues_.startGated()"),
        )
