// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 rx tsf.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for ar9565 rx tsf.
// - Description:
//   - Implements or verifies the Ar9565RxTsf source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 rx tsf.

// Source-only AR9565 receive timestamp bridge. No RF or AWDL permission.
#ifndef SIMPLEATH_AR9565_RX_TSF_HPP
#define SIMPLEATH_AR9565_RX_TSF_HPP

#include <stdint.h>

namespace simpleath
{
    enum class RxTsfResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        OwnershipLost,
        ReadFailed,
        InvalidClock,
        UnstableClock,
        StaleFrame,
    };

    struct RxTsfBackend
    {
            void *context {};
            uint64_t ownerEpoch {};
            uint32_t barLengthBytes {};
            // Revalidate D0, owner epoch, channel-6 RX, RF-kill and the live
            // PCI/EDMA lease BEFORE each register access. Never write TSF.
            bool (*permitRead)(void *, uint64_t) {};
            bool (*read32)(void *, uint32_t, uint32_t *) {};
            // Uptime in microseconds; same monotonic domain used for AWDL
            // peer expiry. Called both before and after the TSF register read.
            uint64_t (*monotonicMicros)(void *) {};
    };

    struct RxTsfSample
    {
            uint64_t ownerEpoch {};
            uint64_t hardwareRxTsfUsec {};
            uint64_t hardwareCaptureTsfUsec {};
            uint64_t captureMonotonicUsec {};
            uint64_t frameMonotonicUsec {};
            uint32_t ageUsec {};
    };

    // Extend the EDMA status3 low 32-bit RX timestamp using a coherent,
    // same-epoch TSF upper/lower/upper snapshot (ath9k_hw_gettsf64). Reject
    // a future/stale timestamp or uncertain host-clock correlation. No MIF,
    // AWDL election, RF transmit or macOS peer permission is established.
    // Ordinary failure clears out; caller must keep output independent of
    // backend/context storage.
    RxTsfResult captureAr9565RxTsf(const RxTsfBackend &backend,
                                   uint32_t descriptorTsfLow, RxTsfSample &out);
} // namespace simpleath

#endif
