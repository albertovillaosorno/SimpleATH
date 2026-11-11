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
//   - Native driver contracts and implementation for ar9565 ani mib.
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
//   - Native driver contracts and implementation for ar9565 ani mib.
// - Description:
//   - Implements or verifies the Ar9565AniMib source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 ani mib.

#ifndef SIMPLEATH_AR9565_ANI_MIB_HPP
#define SIMPLEATH_AR9565_ANI_MIB_HPP

#include "Ar9565Ani.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    enum class AniMibResult : uint8_t
    {
        Ok,
        InvalidBackend,
        InvalidBar,
        MissingAuthorization,
        NotInitialized,
        ResetRequired,
        OwnershipLost,
        ReadFailed,
        WriteFailed,
        ReadbackMismatch,
        InvalidCaptureTime,
        CounterSaturated,
        InvalidChannel,
    };

    struct AniMibBackend
    {
            void *context {};
            uint64_t ownerEpoch {};
            uint32_t barLengthBytes {};
            // The physical PCI owner MUST serialize all other MIB users,
            // including surveys, interrupts, reset, channel and suspend.
            // This callback attests D0, exact channel, BAR and exclusive MIB
            // ownership at each MMIO access, not merely a matching number.
            bool (*permit)(void *, uint64_t) {};
            bool (*read32)(void *, uint32_t, uint32_t *) {};
            bool (*write32)(void *, uint32_t, uint32_t) {};
    };

    struct AniMibState
    {
            uint64_t ownerEpoch {};
            uint64_t captureSequence {};
            uint64_t lastCaptureMs {};
            uint8_t channel {};
            Revision silicon {Revision::Unknown};
            RfReferenceClock referenceClock {RfReferenceClock::Crystal25Mhz};
            ChannelWidth width {ChannelWidth::Ht20};
            uint8_t secondary {};
            bool initialized {};
            bool requiresReset {};
    };

    struct AniMibProgress
    {
            AniMibResult result {AniMibResult::InvalidBackend};
            size_t completedReads {};
            size_t completedWrites {};
            uint32_t lastOffset {};
            bool requiresReset {};
    };

    // Initialize one physical ANI counter epoch AFTER the channel INI and
    // receiver-calibration baseline has been captured, but before the radio
    // can receive. Freezes and zeros MIB cycle/PHY counters; configures the
    // ath9k OFDM/CCK timing masks and releases MIB freeze on success.
    // The supplied owner monotonic time begins the first no-wrap interval.
    // This is a hardware-mutating operation, not a passive capability flag.
    // Any ambiguous partial programming requires owner-controlled reset.
    AniMibProgress
    initializeAr9565AniMib(const Ar9565AniState &ini,
                           const CalibrationAndRegulatory &authority,
                           const AniMibBackend &backend,
                           uint64_t monotonicMilliseconds, AniMibState &state);

    // Capture a physically frozen CCCNT/RFCNT/TFCNT and PHY_ERR_1/2 sample
    // under an exclusive live MIB lease. Independent owner monotonic time
    // bounds the no-wrap interval to <=5 seconds; it NEVER substitutes for
    // actual cycle counters. A failed or stale observation invalidates this
    // epoch and requires PHY reset, not fabricated ANI evidence. The owner
    // feeds pairs of successful samples into deriveAr9565AniErrorWindow.
    // This adapter is compiled but not yet invoked by the native PCI owner.
    AniMibProgress captureAr9565AniMib(
        const Ar9565AniState &ini, const CalibrationAndRegulatory &authority,
        const AniMibBackend &backend, uint64_t monotonicMilliseconds,
        AniMibState &state, AniHardwareSample &out);
} // namespace simpleath

#endif // SIMPLEATH_AR9565_ANI_MIB_HPP
