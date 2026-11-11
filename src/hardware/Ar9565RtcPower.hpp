// Copyright:
//   - Original Atheros / Qualcomm Atheros copyright holders
// SPDX-License-Identifier:
//   - ISC
// Confidential:
//   - false
// License-File:
//   - LICENSE-ISC
// Provenance:
//   - Linux ath9k-derived material; preserve original in-file notices and
//     source hashes
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for ar9565 rtc power.
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
//   - Native driver contracts and implementation for ar9565 rtc power.
// - Description:
//   - Implements or verifies the Ar9565RtcPower source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 rtc power.

/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef SIMPLEATH_AR9565_RTC_POWER_HPP
#define SIMPLEATH_AR9565_RTC_POWER_HPP

#include "Ar9565Core.hpp"

namespace simpleath
{

    enum class RtcOperation : uint8_t
    {
        BootstrapPowerOn,
        EnsureAwake,
        WarmReset,
        ColdReset,
    };
    enum class RtcResult : uint8_t
    {
        Ok,
        InvalidArgument,
        AccessRevoked,
        UnsupportedIdentity,
        UnsupportedSilicon,
        ProviderChanged,
        BootstrapRequired,
        ReadFailed,
        WriteFailed,
        InvalidRegister,
        InvalidClock,
        DelayTooShort,
        OperationTimeout,
        ResetTimeout,
        WakeTimeout,
        CoexistenceUnavailable,
    };

    // ACTIVE access, never the passive RegisterBus. The controller supplies
    // this only with exclusive physical ownership, stable provider D0/BAR,
    // interrupts masked and DMA/RX/TX/automatic MAC responses already quiesced.
    // canReset must enforce those conditions and the epoch throughout every
    // callback. Serialize all operations; no hard interrupt context or
    // unbounded callback is permitted.
    struct RtcPowerBackend
    {
            void *context;
            uint64_t providerToken; // Stable nonzero identity for this retained
                                    // PCI provider.
            uint64_t ownerEpoch;    // Current nonzero powered/serialized access
                                    // generation.
            bool (*canReset)(void *context, uint64_t ownerEpoch);
            // Ordered little-endian accesses. write32 must drain posted writes
            // before returning, so subsequent delayMicros measures the DEVICE
            // reset pulse. nowMicros must measure the same monotonic clock
            // used by delayMicros, including at least the requested interval.
            // Report false if delivery/draining is uncertain;
            // never claim completion solely from a CPU store or compiler fence.
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
            bool (*write32)(void *context, uint32_t offset, uint32_t value);
            uint64_t (*nowMicros)(void *context);
            void (*delayMicros)(void *context, uint32_t microseconds);
            uint32_t barLengthBytes;
            bool mciEnabled;
            bool (*beforeMacReset)(void *context);
            bool (*afterRtcAwake)(void *context);
    };

    // Retain the WA snapshot for the SAME provider across sleep; never RMW
    // AR_WA while asleep. Initial capture follows ath9k's
    // first-PCI-initialization access assumption. A new provider requires a
    // fresh context; never recycle its token.
    struct RtcPowerContext
    {
            uint64_t providerToken = 0;
            // Bootstrap is valid only in the same powered ownership epoch.
            // A new epoch retains WA but requires fresh power-on reset.
            uint64_t bootstrapEpoch = 0;
            uint32_t srev = 0;
            uint32_t workaroundValue = 0;
            bool workaroundCaptured = false;
            bool bootstrapCompleted = false;
    };

    struct RtcPowerStatus
    {
            RtcResult result;
            Silicon silicon;
            uint32_t lastRegister;
            uint32_t lastValue;
            uint32_t reads;
            uint32_t writes;
            uint32_t polls;
            bool rtcAwake;
            bool resetCompleted;
            // Set BEFORE the first attempted write, even if its completion is
            // unknown. Owner must invalidate channel, calibration, keys and
            // queue state as needed.
            bool boardStateInvalidated;
    };

    // RTC/MAC reset only. Does not initialize PLL/PHY/RF, clear STA_ID1
    // power-save, configure antenna/regulatory/TPC, start RX, enable DMA or
    // authorize ANY TX. On failure do not restore guessed register values or
    // free hardware-owned DMA. Context and status must not overlap one
    // another, the backend or identity. The callback context cannot start
    // inside either output, the callback table or physical identity; the
    // owner's entire opaque context storage must be disjoint from all of them.
    // Aliasing returns InvalidArgument WITHOUT writing either output.
    // Total callbacks are bounded even with a
    // stalled monotonic clock; wall time includes callback cost.
    RtcResult transitionAr9565Rtc(const RtcPowerBackend &backend,
                                  const Identity &physicalIdentity,
                                  RtcOperation operation,
                                  RtcPowerContext &context,
                                  RtcPowerStatus &status);

} // namespace simpleath
#endif
