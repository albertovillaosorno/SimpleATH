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
// Counter MMIO order and constants adapted from pinned Linux ath9k ani.c,
// ath/hw.c, ath/reg.h and ath9k/reg.h. No Linux kernel runtime is linked.
#include "Ar9565AniMib.hpp"
#include "Ar9565Ani.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kMibControl = 0x0040U;
        constexpr uint32_t kMibFreeze = 0x00000002U;
        constexpr uint32_t kTransmitFrames = 0x80ecU;
        constexpr uint32_t kReceiveFrames = 0x80f0U;
        constexpr uint32_t kCycles = 0x80f8U;
        constexpr uint32_t kOfdmFilter = 0x8124U;
        constexpr uint32_t kCckFilter = 0x8128U;
        constexpr uint32_t kOfdmErrors = 0x812cU;
        constexpr uint32_t kOfdmMask = 0x8130U;
        constexpr uint32_t kCckErrors = 0x8134U;
        constexpr uint32_t kCckMask = 0x8138U;
        constexpr uint32_t kOfdmTiming = 0x00020000U;
        constexpr uint32_t kCckTiming = 0x02000000U;
        constexpr uint32_t kErrorCountMask = 0x00ffffffU;
        constexpr uint64_t kMaximumSampleIntervalMs = 5000U;
        constexpr uint8_t kJapanChannel = 14U;
        constexpr uint8_t kHt40ChannelSpacing = 4U;
        constexpr uint32_t kRegisters[] {
            kMibControl, kTransmitFrames, kReceiveFrames, kCycles,
            kOfdmFilter, kCckFilter,      kOfdmErrors,    kOfdmMask,
            kCckErrors,  kCckMask,
        };

        AniMibResult preflight(const Ar9565AniState &ini,
                               const CalibrationAndRegulatory &authority,
                               const AniMibBackend &io)
        {
            if (io.context == nullptr || io.ownerEpoch == 0U ||
                io.permit == nullptr || io.read32 == nullptr ||
                io.write32 == nullptr)
            {
                return AniMibResult::InvalidBackend;
            }
            for (const uint32_t offset : kRegisters)
            {
                if (offset > io.barLengthBytes ||
                    io.barLengthBytes - offset < sizeof(uint32_t))
                {
                    return AniMibResult::InvalidBar;
                }
            }
            // A stale or corrupt ANI baseline must never authorize physical
            // MIB programming. Check canonical channel geometry independently
            // of a caller-supplied initialized flag.
            Channel primary {};
            Channel secondary {};
            if (ini.silicon == Revision::Unknown ||
                (ini.referenceClock != RfReferenceClock::Crystal25Mhz &&
                 ini.referenceClock != RfReferenceClock::Crystal40Mhz) ||
                mapChannel(ini.channel, primary) != Result::Ok ||
                (ini.width == ChannelWidth::Ht20 && ini.secondary != 0U) ||
                (ini.width == ChannelWidth::Ht40 &&
                 (ini.channel == kJapanChannel ||
                  mapChannel(ini.secondary, secondary) != Result::Ok ||
                  (ini.secondary + kHt40ChannelSpacing != ini.channel &&
                   ini.channel + kHt40ChannelSpacing != ini.secondary))) ||
                (ini.width != ChannelWidth::Ht20 &&
                 ini.width != ChannelWidth::Ht40))
            {
                return AniMibResult::InvalidChannel;
            }
            if (!ini.initialized || ini.ownerEpoch != io.ownerEpoch ||
                authority.use != RadioInitialization::ReceiveOnly ||
                !radioInitializationAuthorized(authority) ||
                (ini.channel == kJapanChannel &&
                 !authority.localCountryRulesAvailable))
            {
                return AniMibResult::MissingAuthorization;
            }
            return AniMibResult::Ok;
        }

        bool owned(const AniMibBackend &io, AniMibProgress &progress)
        {
            if (io.permit(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = AniMibResult::OwnershipLost;
            return false;
        }

        bool read(const AniMibBackend &io, uint32_t offset, uint32_t &value,
                  AniMibProgress &progress)
        {
            if (!owned(io, progress))
            {
                return false;
            }
            progress.lastOffset = offset;
            const bool success = io.read32(io.context, offset, &value);
            if (!owned(io, progress))
            {
                return false;
            }
            if (!success)
            {
                progress.result = AniMibResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            return true;
        }

        bool write(const AniMibBackend &io, uint32_t offset, uint32_t value,
                   AniMibProgress &progress)
        {
            if (!owned(io, progress))
            {
                return false;
            }
            progress.lastOffset = offset;
            // A callback may have committed a write before returning an
            // error or revoking the lease. Reset is mandatory in both cases.
            progress.requiresReset = true;
            const bool success = io.write32(io.context, offset, value);
            if (!owned(io, progress))
            {
                return false;
            }
            if (!success)
            {
                progress.result = AniMibResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            return true;
        }

        struct MibReadback
        {
                uint32_t offset;
                uint32_t expected;
        };

        bool confirm(const AniMibBackend &io, MibReadback registerValue,
                     AniMibProgress &progress)
        {
            uint32_t actual = 0;
            if (!read(io, registerValue.offset, actual, progress))
            {
                return false;
            }
            if (actual == registerValue.expected)
            {
                return true;
            }
            progress.result = AniMibResult::ReadbackMismatch;
            return false;
        }

        void invalidate(AniMibState &state, AniMibProgress &progress)
        {
            const bool reset = progress.requiresReset || state.requiresReset;
            const uint64_t failedEpoch = state.ownerEpoch;
            state = {};
            state.ownerEpoch = failedEpoch;
            state.requiresReset = reset;
            progress.requiresReset = reset;
        }

        bool matches(const AniMibState &state, const Ar9565AniState &ini,
                     const AniMibBackend &io)
        {
            return state.initialized && !state.requiresReset &&
                   state.silicon == ini.silicon &&
                   state.referenceClock == ini.referenceClock &&
                   state.ownerEpoch == io.ownerEpoch &&
                   state.ownerEpoch == ini.ownerEpoch &&
                   state.channel == ini.channel && state.width == ini.width &&
                   state.secondary == ini.secondary && ini.initialized;
        }
    } // namespace

    AniMibProgress
    initializeAr9565AniMib(const Ar9565AniState &ini,
                           const CalibrationAndRegulatory &authority,
                           const AniMibBackend &backend,
                           uint64_t monotonicMilliseconds, AniMibState &state)
    {
        const Ar9565AniState input = ini;
        const CalibrationAndRegulatory evidence = authority;
        const AniMibBackend io = backend;
        AniMibProgress progress {};
        progress.result = preflight(input, evidence, io);
        if (progress.result != AniMibResult::Ok)
        {
            // The baseline cannot survive loss of a live same-epoch radio
            // permission, including a failed BAR/INI consistency check.
            if (state.initialized && state.ownerEpoch == io.ownerEpoch)
            {
                progress.requiresReset = true;
                invalidate(state, progress);
            }
            return progress;
        }
        // A second call cannot silently reset an active counter session or
        // erase a failed partial-programming reset obligation. A physical
        // reset/channel change must replace the owner epoch first.
        if (state.ownerEpoch == io.ownerEpoch &&
            (state.initialized || state.requiresReset))
        {
            progress.result = AniMibResult::ResetRequired;
            progress.requiresReset = state.requiresReset;
            return progress;
        }
        if (monotonicMilliseconds == 0U)
        {
            progress.result = AniMibResult::InvalidCaptureTime;
            return progress;
        }
        state = {};
        state.ownerEpoch = io.ownerEpoch;
        if (!write(io, kMibControl, kMibFreeze, progress) ||
            !confirm(io, {kMibControl, kMibFreeze}, progress))
        {
            invalidate(state, progress);
            return progress;
        }
        // Reset while frozen. Counter readbacks are explicitly checked; an
        // apparently successful write with stale counters is not a baseline.
        constexpr uint32_t kClear[] {
            kCycles,    kReceiveFrames, kTransmitFrames, kOfdmErrors,
            kCckErrors, kOfdmFilter,    kCckFilter,
        };
        for (const uint32_t offset : kClear)
        {
            if (!write(io, offset, 0U, progress) ||
                !confirm(io, {offset, 0U}, progress))
            {
                invalidate(state, progress);
                return progress;
            }
        }
        if (!write(io, kOfdmMask, kOfdmTiming, progress) ||
            !confirm(io, {kOfdmMask, kOfdmTiming}, progress) ||
            !write(io, kCckMask, kCckTiming, progress) ||
            !confirm(io, {kCckMask, kCckTiming}, progress) ||
            !write(io, kMibControl, 0U, progress) ||
            !confirm(io, {kMibControl, 0U}, progress) || !owned(io, progress))
        {
            invalidate(state, progress);
            return progress;
        }
        state.ownerEpoch = io.ownerEpoch;
        state.lastCaptureMs = monotonicMilliseconds;
        state.channel = input.channel;
        state.silicon = input.silicon;
        state.referenceClock = input.referenceClock;
        state.width = input.width;
        state.secondary = input.secondary;
        state.initialized = true;
        // The completed unfreeze is the only hardware operation that makes
        // the new epoch usable; no reset obligation survives this success.
        progress.requiresReset = false;
        progress.result = AniMibResult::Ok;
        return progress;
    }

    AniMibProgress captureAr9565AniMib(
        const Ar9565AniState &ini, const CalibrationAndRegulatory &authority,
        const AniMibBackend &backend, uint64_t monotonicMilliseconds,
        AniMibState &state, AniHardwareSample &out)
    {
        const Ar9565AniState input = ini;
        const CalibrationAndRegulatory evidence = authority;
        const AniMibBackend io = backend;
        AniMibProgress progress {};
        out = {};
        progress.result = preflight(input, evidence, io);
        if (progress.result != AniMibResult::Ok)
        {
            // The baseline cannot survive loss of a live same-epoch radio
            // permission, including a failed BAR/INI consistency check.
            if (state.initialized && state.ownerEpoch == io.ownerEpoch)
            {
                progress.requiresReset = true;
                invalidate(state, progress);
            }
            return progress;
        }
        progress.result = AniMibResult::NotInitialized;
        if (state.ownerEpoch == io.ownerEpoch && state.requiresReset)
        {
            progress.result = AniMibResult::ResetRequired;
            progress.requiresReset = true;
            return progress;
        }
        if (!matches(state, input, io))
        {
            // An unexpected same-epoch INI/channel/clock change breaks the
            // no-clear/no-retune promise of this physical counter session.
            if (state.initialized && state.ownerEpoch == io.ownerEpoch)
            {
                progress.requiresReset = true;
                invalidate(state, progress);
            }
            return progress;
        }
        progress.result = AniMibResult::InvalidCaptureTime;
        if (monotonicMilliseconds == 0U ||
            monotonicMilliseconds <= state.lastCaptureMs ||
            monotonicMilliseconds - state.lastCaptureMs >
                kMaximumSampleIntervalMs ||
            state.captureSequence == UINT64_MAX)
        {
            progress.requiresReset = true;
            invalidate(state, progress);
            return progress;
        }
        // The exclusive owner must guarantee no reset or independent MIB
        // clear between captures. Freeze permits a stable register snapshot.
        if (!write(io, kMibControl, kMibFreeze, progress) ||
            !confirm(io, {kMibControl, kMibFreeze}, progress))
        {
            invalidate(state, progress);
            return progress;
        }
        AniHardwareSample observed {};
        uint32_t mask1 = 0;
        uint32_t mask2 = 0;
        uint32_t frozenCycles = 0;
        const bool captured =
            read(io, kCycles, observed.cycleCount, progress) &&
            read(io, kReceiveFrames, observed.receiveFrameCycles, progress) &&
            read(io, kTransmitFrames, observed.transmitFrameCycles, progress) &&
            read(io, kOfdmErrors, observed.ofdmTimingErrors, progress) &&
            read(io, kCckErrors, observed.cckTimingErrors, progress) &&
            read(io, kOfdmMask, mask1, progress) &&
            read(io, kCckMask, mask2, progress) &&
            read(io, kCycles, frozenCycles, progress) &&
            confirm(io, {kMibControl, kMibFreeze}, progress);
        if (!captured)
        {
            invalidate(state, progress);
            return progress;
        }
        if (mask1 != kOfdmTiming || mask2 != kCckTiming ||
            frozenCycles != observed.cycleCount)
        {
            progress.result = AniMibResult::ReadbackMismatch;
            invalidate(state, progress);
            return progress;
        }
        if ((observed.ofdmTimingErrors & ~kErrorCountMask) != 0U ||
            (observed.cckTimingErrors & ~kErrorCountMask) != 0U ||
            observed.ofdmTimingErrors == kErrorCountMask ||
            observed.cckTimingErrors == kErrorCountMask)
        {
            progress.result = AniMibResult::CounterSaturated;
            invalidate(state, progress);
            return progress;
        }
        if (!write(io, kMibControl, 0U, progress) ||
            !confirm(io, {kMibControl, 0U}, progress) || !owned(io, progress))
        {
            invalidate(state, progress);
            return progress;
        }
        observed.ownerEpoch = io.ownerEpoch;
        observed.captureSequence = state.captureSequence + 1U;
        observed.channel = input.channel;
        observed.width = input.width;
        observed.secondary = input.secondary;
        observed.mmioAndMasksVerified = true;
        state.lastCaptureMs = monotonicMilliseconds;
        state.captureSequence = observed.captureSequence;
        out = observed;
        progress.requiresReset = false;
        progress.result = AniMibResult::Ok;
        return progress;
    }
} // namespace simpleath
