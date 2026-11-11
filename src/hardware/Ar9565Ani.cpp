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
// Adapted from Linux ath9k ar9003_phy.c/.h and ani.h, pinned in the ledger.
#include "Ar9565Ani.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kJapanChannel = 14U;
        constexpr uint8_t kMaxFirstStepLevel = 8U;
        constexpr uint8_t kMaxSpurLevel = 7U;
        constexpr uint8_t kDefaultFirstStepLevel = 2U;
        constexpr uint8_t kDefaultSpurLevel = 3U;
        constexpr uint8_t kMaxFirstStepValue = 20U;
        constexpr uint8_t kMaxSpurValue = 22U;
        constexpr uint32_t kMinimumAniWindowMilliseconds = 300U;
        constexpr uint32_t kOfdmHighAboveDefault = 3500U;
        constexpr uint32_t kOfdmHighBelowDefault = 1000U;
        constexpr uint32_t kOfdmLowAboveDefault = 900U;
        constexpr uint32_t kOfdmLowBelowDefault = 400U;
        constexpr uint32_t kCckHigh = 600U;
        constexpr uint32_t kCckLow = 300U;
        constexpr uint8_t kMaxOfdmImmunity = 8U;
        constexpr uint8_t kMaxCckWithoutRssi = 6U;
        constexpr uint32_t kAniPhyCounterSaturated = 0x00ffffffU;
        constexpr uint32_t kMacClockCyclesPerMsHt20 = 44000U;
        constexpr uint32_t kMacClockCyclesPerMsHt40 = 88000U;
        constexpr uint32_t kMaxAniObservationMs = 5000U;

        // First-step/spur-level pairs for ath9k OFDM ANI 0..8. Level 9
        // additionally disables weak-signal detection, which this receive-
        // only subset does not implement and therefore never selects.
        struct OfdmImmunity
        {
                uint8_t firstStep;
                uint8_t spur;
        };

        constexpr OfdmImmunity kOfdmImmunity[] {
            {0U, 0U}, {1U, 1U}, {2U, 2U}, {2U, 3U}, {3U, 4U},
            {4U, 5U}, {5U, 6U}, {6U, 7U}, {7U, 7U},
        };

        enum class AniField : uint8_t
        {
            First,
            FirstLow,
            Spur,
            SpurExt,
        };

        struct RegisterField
        {
                AniField identity;
                uint32_t offset;
                uint32_t mask;
                uint8_t shift;
                uint8_t maxValue;
        };

        // AR9003 PHY FIND_SIG, FIND_SIG_LOW, TIMING5 and EXT_CCA fields.
        constexpr RegisterField kAniFields[] {
            {AniField::First, 0x9e10U, 0x0003f000U, 12U, kMaxFirstStepValue},
            {AniField::FirstLow, 0x9820U, 0x00000fc0U, 6U, kMaxFirstStepValue},
            {AniField::Spur, 0x9810U, 0x000000feU, 1U, kMaxSpurValue},
            {AniField::SpurExt, 0x9830U, 0x0000fe00U, 9U, kMaxSpurValue},
        };

        struct AniChoice
        {
                uint8_t ofdm;
                uint8_t cck;
                bool ofdmTurn;
                bool triggered;
        };

        AniChoice chooseAniImmunity(const Ar9565AniState &state,
                                    const AniErrorWindow &window)
        {
            const uint64_t ofdmRate =
                static_cast<uint64_t>(window.ofdmTimingErrors) * 1000U /
                window.listenedMilliseconds;
            const uint64_t cckRate =
                static_cast<uint64_t>(window.cckTimingErrors) * 1000U /
                window.listenedMilliseconds;
            const uint32_t ofdmHigh = state.ofdmImmunityLevel >= 3U
                                          ? kOfdmHighAboveDefault
                                          : kOfdmHighBelowDefault;
            const uint32_t ofdmLow = state.ofdmImmunityLevel >= 3U
                                         ? kOfdmLowAboveDefault
                                         : kOfdmLowBelowDefault;
            AniChoice next {
                state.ofdmImmunityLevel,
                state.cckImmunityLevel,
                state.ofdmTurn,
                false,
            };
            if (cckRate < kCckLow && ofdmRate < ofdmLow)
            {
                if (next.ofdm > 0U && (next.ofdmTurn || next.cck == 0U))
                {
                    --next.ofdm;
                }
                else if (next.cck > 0U)
                {
                    --next.cck;
                }
                next.ofdmTurn = !next.ofdmTurn;
            }
            else if (ofdmRate > ofdmHigh)
            {
                if (next.ofdm < kMaxOfdmImmunity)
                {
                    ++next.ofdm;
                }
                next.ofdmTurn = false;
            }
            else if (cckRate > kCckHigh)
            {
                if (next.cck < kMaxCckWithoutRssi)
                {
                    ++next.cck;
                }
                next.ofdmTurn = true;
            }
            else
            {
                return next;
            }
            next.triggered = true;
            return next;
        }

        OfdmImmunity ofdmImmunity(uint8_t level)
        {
            for (const OfdmImmunity &entry : kOfdmImmunity)
            {
                if (level == 0U)
                {
                    return entry;
                }
                --level;
            }
            __builtin_trap(); // Already validated 0..8 before this call.
        }

        bool validRequest(const RfChannelRequest &channel)
        {
            if ((channel.silicon != Revision::V1_0 &&
                 channel.silicon != Revision::V1_0_1 &&
                 channel.silicon != Revision::V1_1) ||
                (channel.referenceClock != RfReferenceClock::Crystal25Mhz &&
                 channel.referenceClock != RfReferenceClock::Crystal40Mhz))
            {
                return false;
            }
            Channel canonical {};
            if (mapChannel(channel.control.number, canonical) != Result::Ok ||
                canonical.centerMhz != channel.control.centerMhz ||
                canonical.requiresJapanAuthorization !=
                    channel.control.requiresJapanAuthorization)
            {
                return false;
            }
            if (channel.width == ChannelWidth::Ht20)
            {
                return channel.secondary == 0U;
            }
            if (channel.width != ChannelWidth::Ht40 ||
                channel.control.number == kJapanChannel ||
                channel.secondary == kJapanChannel)
            {
                return false;
            }
            const int difference = static_cast<int>(channel.secondary) -
                                   static_cast<int>(channel.control.number);
            Channel secondary {};
            return (difference == 4 || difference == -4) &&
                   mapChannel(channel.secondary, secondary) == Result::Ok;
        }

        AniResult preflight(const RfChannelRequest &channel,
                            const CalibrationAndRegulatory &authorization,
                            const RxAgcBackend &backend)
        {
            const RfIniBackend &io = backend.io;
            if (io.context == nullptr || io.ownerEpoch == 0U ||
                io.permitWrite == nullptr || io.write32 == nullptr ||
                backend.read32 == nullptr)
            {
                return AniResult::InvalidBackend;
            }
            if (!validRequest(channel))
            {
                return AniResult::InvalidChannel;
            }
            if (authorization.use != RadioInitialization::ReceiveOnly ||
                !radioInitializationAuthorized(authorization) ||
                (channel.control.number == kJapanChannel &&
                 !authorization.localCountryRulesAvailable))
            {
                return AniResult::MissingAuthorization;
            }
            for (const RegisterField &field : kAniFields)
            {
                if (field.offset > io.barLengthBytes ||
                    io.barLengthBytes - field.offset < sizeof(uint32_t))
                {
                    return AniResult::InvalidBar;
                }
            }
            return AniResult::Ok;
        }

        bool allowed(const RfIniBackend &io, AniProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = AniResult::OwnershipLost;
            return false;
        }

        bool read(const RxAgcBackend &backend, uint32_t offset, uint32_t &value,
                  AniProgress &progress)
        {
            const auto &io = backend.io;
            if (!allowed(io, progress))
            {
                return false;
            }
            progress.lastOffset = offset;
            if (!backend.read32(io.context, offset, &value))
            {
                progress.result = AniResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            return true;
        }

    } // namespace

    AniProgress
    cacheAr9565AniIniDefaults(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend,
                              Ar9565AniState &state)
    {
        AniProgress progress {};
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory evidence = authorization;
        const RxAgcBackend stable = backend;
        // Clear an old channel's levels even on failure: they may never be
        // reused across a reset, failed calibration or subsequent channel.
        state = {};
        progress.result = preflight(channel, evidence, stable);
        if (progress.result != AniResult::Ok)
        {
            return progress;
        }
        Ar9565AniState captured {};
        captured.ownerEpoch = stable.io.ownerEpoch;
        captured.channel = channel.control.number;
        captured.silicon = channel.silicon;
        captured.width = channel.width;
        captured.secondary = channel.secondary;
        captured.referenceClock = channel.referenceClock;
        for (const RegisterField &field : kAniFields)
        {
            uint32_t word = 0;
            if (!read(stable, field.offset, word, progress))
            {
                return progress;
            }
            const auto extracted =
                static_cast<uint8_t>((word & field.mask) >> field.shift);
            switch (field.identity)
            {
                case AniField::First:
                    captured.firstStepDefault = extracted;
                    break;
                case AniField::FirstLow:
                    captured.firstStepLowDefault = extracted;
                    break;
                case AniField::Spur:
                    captured.spurDefault = extracted;
                    break;
                case AniField::SpurExt:
                    captured.spurExtDefault = extracted;
                    break;
            }
        }
        if (!allowed(stable.io, progress))
        {
            return progress;
        }
        captured.initialized = true;
        state = captured;
        progress.result = AniResult::Ok;
        return progress;
    }

    AniProgress
    programAr9565AniLevels(const RfChannelRequest &request,
                           const CalibrationAndRegulatory &authorization,
                           const RxAgcBackend &backend, Ar9565AniState &state,
                           uint8_t firstStepLevel, uint8_t spurLevel)
    {
        AniProgress progress {};
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory evidence = authorization;
        const RxAgcBackend stable = backend;
        const Ar9565AniState saved = state;
        progress.result = preflight(channel, evidence, stable);
        if (progress.result != AniResult::Ok)
        {
            return progress;
        }
        progress.result = AniResult::NotInitialized;
        if (!saved.initialized || saved.ownerEpoch != stable.io.ownerEpoch ||
            saved.silicon != channel.silicon ||
            saved.channel != channel.control.number ||
            saved.width != channel.width ||
            saved.secondary != channel.secondary ||
            saved.referenceClock != channel.referenceClock)
        {
            return progress;
        }
        progress.result = AniResult::InvalidLevel;
        if (firstStepLevel > kMaxFirstStepLevel || spurLevel > kMaxSpurLevel)
        {
            return progress;
        }
        const int firstDelta = 2 * (static_cast<int>(firstStepLevel) -
                                    static_cast<int>(kDefaultFirstStepLevel));
        const int spurDelta = 2 * (static_cast<int>(spurLevel) -
                                   static_cast<int>(kDefaultSpurLevel));
        for (const RegisterField &field : kAniFields)
        {
            uint8_t iniDefault = 0;
            int adjustment = 0;
            switch (field.identity)
            {
                case AniField::First:
                    iniDefault = saved.firstStepDefault;
                    adjustment = firstDelta;
                    break;
                case AniField::FirstLow:
                    iniDefault = saved.firstStepLowDefault;
                    adjustment = firstDelta;
                    break;
                case AniField::Spur:
                    iniDefault = saved.spurDefault;
                    adjustment = spurDelta;
                    break;
                case AniField::SpurExt:
                    iniDefault = saved.spurExtDefault;
                    adjustment = spurDelta;
                    break;
            }
            int adjusted = static_cast<int>(iniDefault) + adjustment;
            // Clamp without hosted std::min/max (libc++ is unavailable in
            // the macOS kernel extension).
            if (adjusted < 0 || adjusted > field.maxValue)
            {
                adjusted = adjusted < 0 ? 0 : field.maxValue;
            }
            uint32_t before = 0;
            if (!read(stable, field.offset, before, progress))
            {
                return progress;
            }
            const uint32_t programmed =
                (before & ~field.mask) |
                (static_cast<uint32_t>(adjusted) << field.shift);
            if (!allowed(stable.io, progress))
            {
                return progress;
            }
            progress.lastOffset = field.offset;
            // The first potentially posted hardware write invalidates the
            // previous software baseline until ALL registers read back and
            // the owner is revalidated. A caller must reset after any fault.
            state.initialized = false;
            progress.requiresReset = true;
            if (!stable.io.write32(stable.io.context, field.offset, programmed))
            {
                progress.result = AniResult::WriteFailed;
                return progress;
            }
            ++progress.completedWrites;
            uint32_t observed = 0;
            if (!read(stable, field.offset, observed, progress))
            {
                return progress;
            }
            if (observed != programmed)
            {
                progress.result = AniResult::ReadbackMismatch;
                return progress;
            }
        }
        if (!allowed(stable.io, progress))
        {
            return progress;
        }
        state = saved;
        state.firstStepLevel = firstStepLevel;
        state.spurLevel = spurLevel;
        progress.requiresReset = false;
        progress.result = AniResult::Ok;
        return progress;
    }

    AniResult deriveAr9565AniErrorWindow(const RfChannelRequest &request,
                                         const AniHardwareSample &begin,
                                         const AniHardwareSample &end,
                                         uint32_t elapsedMilliseconds,
                                         bool scanning, AniErrorWindow &out)
    {
        // Local input snapshots guard against caller-owned sample mutation.
        const RfChannelRequest channel = request;
        const AniHardwareSample first = begin;
        const AniHardwareSample last = end;
        out = {};
        if (!validRequest(channel))
        {
            return AniResult::InvalidChannel;
        }
        if (first.ownerEpoch == 0U || first.ownerEpoch != last.ownerEpoch ||
            first.captureSequence == 0U ||
            last.captureSequence <= first.captureSequence ||
            first.channel != channel.control.number ||
            last.channel != channel.control.number ||
            first.width != channel.width || last.width != channel.width ||
            first.secondary != channel.secondary ||
            last.secondary != channel.secondary)
        {
            return AniResult::StaleErrorWindow;
        }
        if (!first.mmioAndMasksVerified || !last.mmioAndMasksVerified ||
            elapsedMilliseconds == 0U ||
            elapsedMilliseconds > kMaxAniObservationMs ||
            first.ofdmTimingErrors >= kAniPhyCounterSaturated ||
            last.ofdmTimingErrors >= kAniPhyCounterSaturated ||
            first.cckTimingErrors >= kAniPhyCounterSaturated ||
            last.cckTimingErrors >= kAniPhyCounterSaturated ||
            last.cycleCount <= first.cycleCount ||
            last.receiveFrameCycles < first.receiveFrameCycles ||
            last.transmitFrameCycles < first.transmitFrameCycles ||
            last.ofdmTimingErrors < first.ofdmTimingErrors ||
            last.cckTimingErrors < first.cckTimingErrors)
        {
            return AniResult::InvalidErrorWindow;
        }
        const uint64_t cycles =
            static_cast<uint64_t>(last.cycleCount) - first.cycleCount;
        const uint64_t receive =
            static_cast<uint64_t>(last.receiveFrameCycles) -
            first.receiveFrameCycles;
        const uint64_t transmit =
            static_cast<uint64_t>(last.transmitFrameCycles) -
            first.transmitFrameCycles;
        const uint32_t cyclesPerMs = channel.width == ChannelWidth::Ht40
                                         ? kMacClockCyclesPerMsHt40
                                         : kMacClockCyclesPerMsHt20;
        // Two independent sanity conditions catch unsafe byte-order and MIB
        // snapshots taken after a hardware counter clear. The MIB owner must
        // separately guarantee that no full wrap occurred between samples.
        if (receive + transmit >= cycles ||
            cycles > static_cast<uint64_t>(cyclesPerMs) * elapsedMilliseconds)
        {
            return AniResult::InvalidErrorWindow;
        }
        const uint64_t listened = (cycles - receive - transmit) / cyclesPerMs;
        if (listened == 0U || listened > elapsedMilliseconds)
        {
            return AniResult::InvalidErrorWindow;
        }
        out.ownerEpoch = last.ownerEpoch;
        out.counterSequence = last.captureSequence;
        out.listenedMilliseconds = static_cast<uint32_t>(listened);
        out.ofdmTimingErrors = last.ofdmTimingErrors - first.ofdmTimingErrors;
        out.cckTimingErrors = last.cckTimingErrors - first.cckTimingErrors;
        out.hardwareCountersVerified = true;
        out.scanning = scanning;
        return AniResult::Ok;
    }

    AniMonitorProgress
    adaptAr9565AniToPhyErrors(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend,
                              const AniErrorWindow &window,
                              Ar9565AniState &state)
    {
        AniMonitorProgress progress {};
        // Snapshot caller-owned inputs before invoking any owner callback.
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory evidence = authorization;
        const RxAgcBackend stable = backend;
        const AniErrorWindow observed = window;
        const Ar9565AniState before = state;

        progress.result = preflight(channel, evidence, stable);
        if (progress.result != AniResult::Ok)
        {
            return progress;
        }
        progress.result = AniResult::NotInitialized;
        if (!before.initialized || before.ownerEpoch != stable.io.ownerEpoch ||
            before.silicon != channel.silicon ||
            before.channel != channel.control.number ||
            before.width != channel.width ||
            before.secondary != channel.secondary ||
            before.referenceClock != channel.referenceClock ||
            before.ofdmImmunityLevel > kMaxOfdmImmunity ||
            before.cckImmunityLevel > kMaxCckWithoutRssi)
        {
            return progress;
        }
        progress.result = AniResult::InvalidErrorWindow;
        if (!observed.hardwareCountersVerified ||
            observed.listenedMilliseconds == 0U ||
            observed.counterSequence == 0U ||
            observed.ofdmTimingErrors >= kAniPhyCounterSaturated ||
            observed.cckTimingErrors >= kAniPhyCounterSaturated)
        {
            return progress;
        }
        progress.result = AniResult::StaleErrorWindow;
        if (observed.ownerEpoch != before.ownerEpoch ||
            observed.counterSequence <= before.lastCounterSequence)
        {
            return progress;
        }
        progress.result = AniResult::OwnershipLost;
        if (!stable.io.permitWrite(stable.io.context, stable.io.ownerEpoch))
        {
            return progress;
        }
        progress.ofdmImmunityLevel = before.ofdmImmunityLevel;
        progress.cckImmunityLevel = before.cckImmunityLevel;
        progress.result = AniResult::Ok;
        if (observed.scanning ||
            observed.listenedMilliseconds <= kMinimumAniWindowMilliseconds)
        {
            state.lastCounterSequence = observed.counterSequence;
            return progress;
        }

        const AniChoice next = chooseAniImmunity(before, observed);
        if (!next.triggered)
        {
            state.lastCounterSequence = observed.counterSequence;
            return progress;
        }
        if (!stable.io.permitWrite(stable.io.context, stable.io.ownerEpoch))
        {
            progress.result = AniResult::OwnershipLost;
            return progress;
        }
        if (next.ofdm == before.ofdmImmunityLevel &&
            next.cck == before.cckImmunityLevel &&
            next.ofdmTurn == before.ofdmTurn)
        {
            state.lastCounterSequence = observed.counterSequence;
            return progress;
        }
        const OfdmImmunity ofdm = ofdmImmunity(next.ofdm);
        const uint8_t nextFirstStep =
            ofdm.firstStep > next.cck ? ofdm.firstStep : next.cck;
        const uint8_t nextSpur = ofdm.spur;
        if (nextFirstStep != before.firstStepLevel ||
            nextSpur != before.spurLevel)
        {
            progress.programming = programAr9565AniLevels(
                channel, evidence, stable, state, nextFirstStep, nextSpur);
            progress.result = progress.programming.result;
            if (progress.result != AniResult::Ok)
            {
                return progress;
            }
            progress.registerProgrammed = true;
        }
        // A callback may revoke the epoch at the final readback. Never
        // publish a successfully adapted policy for a revoked physical owner.
        if (!stable.io.permitWrite(stable.io.context, stable.io.ownerEpoch))
        {
            state.initialized = false;
            progress.result = AniResult::OwnershipLost;
            progress.programming.requiresReset = progress.registerProgrammed;
            return progress;
        }
        state.lastCounterSequence = observed.counterSequence;
        state.ofdmImmunityLevel = next.ofdm;
        state.cckImmunityLevel = next.cck;
        state.ofdmTurn = next.ofdmTurn;
        progress.ofdmImmunityLevel = next.ofdm;
        progress.cckImmunityLevel = next.cck;
        progress.adjusted = next.ofdm != before.ofdmImmunityLevel ||
                            next.cck != before.cckImmunityLevel;
        return progress;
    }

} // namespace simpleath
