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
            saved.channel != channel.control.number)
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
} // namespace simpleath
