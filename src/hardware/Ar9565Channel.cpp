// SPDX-License-Identifier: GPL-2.0-only
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <cstdint>

namespace simpleath
{
    namespace
    {
        // Linux ath9k ar9003_phy.h: AR_SM_BASE + 0x140, and 65nm CH0.
        // https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath9k/ar9003_phy.c
        constexpr uint8_t kJapanChannel = 14;
        constexpr uint32_t kSynthControl = 0xa340;
        constexpr uint32_t kSynth4 = 0x1608c;
        constexpr uint32_t kSynth7 = 0x16098;
        constexpr uint32_t kSynthLongShift = 1U;
        constexpr uint32_t kSynth2G = 1U << 29U;
        constexpr uint32_t kSynthFractional = 1U << 30U;
        constexpr uint32_t kSynthLoad = 1U << 31U;
        constexpr uint32_t kFracScale = 0x20000;

        bool authorized(const CalibrationAndRegulatory &r)
        {
            return radioInitializationAuthorized(r);
        }

        bool supportsRevision(Revision revision)
        {
            return revision == Revision::V1_0 || revision == Revision::V1_0_1 ||
                   revision == Revision::V1_1;
        }

        bool centerFrequency(const RfChannelRequest &r, uint16_t &out)
        {
            Channel canonical {};
            if (!supportsRevision(r.silicon) ||
                mapChannel(r.control.number, canonical) != Result::Ok ||
                r.control.centerMhz != canonical.centerMhz ||
                r.control.requiresJapanAuthorization !=
                    canonical.requiresJapanAuthorization)
            {
                return false;
            }
            if (r.width == ChannelWidth::Ht20 && r.secondary == 0)
            {
                out = canonical.centerMhz;
                return true;
            }
            if (r.width != ChannelWidth::Ht40 || r.secondary == 0 ||
                r.control.number == kJapanChannel ||
                r.secondary == kJapanChannel)
            {
                return false;
            }
            Channel second {};
            if (mapChannel(r.secondary, second) != Result::Ok ||
                (static_cast<int>(r.secondary) -
                         static_cast<int>(r.control.number) !=
                     4 &&
                 static_cast<int>(r.control.number) -
                         static_cast<int>(r.secondary) !=
                     4))
            {
                return false;
            }
            out = static_cast<uint16_t>(
                (canonical.centerMhz + second.centerMhz) / 2U);
            return true;
        }

        bool fitsBar(uint32_t length, uint32_t offset)
        {
            return length >= sizeof(uint32_t) && offset <= length &&
                   length - offset >= sizeof(uint32_t);
        }
    } // namespace

    RfChannelProgress
    tuneAr9565Channel(const RfChannelRequest &request,
                      const CalibrationAndRegulatory &authorization,
                      const RfChannelBackend &backend)
    {
        RfChannelProgress progress {
            RfChannelResult::InvalidBackend, 0, 0, 0, false,
        };
        // Freeze callback pointers and the requested channel before invoking
        // any external callback. Neither may change mid-transaction.
        const RfChannelBackend stable = backend;
        const RfChannelRequest channel = request;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.barLengthBytes == 0 || io.permitWrite == nullptr ||
            io.write32 == nullptr || stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = RfChannelResult::InvalidChannel;
        if ((channel.referenceClock != RfReferenceClock::Crystal25Mhz &&
             channel.referenceClock != RfReferenceClock::Crystal40Mhz) ||
            !centerFrequency(channel, progress.synthesizerMhz))
        {
            progress.synthesizerMhz = 0;
            return progress;
        }
        progress.result = RfChannelResult::MissingAuthorization;
        if (!authorized(authorization))
        {
            progress.synthesizerMhz = 0;
            return progress;
        }
        progress.result = RfChannelResult::InvalidBar;
        if (!fitsBar(io.barLengthBytes, kSynthControl) ||
            !fitsBar(io.barLengthBytes, kSynth4) ||
            !fitsBar(io.barLengthBytes, kSynth7))
        {
            progress.synthesizerMhz = 0;
            return progress;
        }

        const uint32_t divider =
            channel.referenceClock == RfReferenceClock::Crystal25Mhz ? 75U
                                                                     : 120U;
        const uint32_t scaled =
            static_cast<uint32_t>(progress.synthesizerMhz) * 4U;
        // Linux AR9565 uses a 9-bit integer and 17-bit fraction. Everything
        // here is 2.4 GHz and fits before shifting into SYNTH7 [27:2].
        const uint32_t selection =
            ((scaled / divider) << 17U) |
            (((scaled % divider) * kFracScale) / divider);
        const uint32_t synthValue = (selection << 2U) | kSynthFractional;

        const auto permit = [&]
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = RfChannelResult::OwnershipLost;
            progress.requiresReset = progress.completedWrites != 0;
            return false;
        };
        const auto write = [&](uint32_t offset, uint32_t value)
        {
            if (!permit())
            {
                return false;
            }
            progress.lastOffset = offset;
            // A failing MMIO callback may already have posted the write.
            progress.requiresReset = true;
            if (!io.write32(io.context, offset, value))
            {
                progress.result = RfChannelResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            return true;
        };

        if (!write(kSynthControl, kSynth2G) || !permit())
        {
            return progress;
        }
        uint32_t synth4 = 0;
        if (!stable.read32(io.context, kSynth4, &synth4))
        {
            progress.result = RfChannelResult::ReadFailed;
            progress.requiresReset = true;
            return progress;
        }
        if (!write(kSynth4, synth4 | kSynthLongShift) ||
            !write(kSynth7, synthValue) ||
            !write(kSynth7, synthValue | kSynthLoad) || !permit())
        {
            return progress;
        }
        progress.requiresReset = false;
        progress.result = RfChannelResult::Ok;
        return progress;
    }
} // namespace simpleath
