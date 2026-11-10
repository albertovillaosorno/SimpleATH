// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565Pll.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <cstdint>

namespace simpleath
{
    namespace
    {
        // Linux ath9k hw.c: ath9k_hw_init_pll(), AR_SREV_9565 branch;
        // reg.h: AR_CH0_BB_DPLL1/2/3, AR_RTC_PLL_CONTROL, SLEEP_CLK.
        // https://github.com/torvalds/linux/blob/master/drivers/net/wireless/ath/ath9k/hw.c
        constexpr uint32_t kBbDpll1 = 0x16180;
        constexpr uint32_t kBbDpll2 = 0x16184;
        constexpr uint32_t kBbDpll3 = 0x16188;
        constexpr uint32_t kRtcPllControl = 0x7014;
        constexpr uint32_t kRtcSleepClock = 0x7048;
        constexpr uint8_t kJapan = 14;
        constexpr uint8_t kHt40Spacing = 4;
        constexpr uint32_t kRtcPllSetting = 0x0004142c;
        constexpr uint32_t kForceDerivedClock = 0x2;
        constexpr uint32_t kBbLockMicros = 1000;
        constexpr uint32_t kRtcSettleMicros = 100;

        struct Field
        {
                uint32_t address;
                uint32_t mask;
                uint8_t shift;
                uint32_t value;
        };

        // Ordered RMW operations, intentionally including repeated DPLL2
        // writes: the first powers down the PLL, the last powers it back up.
        // Preserve unrelated live hardware bitfields at every write.
        constexpr Field kFields[] = {
            {kBbDpll2, 0x00010000, 16, 1},    {kBbDpll2, 0x03f80000, 19, 0x40},
            {kBbDpll2, 0x3c000000, 26, 0x4},  {kBbDpll1, 0xf8000000, 27, 0x5},
            {kBbDpll1, 0x07fc0000, 18, 0x58}, {kBbDpll1, 0x0003ffff, 0, 0},
            {kBbDpll2, 0x0000e000, 13, 1},    {kBbDpll2, 0x40000000, 30, 1},
            {kBbDpll2, 0x00040000, 18, 1},    {kBbDpll3, 0x3f800000, 23, 0x6},
            {kBbDpll2, 0x00010000, 16, 0},
        };

        bool validChannel(const RfChannelRequest &request)
        {
            if (request.silicon != Revision::V1_0 &&
                request.silicon != Revision::V1_0_1 &&
                request.silicon != Revision::V1_1)
            {
                return false;
            }
            if (request.referenceClock != RfReferenceClock::Crystal25Mhz &&
                request.referenceClock != RfReferenceClock::Crystal40Mhz)
            {
                return false;
            }
            Channel canonical {};
            if (mapChannel(request.control.number, canonical) != Result::Ok ||
                request.control.centerMhz != canonical.centerMhz ||
                request.control.requiresJapanAuthorization !=
                    canonical.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20)
            {
                return request.secondary == 0;
            }
            if (request.width != ChannelWidth::Ht40 ||
                request.control.number == kJapan || request.secondary == kJapan)
            {
                return false;
            }
            Channel secondary {};
            return mapChannel(request.secondary, secondary) == Result::Ok &&
                   (static_cast<int>(request.secondary) -
                            static_cast<int>(request.control.number) ==
                        kHt40Spacing ||
                    static_cast<int>(request.control.number) -
                            static_cast<int>(request.secondary) ==
                        kHt40Spacing);
        }

        bool authorized(const CalibrationAndRegulatory &a)
        {
            return a.eepromContentsVerified &&
                   a.boardAntennaConfigurationVerified &&
                   a.localCountryRulesAvailable && a.channelPermitted &&
                   a.txPowerLimitsVerified && a.radioKillUnblocked &&
                   a.coexistenceConfigurationVerified;
        }

        bool fits(uint32_t length, uint32_t offset)
        {
            return offset <= length && length - offset >= sizeof(uint32_t);
        }
    } // namespace

    RfPllProgress
    initializeAr9565Pll(const RfChannelRequest &request,
                        const CalibrationAndRegulatory &authorization,
                        const RfChannelBackend &backend)
    {
        RfPllProgress result {
            RfPllResult::InvalidBackend, 0, 0, 0, false,
        };
        const RfChannelBackend stable = backend;
        const RfChannelRequest channel = request;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.barLengthBytes == 0 || io.permitWrite == nullptr ||
            io.write32 == nullptr || io.delayMicros == nullptr ||
            stable.read32 == nullptr)
        {
            return result;
        }
        result.result = RfPllResult::InvalidChannel;
        if (!validChannel(channel))
        {
            return result;
        }
        result.result = RfPllResult::MissingAuthorization;
        if (!authorized(authorization))
        {
            return result;
        }
        result.result = RfPllResult::InvalidBar;
        if (!fits(io.barLengthBytes, kBbDpll1) ||
            !fits(io.barLengthBytes, kBbDpll2) ||
            !fits(io.barLengthBytes, kBbDpll3) ||
            !fits(io.barLengthBytes, kRtcPllControl) ||
            !fits(io.barLengthBytes, kRtcSleepClock))
        {
            return result;
        }
        const auto permit = [&]
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            result.result = RfPllResult::OwnershipLost;
            result.requiresReset =
                result.requiresReset || result.completedWrites != 0;
            return false;
        };
        const auto write = [&](uint32_t offset, uint32_t value)
        {
            if (!permit())
            {
                return false;
            }
            result.lastOffset = offset;
            result.requiresReset = true;
            if (!io.write32(io.context, offset, value))
            {
                result.result = RfPllResult::WriteFailed;
                return false;
            }
            ++result.completedWrites;
            return true;
        };
        for (const auto &field : kFields)
        {
            if (!permit())
            {
                return result;
            }
            uint32_t before = 0;
            result.lastOffset = field.address;
            if (!stable.read32(io.context, field.address, &before))
            {
                result.result = RfPllResult::ReadFailed;
                result.requiresReset = result.completedWrites != 0;
                return result;
            }
            ++result.completedReads;
            const uint32_t value = (before & ~field.mask) |
                                   ((field.value << field.shift) & field.mask);
            if (!write(field.address, value))
            {
                return result;
            }
        }
        if (!permit())
        {
            return result;
        }
        io.delayMicros(io.context, kBbLockMicros);
        if (!write(kRtcPllControl, kRtcPllSetting) || !permit())
        {
            return result;
        }
        io.delayMicros(io.context, kRtcSettleMicros);
        if (!write(kRtcSleepClock, kForceDerivedClock) || !permit())
        {
            return result;
        }
        result.requiresReset = false;
        result.result = RfPllResult::Ok;
        return result;
    }
} // namespace simpleath
