// AR9003 channel PHY/MAC mode based on Linux ath9k v6.12 ar9003_phy.c,
// hw.c and ar9003_phy.h/reg.h, Atheros/Qualcomm ISC-licensed reference.
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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
#include "Ar9565PhyMode.hpp"
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "Ar9565RfIni.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        // Linux AR_SM_BASE 0xa200, AR_PHY_GEN_CTRL +4;
        // MAC PCU AR_2040_MODE, AR_GTXTO, AR_CST.
        constexpr uint32_t kPhyGenControl = 0xa204;
        constexpr uint32_t kMacJoinedCca = 0x8318;
        constexpr uint32_t kGlobalTxTimeout = 0x0064;
        constexpr uint32_t kCarrierSenseTimeout = 0x006c;
        constexpr uint32_t kPhyDynamic40 = 0x00000004;
        constexpr uint32_t kPhyPrimaryUpper = 0x00000010;
        constexpr uint32_t kPhyHt = 0x00000040;
        constexpr uint32_t kPhyShortGi = 0x00000080;
        constexpr uint32_t kPhySingleHtLtf = 0x00000200;
        constexpr uint32_t kPhyGreenfieldDetect = 0x00000400;
        constexpr uint32_t kPhyModeMask = 0x000007ff;
        constexpr uint32_t kJoinedCcaMask = 1;
        constexpr uint32_t kTimeoutMask = 0xffff0000;
        constexpr uint32_t kTimeoutShift = 16;
        constexpr uint32_t kTxTimeoutTu = 25;
        constexpr uint32_t kCarrierTimeoutTu = 15;
        constexpr uint8_t kJapanChannel = 14;
        constexpr int kHt40ChannelSpacing = 4;

        struct RegisterChange
        {
                uint32_t offset;
                uint32_t mask;
                uint32_t value;
        };

        bool validChannel(const RfChannelRequest &request)
        {
            if ((request.silicon != Revision::V1_0 &&
                 request.silicon != Revision::V1_0_1 &&
                 request.silicon != Revision::V1_1) ||
                (request.referenceClock != RfReferenceClock::Crystal25Mhz &&
                 request.referenceClock != RfReferenceClock::Crystal40Mhz))
            {
                return false;
            }
            Channel mapped {};
            if (mapChannel(request.control.number, mapped) != Result::Ok ||
                mapped.centerMhz != request.control.centerMhz ||
                mapped.requiresJapanAuthorization !=
                    request.control.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20)
            {
                return request.secondary == 0;
            }
            if (request.width != ChannelWidth::Ht40 ||
                request.control.number == kJapanChannel ||
                request.secondary == kJapanChannel)
            {
                return false;
            }
            Channel secondary {};
            if (mapChannel(request.secondary, secondary) != Result::Ok)
            {
                return false;
            }
            const int step = static_cast<int>(request.secondary) -
                             static_cast<int>(request.control.number);
            return step == kHt40ChannelSpacing || step == -kHt40ChannelSpacing;
        }

        bool fitsBar(uint32_t length, uint32_t offset)
        {
            return offset <= length && length - offset >= sizeof(uint32_t);
        }

        bool permit(const RfIniBackend &io, PhyModeProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = PhyModeResult::OwnershipLost;
            return false;
        }

        bool program(const RxAgcBackend &backend, const RegisterChange &change,
                     PhyModeProgress &progress)
        {
            const RfIniBackend &io = backend.io;
            progress.lastOffset = change.offset;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t before = 0;
            if (!backend.read32(io.context, change.offset, &before))
            {
                progress.result = PhyModeResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            const uint32_t next =
                (before & ~change.mask) | (change.value & change.mask);
            if (!permit(io, progress))
            {
                return false;
            }
            // A failing MMIO callback may already have posted to the card.
            progress.requiresReset = true;
            if (!io.write32(io.context, change.offset, next))
            {
                progress.result = PhyModeResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            if (!permit(io, progress))
            {
                return false;
            }
            uint32_t observed = 0;
            if (!backend.read32(io.context, change.offset, &observed))
            {
                progress.result = PhyModeResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            if ((observed & change.mask) != (next & change.mask))
            {
                progress.result = PhyModeResult::ReadbackMismatch;
                return false;
            }
            return true;
        }
    } // namespace

    PhyModeProgress programAr9565ReceiveOnlyPhyMode(
        const RfChannelRequest &request,
        const CalibrationAndRegulatory &authorization,
        const RxAgcBackend &backend)
    {
        PhyModeProgress progress {
            PhyModeResult::InvalidBackend, 0, 0, 0, false,
        };
        const RxAgcBackend stable = backend;
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory allowed = authorization;
        const RfIniBackend &io = stable.io;
        if (io.context == nullptr || io.ownerEpoch == 0 ||
            io.barLengthBytes == 0 || io.permitWrite == nullptr ||
            io.write32 == nullptr || stable.read32 == nullptr)
        {
            return progress;
        }
        progress.result = PhyModeResult::InvalidChannel;
        if (!validChannel(channel) ||
            (channel.control.number == kJapanChannel &&
             !allowed.localCountryRulesAvailable))
        {
            return progress;
        }
        progress.result = PhyModeResult::MissingAuthorization;
        if (allowed.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(allowed))
        {
            return progress;
        }
        progress.result = PhyModeResult::InvalidBar;
        if (!fitsBar(io.barLengthBytes, kPhyGenControl) ||
            !fitsBar(io.barLengthBytes, kMacJoinedCca) ||
            !fitsBar(io.barLengthBytes, kGlobalTxTimeout) ||
            !fitsBar(io.barLengthBytes, kCarrierSenseTimeout))
        {
            return progress;
        }
        uint32_t mode = 0;
        if (channel.control.number != kJapanChannel)
        {
            mode = kPhyHt | kPhyShortGi | kPhySingleHtLtf;
        }
        const bool wide = channel.width == ChannelWidth::Ht40;
        if (wide)
        {
            mode |= kPhyDynamic40;
            if (channel.secondary > channel.control.number)
            {
                mode |= kPhyPrimaryUpper;
            }
        }
        const RegisterChange changes[] = {
            {kPhyGenControl, kPhyModeMask, mode & ~kPhyGreenfieldDetect},
            {kMacJoinedCca, kJoinedCcaMask, wide ? kJoinedCcaMask : 0U},
            {kGlobalTxTimeout, kTimeoutMask, kTxTimeoutTu << kTimeoutShift},
            {
                kCarrierSenseTimeout,
                kTimeoutMask,
                kCarrierTimeoutTu << kTimeoutShift,
            },
        };
        for (const auto &change : changes)
        {
            if (!program(stable, change, progress))
            {
                return progress;
            }
        }
        if (!permit(io, progress))
        {
            return progress;
        }
        progress.result = PhyModeResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
