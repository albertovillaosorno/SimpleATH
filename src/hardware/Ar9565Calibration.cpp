// SPDX-License-Identifier: AGPL-3.0-only
// Register sequence and hardware algorithm provenance (ath9k):
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
#include "Ar9565Calibration.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        // ath9k ar9003_calib.c: ar9003_hw_init_cal_pcoem / AGC wait;
        // ath9k ar9003_phy.h and reg.h (AR9300 SM base 0xa200).
        constexpr uint32_t kAgcControl = 0xa2c4;
        constexpr uint32_t kCarrierLeakControl = 0xa2d8;
        constexpr uint32_t kTxIqControl = 0xa5c4;
        constexpr uint32_t kAgcCal = 0x1;
        constexpr uint32_t kAgcOffset = 0x800;
        constexpr uint32_t kAgcTxFilter = 0x10000;
        constexpr uint32_t kAgcPeakDetector = 0x100000;
        constexpr uint32_t kCarrierLeakEnable = 0x2;
        constexpr uint32_t kTxIqEnable = 0x80000000;
        constexpr uint32_t kPollingMicros = 10;
        constexpr size_t kMaximumPolls = 100000 / kPollingMicros;
        constexpr uint8_t kChannel14 = 14;
        constexpr uint8_t kHt40Separation = 4;

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
            Channel channel {};
            if (mapChannel(request.control.number, channel) != Result::Ok ||
                channel.centerMhz != request.control.centerMhz ||
                channel.requiresJapanAuthorization !=
                    request.control.requiresJapanAuthorization)
            {
                return false;
            }
            if (request.width == ChannelWidth::Ht20)
            {
                return request.secondary == 0;
            }
            if (request.width != ChannelWidth::Ht40 ||
                request.control.number == kChannel14 ||
                request.secondary == kChannel14)
            {
                return false;
            }
            Channel secondary {};
            if (mapChannel(request.secondary, secondary) != Result::Ok)
            {
                return false;
            }
            const int delta = static_cast<int>(request.control.number) -
                              static_cast<int>(request.secondary);
            return delta == kHt40Separation || delta == -kHt40Separation;
        }

        bool validBackend(const RxAgcBackend &backend)
        {
            const auto &io = backend.io;
            return io.context != nullptr && io.ownerEpoch != 0 &&
                   io.permitWrite != nullptr && io.write32 != nullptr &&
                   io.delayMicros != nullptr && backend.read32 != nullptr;
        }

        bool permit(const RfIniBackend &io, RxAgcProgress &progress)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = RxAgcResult::OwnershipLost;
            return false;
        }

        bool read(const RxAgcBackend &backend, RxAgcProgress &progress,
                  uint32_t address, uint32_t &value)
        {
            const auto &io = backend.io;
            if (!permit(io, progress))
            {
                return false;
            }
            progress.lastOffset = address;
            if (!backend.read32(io.context, address, &value))
            {
                progress.result = RxAgcResult::ReadFailed;
                return false;
            }
            ++progress.completedReads;
            return true;
        }

        bool write(const RfIniBackend &io, RxAgcProgress &progress,
                   uint32_t address, uint32_t value)
        {
            if (!permit(io, progress))
            {
                return false;
            }
            progress.lastOffset = address;
            // A false write return does not prove that hardware ignored it.
            progress.requiresReset = true;
            if (!io.write32(io.context, address, value))
            {
                progress.result = RxAgcResult::WriteFailed;
                return false;
            }
            ++progress.completedWrites;
            return true;
        }

        void poll(const RxAgcBackend &backend, RxAgcProgress &progress)
        {
            const auto &io = backend.io;
            for (size_t i = 0; i < kMaximumPolls; ++i)
            {
                uint32_t status = 0;
                if (!read(backend, progress, kAgcControl, status))
                {
                    return;
                }
                ++progress.polls;
                if ((status & kAgcCal) == 0)
                {
                    if (permit(io, progress))
                    {
                        progress.result = RxAgcResult::Ok;
                        progress.requiresReset = false;
                    }
                    return;
                }
                if (i + 1 < kMaximumPolls)
                {
                    io.delayMicros(io.context, kPollingMicros);
                }
            }
            progress.result = RxAgcResult::Timeout;
        }
    } // namespace

    RxAgcProgress
    runAr9565RxAgcCalibration(const RfChannelRequest &request,
                              const CalibrationAndRegulatory &authorization,
                              const RxAgcBackend &backend)
    {
        RxAgcProgress progress {RxAgcResult::InvalidBackend, 0, 0, 0, 0, false};
        const RxAgcBackend stable = backend;
        const RfChannelRequest channel = request;
        const CalibrationAndRegulatory permissions = authorization;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RxAgcResult::InvalidChannel;
        if (!validChannel(channel))
        {
            return progress;
        }
        progress.result = RxAgcResult::MissingAuthorization;
        if (permissions.use != RadioInitialization::ReceiveOnly ||
            !radioInitializationAuthorized(permissions))
        {
            return progress;
        }
        const RfIniBackend &io = stable.io;
        progress.result = RxAgcResult::InvalidBar;
        if (io.barLengthBytes < kTxIqControl + sizeof(uint32_t))
        {
            return progress;
        }
        uint32_t agc = 0;
        uint32_t txIq = 0;
        uint32_t carrierLeak = 0;
        if (!read(stable, progress, kAgcControl, agc) ||
            !read(stable, progress, kTxIqControl, txIq) ||
            !read(stable, progress, kCarrierLeakControl, carrierLeak))
        {
            return progress;
        }
        progress.result = RxAgcResult::AlreadyBusy;
        if ((agc & kAgcCal) != 0)
        {
            return progress;
        }
        if (!write(io, progress, kTxIqControl, txIq & ~kTxIqEnable) ||
            !write(io, progress, kCarrierLeakControl,
                   carrierLeak & ~kCarrierLeakEnable) ||
            !write(io, progress, kAgcControl,
                   (agc | kAgcOffset | kAgcCal) &
                       ~(kAgcTxFilter | kAgcPeakDetector)))
        {
            return progress;
        }
        // Hardware must deassert AGC.CAL on completion. A bounded wait
        // never establishes PHY or regulatory readiness by itself.
        poll(stable, progress);
        return progress;
    }
} // namespace simpleath
