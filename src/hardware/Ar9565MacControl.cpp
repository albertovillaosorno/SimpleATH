// SPDX-License-Identifier: AGPL-3.0-only
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
// AR9565 register protocol derived from pinned ath9k mac.c/reg.h.
#include "Ar9565MacControl.hpp"
#include "Ar9565Core.hpp"
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kInterruptEnable = 0x0024;
        constexpr uint32_t kSyncInterruptEnable = 0x402c;
        constexpr uint32_t kReceiveControl = 0x0008;
        constexpr uint32_t kReceiveDisable = 0x20;
        constexpr uint32_t kReceiveEnableMask = 0x0c;
        constexpr uint32_t kTransmitDisable = 0x0880;
        constexpr uint32_t kTransmitEnable = 0x0840;
        constexpr uint32_t kAllTransmitQueues = 0x3ff;
        constexpr uint32_t kDiagnosticControl = 0x8048;
        constexpr uint32_t kBlockReceiveAndResponses = 0x02000026;
        constexpr uint32_t kObserveBus = 0x806c;
        constexpr uint32_t kReceiveState = 0x01f00000;
        constexpr uint32_t kRtcShutdown = 1;
        constexpr uint32_t kRtcSleep = 4;
        constexpr uint32_t kRtcWakeup = 8;
        constexpr unsigned int kMaximumWaitPolls = 1000U;
        constexpr uint32_t kPollIntervalMicros = 10U;

        bool read(const RegisterBus &bus, uint32_t offset, uint32_t &value)
        {
            return bus.read32(bus.context, offset, &value) &&
                   value != UINT32_MAX;
        }

        bool validBackend(const RegisterBus &bus,
                          void (*delayMicros)(void *, uint32_t))
        {
            return bus.context != nullptr && bus.read32 != nullptr &&
                   bus.write32 != nullptr && delayMicros != nullptr &&
                   bus.barLengthBytes >= kObserveBus + sizeof(uint32_t);
        }
    } // namespace

    MacStopResult quiesceAr9565Mac(const RegisterBus &supplied,
                                   void (*delayMicros)(void *, uint32_t))
    {
        const RegisterBus bus = supplied;
        if (!validBackend(bus, delayMicros))
        {
            return MacStopResult::InvalidBackend;
        }
        uint32_t rtc = 0;
        if (!read(bus, kRtcStatusRegister, rtc))
        {
            return MacStopResult::ReadFailed;
        }
        rtc &= kRtcStatusMask;
        if (rtc != kRtcShutdown && rtc != kRtcSleep && rtc != kRtcOn &&
            rtc != kRtcWakeup)
        {
            return MacStopResult::UnknownRtcState;
        }
        if (!bus.write32(bus.context, kSyncInterruptEnable, 0))
        {
            return MacStopResult::WriteFailed;
        }
        // RTC shutdown/sleep cannot run MAC queues. Never touch sleeping MAC
        // registers. The caller bootstraps RTC, then quiesces again while on.
        if (rtc == kRtcShutdown || rtc == kRtcSleep)
        {
            return MacStopResult::Ok;
        }
        for (unsigned int poll = 0;
             rtc == kRtcWakeup && poll < kMaximumWaitPolls; ++poll)
        {
            delayMicros(bus.context, kPollIntervalMicros);
            if (!read(bus, kRtcStatusRegister, rtc))
            {
                return MacStopResult::ReadFailed;
            }
            rtc &= kRtcStatusMask;
        }
        if (rtc == kRtcWakeup)
        {
            return MacStopResult::Timeout;
        }
        if (rtc == kRtcShutdown || rtc == kRtcSleep)
        {
            return MacStopResult::Ok;
        }
        if (rtc != kRtcOn)
        {
            return MacStopResult::UnknownRtcState;
        }
        uint32_t diagnostic = 0;
        if (!read(bus, kDiagnosticControl, diagnostic))
        {
            return MacStopResult::ReadFailed;
        }
        if (!bus.write32(bus.context, kInterruptEnable, 0) ||
            !bus.write32(bus.context, kDiagnosticControl,
                         diagnostic | kBlockReceiveAndResponses) ||
            !bus.write32(bus.context, kReceiveControl, kReceiveDisable) ||
            !bus.write32(bus.context, kTransmitDisable, kAllTransmitQueues))
        {
            return MacStopResult::WriteFailed;
        }
        for (unsigned int poll = 0; poll < kMaximumWaitPolls; ++poll)
        {
            uint32_t rx = 0;
            uint32_t tx = 0;
            uint32_t observe = 0;
            if (!read(bus, kReceiveControl, rx) ||
                !read(bus, kTransmitEnable, tx) ||
                !read(bus, kObserveBus, observe))
            {
                return MacStopResult::ReadFailed;
            }
            if (((rx & kReceiveEnableMask) == 0U) &&
                ((tx & kAllTransmitQueues) == 0U) &&
                ((observe & kReceiveState) == 0U))
            {
                return MacStopResult::Ok;
            }
            delayMicros(bus.context, kPollIntervalMicros);
        }
        return MacStopResult::Timeout;
    }
} // namespace simpleath
