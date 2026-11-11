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
// TSF register reads and 32-bit RX timestamp extension adapted from pinned
// Linux ath9k hw.c and recv.c (see .references/ledger.jsonl).
#include "Ar9565RxTsf.hpp"
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kTsfLower = 0x804cU;
        constexpr uint32_t kTsfUpper = 0x8050U;
        constexpr uint64_t kOneTsfWrap = 0x100000000ULL;
        constexpr uint32_t kMaxStableReads = 10U;
        // Bounds the host clock correlation and RX processing latency.
        constexpr uint64_t kMaxHostCaptureSpanUsec = 2000U;
        constexpr uint64_t kMaxFrameAgeUsec = 200000U;

        bool access(const RxTsfBackend &io, uint32_t offset, uint32_t &value,
                    RxTsfResult &result)
        {
            if (!io.permitRead(io.context, io.ownerEpoch))
            {
                result = RxTsfResult::OwnershipLost;
                return false;
            }
            if (!io.read32(io.context, offset, &value))
            {
                result = RxTsfResult::ReadFailed;
                return false;
            }
            return true;
        }
    } // namespace

    RxTsfResult captureAr9565RxTsf(const RxTsfBackend &backend,
                                   uint32_t descriptorTsfLow, RxTsfSample &out)
    {
        // Snapshot callback pointers before invoking any of them.
        const RxTsfBackend io = backend;
        out = {};
        if (io.context == nullptr || io.ownerEpoch == 0U ||
            io.permitRead == nullptr || io.read32 == nullptr ||
            io.monotonicMicros == nullptr)
        {
            return RxTsfResult::InvalidBackend;
        }
        if (io.barLengthBytes < kTsfUpper + sizeof(uint32_t))
        {
            return RxTsfResult::InvalidBar;
        }
        if (!io.permitRead(io.context, io.ownerEpoch))
        {
            return RxTsfResult::OwnershipLost;
        }
        const uint64_t before = io.monotonicMicros(io.context);
        if (before == 0U)
        {
            return RxTsfResult::InvalidClock;
        }
        RxTsfResult result = RxTsfResult::UnstableClock;
        uint32_t upperBefore = 0;
        if (!access(io, kTsfUpper, upperBefore, result))
        {
            return result;
        }
        uint32_t lower = 0;
        uint32_t upperAfter = 0;
        bool stable = false;
        for (uint32_t attempt = 0U; attempt < kMaxStableReads; ++attempt)
        {
            if (!access(io, kTsfLower, lower, result) ||
                !access(io, kTsfUpper, upperAfter, result))
            {
                return result;
            }
            if (upperAfter == upperBefore)
            {
                stable = true;
                break;
            }
            upperBefore = upperAfter;
        }
        if (!stable)
        {
            return RxTsfResult::UnstableClock;
        }
        if (!io.permitRead(io.context, io.ownerEpoch))
        {
            return RxTsfResult::OwnershipLost;
        }
        const uint64_t after = io.monotonicMicros(io.context);
        if (after < before || after - before > kMaxHostCaptureSpanUsec)
        {
            return RxTsfResult::InvalidClock;
        }
        const uint64_t current =
            (static_cast<uint64_t>(upperBefore) << 32U) | lower;
        const uint64_t base = current & ~(kOneTsfWrap - 1U);
        uint64_t received = base | descriptorTsfLow;
        if (received > current)
        {
            if (base == 0U)
            {
                return RxTsfResult::StaleFrame;
            }
            received -= kOneTsfWrap;
        }
        const uint64_t age = current - received;
        const uint64_t hostCapture = before + ((after - before) / 2U);
        if (age > kMaxFrameAgeUsec || hostCapture < age)
        {
            return RxTsfResult::StaleFrame;
        }
        out.ownerEpoch = io.ownerEpoch;
        out.hardwareRxTsfUsec = received;
        out.hardwareCaptureTsfUsec = current;
        out.captureMonotonicUsec = hostCapture;
        out.frameMonotonicUsec = hostCapture - age;
        out.ageUsec = static_cast<uint32_t>(age);
        return RxTsfResult::Ok;
    }
} // namespace simpleath
