// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for ar9565 ofdm timing.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for ar9565 ofdm timing.
// - Description:
//   - Implements or verifies the test_ar9565_ofdm_timing source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 ofdm timing.

// Synthetic channel/epoch/MMIO test: never touches PCI or RF hardware.
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565OfdmTiming.hpp"
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 31;
    constexpr uint32_t kMismatchBit = 0x20000;
    constexpr size_t kRevokeAfterFirstWrite = 5;
    constexpr uint8_t kInvalidHt40Secondary = 9;
    constexpr uint16_t kJapanCenter = 2484;
    constexpr uint16_t kNormalCh6 = 21514;
    constexpr uint16_t kShortCh6 = 19362;
    constexpr uint16_t kNormalUpper = 21426;
    constexpr uint16_t kShortUpper = 19283;
    constexpr uint16_t kNormalLower = 21602;
    constexpr uint16_t kShortLower = 19442;
    constexpr uint16_t kNormalJapan = 21107;
    constexpr uint16_t kShortJapan = 18996;
    constexpr uint32_t kBarLength = 0x20000;
    constexpr uint32_t kTiming3 = 0x9808;
    constexpr uint32_t kSgiDelta = 0x9c14;
    constexpr uint32_t kTimingMask = 0xffffe000;
    constexpr uint32_t kSgiMask = 0x0007ffff;
    constexpr uint32_t kTimingInitial = 0x00001a53;
    constexpr uint32_t kSgiInitial = 0xa5500000;
    constexpr uint8_t kCh6 = 6;
    constexpr uint8_t kCh10 = 10;
    constexpr uint8_t kCh2 = 2;
    constexpr uint8_t kCh14 = 14;
    constexpr uint16_t kCenter6 = 2437;
    constexpr uint16_t kCenterUpper = 2447;
    constexpr uint16_t kCenterLower = 2427;

    struct Mock
    {
            uint32_t timing3 = kTimingInitial;
            uint32_t sgi = kSgiInitial;
            size_t permits = 0;
            size_t reads = 0;
            size_t writes = 0;
            size_t revokeAt = 0;
            size_t failReadAt = 0;
            size_t failWriteAt = 0;
            size_t distortReadAt = 0;
            bool deny = false;
    };

    bool permit(void *p, uint64_t epoch)
    {
        auto &mock = *static_cast<Mock *>(p);
        ++mock.permits;
        return epoch == kEpoch && !mock.deny &&
               (mock.revokeAt == 0 || mock.permits < mock.revokeAt);
    }

    bool read(void *p, uint32_t offset, uint32_t *out)
    {
        auto &mock = *static_cast<Mock *>(p);
        ++mock.reads;
        if (mock.reads == mock.failReadAt || out == nullptr)
        {
            return false;
        }
        if (offset != kTiming3 && offset != kSgiDelta)
        {
            return false;
        }
        const uint32_t observed = offset == kTiming3 ? mock.timing3 : mock.sgi;
        *out = mock.reads == mock.distortReadAt ? observed ^ kMismatchBit
                                                : observed;
        return true;
    }

    bool write(void *p, uint32_t offset, const uint32_t value)
    {
        auto &mock = *static_cast<Mock *>(p);
        ++mock.writes;
        if (mock.writes == mock.failWriteAt)
        {
            return false;
        }
        if (offset == kTiming3)
        {
            mock.timing3 = value;
            return true;
        }
        if (offset == kSgiDelta)
        {
            mock.sgi = value;
            return true;
        }
        return false;
    }

    void delay(void * /*context*/, uint32_t /*micros*/)
    {
    }

    RxAgcBackend backend(Mock &mock)
    {
        return {{&mock, kEpoch, kBarLength, permit, write, delay}, read};
    }

    RfChannelRequest request(uint8_t number,
                             ChannelWidth width = ChannelWidth::Ht20,
                             uint8_t secondary = 0)
    {
        Channel channel {};
        (void)mapChannel(number, channel);
        return {
            Revision::V1_1,
            channel,
            width,
            secondary,
            RfReferenceClock::Crystal25Mhz,
        };
    }

    const CalibrationAndRegulatory kRxOnly {
        true,  true, false, true,
        false, true, true,  RadioInitialization::ReceiveOnly,
    };

    bool verify(Mock &mock, const RfChannelRequest &channel,
                uint16_t expectedCenter, uint16_t normal,
                uint16_t shortInterval,
                const CalibrationAndRegulatory &authorization = kRxOnly)
    {
        const auto progress =
            programAr9565OfdmTiming(channel, authorization, backend(mock));
        if (progress.result != OfdmTimingResult::Ok || progress.requiresReset ||
            progress.completedReads != 4 || progress.completedWrites != 2 ||
            mock.reads != 4 || mock.writes != 2 ||
            progress.lastOffset != kSgiDelta ||
            progress.synthesizerMhz != expectedCenter ||
            progress.normalMantissa != normal ||
            progress.shortMantissa != shortInterval ||
            progress.normalExponent != 3 || progress.shortExponent != 3)
        {
            return false;
        }
        const uint32_t timingBits =
            (static_cast<uint32_t>(normal) << 17U) | (3U << 13U);
        const uint32_t sgiBits =
            (static_cast<uint32_t>(shortInterval) << 4U) | 3U;
        return mock.timing3 == (kTimingInitial | timingBits) &&
               mock.sgi == (kSgiInitial | sgiBits) &&
               (mock.timing3 & ~kTimingMask) == kTimingInitial &&
               (mock.sgi & ~kSgiMask) == kSgiInitial;
    }

    bool validChannels()
    {
        Mock mock {};
        if (!verify(mock, request(kCh6), kCenter6, kNormalCh6, kShortCh6))
        {
            return false;
        }
        mock = {};
        if (!verify(mock, request(kCh6, ChannelWidth::Ht40, kCh10),
                    kCenterUpper, kNormalUpper, kShortUpper))
        {
            return false;
        }
        mock = {};
        if (!verify(mock, request(kCh6, ChannelWidth::Ht40, kCh2), kCenterLower,
                    kNormalLower, kShortLower))
        {
            return false;
        }
        mock = {};
        auto japanAuthorized = kRxOnly;
        japanAuthorized.localCountryRulesAvailable = true;
        return verify(mock, request(kCh14), kJapanCenter, kNormalJapan,
                      kShortJapan, japanAuthorized);
    }

    bool rejectedInputs()
    {
        Mock mock {};
        const auto denied = [&](const RfChannelRequest &channel,
                                const CalibrationAndRegulatory &auth)
        {
            mock = {};
            const auto result =
                programAr9565OfdmTiming(channel, auth, backend(mock));
            return result.result != OfdmTimingResult::Ok &&
                   result.completedWrites == 0 && mock.reads == 0 &&
                   mock.writes == 0 && !result.requiresReset;
        };
        if (!denied(request(kCh14), kRxOnly) ||
            !denied(request(kCh14, ChannelWidth::Ht40, kCh10), kRxOnly) ||
            !denied(request(kCh6, ChannelWidth::Ht40, kInvalidHt40Secondary),
                    kRxOnly) ||
            !denied(request(kCh6, ChannelWidth::Ht20, kCh10), kRxOnly))
        {
            return false;
        }
        auto invalid = request(kCh6);
        invalid.control.centerMhz++;
        if (!denied(invalid, kRxOnly))
        {
            return false;
        }
        invalid = request(kCh6);
        invalid.silicon = Revision::Unknown;
        if (!denied(invalid, kRxOnly))
        {
            return false;
        }
        auto unauthorized = kRxOnly;
        unauthorized.radioKillUnblocked = false;
        if (!denied(request(kCh6), unauthorized))
        {
            return false;
        }
        mock = {};
        auto io = backend(mock);
        io.io.barLengthBytes = kSgiDelta;
        const auto badBar = programAr9565OfdmTiming(request(kCh6), kRxOnly, io);
        if (badBar.result != OfdmTimingResult::InvalidBar || mock.reads != 0 ||
            mock.writes != 0)
        {
            return false;
        }
        mock = {};
        io = backend(mock);
        io.read32 = nullptr;
        const auto badBackend =
            programAr9565OfdmTiming(request(kCh6), kRxOnly, io);
        return badBackend.result == OfdmTimingResult::InvalidBackend &&
               mock.reads == 0 && mock.writes == 0;
    }

    bool failureAndReset()
    {
        Mock mock {};
        const auto run = [&]
        {
            return programAr9565OfdmTiming(request(kCh6), kRxOnly,
                                           backend(mock));
        };
        mock.deny = true;
        auto result = run();
        if (result.result != OfdmTimingResult::OwnershipLost ||
            result.requiresReset || mock.writes != 0)
        {
            return false;
        }
        mock = {};
        mock.failReadAt = 1;
        result = run();
        if (result.result != OfdmTimingResult::ReadFailed ||
            result.requiresReset || mock.writes != 0)
        {
            return false;
        }
        mock = {};
        mock.failWriteAt = 1;
        result = run();
        if (result.result != OfdmTimingResult::WriteFailed ||
            !result.requiresReset || mock.writes != 1)
        {
            return false;
        }
        mock = {};
        mock.failReadAt = 3;
        result = run();
        if (result.result != OfdmTimingResult::ReadFailed ||
            !result.requiresReset || result.completedWrites != 1)
        {
            return false;
        }
        mock = {};
        mock.failWriteAt = 2;
        result = run();
        if (result.result != OfdmTimingResult::WriteFailed ||
            !result.requiresReset || mock.writes != 2)
        {
            return false;
        }
        mock = {};
        mock.distortReadAt = 4;
        result = run();
        if (result.result != OfdmTimingResult::ReadbackMismatch ||
            !result.requiresReset || mock.writes != 2)
        {
            return false;
        }
        mock = {};
        mock.revokeAt = kRevokeAfterFirstWrite;
        result = run();
        return result.result == OfdmTimingResult::OwnershipLost &&
               result.requiresReset && result.completedWrites == 1;
    }
} // namespace

int main()
{
    return validChannels() && rejectedInputs() && failureAndReset() ? 0 : 1;
}
