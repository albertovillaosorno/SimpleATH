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
//   - Offline regression cases for ar9565 pll.
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
//   - Offline regression cases for ar9565 pll.
// - Description:
//   - Implements or verifies the test_ar9565_pll source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 pll.

// Synthetic PLL register protocol, no live PCI, RF or kext dependency.
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565Pll.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr size_t kRmwWrites = 11;
    constexpr size_t kAllWrites = 13;
    constexpr uint64_t kEpoch = 42;
    constexpr uint32_t kBar = 0x20000;
    constexpr uint32_t kDpll1 = 0x16180;
    constexpr uint32_t kDpll2 = 0x16184;
    constexpr uint32_t kDpll3 = 0x16188;
    constexpr uint32_t kRtcPll = 0x7014;
    constexpr uint32_t kRtcSleep = 0x7048;
    constexpr uint32_t kPllValue = 0x0004142c;
    constexpr uint32_t kDerivedClock = 0x2;
    constexpr uint32_t kBbDelay = 1000;
    constexpr uint32_t kRtcDelay = 100;
    constexpr uint32_t kFinalDpll1 = 0x29600000;
    constexpr uint32_t kFinalDpll2 = 0x52042000;
    constexpr uint32_t kFinalDpll3 = 0x03000000;
    constexpr uint32_t kUnrelatedDpll2Bits = 0x80000a5a;
    constexpr size_t kAfterBbWrites = 11;
    constexpr size_t kAfterRtcWrites = 12;
    constexpr uint8_t kChannel = 6;
    constexpr uint8_t kJapan = 14;
    constexpr uint8_t kUpper = 10;
    constexpr uint8_t kBadSecondary = 9;

    struct Register
    {
            uint32_t address;
            uint32_t value;
    };

    struct Mock
    {
            uint32_t dpll1 = 0;
            uint32_t dpll2 = 0;
            uint32_t dpll3 = 0;
            uint32_t rtcPll = 0;
            uint32_t rtcSleep = 0;
            std::array<Register, kAllWrites> writes {};
            std::array<uint32_t, 2> delays {};
            std::array<size_t, 2> delayAtWrites {};
            size_t writeCount = 0;
            size_t readCount = 0;
            size_t delayCount = 0;
            size_t permitCount = 0;
            size_t revokeAt = 0;
            size_t failReadAt = 0;
            size_t failWriteAt = 0;
            bool deny = false;
    };

    uint32_t *location(Mock &m, uint32_t address)
    {
        switch (address)
        {
            case kDpll1:
                return &m.dpll1;
            case kDpll2:
                return &m.dpll2;
            case kDpll3:
                return &m.dpll3;
            case kRtcPll:
                return &m.rtcPll;
            case kRtcSleep:
                return &m.rtcSleep;
            default:
                return nullptr;
        }
    }

    bool permit(void *context, uint64_t epoch)
    {
        auto &m = *static_cast<Mock *>(context);
        ++m.permitCount;
        return epoch == kEpoch && !m.deny &&
               (m.revokeAt == 0 || m.permitCount < m.revokeAt);
    }

    bool read(void *context, uint32_t address, uint32_t *out)
    {
        auto &m = *static_cast<Mock *>(context);
        ++m.readCount;
        if ((m.failReadAt != 0 && m.readCount == m.failReadAt) ||
            location(m, address) == nullptr)
        {
            return false;
        }
        *out = *location(m, address);
        return true;
    }

    bool write(void *context, uint32_t address, const uint32_t value)
    {
        auto &m = *static_cast<Mock *>(context);
        if ((m.failWriteAt != 0 && m.writeCount + 1 == m.failWriteAt) ||
            m.writeCount >= kAllWrites || location(m, address) == nullptr)
        {
            return false;
        }
        m.writes.at(m.writeCount) = {
            address,
            value,
        };
        *location(m, address) = value;
        ++m.writeCount;
        return true;
    }

    void delay(void *context, uint32_t usec)
    {
        auto &m = *static_cast<Mock *>(context);
        if (m.delayCount < m.delays.size())
        {
            m.delays.at(m.delayCount) = usec;
            m.delayAtWrites.at(m.delayCount) = m.writeCount;
            ++m.delayCount;
        }
    }

    RfChannelBackend backend(Mock &m)
    {
        return {
            {
                &m,
                kEpoch,
                kBar,
                permit,
                write,
                delay,
            },
            read,
        };
    }

    RfChannelRequest request()
    {
        Channel channel {};
        (void)mapChannel(kChannel, channel);
        return {
            Revision::V1_1,
            channel,
            ChannelWidth::Ht20,
            0,
            RfReferenceClock::Crystal25Mhz,
        };
    }

    const CalibrationAndRegulatory kTrusted {
        true, true, true, true, true, true, true,
    };

    constexpr std::array<Register, kAllWrites> kExpectedSequence {
        {
            {kDpll2, 0x00010000},
            {kDpll2, 0x02010000},
            {kDpll2, 0x12010000},
            {kDpll1, 0x28000000},
            {kDpll1, 0x29600000},
            {kDpll1, 0x29600000},
            {kDpll2, 0x12012000},
            {kDpll2, 0x52012000},
            {kDpll2, 0x52052000},
            {kDpll3, 0x03000000},
            {kDpll2, 0x52042000},
            {kRtcPll, kPllValue},
            {kRtcSleep, kDerivedClock},
        },
    };

    bool testSequence()
    {
        Mock mock {};
        const auto io = backend(mock);
        auto progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::Ok || progress.requiresReset ||
            progress.completedWrites != kAllWrites ||
            progress.completedReads != kRmwWrites ||
            mock.writeCount != kAllWrites || mock.delayCount != 2 ||
            mock.delays.at(0) != kBbDelay || mock.delays.at(1) != kRtcDelay ||
            mock.dpll1 != kFinalDpll1 || mock.dpll2 != kFinalDpll2 ||
            mock.dpll3 != kFinalDpll3 || mock.rtcPll != kPllValue ||
            mock.rtcSleep != kDerivedClock ||
            mock.writes.at(kRmwWrites).address != kRtcPll ||
            mock.writes.at(kRmwWrites + 1).address != kRtcSleep ||
            mock.delayAtWrites.at(0) != kAfterBbWrites ||
            mock.delayAtWrites.at(1) != kAfterRtcWrites)
        {
            return false;
        }
        for (size_t i = 0; i < kAllWrites; ++i)
        {
            if (mock.writes.at(i).address != kExpectedSequence.at(i).address ||
                mock.writes.at(i).value != kExpectedSequence.at(i).value)
            {
                return false;
            }
        }
        // The PLL register programming is identical for 25/40 MHz input;
        // only the later channel SYNTH divider changes with the crystal.
        mock = {};
        auto channel = request();
        channel.referenceClock = RfReferenceClock::Crystal40Mhz;
        progress = initializeAr9565Pll(channel, kTrusted, io);
        if (progress.result != RfPllResult::Ok || mock.rtcPll != kPllValue)
        {
            return false;
        }
        // Unrelated bits in BB PLL registers must survive field RMW.
        mock = {};
        mock.dpll2 = kUnrelatedDpll2Bits;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        return progress.result == RfPllResult::Ok &&
               mock.dpll2 == (kFinalDpll2 | kUnrelatedDpll2Bits);
    }

    bool testRejections()
    {
        Mock mock {};
        auto io = backend(mock);
        auto wrong = request();
        wrong.silicon = Revision::Unknown;
        auto progress = initializeAr9565Pll(wrong, kTrusted, io);
        if (progress.result != RfPllResult::InvalidChannel ||
            mock.writeCount != 0)
        {
            return false;
        }
        wrong = request();
        wrong.control.centerMhz++;
        progress = initializeAr9565Pll(wrong, kTrusted, io);
        if (progress.result != RfPllResult::InvalidChannel ||
            mock.writeCount != 0)
        {
            return false;
        }
        wrong = request();
        wrong.width = ChannelWidth::Ht40;
        wrong.secondary = kBadSecondary;
        progress = initializeAr9565Pll(wrong, kTrusted, io);
        if (progress.result != RfPllResult::InvalidChannel ||
            mock.writeCount != 0)
        {
            return false;
        }
        wrong.secondary = kUpper;
        progress = initializeAr9565Pll(wrong, kTrusted, io);
        if (progress.result != RfPllResult::Ok)
        {
            return false;
        }
        mock = {};
        Channel japan {};
        (void)mapChannel(kJapan, japan);
        wrong.control = japan;
        wrong.secondary = kUpper;
        progress = initializeAr9565Pll(wrong, kTrusted, io);
        if (progress.result != RfPllResult::InvalidChannel ||
            mock.writeCount != 0)
        {
            return false;
        }
        auto denied = kTrusted;
        denied.radioKillUnblocked = false;
        progress = initializeAr9565Pll(request(), denied, io);
        if (progress.result != RfPllResult::MissingAuthorization ||
            mock.writeCount != 0)
        {
            return false;
        }
        io.io.barLengthBytes = kDpll3;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        return progress.result == RfPllResult::InvalidBar &&
               mock.writeCount == 0;
    }

    bool testFailures()
    {
        Mock mock {};
        const auto io = backend(mock);
        mock.deny = true;
        auto progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::OwnershipLost ||
            mock.writeCount != 0 || progress.requiresReset)
        {
            return false;
        }
        mock = {};
        mock.revokeAt = 3;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::OwnershipLost ||
            mock.writeCount != 1 || !progress.requiresReset)
        {
            return false;
        }
        mock = {};
        mock.failReadAt = 1;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::ReadFailed ||
            mock.writeCount != 0 || progress.requiresReset)
        {
            return false;
        }
        mock = {};
        mock.failReadAt = 2;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::ReadFailed ||
            mock.writeCount != 1 || !progress.requiresReset)
        {
            return false;
        }
        mock = {};
        mock.failWriteAt = 1;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        if (progress.result != RfPllResult::WriteFailed ||
            mock.writeCount != 0 || !progress.requiresReset)
        {
            return false;
        }
        mock = {};
        mock.failWriteAt = kAllWrites;
        progress = initializeAr9565Pll(request(), kTrusted, io);
        return progress.result == RfPllResult::WriteFailed &&
               mock.writeCount == kAllWrites - 1 && progress.requiresReset;
    }

    bool testReceiveOnly()
    {
        Mock mock {};
        const auto io = backend(mock);
        auto rx = kTrusted;
        rx.use = RadioInitialization::ReceiveOnly;
        rx.localCountryRulesAvailable = false;
        rx.txPowerLimitsVerified = false;
        const auto result = initializeAr9565Pll(request(), rx, io);
        return result.result == RfPllResult::Ok &&
               result.completedWrites == kAllWrites && !result.requiresReset;
    }
} // namespace

int main()
{
    return testSequence() && testRejections() && testFailures() &&
                   testReceiveOnly()
               ? 0
               : 1;
}
