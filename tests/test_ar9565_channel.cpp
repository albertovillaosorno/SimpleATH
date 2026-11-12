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
//   - Offline regression cases for ar9565 channel.
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
//   - Offline regression cases for ar9565 channel.
// - Description:
//   - Implements or verifies the test_ar9565_channel source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 channel.

// Synthetic MMIO and epoch tests; does not touch a PCI device or radio.
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr size_t kExpectedWrites = 4;
    constexpr uint64_t kOwnerEpoch = 11;
    constexpr uint32_t kBarSize = 0x20000;
    constexpr uint32_t kSynthControl = 0xa340;
    constexpr uint32_t kSynth4 = 0x1608c;
    constexpr uint32_t kSynth7 = 0x16098;
    constexpr uint32_t kSynth4Initial = 0x1200;
    constexpr uint32_t kSynth4Updated = 0x1201;
    constexpr uint32_t kBMode = 0x20000000;
    constexpr uint32_t kLoadBit = 0x80000000;
    constexpr uint32_t kCh6At25 = 0x440fc960;
    constexpr uint32_t kCh6At40 = 0x4289dddc;
    constexpr uint32_t kCh6Upper = 0x44140da4;
    constexpr uint32_t kCh14At25 = 0x4423d708;
    constexpr uint8_t kCh6 = 6;
    constexpr uint8_t kCh14 = 14;
    constexpr uint8_t kAbove = 10;
    constexpr uint8_t kBelow = 2;
    constexpr uint8_t kInvalidExtension = 9;
    constexpr uint16_t kCh6MHz = 2437;
    constexpr uint16_t kCh6UpperMHz = 2447;
    constexpr uint16_t kCh6LowerMHz = 2427;
    constexpr uint16_t kCh14MHz = 2484;

    struct Mock
    {
            std::array<uint32_t, kExpectedWrites> offsets {};
            std::array<uint32_t, kExpectedWrites> values {};
            uint32_t synth4 = kSynth4Initial;
            size_t writes = 0;
            size_t reads = 0;
            size_t permits = 0;
            size_t revokeAt = 0;
            size_t failWriteAt = 0;
            bool deny = false;
            bool failRead = false;
    };

    bool permit(void *p, uint64_t epoch)
    {
        auto &m = *static_cast<Mock *>(p);
        ++m.permits;
        return epoch == kOwnerEpoch && !m.deny &&
               (m.revokeAt == 0 || m.permits < m.revokeAt);
    }

    bool write(void *p, uint32_t offset, const uint32_t value)
    {
        auto &m = *static_cast<Mock *>(p);
        if (m.failWriteAt != 0 && m.writes + 1 == m.failWriteAt)
        {
            return false;
        }
        if (m.writes >= kExpectedWrites)
        {
            return false;
        }
        m.offsets.at(m.writes) = offset;
        m.values.at(m.writes) = value;
        ++m.writes;
        return true;
    }

    bool read(void *p, uint32_t offset, uint32_t *value)
    {
        auto &m = *static_cast<Mock *>(p);
        if (offset != kSynth4 || m.failRead)
        {
            return false;
        }
        *value = m.synth4;
        ++m.reads;
        return true;
    }

    void delay(void * /*context*/, uint32_t /*micros*/)
    {
    }

    RfChannelBackend backend(Mock &m)
    {
        return {{&m, kOwnerEpoch, kBarSize, permit, write, delay}, read};
    }

    bool sequence(const Mock &m, uint32_t value)
    {
        return m.writes == kExpectedWrites && m.reads == 1 &&
               m.offsets.at(0) == kSynthControl && m.values.at(0) == kBMode &&
               m.offsets.at(1) == kSynth4 && m.values.at(1) == kSynth4Updated &&
               m.offsets.at(2) == kSynth7 && m.values.at(2) == value &&
               m.offsets.at(3) == kSynth7 &&
               m.values.at(3) == (value | kLoadBit);
    }

    RfChannelRequest request(uint8_t number, RfReferenceClock clock,
                             ChannelWidth width = ChannelWidth::Ht20,
                             uint8_t secondary = 0)
    {
        Channel c {};
        (void)mapChannel(number, c);
        return {
            Revision::V1_1, c, width, secondary, clock,
        };
    }

    const CalibrationAndRegulatory kApproved {
        true, true, true, true, true, true, true,
    };

    bool testValid()
    {
        // Upstream 25/40 MHz reference divider math on channel 6 (2437 MHz).
        Mock m {};
        const auto b = backend(m);
        auto r = tuneAr9565Channel(
            request(kCh6, RfReferenceClock::Crystal25Mhz), kApproved, b);
        if (r.result != RfChannelResult::Ok || r.requiresReset ||
            r.completedWrites != kExpectedWrites ||
            r.synthesizerMhz != kCh6MHz || !sequence(m, kCh6At25))
        {
            return false;
        }
        m = {};
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal40Mhz),
                              kApproved, b);
        if (r.result != RfChannelResult::Ok || !sequence(m, kCh6At40))
        {
            return false;
        }

        // HT40 synth center is between the two legal 20 MHz centers.
        m = {};
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz,
                                      ChannelWidth::Ht40, kAbove),
                              kApproved, b);
        if (r.result != RfChannelResult::Ok ||
            r.synthesizerMhz != kCh6UpperMHz || !sequence(m, kCh6Upper))
        {
            return false;
        }
        m = {};
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz,
                                      ChannelWidth::Ht40, kBelow),
                              kApproved, b);
        if (r.result != RfChannelResult::Ok || r.synthesizerMhz != kCh6LowerMHz)
        {
            return false;
        }

        // Channel 14 is 2484 MHz and cannot be paired into HT40.
        m = {};
        r = tuneAr9565Channel(request(kCh14, RfReferenceClock::Crystal25Mhz),
                              kApproved, b);
        return r.result == RfChannelResult::Ok &&
               r.synthesizerMhz == kCh14MHz && sequence(m, kCh14At25);
    }

    bool testRejected()
    {
        Mock m {};
        auto b = backend(m);
        const auto invalid = [&](RfChannelRequest candidate,
                                 const CalibrationAndRegulatory &auth)
        {
            m = {};
            const auto result = tuneAr9565Channel(candidate, auth, b);
            return result.result != RfChannelResult::Ok && m.writes == 0 &&
                   !result.requiresReset;
        };
        if (!invalid(request(kCh14, RfReferenceClock::Crystal25Mhz,
                             ChannelWidth::Ht40, kAbove),
                     kApproved) ||
            !invalid(request(kCh6, RfReferenceClock::Crystal25Mhz,
                             ChannelWidth::Ht40, kInvalidExtension),
                     kApproved))
        {
            return false;
        }
        // Default-initialized clock data must not silently authorize a
        // physical 25-MHz reference or any PLL/synthesizer write.
        const RfChannelRequest unproven = request(kCh6, RfReferenceClock {});
        if (unproven.referenceClock != RfReferenceClock::Unknown ||
            !invalid(unproven, kApproved))
        {
            return false;
        }
        auto modified = request(kCh6, RfReferenceClock::Crystal25Mhz);
        modified.control.centerMhz++;
        if (!invalid(modified, kApproved))
        {
            return false;
        }
        modified = request(kCh6, RfReferenceClock::Crystal25Mhz);
        modified.silicon = Revision::Unknown;
        if (!invalid(modified, kApproved))
        {
            return false;
        }
        auto denied = kApproved;
        denied.localCountryRulesAvailable = false;
        if (!invalid(request(kCh6, RfReferenceClock::Crystal25Mhz), denied))
        {
            return false;
        }
        m = {};
        b.io.barLengthBytes = kSynth7;
        const auto r = tuneAr9565Channel(
            request(kCh6, RfReferenceClock::Crystal25Mhz), kApproved, b);
        return r.result == RfChannelResult::InvalidBar && m.writes == 0;
    }

    bool testFailures()
    {
        Mock m {};
        const auto b = backend(m);
        m.deny = true;
        auto r = tuneAr9565Channel(
            request(kCh6, RfReferenceClock::Crystal25Mhz), kApproved, b);
        if (r.result != RfChannelResult::OwnershipLost || m.writes != 0 ||
            r.requiresReset)
        {
            return false;
        }
        m = {};
        m.revokeAt = 4;
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz),
                              kApproved, b);
        if (r.result != RfChannelResult::OwnershipLost || m.writes != 2 ||
            !r.requiresReset)
        {
            return false;
        }
        m = {};
        m.failRead = true;
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz),
                              kApproved, b);
        if (r.result != RfChannelResult::ReadFailed || m.writes != 1 ||
            !r.requiresReset)
        {
            return false;
        }
        m = {};
        m.failWriteAt = 1;
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz),
                              kApproved, b);
        if (r.result != RfChannelResult::WriteFailed || m.writes != 0 ||
            !r.requiresReset)
        {
            return false;
        }
        m = {};
        m.failWriteAt = 4;
        r = tuneAr9565Channel(request(kCh6, RfReferenceClock::Crystal25Mhz),
                              kApproved, b);
        return r.result == RfChannelResult::WriteFailed && m.writes == 3 &&
               r.requiresReset;
    }

    bool testReceiveOnly()
    {
        Mock m {};
        const auto io = backend(m);
        auto rx = kApproved;
        rx.use = RadioInitialization::ReceiveOnly;
        rx.localCountryRulesAvailable = false;
        rx.txPowerLimitsVerified = false;
        const auto result = tuneAr9565Channel(
            request(kCh6, RfReferenceClock::Crystal25Mhz), rx, io);
        return result.result == RfChannelResult::Ok &&
               result.completedWrites == kExpectedWrites &&
               !result.requiresReset;
    }
} // namespace

int main()
{
    return testValid() && testRejected() && testFailures() && testReceiveOnly()
               ? 0
               : 1;
}
