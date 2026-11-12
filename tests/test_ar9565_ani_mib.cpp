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
//   - Offline regression cases for ar9565 ani mib.
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
//   - Offline regression cases for ar9565 ani mib.
// - Description:
//   - Implements or verifies the test_ar9565_ani_mib source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 ani mib.

// Synthetic PCI MMIO for the physical ANI/MIB collector. Never touches RF.
#include "hardware/Ar9565Ani.hpp"
#include "hardware/Ar9565AniMib.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 87U;
    constexpr uint32_t kBar = 0x9000U;
    constexpr uint32_t kMibControl = 0x40U;
    constexpr uint32_t kCycleCount = 0x80f8U;
    constexpr uint32_t kRxCount = 0x80f0U;
    constexpr uint32_t kTxCount = 0x80ecU;
    constexpr uint32_t kPhyOfdm = 0x812cU;
    constexpr uint32_t kPhyCck = 0x8134U;
    constexpr uint32_t kMaskOfdm = 0x8130U;
    constexpr uint32_t kMaskCck = 0x8138U;
    constexpr uint32_t kOfdmTiming = 0x00020000U;
    constexpr uint32_t kCckTiming = 0x02000000U;
    constexpr size_t kExpectedInitWrites = 11U;
    constexpr size_t kExpectedSampleReads = 11U;

    struct Fake
    {
            std::array<uint32_t, kBar / 4U> registers {};
            size_t reads {};
            size_t writes {};
            size_t permits {};
            size_t revokeAtRead {};
            size_t revokeAtWrite {};
            uint32_t failReadOffset {UINT32_MAX};
            uint32_t failWriteOffset {UINT32_MAX};
            uint32_t tamperOffset {UINT32_MAX};
            bool live {true};
            bool changeFrozenCounter {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &f = *static_cast<Fake *>(context);
        ++f.permits;
        return f.live && epoch == kEpoch;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &f = *static_cast<Fake *>(context);
        ++f.reads;
        if (offset >= kBar || (offset % 4U) != 0U || value == nullptr ||
            offset == f.failReadOffset)
        {
            return false;
        }
        *value = f.registers.at(offset / 4U) ^
                 static_cast<uint32_t>(offset == f.tamperOffset);
        if (offset == kCycleCount && f.changeFrozenCounter && f.reads > 1U)
        {
            ++f.registers.at(offset / 4U);
        }
        if (f.revokeAtRead != 0U && f.reads >= f.revokeAtRead)
        {
            f.live = false;
        }
        return true;
    }

    bool write(void *context, uint32_t offset, uint32_t value)
    {
        auto &f = *static_cast<Fake *>(context);
        ++f.writes;
        if (offset >= kBar || (offset % 4U) != 0U ||
            offset == f.failWriteOffset)
        {
            return false;
        }
        f.registers.at(offset / 4U) = value;
        if (f.revokeAtWrite != 0U && f.writes >= f.revokeAtWrite)
        {
            f.live = false;
        }
        return true;
    }

    AniMibBackend backend(Fake &fake)
    {
        return {&fake, kEpoch, kBar, permit, read, write};
    }

    Ar9565AniState baseline(uint8_t channel = 6U)
    {
        Ar9565AniState state {};
        state.ownerEpoch = kEpoch;
        state.channel = channel;
        state.silicon = Revision::V1_1;
        state.referenceClock = RfReferenceClock::Crystal25Mhz;
        state.initialized = true;
        return state;
    }

    CalibrationAndRegulatory authority()
    {
        CalibrationAndRegulatory evidence {};
        evidence.use = RadioInitialization::ReceiveOnly;
        evidence.eepromContentsVerified = true;
        evidence.boardAntennaConfigurationVerified = true;
        evidence.channelPermitted = true;
        evidence.radioKillUnblocked = true;
        evidence.coexistenceConfigurationVerified = true;
        return evidence;
    }

    bool setup(Fake &fake, AniMibState &state)
    {
        const AniMibProgress p = initializeAr9565AniMib(
            baseline(), authority(), backend(fake), 100U, state);
        return p.result == AniMibResult::Ok && !p.requiresReset &&
               p.completedWrites == kExpectedInitWrites &&
               fake.writes == kExpectedInitWrites && state.initialized &&
               state.ownerEpoch == kEpoch && !state.requiresReset &&
               fake.registers.at(kMibControl / 4U) == 0U &&
               fake.registers.at(kMaskOfdm / 4U) == kOfdmTiming &&
               fake.registers.at(kMaskCck / 4U) == kCckTiming;
    }

    struct CounterReadings
    {
            uint32_t cycles;
            uint32_t receive;
            uint32_t transmit;
            uint32_t ofdm;
            uint32_t cck;
    };

    void counters(Fake &fake, CounterReadings values)
    {
        fake.registers.at(kCycleCount / 4U) = values.cycles;
        fake.registers.at(kRxCount / 4U) = values.receive;
        fake.registers.at(kTxCount / 4U) = values.transmit;
        fake.registers.at(kPhyOfdm / 4U) = values.ofdm;
        fake.registers.at(kPhyCck / 4U) = values.cck;
    }

    bool rejected(const AniMibProgress &result, AniMibResult expected,
                  const AniMibState &state, const AniHardwareSample &sample)
    {
        return result.result == expected && result.requiresReset &&
               state.requiresReset && !state.initialized &&
               !sample.mmioAndMasksVerified && sample.captureSequence == 0U;
    }

    int checkOutputAndStateIsolation()
    {
        Fake fake {};

        // An intentionally invalid caller may alias the beginning of a
        // larger owner allocation. Keep enough backing storage to represent
        // either view even when constructing this negative-test reference.
        struct StateBacking
        {
                AniMibState state {};
                std::array<uint8_t, sizeof(AniHardwareSample)> tail {};
        } backing {};

        AniMibState &state = backing.state;
        AniMibBackend io = backend(fake);
        state.ownerEpoch = 111U;
        io.context = &state;
        // The mutable MIB state cannot be the backend's opaque owner.
        // Reject before MMIO, before clearing or publishing any new epoch.
        if (initializeAr9565AniMib(baseline(), authority(), io, 100U, state)
                    .result != AniMibResult::OverlappingBuffers ||
            state.ownerEpoch != 111U || fake.writes != 0U || fake.permits != 0U)
        {
            return 40;
        }
        state = {};
        if (!setup(fake, state))
        {
            return 41;
        }
        const size_t reads = fake.reads;
        const size_t writes = fake.writes;
        const size_t permits = fake.permits;
        AniHardwareSample sample {};
        sample.ownerEpoch = 222U;
        sample.captureSequence = 333U;
        io = backend(fake);
        io.context = &sample.captureSequence;
        if (captureAr9565AniMib(baseline(), authority(), io, 1000U, state,
                                sample)
                    .result != AniMibResult::OverlappingBuffers ||
            state.initialized == false || state.ownerEpoch != kEpoch ||
            state.requiresReset || sample.ownerEpoch != 222U ||
            sample.captureSequence != 333U || fake.reads != reads ||
            fake.writes != writes || fake.permits != permits)
        {
            return 42;
        }
        io = backend(fake);
        // Deliberately overlapping references must not allow out={} to
        // corrupt a live same-epoch counter baseline before the freeze.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto &stateAlias = *reinterpret_cast<AniHardwareSample *>(&state);
        if (captureAr9565AniMib(baseline(), authority(), io, 1000U, state,
                                stateAlias)
                    .result != AniMibResult::OverlappingBuffers ||
            !state.initialized || state.ownerEpoch != kEpoch ||
            fake.reads != reads || fake.writes != writes ||
            fake.permits != permits)
        {
            return 43;
        }
        counters(fake, {4400000U, 400000U, 100000U, 40U, 70U});
        if (captureAr9565AniMib(baseline(), authority(), io, 1000U, state,
                                sample)
                    .result != AniMibResult::Ok ||
            !sample.mmioAndMasksVerified || sample.ownerEpoch != kEpoch ||
            state.captureSequence != 1U)
        {
            return 44;
        }
        return 0;
    }

    int checkSuccessAndWindow()
    {
        Fake f {};
        AniMibState state {};
        if (!setup(f, state))
        {
            return 1;
        }
        counters(f, {44000U * 100U, 400000U, 100000U, 40U, 70U});
        AniHardwareSample before {};
        const auto first = captureAr9565AniMib(
            baseline(), authority(), backend(f), 1000U, state, before);
        if (first.result != AniMibResult::Ok || first.requiresReset ||
            first.completedReads != kExpectedSampleReads ||
            first.completedWrites != 2U || before.ownerEpoch != kEpoch ||
            before.captureSequence != 1U || !before.mmioAndMasksVerified ||
            before.cycleCount != 44000U * 100U || state.lastCaptureMs != 1000U)
        {
            return 2;
        }
        counters(f, {44000U * 700U, 800000U, 300000U, 2050U, 1470U});
        AniHardwareSample after {};
        const auto second = captureAr9565AniMib(
            baseline(), authority(), backend(f), 1600U, state, after);
        if (second.result != AniMibResult::Ok || after.captureSequence != 2U ||
            f.registers.at(kMibControl / 4U) != 0U)
        {
            return 3;
        }
        Channel channel {};
        if (mapChannel(6U, channel) != Result::Ok)
        {
            return 4;
        }
        const RfChannelRequest request {
            Revision::V1_1,
            channel,
            ChannelWidth::Ht20,
            0U,
            RfReferenceClock::Crystal25Mhz,
        };
        AniErrorWindow window {};
        if (deriveAr9565AniErrorWindow(request, before, after, 600U, false,
                                       window) != AniResult::Ok ||
            !window.hardwareCountersVerified || window.counterSequence != 2U ||
            window.listenedMilliseconds != 586U ||
            window.ofdmTimingErrors != 2010U || window.cckTimingErrors != 1400U)
        {
            return 5;
        }
        return 0;
    }

    int checkPreflight()
    {
        Fake f {};
        AniMibState state {};
        auto bad = backend(f);
        bad.barLengthBytes = kMaskCck;
        if (initializeAr9565AniMib(baseline(), authority(), bad, 100U, state)
                    .result != AniMibResult::InvalidBar ||
            f.writes != 0U)
        {
            return 10;
        }
        const auto missing = initializeAr9565AniMib(
            baseline(), CalibrationAndRegulatory {}, backend(f), 100U, state);
        if (missing.result != AniMibResult::MissingAuthorization ||
            f.writes != 0U)
        {
            return 11;
        }
        auto japan = baseline(14U);
        if (initializeAr9565AniMib(japan, authority(), backend(f), 100U, state)
                    .result != AniMibResult::MissingAuthorization ||
            f.writes != 0U)
        {
            return 12;
        }
        japan.initialized = false;
        if (initializeAr9565AniMib(japan, authority(), backend(f), 100U, state)
                .result != AniMibResult::MissingAuthorization)
        {
            return 13;
        }
        // Invalid canonical geometry must never touch PHY counters even if
        // a forged baseline asserts that its INI stage was initialized.
        for (size_t scenario = 0U; scenario < 10U; ++scenario)
        {
            auto invalid = baseline();
            switch (scenario)
            {
                case 0U:
                    invalid.channel = 0U;
                    break;
                case 1U:
                    invalid.channel = 15U;
                    break;
                case 2U:
                    invalid.secondary = 10U;
                    break;
                case 3U:
                    invalid.width = ChannelWidth::Ht40;
                    invalid.secondary = 0U;
                    break;
                case 4U:
                    invalid.width = ChannelWidth::Ht40;
                    invalid.secondary = 14U;
                    break;
                case 5U:
                    invalid.width = ChannelWidth::Ht40;
                    invalid.secondary = 15U;
                    break;
                case 6U:
                    invalid.silicon = Revision::Unknown;
                    break;
                case 7U:
                    invalid.referenceClock =
                        static_cast<RfReferenceClock>(UINT8_MAX);
                    break;
                case 8U:
                    invalid.width = static_cast<ChannelWidth>(UINT8_MAX);
                    break;
                case 9U:
                    invalid.width = ChannelWidth::Ht40;
                    invalid.secondary = 9U;
                    break;
                default:
                    return 17;
            }
            if (initializeAr9565AniMib(invalid, authority(), backend(f), 100U,
                                       state)
                        .result != AniMibResult::InvalidChannel ||
                f.writes != 0U)
            {
                return 17;
            }
        }
        if (!setup(f, state))
        {
            return 14;
        }
        AniHardwareSample sample {};
        const size_t priorWrites = f.writes;
        const auto retry = initializeAr9565AniMib(baseline(), authority(),
                                                  backend(f), 100U, state);
        if (retry.result != AniMibResult::ResetRequired ||
            retry.requiresReset || f.writes != priorWrites ||
            !state.initialized)
        {
            return 16;
        }
        if (captureAr9565AniMib(baseline(7U), authority(), backend(f), 1000U,
                                state, sample)
                    .result != AniMibResult::NotInitialized ||
            f.writes != priorWrites || state.initialized ||
            !state.requiresReset)
        {
            return 15;
        }
        const auto retryCapture = captureAr9565AniMib(
            baseline(), authority(), backend(f), 1000U, state, sample);
        if (!rejected(retryCapture, AniMibResult::ResetRequired, state, sample))
        {
            return 20;
        }
        // Every same-epoch mismatch invalidates this exclusive baseline;
        // neither the silicon nor the physical crystal can silently change.
        for (size_t scenario = 0U; scenario < 2U; ++scenario)
        {
            Fake isolated {};
            AniMibState active {};
            if (!setup(isolated, active))
            {
                return 18;
            }
            auto forged = baseline();
            if (scenario == 0U)
            {
                forged.silicon = Revision::V1_0;
            }
            else
            {
                forged.referenceClock = RfReferenceClock::Crystal40Mhz;
            }
            AniHardwareSample capture {};
            const auto invalid = captureAr9565AniMib(
                forged, authority(), backend(isolated), 1000U, active, capture);
            if (!rejected(invalid, AniMibResult::NotInitialized, active,
                          capture) ||
                isolated.writes != kExpectedInitWrites)
            {
                return 19;
            }
        }
        // A physical RF-kill change must revoke a previously initialized
        // window even though this call performs no new MMIO writes.
        {
            Fake isolated {};
            AniMibState active {};
            if (!setup(isolated, active))
            {
                return 21;
            }
            auto revoked = authority();
            revoked.radioKillUnblocked = false;
            AniHardwareSample capture {};
            const auto invalid = captureAr9565AniMib(
                baseline(), revoked, backend(isolated), 1000U, active, capture);
            if (!rejected(invalid, AniMibResult::MissingAuthorization, active,
                          capture) ||
                isolated.writes != kExpectedInitWrites)
            {
                return 22;
            }
        }
        return 0;
    }

    int checkFailures()
    {
        for (size_t failAtWrite = 1U; failAtWrite <= 11U; ++failAtWrite)
        {
            Fake f {};
            AniMibState state {};
            f.revokeAtWrite = failAtWrite;
            const auto result = initializeAr9565AniMib(baseline(), authority(),
                                                       backend(f), 100U, state);
            if (result.result != AniMibResult::OwnershipLost ||
                !result.requiresReset || !state.requiresReset ||
                state.initialized)
            {
                return 20;
            }
        }
        {
            Fake f {};
            AniMibState state {};
            f.failWriteOffset = kMaskOfdm;
            const auto result = initializeAr9565AniMib(baseline(), authority(),
                                                       backend(f), 100U, state);
            if (result.result != AniMibResult::WriteFailed ||
                !result.requiresReset || state.initialized ||
                state.ownerEpoch != kEpoch)
            {
                return 21;
            }
            const size_t writes = f.writes;
            const auto retry = initializeAr9565AniMib(baseline(), authority(),
                                                      backend(f), 100U, state);
            if (retry.result != AniMibResult::ResetRequired ||
                !retry.requiresReset || f.writes != writes)
            {
                return 25;
            }
        }
        {
            Fake f {};
            AniMibState state {};
            f.tamperOffset = kMaskCck;
            const auto result = initializeAr9565AniMib(baseline(), authority(),
                                                       backend(f), 100U, state);
            if (result.result != AniMibResult::ReadbackMismatch ||
                !result.requiresReset || state.initialized)
            {
                return 22;
            }
        }
        for (const uint32_t offset :
             {kMibControl, kCycleCount, kPhyOfdm, kMaskCck})
        {
            Fake f {};
            AniMibState state {};
            if (!setup(f, state))
            {
                return 23;
            }
            f.failReadOffset = offset;
            AniHardwareSample sample {};
            const auto result = captureAr9565AniMib(
                baseline(), authority(), backend(f), 400U, state, sample);
            if (!rejected(result, AniMibResult::ReadFailed, state, sample))
            {
                return 24;
            }
        }
        return 0;
    }

    int checkCaptureInvariants()
    {
        for (size_t scenario = 0U; scenario < 7U; ++scenario)
        {
            Fake f {};
            AniMibState state {};
            if (!setup(f, state))
            {
                return 30;
            }
            counters(f, {44000U * 500U, 500000U, 100000U, 10U, 20U});
            if (scenario == 0U)
            {
                f.registers.at(kMaskCck / 4U) = 0U;
            }
            if (scenario == 1U)
            {
                f.registers.at(kPhyOfdm / 4U) = 0x00ffffffU;
            }
            if (scenario == 2U)
            {
                f.registers.at(kPhyCck / 4U) = 0x01000000U;
            }
            if (scenario == 3U)
            {
                f.changeFrozenCounter = true;
            }
            if (scenario == 4U)
            {
                f.revokeAtRead = f.reads + 3U;
            }
            if (scenario == 5U)
            {
                f.revokeAtWrite = f.writes + 2U;
            }
            if (scenario == 6U)
            {
                f.tamperOffset = kMibControl;
            }
            const AniMibResult expected = scenario == 1U || scenario == 2U
                                              ? AniMibResult::CounterSaturated
                                          : scenario == 4U || scenario == 5U
                                              ? AniMibResult::OwnershipLost
                                              : AniMibResult::ReadbackMismatch;
            AniHardwareSample sample {};
            const auto result = captureAr9565AniMib(
                baseline(), authority(), backend(f), 400U, state, sample);
            if (!rejected(result, expected, state, sample))
            {
                return 31;
            }
        }
        for (const uint64_t timestamp : {0U, 6002U})
        {
            Fake f {};
            AniMibState state {};
            if (!setup(f, state))
            {
                return 32;
            }
            AniHardwareSample sample {};
            if (captureAr9565AniMib(baseline(), authority(), backend(f), 1000U,
                                    state, sample)
                    .result != AniMibResult::Ok)
            {
                return 33;
            }
            const size_t writes = f.writes;
            const auto result = captureAr9565AniMib(
                baseline(), authority(), backend(f), timestamp, state, sample);
            if (!rejected(result, AniMibResult::InvalidCaptureTime, state,
                          sample) ||
                f.writes != writes)
            {
                return 34;
            }
        }
        return 0;
    }
} // namespace

int main()
{
    for (const int result :
         {checkSuccessAndWindow(), checkPreflight(), checkFailures(),
          checkCaptureInvariants(), checkOutputAndStateIsolation()})
    {
        if (result != 0)
        {
            return result;
        }
    }
    return 0;
}
