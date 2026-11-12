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
//   - Offline regression cases for ar9565 ani.
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
//   - Offline regression cases for ar9565 ani.
// - Description:
//   - Implements or verifies the test_ar9565_ani source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 ani.

// Synthetic AR9565 ANI MMIO: no IOKit, native RF activation, or real PCI.
#include "hardware/Ar9565Ani.hpp"
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 76U;
    constexpr uint8_t kTestChannel = 6U;
    constexpr uint8_t kHt40SecondaryChannel = 10U;
    constexpr size_t kProgramReadCount = 8U;
    constexpr uint8_t kOtherChannel = 7U;
    constexpr uint8_t kJapanChannel = 14U;
    constexpr uint8_t kFirstDefault = 10U;
    constexpr uint8_t kFirstLowDefault = 11U;
    constexpr uint8_t kSpurDefault = 12U;
    constexpr uint8_t kSpurExtDefault = 13U;
    constexpr uint8_t kRaisedLevel = 5U;
    constexpr uint8_t kMaximumFirstLevel = 8U;
    constexpr uint8_t kMaximumSpurLevel = 7U;
    constexpr uint8_t kInvalidFirstLevel = 9U;
    constexpr uint8_t kInvalidSpurLevel = 8U;
    constexpr uint8_t kFirstLevelOnFailure = 6U;
    constexpr uint8_t kSpurLevelOnFailure = 4U;
    constexpr uint8_t kExpectedRaisedFirst = 16U;
    constexpr uint8_t kExpectedRaisedLow = 17U;
    constexpr uint8_t kExpectedReducedFirst = 6U;
    constexpr uint8_t kExpectedReducedLow = 7U;
    constexpr uint8_t kExpectedMax = 20U;
    constexpr uint8_t kExpectedMaxExtended = 21U;
    constexpr uint32_t kUnrelatedBits = 0xa5a5a5a5U;
    enum class TestExit : int
    {
        Success = 0,
        Baseline = 1,
        Raised = 2,
        OtherBits = 3,
        Reduced = 4,
        Capped = 5,
        InvalidLevel = 6,
        Authorization = 7,
        Epoch = 8,
        Revoked = 9,
        Bar = 10,
        Japan = 11,
        Read = 12,
        Recovered = 13,
        Write = 14,
        Recache = 15,
        Readback = 16,
        InvalidChip = 17,
        RevokedAfterWrite = 18,
        MonitorUntrusted = 19,
        MonitorWindow = 20,
        MonitorOfdmHigh = 21,
        MonitorCckHigh = 22,
        MonitorLow = 23,
        MonitorCaps = 24,
        MonitorRevoked = 25,
        MonitorFailure = 26,
        MonitorOverflow = 27,
        MonitorStale = 28,
        MonitorReplay = 29,
        MonitorBadCounter = 30,
        HardwareWindow = 31,
        HardwareWindowPolicy = 32,
        HardwareWindowReject = 33,
        HardwareWindowHt40 = 34,
    };
    constexpr uint32_t kBar = 0xa000U;
    constexpr uint32_t kFirstStep = 0x9e10U;
    constexpr uint32_t kFirstStepLow = 0x9820U;
    constexpr uint32_t kSpur = 0x9810U;
    constexpr uint32_t kSpurExt = 0x9830U;
    constexpr std::array<uint32_t, 4U> kMasks {
        0x0003f000U,
        0x00000fc0U,
        0x000000feU,
        0x0000fe00U,
    };
    constexpr std::array<uint32_t, 4U> kOffsets {
        kFirstStep,
        kFirstStepLow,
        kSpur,
        kSpurExt,
    };
    constexpr std::array<uint8_t, 4U> kShifts {12U, 6U, 1U, 9U};

    struct Fake
    {
            std::array<uint32_t, kBar / sizeof(uint32_t)> registers {};
            size_t reads {};
            size_t writes {};
            size_t revokeAtWrite {};
            bool live {true};
            uint32_t failedRead {};
            uint32_t failedWrite {};
            uint32_t wrongReadback {};
            bool changedEpoch {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        const auto &fake = *static_cast<Fake *>(context);
        return fake.live && epoch == kEpoch && !fake.changedEpoch;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.reads;
        if (value == nullptr || offset >= kBar || (offset % 4U) != 0U ||
            offset == fake.failedRead)
        {
            return false;
        }
        *value = fake.registers.at(offset / 4U) ^
                 static_cast<uint32_t>(offset == fake.wrongReadback &&
                                       fake.writes != 0U);
        return true;
    }

    bool write(void *context, uint32_t offset, uint32_t value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.writes;
        if (offset >= kBar || (offset % 4U) != 0U || offset == fake.failedWrite)
        {
            return false;
        }
        fake.registers.at(offset / 4U) = value;
        if (fake.revokeAtWrite != 0U && fake.writes >= fake.revokeAtWrite)
        {
            fake.changedEpoch = true;
        }
        return true;
    }

    void delay(void * /*context*/, uint32_t /*micros*/)
    {
    }

    RxAgcBackend backend(Fake &fake, uint64_t epoch = kEpoch,
                         uint32_t length = kBar)
    {
        return {{&fake, epoch, length, permit, write, delay}, read};
    }

    RfChannelRequest channel(uint8_t number = kTestChannel)
    {
        Channel control {};
        (void)mapChannel(number, control);
        return {
            Revision::V1_1,
            control,
            ChannelWidth::Ht20,
            0U,
            RfReferenceClock::Crystal25Mhz,
        };
    }

    CalibrationAndRegulatory permitted()
    {
        CalibrationAndRegulatory value {};
        value.eepromContentsVerified = true;
        value.boardAntennaConfigurationVerified = true;
        value.channelPermitted = true;
        value.radioKillUnblocked = true;
        value.coexistenceConfigurationVerified = true;
        value.use = RadioInitialization::ReceiveOnly;
        return value;
    }

    void setIni(Fake &fake, uint8_t firstStep = kFirstDefault,
                uint8_t firstStepLow = kFirstLowDefault,
                uint8_t spur = kSpurDefault, uint8_t spurExt = kSpurExtDefault)
    {
        const std::array<uint8_t, 4U> defaults {
            firstStep,
            firstStepLow,
            spur,
            spurExt,
        };
        for (size_t i = 0; i < 4U; ++i)
        {
            fake.registers.at(kOffsets.at(i) / 4U) =
                (~kMasks.at(i) & kUnrelatedBits) |
                (static_cast<uint32_t>(defaults.at(i)) << kShifts.at(i));
        }
    }

    uint8_t field(const Fake &fake, size_t i)
    {
        return static_cast<uint8_t>(
            (fake.registers.at(kOffsets.at(i) / 4U) & kMasks.at(i)) >>
            kShifts.at(i));
    }

    bool matches(const Fake &fake, uint8_t firstStep, uint8_t firstStepLow,
                 uint8_t spur, uint8_t spurExt)
    {
        return field(fake, 0) == firstStep && field(fake, 1) == firstStepLow &&
               field(fake, 2) == spur && field(fake, 3) == spurExt;
    }
} // namespace

static int checkSuccessfulStages(Fake &fake, Ar9565AniState &state)
{
    setIni(fake);
    const auto baseline =
        cacheAr9565AniIniDefaults(channel(), permitted(), backend(fake), state);
    if (baseline.result != AniResult::Ok || baseline.completedReads != 4U ||
        baseline.completedWrites != 0U || fake.writes != 0U ||
        !state.initialized || state.ownerEpoch != kEpoch ||
        state.channel != kTestChannel || state.silicon != Revision::V1_1 ||
        state.width != ChannelWidth::Ht20 || state.secondary != 0U ||
        state.referenceClock != RfReferenceClock::Crystal25Mhz ||
        state.firstStepDefault != kFirstDefault ||
        state.firstStepLowDefault != kFirstLowDefault ||
        state.spurDefault != kSpurDefault ||
        state.spurExtDefault != kSpurExtDefault || state.firstStepLevel != 2U ||
        state.spurLevel != 3U)
    {
        return static_cast<int>(TestExit::Baseline);
    }
    // The hardware fields are NOT all of the register: reserved/other
    // calibration bits must survive every ANI level adjustment.
    const std::array<uint32_t, 4U> retained {
        fake.registers.at(kFirstStep / 4U) & ~kMasks.at(0),
        fake.registers.at(kFirstStepLow / 4U) & ~kMasks.at(1),
        fake.registers.at(kSpur / 4U) & ~kMasks.at(2),
        fake.registers.at(kSpurExt / 4U) & ~kMasks.at(3),
    };
    const auto raised =
        programAr9565AniLevels(channel(), permitted(), backend(fake), state,
                               kRaisedLevel, kRaisedLevel);
    if (raised.result != AniResult::Ok || raised.completedWrites != 4U ||
        raised.completedReads != kProgramReadCount || raised.requiresReset ||
        !matches(fake, kExpectedRaisedFirst, kExpectedRaisedLow,
                 kExpectedRaisedFirst, kExpectedRaisedLow) ||
        state.firstStepLevel != kRaisedLevel ||
        state.spurLevel != kRaisedLevel || !state.initialized)
    {
        return static_cast<int>(TestExit::Raised);
    }
    for (size_t i = 0; i < 4U; ++i)
    {
        if ((fake.registers.at(kOffsets.at(i) / 4U) & ~kMasks.at(i)) !=
            retained.at(i))
        {
            return static_cast<int>(TestExit::OtherBits);
        }
    }
    // The ANI base remains INI, not the previous adjusted register value.
    const auto reduced = programAr9565AniLevels(channel(), permitted(),
                                                backend(fake), state, 0U, 0U);
    if (reduced.result != AniResult::Ok ||
        !matches(fake, kExpectedReducedFirst, kExpectedReducedLow,
                 kExpectedReducedFirst, kExpectedReducedLow) ||
        state.firstStepLevel != 0U || state.spurLevel != 0U)
    {
        return static_cast<int>(TestExit::Reduced);
    }
    const auto capped =
        programAr9565AniLevels(channel(), permitted(), backend(fake), state,
                               kMaximumFirstLevel, kMaximumSpurLevel);
    if (capped.result != AniResult::Ok ||
        !matches(fake, kExpectedMax, kExpectedMax, kExpectedMax,
                 kExpectedMaxExtended))
    {
        return static_cast<int>(TestExit::Capped);
    }
    return 0;
}

static int checkRejectedAndAmbiguous(Fake &fake, Ar9565AniState &state)
{
    const size_t beforeDenial = fake.writes;
    if (programAr9565AniLevels(channel(), permitted(), backend(fake), state,
                               kInvalidFirstLevel, 0U)
                .result != AniResult::InvalidLevel ||
        programAr9565AniLevels(channel(), permitted(), backend(fake), state, 2U,
                               kInvalidSpurLevel)
                .result != AniResult::InvalidLevel ||
        fake.writes != beforeDenial)
    {
        return static_cast<int>(TestExit::InvalidLevel);
    }
    auto denied = permitted();
    denied.channelPermitted = false;
    if (programAr9565AniLevels(channel(), denied, backend(fake), state, 2U, 3U)
                .result != AniResult::MissingAuthorization ||
        fake.writes != beforeDenial)
    {
        return static_cast<int>(TestExit::Authorization);
    }
    Fake stale {};
    setIni(stale);
    Ar9565AniState old = state;
    if (programAr9565AniLevels(channel(kOtherChannel), permitted(),
                               backend(stale), old, 2U, 3U)
                .result != AniResult::NotInitialized ||
        programAr9565AniLevels(channel(), permitted(),
                               backend(stale, kEpoch + 1U), old, 2U, 3U)
                .result != AniResult::NotInitialized ||
        stale.writes != 0U)
    {
        return static_cast<int>(TestExit::Epoch);
    }
    // The same primary 2.4-GHz channel has distinct PHY defaults in HT40,
    // for a new silicon revision, or under a different crystal: never reuse.
    auto changedGeometry = channel();
    changedGeometry.width = ChannelWidth::Ht40;
    changedGeometry.secondary = kHt40SecondaryChannel;
    if (programAr9565AniLevels(changedGeometry, permitted(), backend(stale),
                               old, 2U, 3U)
                .result != AniResult::NotInitialized ||
        stale.writes != 0U)
    {
        return static_cast<int>(TestExit::Epoch);
    }
    changedGeometry = channel();
    changedGeometry.referenceClock = RfReferenceClock::Crystal40Mhz;
    if (programAr9565AniLevels(changedGeometry, permitted(), backend(stale),
                               old, 2U, 3U)
                .result != AniResult::NotInitialized ||
        stale.writes != 0U)
    {
        return static_cast<int>(TestExit::Epoch);
    }
    changedGeometry = channel();
    changedGeometry.silicon = Revision::V1_0;
    if (programAr9565AniLevels(changedGeometry, permitted(), backend(stale),
                               old, 2U, 3U)
                .result != AniResult::NotInitialized ||
        stale.writes != 0U)
    {
        return static_cast<int>(TestExit::Epoch);
    }
    // The standalone ANI executor must not accept forged silicon, even
    // when the control channel itself is canonical.
    auto wrongChip = channel();
    wrongChip.silicon = Revision::Unknown;
    const size_t readsBeforeInvalidChip = stale.reads;
    if (cacheAr9565AniIniDefaults(wrongChip, permitted(), backend(stale), old)
                .result != AniResult::InvalidChannel ||
        stale.reads != readsBeforeInvalidChip)
    {
        return static_cast<int>(TestExit::InvalidChip);
    }
    // Lost initial owner and malformed BAR do not attempt reads or writes.
    old = state;
    stale.live = false;
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(stale), old)
                .result != AniResult::OwnershipLost ||
        old.initialized || stale.reads != 0U)
    {
        return static_cast<int>(TestExit::Revoked);
    }
    stale.live = true;
    if (cacheAr9565AniIniDefaults(channel(), permitted(),
                                  backend(stale, kEpoch, kSpurExt + 3U), old)
                .result != AniResult::InvalidBar ||
        stale.writes != 0U)
    {
        return static_cast<int>(TestExit::Bar);
    }
    // Unknown country must not admit a Japan-only channel even for RX.
    if (cacheAr9565AniIniDefaults(channel(kJapanChannel), permitted(),
                                  backend(stale), old)
                .result != AniResult::MissingAuthorization ||
        stale.reads != 0U)
    {
        return static_cast<int>(TestExit::Japan);
    }
    return 0;
}

static int checkReadWriteFailures()
{
    Fake failed {};
    setIni(failed);
    Ar9565AniState old {};
    failed.failedRead = kFirstStepLow;
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(failed), old)
                .result != AniResult::ReadFailed ||
        old.initialized || failed.writes != 0U)
    {
        return static_cast<int>(TestExit::Read);
    }
    failed.failedRead = 0U;
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(failed), old)
            .result != AniResult::Ok)
    {
        return static_cast<int>(TestExit::Recovered);
    }
    failed.failedWrite = kSpur;
    const auto writeFailure =
        programAr9565AniLevels(channel(), permitted(), backend(failed), old,
                               kFirstLevelOnFailure, kSpurLevelOnFailure);
    if (writeFailure.result != AniResult::WriteFailed ||
        !writeFailure.requiresReset || writeFailure.completedWrites != 2U ||
        old.initialized)
    {
        return static_cast<int>(TestExit::Write);
    }
    failed.failedWrite = 0U;
    setIni(failed);
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(failed), old)
            .result != AniResult::Ok)
    {
        return static_cast<int>(TestExit::Recache);
    }
    failed.wrongReadback = kFirstStep;
    const auto mismatch =
        programAr9565AniLevels(channel(), permitted(), backend(failed), old,
                               kFirstLevelOnFailure, kSpurLevelOnFailure);
    if (mismatch.result != AniResult::ReadbackMismatch ||
        !mismatch.requiresReset || old.initialized)
    {
        return static_cast<int>(TestExit::Readback);
    }
    // A posted first write may revoke RF ownership before its readback:
    // stop immediately, require reset and never export a valid baseline.
    Fake revoked {};
    setIni(revoked);
    Ar9565AniState revokedState {};
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(revoked),
                                  revokedState)
            .result != AniResult::Ok)
    {
        return static_cast<int>(TestExit::RevokedAfterWrite);
    }
    revoked.revokeAtWrite = 1U;
    const auto midWriteRevoke = programAr9565AniLevels(
        channel(), permitted(), backend(revoked), revokedState,
        kFirstLevelOnFailure, kSpurLevelOnFailure);
    if (midWriteRevoke.result != AniResult::OwnershipLost ||
        midWriteRevoke.completedWrites != 1U || !midWriteRevoke.requiresReset ||
        revokedState.initialized || revoked.writes != 1U)
    {
        return static_cast<int>(TestExit::RevokedAfterWrite);
    }
    return 0;
}

static int checkHardwareWindowDerivation()
{
    constexpr uint32_t kSampleElapsed = 1000U;
    constexpr uint32_t kSampleCycles = 44000000U;
    AniHardwareSample begin {};
    begin.ownerEpoch = kEpoch;
    begin.captureSequence = 3U;
    begin.channel = kTestChannel;
    begin.width = ChannelWidth::Ht20;
    begin.cycleCount = 500U;
    begin.receiveFrameCycles = 100U;
    begin.transmitFrameCycles = 100U;
    begin.ofdmTimingErrors = 2U;
    begin.cckTimingErrors = 8U;
    begin.mmioAndMasksVerified = true;
    AniHardwareSample end = begin;
    end.captureSequence = 4U;
    end.cycleCount += kSampleCycles;
    end.receiveFrameCycles += 2200000U;
    end.transmitFrameCycles += 1100000U;
    end.ofdmTimingErrors += 3501U;
    end.cckTimingErrors += 601U;
    AniErrorWindow window {};
    const auto result = deriveAr9565AniErrorWindow(
        channel(), begin, end, kSampleElapsed, false, window);
    if (result != AniResult::Ok || !window.hardwareCountersVerified ||
        window.listenedMilliseconds != 925U || window.counterSequence != 4U ||
        window.ownerEpoch != kEpoch || window.ofdmTimingErrors != 3501U ||
        window.cckTimingErrors != 601U || window.scanning)
    {
        return static_cast<int>(TestExit::HardwareWindow);
    }
    // The derived real-clock window can drive the ANI writer, but does not
    // create its PHY/BT/country or native-queue ownership on its own.
    Fake fake {};
    setIni(fake);
    Ar9565AniState state {};
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(fake), state)
                .result != AniResult::Ok ||
        adaptAr9565AniToPhyErrors(channel(), permitted(), backend(fake), window,
                                  state)
                .result != AniResult::Ok ||
        state.ofdmImmunityLevel != 4U ||
        state.lastCounterSequence != window.counterSequence)
    {
        return static_cast<int>(TestExit::HardwareWindowPolicy);
    }
    // Every malformed physical sample must wipe any prior produced window.
    const auto rejects = [&](const AniHardwareSample &start,
                             const AniHardwareSample &finish, uint32_t elapsed,
                             AniResult expected)
    {
        AniErrorWindow output = window;
        const auto error = deriveAr9565AniErrorWindow(channel(), start, finish,
                                                      elapsed, false, output);
        return error == expected && !output.hardwareCountersVerified &&
               output.ownerEpoch == 0U && output.counterSequence == 0U;
    };
    AniHardwareSample bad = end;
    bad.mmioAndMasksVerified = false;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.ownerEpoch = kEpoch + 1U;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::StaleErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.captureSequence = begin.captureSequence;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::StaleErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.channel = kOtherChannel;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::StaleErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.cycleCount = begin.cycleCount;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.receiveFrameCycles = begin.receiveFrameCycles - 1U;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.ofdmTimingErrors = 0x00ffffffU;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    bad = end;
    bad.receiveFrameCycles = bad.cycleCount;
    if (!rejects(begin, bad, kSampleElapsed, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    if (!rejects(begin, end, 5001U, AniResult::InvalidErrorWindow) ||
        !rejects(begin, end, 10U, AniResult::InvalidErrorWindow))
    {
        return static_cast<int>(TestExit::HardwareWindowReject);
    }
    // HT40 uses 88 MHz MAC reference; reusing HT20 timing would incorrectly
    // double the observed listen time and trigger a false ANI policy window.
    auto ht40 = channel();
    ht40.width = ChannelWidth::Ht40;
    ht40.secondary = kHt40SecondaryChannel;
    AniHardwareSample wideBefore = begin;
    AniHardwareSample wideAfter = end;
    wideBefore.width = ChannelWidth::Ht40;
    wideAfter.width = ChannelWidth::Ht40;
    wideBefore.secondary = kHt40SecondaryChannel;
    wideAfter.secondary = kHt40SecondaryChannel;
    wideAfter.cycleCount = wideBefore.cycleCount + 88000000U;
    wideAfter.receiveFrameCycles = wideBefore.receiveFrameCycles + 8800000U;
    wideAfter.transmitFrameCycles = wideBefore.transmitFrameCycles + 8800000U;
    if (deriveAr9565AniErrorWindow(ht40, wideBefore, wideAfter, kSampleElapsed,
                                   true, window) != AniResult::Ok ||
        !window.scanning || window.listenedMilliseconds != 800U)
    {
        return static_cast<int>(TestExit::HardwareWindowHt40);
    }
    return 0;
}

static int checkAdaptiveMonitor()
{
    Fake fake {};
    setIni(fake);
    Ar9565AniState state {};
    if (cacheAr9565AniIniDefaults(channel(), permitted(), backend(fake), state)
            .result != AniResult::Ok)
    {
        return static_cast<int>(TestExit::MonitorUntrusted);
    }
    uint64_t nextCounterSequence = 1U;
    const auto monitor = [&](AniErrorWindow sample)
    {
        sample.counterSequence = nextCounterSequence++;
        return adaptAr9565AniToPhyErrors(channel(), permitted(), backend(fake),
                                         sample, state);
    };
    const size_t initialReads = fake.reads;
    AniErrorWindow window {kEpoch, 1U, 1000U, 4000U, 0U, false, false};
    if (monitor(window).result != AniResult::InvalidErrorWindow ||
        fake.writes != 0U || fake.reads != initialReads ||
        state.ofdmImmunityLevel != 3U)
    {
        return static_cast<int>(TestExit::MonitorUntrusted);
    }
    window.hardwareCountersVerified = true;
    window.listenedMilliseconds = 0U;
    if (monitor(window).result != AniResult::InvalidErrorWindow)
    {
        return static_cast<int>(TestExit::MonitorUntrusted);
    }
    window.listenedMilliseconds = 300U;
    if (monitor(window).result != AniResult::Ok || fake.writes != 0U)
    {
        return static_cast<int>(TestExit::MonitorWindow);
    }
    window.listenedMilliseconds = 1000U;
    window.scanning = true;
    if (monitor(window).result != AniResult::Ok || fake.writes != 0U)
    {
        return static_cast<int>(TestExit::MonitorWindow);
    }
    window.scanning = false;
    // The OFDM threshold is strict: equality must not raise immunity.
    window.ofdmTimingErrors = 3500U;
    if (monitor(window).adjusted || fake.writes != 0U)
    {
        return static_cast<int>(TestExit::MonitorWindow);
    }
    window.ofdmTimingErrors = 3501U;
    const auto raised = monitor(window);
    if (raised.result != AniResult::Ok || !raised.adjusted ||
        !raised.registerProgrammed ||
        raised.programming.completedWrites != 4U ||
        state.ofdmImmunityLevel != 4U || state.cckImmunityLevel != 2U ||
        state.firstStepLevel != 3U || state.spurLevel != 4U ||
        !matches(fake, 12U, 13U, 14U, 15U))
    {
        return static_cast<int>(TestExit::MonitorOfdmHigh);
    }
    // A second call for an already-consumed counter sample may not
    // progressively tune the PHY again under the same physical epoch.
    const size_t beforeReplay = fake.writes;
    AniErrorWindow replay = window;
    replay.counterSequence = state.lastCounterSequence;
    const auto repeated = adaptAr9565AniToPhyErrors(
        channel(), permitted(), backend(fake), replay, state);
    if (repeated.result != AniResult::StaleErrorWindow ||
        state.ofdmImmunityLevel != 4U || fake.writes != beforeReplay)
    {
        return static_cast<int>(TestExit::MonitorReplay);
    }
    // The event window must also match the real PCI/PHY epoch and bound the
    // 24-bit hardware counters before any register write or state transition.
    replay.ownerEpoch = kEpoch + 1U;
    replay.counterSequence = nextCounterSequence + 10U;
    if (adaptAr9565AniToPhyErrors(channel(), permitted(), backend(fake), replay,
                                  state)
            .result != AniResult::StaleErrorWindow)
    {
        return static_cast<int>(TestExit::MonitorReplay);
    }
    replay.ownerEpoch = kEpoch;
    replay.ofdmTimingErrors = 0x00ffffffU;
    if (adaptAr9565AniToPhyErrors(channel(), permitted(), backend(fake), replay,
                                  state)
                .result != AniResult::InvalidErrorWindow ||
        fake.writes != beforeReplay)
    {
        return static_cast<int>(TestExit::MonitorBadCounter);
    }
    // CCK may advance without a redundant register write when OFDM already
    // sets a stronger first-step; keep their policy levels independent.
    window.ofdmTimingErrors = 950U;
    window.cckTimingErrors = 601U;
    const size_t afterOfdm = fake.writes;
    const auto cckRaised = monitor(window);
    if (cckRaised.result != AniResult::Ok || !cckRaised.adjusted ||
        cckRaised.registerProgrammed || fake.writes != afterOfdm ||
        state.ofdmImmunityLevel != 4U || state.cckImmunityLevel != 3U ||
        !state.ofdmTurn)
    {
        return static_cast<int>(TestExit::MonitorCckHigh);
    }
    window.cckTimingErrors = 0U;
    window.ofdmTimingErrors = 0U;
    const auto loweredOfdm = monitor(window);
    const auto loweredCck = monitor(window);
    if (loweredOfdm.result != AniResult::Ok || !loweredOfdm.adjusted ||
        !loweredOfdm.registerProgrammed || loweredCck.result != AniResult::Ok ||
        !loweredCck.adjusted || !loweredCck.registerProgrammed ||
        state.ofdmImmunityLevel != 3U || state.cckImmunityLevel != 2U ||
        !state.ofdmTurn || state.firstStepLevel != 2U ||
        state.spurLevel != 3U || fake.writes != afterOfdm + 8U)
    {
        return static_cast<int>(TestExit::MonitorLow);
    }
    // Without verified per-BSSID RSSI, the AR9565 is limited to the
    // conservative low-signal CCK range from ath9k, never levels 7 or 8.
    window.ofdmTimingErrors = 950U;
    window.cckTimingErrors = 700U;
    for (size_t i = 0U; i < 12U; ++i)
    {
        if (monitor(window).result != AniResult::Ok)
        {
            return static_cast<int>(TestExit::MonitorCaps);
        }
    }
    if (state.cckImmunityLevel != 6U || state.ofdmImmunityLevel != 3U ||
        state.firstStepLevel != 6U || !state.initialized)
    {
        return static_cast<int>(TestExit::MonitorCaps);
    }
    // Scaling a near-overflow 24-bit PHY counter must not wrap uint32.
    window.ofdmTimingErrors = 0x00fffffeU;
    window.cckTimingErrors = 0U;
    if (monitor(window).result != AniResult::Ok ||
        state.ofdmImmunityLevel != 4U)
    {
        return static_cast<int>(TestExit::MonitorOverflow);
    }
    const auto older = state;
    fake.live = false;
    const size_t oldWrites = fake.writes;
    if (monitor(window).result != AniResult::OwnershipLost ||
        fake.writes != oldWrites ||
        state.ofdmImmunityLevel != older.ofdmImmunityLevel)
    {
        return static_cast<int>(TestExit::MonitorRevoked);
    }
    fake.live = true;
    if (adaptAr9565AniToPhyErrors(channel(kOtherChannel), permitted(),
                                  backend(fake), window, state)
                .result != AniResult::NotInitialized ||
        state.initialized != older.initialized)
    {
        return static_cast<int>(TestExit::MonitorStale);
    }
    // A posted first-step MMIO failure destroys the baseline; no caller can
    // interpret the uncommitted monitor policy as a working register state.
    fake.failedWrite = kFirstStep;
    window.ofdmTimingErrors = 0U;
    window.cckTimingErrors = 0U;
    const auto failed = monitor(window);
    if (failed.result != AniResult::WriteFailed ||
        !failed.programming.requiresReset || failed.adjusted ||
        state.initialized || state.ofdmImmunityLevel != older.ofdmImmunityLevel)
    {
        return static_cast<int>(TestExit::MonitorFailure);
    }
    return 0;
}

int main()
{
    Fake fake {};
    Ar9565AniState state {};
    if (state.referenceClock != RfReferenceClock::Unknown)
    {
        return static_cast<int>(TestExit::Baseline);
    }
    const int success = checkSuccessfulStages(fake, state);
    if (success != 0)
    {
        return success;
    }
    const int safety = checkRejectedAndAmbiguous(fake, state);
    if (safety != 0)
    {
        return safety;
    }
    const int readWrite = checkReadWriteFailures();
    if (readWrite != 0)
    {
        return readWrite;
    }
    const int physicalCounters = checkHardwareWindowDerivation();
    if (physicalCounters != 0)
    {
        return physicalCounters;
    }
    return checkAdaptiveMonitor();
}
