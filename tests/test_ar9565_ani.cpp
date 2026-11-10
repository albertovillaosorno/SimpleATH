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
    return 0;
}

int main()
{
    Fake fake {};
    Ar9565AniState state {};
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
    return checkReadWriteFailures();
}
