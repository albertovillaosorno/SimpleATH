// Full synthetic RX-only RF epoch: no native IOKit, PCI, radio, or USB.
#include "hardware/Ar9565Ani.hpp"
#include "hardware/Ar9565BoardModal.hpp"
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565OfdmTiming.hpp"
#include "hardware/Ar9565PhyMode.hpp"
#include "hardware/Ar9565Pll.hpp"
#include "hardware/Ar9565RadioSequence.hpp"
#include "hardware/Ar9565RfBus.hpp"
#include "hardware/Ar9565RfIni.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace simpleath;

namespace
{
    enum class TestExit : int
    {
        Success = 1,
        Authorization = 2,
        Board = 3,
        Epoch = 4,
        Japan = 5,
        Ini = 6,
        Modal = 7,
        Grant = 8,
        Pll = 9,
        Ofdm = 10,
        Calibration = 11,
        JapanAllowed = 12,
        Ht40 = 13,
        Revocation = 14,
        Mode = 15,
        BoardSnapshot = 16,
        Ani = 17,
        SplitBackend = 18,
    };

    constexpr uint64_t kEpoch = 69;
    constexpr uint8_t kJapanChannel = 14;
    constexpr uint8_t kTamperedEepromVersion = 0xffU;
    constexpr uint8_t kChannel6 = 6;
    constexpr uint8_t kInvalidSecondary = 9;
    constexpr size_t kMinIniWrites = 500;
    constexpr uint32_t kSelfgenMask = 0x832c;
    constexpr uint32_t kBar = 0x24000;
    constexpr uint32_t kRfRequest = 0xa23c;
    constexpr uint32_t kRfGrant = 0xa240;
    constexpr uint32_t kBbDpll2 = 0x16184;
    constexpr uint32_t kPhyGenControl = 0xa204;
    constexpr uint32_t kAniFirstStepRegister = 0x9e10U;
    constexpr uint32_t kJoinedMacCca = 0x8318;
    constexpr uint32_t kPhyHt = 0x40;
    constexpr uint32_t kPhyDynamic40 = 4;
    constexpr uint32_t kPhyUpperPrimary = 0x10;
    constexpr uint32_t kTiming3 = 0x9808;
    constexpr uint32_t kAgc = 0xa2c4;
    constexpr uint32_t kIqTiming = 0x980c;
    constexpr uint32_t kIqPowerI = 0x98c0;
    constexpr uint32_t kIqPowerQ = 0x98c4;
    constexpr uint32_t kIqCorrelation = 0x98c8;
    constexpr uint32_t kNoisePrimary = 0x9e1c;
    constexpr uint32_t kNoiseExtension = 0x9830;
    constexpr uint32_t kNoiseExtensionSample = 0x019a0000;
    constexpr uint8_t kSecondary10 = 10;
    constexpr uint32_t kAgcCal = 1;
    constexpr uint32_t kNoiseCal = 2;
    constexpr uint32_t kIqDoCal = 0x10000;
    constexpr uint32_t kNoiseSample = 0x19c00000;
    constexpr uint32_t kSampleI = 98304;
    constexpr uint32_t kSampleQ = 65536;
    constexpr uint32_t kSampleCorrelation = 640;

    struct Fake
    {
            std::array<uint32_t, kBar / sizeof(uint32_t)> registers {};
            size_t writes {};
            size_t reads {};
            size_t permits {};
            size_t failedWriteAt {};
            size_t revokeAfterWrite {};
            uint32_t failedWriteOffset {};
            uint32_t failedReadOffset {};
            bool powered {true};
            bool rfGranted {};
            bool grantNever {};
            bool delayChecked {};
            bool badMeasurement {};
            EepromImage *boardToAlter {};
    };

    bool basePermit(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.permits;
        return fake.powered && epoch == kEpoch;
    }

    bool tunerPermit(void *context, uint64_t epoch)
    {
        const auto &fake = *static_cast<Fake *>(context);
        return basePermit(context, epoch) && fake.rfGranted;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.reads;
        if (value == nullptr || offset % sizeof(uint32_t) != 0 ||
            offset >= kBar || offset == fake.failedReadOffset)
        {
            return false;
        }
        if (offset == kRfGrant)
        {
            *value = fake.rfGranted ? 1U : 0U;
            return true;
        }
        if (offset == kIqPowerI || offset == kIqPowerQ ||
            offset == kIqCorrelation)
        {
            if (fake.badMeasurement)
            {
                *value = 0;
            }
            else
            {
                if (offset == kIqPowerI)
                {
                    *value = kSampleI;
                }
                else if (offset == kIqPowerQ)
                {
                    *value = kSampleQ;
                }
                else
                {
                    *value = kSampleCorrelation;
                }
            }
            return true;
        }
        if (offset == kNoisePrimary || offset == kNoiseExtension)
        {
            *value =
                offset == kNoisePrimary ? kNoiseSample : kNoiseExtensionSample;
            return true;
        }
        auto &stored = fake.registers.at(offset / sizeof(uint32_t));
        // The fake hardware finishes a requested one-shot calibration on its
        // first poll. These clear operations do not grant RF/host authority.
        if (offset == kAgc)
        {
            stored &= ~(kAgcCal | kNoiseCal);
        }
        if (offset == kIqTiming)
        {
            stored &= ~kIqDoCal;
        }
        *value = stored;
        return true;
    }

    bool write(void *context, uint32_t offset, uint32_t value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.writes;
        if (offset % sizeof(uint32_t) != 0 || offset >= kBar ||
            fake.writes == fake.failedWriteAt ||
            offset == fake.failedWriteOffset)
        {
            return false;
        }
        fake.registers.at(offset / sizeof(uint32_t)) = value;
        if (fake.writes == 1 && fake.boardToAlter != nullptr)
        {
            fake.boardToAlter->restored = false;
            fake.boardToAlter->bytes[0] = kTamperedEepromVersion;
        }
        if (fake.revokeAfterWrite != 0 && fake.writes == fake.revokeAfterWrite)
        {
            fake.powered = false;
        }
        if (offset == kRfRequest)
        {
            fake.rfGranted = value != 0 && !fake.grantNever;
        }
        return true;
    }

    void delay(void *context, uint32_t micros)
    {
        auto &fake = *static_cast<Fake *>(context);
        if (micros != 0)
        {
            fake.delayChecked = true;
        }
    }

    // Physically equivalent fake operations at distinct callback addresses.
    // A phase may not smuggle a second MMIO transport into one RF epoch.
    bool alternateRead(void *context, uint32_t offset, uint32_t *value)
    {
        return read(context, offset, value);
    }

    bool alternateWrite(void *context, uint32_t offset, uint32_t value)
    {
        return write(context, offset, value);
    }

    void alternateDelay(void *context, uint32_t micros)
    {
        delay(context, micros);
    }

    RadioSequenceBackends backends(Fake &fake)
    {
        const RfIniBackend normal {
            &fake, kEpoch, kBar, basePermit, write, delay,
        };
        const RfIniBackend withLease {
            &fake, kEpoch, kBar, tunerPermit, write, delay,
        };
        return {{normal, read}, {withLease, read}, {normal, read}};
    }

    CalibrationAndRegulatory authorized()
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

    EepromImage board()
    {
        EepromImage image {};
        image.restored = true;
        image.appliedBlocks = 1;

        // Synthetic board fields matching the pinned AR9300 v2 2-GHz modal
        // layout; this test does NOT claim any real EEPROM provenance.
        struct ImageByte
        {
                size_t offset;
                uint8_t value;
        };

        constexpr std::array<ImageByte, 26> kBoardBytes {
            {
                {0, 2},     {1, 3},      {2, 0x02},   {3, 0x11},  {4, 0x22},
                {5, 0x33},  {6, 0x44},   {7, 0x55},   {32, 0x11}, {33, 0x02},
                {53, 0x56}, {54, 0x34},  {55, 0x12},  {57, 0x45}, {58, 0x23},
                {59, 0x01}, {61, 0x50},  {62, 0x01},  {67, 7},    {70, 9},
                {95, 2},    {114, 0x21}, {115, 0x03}, {138, 112}, {139, 137},
                {140, 162},
            },
        };
        std::array<uint8_t, kAr9300EepromImageBytes> packed {};
        for (const auto &entry : kBoardBytes)
        {
            packed.at(entry.offset) = entry.value;
        }
        std::memcpy(static_cast<void *>(&image.bytes[0]), packed.data(),
                    sizeof(image.bytes));
        return image;
    }

    RfChannelRequest channel(uint8_t number = kChannel6,
                             ChannelWidth width = ChannelWidth::Ht20,
                             uint8_t secondary = 0)
    {
        Channel control {};
        (void)mapChannel(number, control);
        return {
            Revision::V1_1,
            control,
            width,
            secondary,
            RfReferenceClock::Crystal25Mhz,
        };
    }

    RadioSequenceProgress
    run(Fake &fake, const RfChannelRequest &request = channel(),
        CalibrationAndRegulatory permission = authorized(),
        const EepromImage &image = board())
    {
        return runAr9565ReceiveOnlyRadioSequence(
            image, request, TxGainProfile::LowOb, RxGainProfile::Standard,
            BoardModalDiversity::WlanOnly, permission, backends(fake));
    }

    int checkSplitBackendTransport()
    {
        constexpr int kVariants = 3;
        for (int variant = 0; variant < kVariants; ++variant)
        {
            Fake fake {};
            auto mixed = backends(fake);
            if (variant == 0)
            {
                mixed.tuning.io.write32 = alternateWrite;
            }
            else if (variant == 1)
            {
                mixed.rfBus.read32 = alternateRead;
            }
            else
            {
                mixed.baseband.io.delayMicros = alternateDelay;
            }
            const auto result = runAr9565ReceiveOnlyRadioSequence(
                board(), channel(), TxGainProfile::LowOb,
                RxGainProfile::Standard, BoardModalDiversity::WlanOnly,
                authorized(), mixed);
            if (result.result != RadioSequenceResult::InvalidBackend ||
                result.stage != RadioSequenceStage::Preflight ||
                result.requiresReset || fake.writes != 0U || fake.reads != 0U ||
                fake.permits != 0U)
            {
                return static_cast<int>(TestExit::SplitBackend);
            }
        }
        return 0;
    }

    int checkAdmissionAndChannelModes()
    {
        // Check the preflight rejects invalid auth/channel/board and
        // cross-epoch descriptor spoofing BEFORE the first register access.
        Fake invalid {};
        auto denied = authorized();
        denied.radioKillUnblocked = false;
        if (run(invalid, channel(), denied).result !=
                RadioSequenceResult::MissingAuthorization ||
            run(invalid,
                channel(kChannel6, ChannelWidth::Ht40, kInvalidSecondary))
                    .result != RadioSequenceResult::InvalidChannel ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestExit::Authorization);
        }
        auto broken = board();
        broken.restored = false;
        if (run(invalid, channel(), authorized(), broken).result !=
                RadioSequenceResult::InvalidBoard ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestExit::Board);
        }
        auto wrong = backends(invalid);
        wrong.tuning.io.ownerEpoch++;
        const auto mismatch = runAr9565ReceiveOnlyRadioSequence(
            board(), channel(), TxGainProfile::LowOb, RxGainProfile::Standard,
            BoardModalDiversity::WlanOnly, authorized(), wrong);
        if (mismatch.result != RadioSequenceResult::InvalidBackend ||
            invalid.writes != 0)
        {
            return static_cast<int>(TestExit::Epoch);
        }
        Fake japan {};
        if (run(japan, channel(kJapanChannel)).result !=
                RadioSequenceResult::InvalidChannel ||
            japan.writes != 0)
        {
            return static_cast<int>(TestExit::Japan);
        }
        auto knownJapan = authorized();
        knownJapan.localCountryRulesAvailable = true;
        Fake japanKnown {};
        if (run(japanKnown, channel(kJapanChannel), knownJapan).result !=
                RadioSequenceResult::Ok ||
            japanKnown.rfGranted ||
            (japanKnown.registers.at(kPhyGenControl / sizeof(uint32_t)) &
             kPhyHt) != 0)
        {
            return static_cast<int>(TestExit::JapanAllowed);
        }
        Fake ht40 {};
        const auto wide =
            run(ht40, channel(kChannel6, ChannelWidth::Ht40, kSecondary10));
        if (wide.result != RadioSequenceResult::Ok || ht40.rfGranted ||
            !wide.calibration.noise.hasExtension ||
            (ht40.registers.at(kPhyGenControl / sizeof(uint32_t)) &
             (kPhyHt | kPhyDynamic40 | kPhyUpperPrimary)) !=
                (kPhyHt | kPhyDynamic40 | kPhyUpperPrimary) ||
            (ht40.registers.at(kJoinedMacCca / sizeof(uint32_t)) & 1U) == 0)
        {
            return static_cast<int>(TestExit::Ht40);
        }
        Fake revoked {};
        revoked.revokeAfterWrite = 1;
        const auto revokedPhase = run(revoked);
        if (revokedPhase.stage != RadioSequenceStage::IniTables ||
            revokedPhase.ini.result != RfIniResult::OwnershipLost ||
            !revokedPhase.requiresReset)
        {
            return static_cast<int>(TestExit::Revocation);
        }
        return 0;
    }
} // namespace

int main()
{
    Fake good {};
    const auto ok = run(good);
    if (ok.result != RadioSequenceResult::Ok ||
        ok.stage != RadioSequenceStage::Completed || ok.requiresReset ||
        ok.ini.completedWrites < kMinIniWrites ||
        ok.board.result != BoardModalResult::Ok ||
        ok.phyMode.result != PhyModeResult::Ok ||
        ok.phyMode.completedWrites != 4 ||
        (good.registers.at(kPhyGenControl / sizeof(uint32_t)) & kPhyHt) == 0 ||
        (good.registers.at(kJoinedMacCca / sizeof(uint32_t)) & 1U) != 0 ||
        ok.pll.result != RfPllResult::Ok ||
        ok.synthesizer.result != RfChannelResult::Ok ||
        ok.ofdm.result != OfdmTimingResult::Ok ||
        ok.calibration.phase != RxCalibrationPhase::Completed ||
        ok.ani.result != AniResult::Ok || !ok.aniState.initialized ||
        good.rfGranted || !good.delayChecked ||
        good.registers.at(kSelfgenMask / sizeof(uint32_t)) != 0)
    {
        return static_cast<int>(TestExit::Success);
    }
    Fake aniReadFailure {};
    aniReadFailure.failedReadOffset = kAniFirstStepRegister;
    const auto failedAni = run(aniReadFailure);
    if (failedAni.stage != RadioSequenceStage::AniBaseline ||
        failedAni.ani.result != AniResult::ReadFailed ||
        failedAni.aniState.initialized || !failedAni.requiresReset ||
        aniReadFailure.rfGranted)
    {
        return static_cast<int>(TestExit::Ani);
    }
    // Native MMIO callbacks must never be able to change the already
    // validated board consumed by a later radio stage.
    EepromImage originalBoard = board();
    Fake mutated {};
    mutated.boardToAlter = &originalBoard;
    const auto snapshot = run(mutated, channel(), authorized(), originalBoard);
    if (snapshot.result != RadioSequenceResult::Ok ||
        snapshot.stage != RadioSequenceStage::Completed ||
        originalBoard.restored ||
        originalBoard.bytes[0] != kTamperedEepromVersion)
    {
        return static_cast<int>(TestExit::BoardSnapshot);
    }
    const int splitBackend = checkSplitBackendTransport();
    if (splitBackend != 0)
    {
        return splitBackend;
    }
    const int admission = checkAdmissionAndChannelModes();
    if (admission != 0)
    {
        return admission;
    }
    // The first failed/ambiguous INI MMIO write demands reset, even if the
    // callback did not count any successful write.
    Fake iniFailure {};
    iniFailure.failedWriteAt = 1;
    const auto ini = run(iniFailure);
    if (ini.stage != RadioSequenceStage::IniTables || !ini.requiresReset ||
        ini.ini.result != RfIniResult::WriteFailed)
    {
        return static_cast<int>(TestExit::Ini);
    }
    Fake modeFailure {};
    modeFailure.failedWriteAt = ok.ini.completedWrites + 1;
    const auto failedMode = run(modeFailure);
    if (failedMode.stage != RadioSequenceStage::PhyMode ||
        !failedMode.requiresReset ||
        failedMode.phyMode.result != PhyModeResult::WriteFailed ||
        modeFailure.rfGranted)
    {
        return static_cast<int>(TestExit::Mode);
    }
    Fake boardFailure {};
    boardFailure.failedWriteAt =
        ok.ini.completedWrites + ok.phyMode.completedWrites + 1;
    const auto modal = run(boardFailure);
    if (modal.stage != RadioSequenceStage::BoardModal || !modal.requiresReset ||
        modal.board.result != BoardModalResult::WriteFailed)
    {
        return static_cast<int>(TestExit::Modal);
    }
    Fake grantFailure {};
    grantFailure.grantNever = true;
    const auto grant = run(grantFailure);
    if (grant.stage != RadioSequenceStage::RfBusRequest ||
        !grant.requiresReset || grant.bus.result != RfBusResult::GrantTimeout)
    {
        return static_cast<int>(TestExit::Grant);
    }
    Fake pllFailure {};
    pllFailure.failedWriteOffset = kBbDpll2;
    const auto pll = run(pllFailure);
    if (pll.stage != RadioSequenceStage::Pll || !pll.requiresReset ||
        !pllFailure.rfGranted || pll.pll.result != RfPllResult::WriteFailed)
    {
        return static_cast<int>(TestExit::Pll);
    }
    Fake ofdmFailure {};
    ofdmFailure.failedReadOffset = kTiming3;
    const auto ofdm = run(ofdmFailure);
    if (ofdm.stage != RadioSequenceStage::OfdmTiming || !ofdm.requiresReset ||
        ofdmFailure.rfGranted ||
        ofdm.ofdm.result != OfdmTimingResult::ReadFailed)
    {
        return static_cast<int>(TestExit::Ofdm);
    }
    Fake calibrationFailure {};
    calibrationFailure.badMeasurement = true;
    const auto calibration = run(calibrationFailure);
    if (calibration.stage != RadioSequenceStage::ReceiverCalibration ||
        !calibration.requiresReset || calibrationFailure.rfGranted ||
        calibration.calibration.iq.result != RxIqResult::InvalidMeasurement)
    {
        return static_cast<int>(TestExit::Calibration);
    }
    return 0;
}
