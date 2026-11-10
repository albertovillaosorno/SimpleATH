// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic half-dBm EEPROM target selection, NOT a hardware TX power index.
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include "hardware/Ar9565Power.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    // Fixed EEPROM fixture layout offsets and numeric values from the
    // deterministic ath9k power/CTL regression vectors.
    constexpr auto kCalibrationPierHigh = 162;
    constexpr auto kCalibrationPierLow = 112;
    constexpr auto kCalibrationPierMid = 137;
    constexpr auto kCckCtlMode = 0xe1;
    constexpr auto kCckElevenMinimum = 19;
    constexpr auto kCckFiveMinimum = 17;
    constexpr auto kCckOneMbitRate = 0x1b;
    constexpr auto kCckReverseMinimum = 12;
    constexpr auto kCckTargetHalfDbm = 25;
    constexpr auto kCeilingHalfDbm = 30;
    constexpr auto kChannelFourteenMhz = 2484;
    constexpr auto kChannelOneMhz = 2412;
    constexpr auto kChannelSixMhz = 2437;
    constexpr auto kChannelSixNumber = 6;
    constexpr auto kCtlEdgeHalfDbm = 26;
    constexpr auto kCtlGroupAll = 0xe0U;
    constexpr auto kCtlLimitedHalfDbm = 24;
    constexpr auto kCtlTargetBytes = 20U;
    constexpr auto kEepromOffset138 = 138;
    constexpr auto kEepromOffset139 = 139;
    constexpr auto kEepromOffset140 = 140;
    constexpr auto kEepromOffset141 = 141;
    constexpr auto kEepromOffset142 = 142;
    constexpr auto kEepromOffset143 = 143;
    constexpr auto kEepromOffset147 = 147;
    constexpr auto kEepromOffset148 = 148;
    constexpr auto kEepromOffset149 = 149;
    constexpr auto kEepromOffset153 = 153;
    constexpr auto kEepromOffset154 = 154;
    constexpr auto kEepromOffset155 = 155;
    constexpr auto kEepromOffset195 = 195;
    constexpr auto kEepromOffset196 = 196;
    constexpr auto kEepromOffset197 = 197;
    constexpr auto kEepromOffset198 = 198;
    constexpr auto kEepromOffset199 = 199;
    constexpr auto kEepromOffset206 = 206;
    constexpr auto kEepromOffset310 = 310;
    constexpr auto kEepromOffset311 = 311;
    constexpr auto kEepromOffset313 = 313;
    constexpr auto kEepromOffset32 = 32;
    constexpr auto kEepromPowerTableOffset = 39;
    constexpr auto kEepromFeatureEnable = 42;
    constexpr auto kEepromModalTempSlope = 73;
    constexpr auto kEepromModalVoltSlope = 74;
    constexpr auto kPowerTableOffsetMinusSix = 0xfa;
    constexpr auto kModalTemperatureSlopeMinusTwentyFour = 0xe8;
    constexpr auto kModalVoltageSlopeSeven = 7;
    constexpr auto kPowerOffsetExpected = -6;
    constexpr auto kTemperatureSlopeExpected = -24;
    constexpr auto kVoltageSlopeExpected = 7;
    constexpr auto kTemperatureVoltageFeatures = 3;
    constexpr auto kEepromOffset322 = 322;
    constexpr auto kEepromOffset323 = 323;
    constexpr auto kEepromOffset324 = 324;
    constexpr auto kEepromOffset325 = 325;
    constexpr auto kEepromOffset326 = 326;
    constexpr auto kEepromOffset327 = 327;
    constexpr auto kEepromOffset328 = 328;
    constexpr auto kEepromOffset329 = 329;
    constexpr auto kEepromOffset33 = 33;
    constexpr auto kEepromOffset370 = 370;
    constexpr auto kEepromOffset5 = 5;
    constexpr auto kEepromOffset6 = 6;
    constexpr auto kEepromOffset7 = 7;
    constexpr auto kErasedByte = 0xff;
    constexpr auto kExtensionMhz = 2432;
    constexpr auto kHtMcsZeroRate = 0x80;
    constexpr auto kHtTargetHalfDbm = 15;
    constexpr auto kInvalidCtlBin = 185;
    constexpr auto kInvalidExtensionMhz = 2442;
    constexpr auto kInvalidSynthMhz = 2427;
    constexpr auto kNegativeCorrectionEncoded = 0xf8;
    constexpr auto kOfdmCtlMode = 0xe2;
    constexpr auto kOfdmRateCode = 0x0b;
    constexpr auto kOfdmTargetHalfDbm = 18;
    constexpr auto kOffRasterMhz = 2413;
    constexpr auto kOverCeilingHalfDbm = 31;
    constexpr auto kPhysicalMacFive = 0x55;
    constexpr auto kPhysicalMacFour = 0x44;
    constexpr auto kPhysicalMacOne = 0x11;
    constexpr auto kPhysicalMacThree = 0x33;
    constexpr auto kPhysicalMacTwo = 0x22;
    constexpr auto kRawCckElevenTarget = 27;
    constexpr auto kReferenceCorrectionMagnitude = 8;
    constexpr auto kReverseCckRawTarget = 29;
    constexpr auto kSecondPierCorrection = 16;
    constexpr auto kSecondPierTemperature = 50;
    constexpr auto kSecondPierVoltage = 120;
    constexpr auto kSynthMhz = 2422;
    constexpr auto kTemperatureReference = 40;
    constexpr auto kThirdPierTemperature = 60;
    constexpr auto kThirdPierVoltage = 140;
    constexpr auto kTwoCtlRowEdgeBytes = 8U;
    constexpr auto kUnsupportedHtRate = 0x88;
    constexpr auto kVoltageReferenceOrOffbandBin = 100;
    constexpr uint32_t kTxRateBase = 0xa3c0U;
    constexpr uint32_t kTxRateStride = 4U;
    constexpr uint32_t kTxForcedGain = 0xa458U;
    constexpr uint32_t kTxAutoTpc = 0x80e8U;
    constexpr uint32_t kTxInitialAutoTpc = 0xa5000000U;
    constexpr uint32_t kTxAckCtsMask = 0x00003f3fU;
    constexpr uint32_t kTxAckCtsShift = 8U;
    constexpr uint32_t kTxClampedCckWord = 0x11111616U;
    constexpr uint8_t kTxClampedCckLow = 22U;
    constexpr uint8_t kTxClampedCckHigh = 27U;
    constexpr uint8_t kTxClampedCckElevenLow = 17U;
    constexpr uint32_t kTxEpoch = 42U;
    constexpr uint32_t kTxBarBytes = 0xa45cU;
    constexpr uint32_t kTxInitialForcedGain = 99U;
    constexpr uint32_t kTxExpectedPacked = 0x18181818U;
    constexpr uint32_t kTxExpectedPackedCck2 = 0x18180018U;
    constexpr size_t kTxExpectedWrites = 14U;
    constexpr size_t kTxExpectedReads = 15U;
    constexpr size_t kTxHt40RegisterWord = 6U;
    constexpr size_t kTxMixedRateRegisterWord = 10U;
    constexpr size_t kFirstCommittedWrite = 1U;
    constexpr size_t kSecondCommittedWrite = 2U;

    enum class Failure : int
    {
        CckAndHtBase = 1,
        UnsupportedRate = 2,
        AboveLimitHt20 = 3,
        OffRaster = 4,
        Channel14Legacy = 5,
        Channel14HtConflict = 6,
        ValidHt40 = 7,
        InvalidExtension = 8,
        InvalidSynth = 9,
        Ht40OverLimit = 10,
        UnknownBoard = 11,
        ValidCalibratedBoard = 12,
        InteriorCtlZero = 13,
        CtlCoverageMissing = 14,
        TargetOutOfBand = 15,
        CtlOutOfBand = 16,
        CtlOutOfOrder = 17,
        MalformedCtlTable = 18,
        RestoredCtlTable = 19,
        DuplicateCalibrationPier = 20,
        RestoredCalibrationPier = 21,
        PlaceholderMacRejected = 22,
        RestoredMac = 23,
        Cck55Minimum = 24,
        Cck11Minimum = 25,
        Cck55ReverseMinimum = 26,
        Cck11ReverseMinimum = 27,
        Cck12Rates = 28,
        Channel6Calibration = 30,
        TxRatePack = 31,
        TxRateRejected = 32,
        TxGateRejected = 33,
        TxRateReadback = 34,
        TxRateEpochLoss = 35,
        TxRateWriteFailed = 36,
        TxRateReadFailed = 37,
        TxRateHt40Pack = 38,
        TxRateReadMismatch = 39,
        OlpcRegisters = 40,
        OlpcInvalidCandidate = 41,
        OlpcUnauthorized = 42,
        OlpcEpochLost = 43,
        OlpcReadFailed = 44,
        OlpcWriteFailed = 45,
        OlpcReadbackMismatch = 46,
        TxWorkflowSuccessful = 47,
        TxWorkflowUnauthorized = 48,
        TxWorkflowFirstStageFailed = 49,
        TxWorkflowBankFailed = 50,
        TxWorkflowBankReadbackFailed = 51,
        TxWorkflowSourceSnapshot = 52,
        TxWorkflowPreflightBar = 53,
    };

    struct RateFixture
    {
            PowerCandidates candidate {};
            uint8_t halfDbm {};
    };

    struct BoardFixture
    {
            EepromImage image {};
            PowerCandidates output {};
            PowerChannel channel {1U, 0U};
            PowerCeilings ceiling {
                kCtlGroupAll,
                kCeilingHalfDbm,
                kCeilingHalfDbm,
            };
    };

    int verifyInitialRate(RateFixture &fixture)
    {
        auto &candidate = fixture.candidate;
        auto &halfDbm = fixture.halfDbm;
        candidate.controlMhz = kChannelOneMhz;
        candidate.synthMhz = kChannelOneMhz;
        candidate.conductedCeilingHalfDbm = kCeilingHalfDbm;
        candidate.ht20Present = true;
        candidate.cck[0] = kCckTargetHalfDbm;
        candidate.ofdm[0] = kOfdmTargetHalfDbm;
        candidate.ht20[0] = kHtTargetHalfDbm;
        halfDbm = kErasedByte;
        if (candidatePowerForRate(candidate, kCckOneMbitRate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kCckTargetHalfDbm ||
            candidatePowerForRate(candidate, kOfdmRateCode, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kOfdmTargetHalfDbm ||
            candidatePowerForRate(candidate, kHtMcsZeroRate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kHtTargetHalfDbm)
        {
            return 1;
        }

        halfDbm = kErasedByte;
        if (candidatePowerForRate(candidate, kUnsupportedHtRate, false,
                                  halfDbm) != PowerResult::UnsupportedRate ||
            halfDbm != 0 ||
            candidatePowerForRate(candidate, kHtMcsZeroRate, true, halfDbm) !=
                PowerResult::InvalidChannel ||
            halfDbm != 0)
        {
            return 2;
        }
        return 0;
    }

    int verifyCckPreambles(RateFixture &fixture)
    {
        auto &candidate = fixture.candidate;
        auto &halfDbm = fixture.halfDbm;
        // ath9k uses the lower of 1L_5L / 5S for *both* 5.5-Mbps
        // preambles, and the lower of 11L / 11S for *both* 11-Mbps
        // preambles. A public rate selector must not return a higher raw
        // per-preamble EEPROM target than the PHY actually permits.
        candidate.cck[1] = kCckFiveMinimum;
        candidate.cck[2] = kCckElevenMinimum;
        candidate.cck[3] = kRawCckElevenTarget;
        const uint8_t cck55Rates[] {0x19, 0x1d};
        const uint8_t cck11Rates[] {0x18, 0x1c};
        for (const uint8_t rate : cck55Rates)
        {
            if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                    PowerResult::Ok ||
                halfDbm != kCckFiveMinimum)
            {
                return static_cast<int>(Failure::Cck55Minimum);
            }
        }
        for (const uint8_t rate : cck11Rates)
        {
            if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                    PowerResult::Ok ||
                halfDbm != kCckElevenMinimum)
            {
                return static_cast<int>(Failure::Cck11Minimum);
            }
        }
        // Reverse the asymmetric target pairs to test the other minimum
        // direction, while 1/2-Mbps rates still use the original group.
        candidate.cck[0] = kHtTargetHalfDbm;
        candidate.cck[1] = kReverseCckRawTarget;
        candidate.cck[2] = kCtlEdgeHalfDbm;
        candidate.cck[3] = kCckReverseMinimum;
        for (const uint8_t rate : cck55Rates)
        {
            if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                    PowerResult::Ok ||
                halfDbm != kHtTargetHalfDbm)
            {
                return static_cast<int>(Failure::Cck55ReverseMinimum);
            }
        }
        for (const uint8_t rate : cck11Rates)
        {
            if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                    PowerResult::Ok ||
                halfDbm != kCckReverseMinimum)
            {
                return static_cast<int>(Failure::Cck11ReverseMinimum);
            }
        }
        const uint8_t cck12Rates[] {0x1b, 0x1a, 0x1e};
        for (const uint8_t rate : cck12Rates)
        {
            if (candidatePowerForRate(candidate, rate, false, halfDbm) !=
                    PowerResult::Ok ||
                halfDbm != kHtTargetHalfDbm)
            {
                return static_cast<int>(Failure::Cck12Rates);
            }
        }
        candidate.cck[0] = kCckTargetHalfDbm;

        return 0;
    }

    int verifyHtChannels(RateFixture &fixture)
    {
        auto &candidate = fixture.candidate;
        auto &halfDbm = fixture.halfDbm;
        candidate.ht20[0] = kOverCeilingHalfDbm;
        halfDbm = kErasedByte;
        if (candidatePowerForRate(candidate, kHtMcsZeroRate, false, halfDbm) !=
                PowerResult::InvalidCurve ||
            halfDbm != 0)
        {
            return 3;
        }
        candidate.ht20[0] = kHtTargetHalfDbm;
        candidate.controlMhz = kOffRasterMhz; // Invalid 2.4 GHz raster.
        if (candidatePowerForRate(candidate, kOfdmRateCode, false, halfDbm) !=
                PowerResult::InvalidChannel ||
            halfDbm != 0)
        {
            return 4;
        }

        candidate.controlMhz = kChannelFourteenMhz;
        candidate.synthMhz = kChannelFourteenMhz;
        candidate.legacyOnlyChannel14 = true;
        candidate.ht20Present = false;
        if (candidatePowerForRate(candidate, kCckOneMbitRate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kCckTargetHalfDbm ||
            candidatePowerForRate(candidate, kOfdmRateCode, false, halfDbm) !=
                PowerResult::UnsupportedRate ||
            halfDbm != 0 ||
            candidatePowerForRate(candidate, kHtMcsZeroRate, false, halfDbm) !=
                PowerResult::UnsupportedRate ||
            halfDbm != 0)
        {
            return static_cast<int>(Failure::Channel14Legacy);
        }
        candidate.ht20Present = true; // HT on channel 14 is contradictory.
        if (candidatePowerForRate(candidate, kCckOneMbitRate, false, halfDbm) !=
                PowerResult::InvalidCurve ||
            halfDbm != 0)
        {
            return static_cast<int>(Failure::Channel14HtConflict);
        }

        candidate.legacyOnlyChannel14 = false;
        candidate.controlMhz = kChannelOneMhz;
        candidate.extensionMhz = kExtensionMhz;
        candidate.synthMhz = kSynthMhz;
        candidate.ht20Present = true;
        candidate.ht40Present = true;
        candidate.ht40[0] = kCckElevenMinimum;
        if (candidatePowerForRate(candidate, kHtMcsZeroRate, true, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kCckElevenMinimum ||
            candidatePowerForRate(candidate, kHtMcsZeroRate, false, halfDbm) !=
                PowerResult::Ok ||
            halfDbm != kHtTargetHalfDbm)
        {
            return static_cast<int>(Failure::ValidHt40);
        }
        candidate.extensionMhz =
            kInvalidExtensionMhz; // Wrong 30 MHz channel displacement.
        if (candidatePowerForRate(candidate, kHtMcsZeroRate, true, halfDbm) !=
                PowerResult::InvalidChannel ||
            halfDbm != 0)
        {
            return static_cast<int>(Failure::InvalidExtension);
        }
        candidate.extensionMhz = kExtensionMhz;
        candidate.synthMhz = kInvalidSynthMhz; // Contradictory synth center.
        if (candidatePowerForRate(candidate, kHtMcsZeroRate, true, halfDbm) !=
                PowerResult::InvalidChannel ||
            halfDbm != 0)
        {
            return static_cast<int>(Failure::InvalidSynth);
        }
        candidate.synthMhz = kSynthMhz;
        candidate.ht40[0] =
            kOverCeilingHalfDbm; // Above candidate conducted budget.
        if (candidatePowerForRate(candidate, kHtMcsZeroRate, true, halfDbm) !=
                PowerResult::InvalidCurve ||
            halfDbm != 0)
        {
            return static_cast<int>(Failure::Ht40OverLimit);
        }

        return 0;
    }

    int verifyBoardSetup(BoardFixture &fixture)
    {
        auto &image = fixture.image;
        auto &output = fixture.output;
        const auto &channel = fixture.channel;
        const auto &ceiling = fixture.ceiling;
        // An unknown EEPROM image must not leave a stale usable power
        // candidate.
        output.controlMhz = kChannelOneMhz;
        output.cck[0] = kCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidBoard ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
            output.ht20Present || (output.conductedCeilingHalfDbm != 0U))
        {
            return static_cast<int>(Failure::UnknownBoard);
        }

        // Pinned ath9k AR9300 dictionaries carry trailing zero in some 2 GHz
        // CTL edge rows (and 0xff in others). Both are *padding*, not new
        // coverage; construct a synthetic board with explicit, in-range edges.
        image.restored = true;
        image.appliedBlocks = 1;
        image.bytes[0] = 2;
        image.bytes[2] = 0x02;
        image.bytes[3] = kPhysicalMacOne;
        image.bytes[4] = kPhysicalMacTwo;
        image.bytes[kEepromOffset5] = kPhysicalMacThree;
        image.bytes[kEepromOffset6] = kPhysicalMacFour;
        image.bytes[kEepromOffset7] = kPhysicalMacFive;
        image.bytes[kEepromOffset32] = kPhysicalMacOne;
        image.bytes[kEepromPowerTableOffset] = kPowerTableOffsetMinusSix;
        image.bytes[kEepromFeatureEnable] = kTemperatureVoltageFeatures;
        image.bytes[kEepromModalTempSlope] =
            kModalTemperatureSlopeMinusTwentyFour;
        image.bytes[kEepromModalVoltSlope] = kModalVoltageSlopeSeven;
        image.bytes[kEepromOffset33] =
            kPhysicalMacTwo; // 2 GHz, with HT target lookup disabled.
        // A reconstructed AR9565 board has three structurally ordered 2G
        // calibration piers even when this test only evaluates target limits.
        image.bytes[kEepromOffset138] = kCalibrationPierLow;
        image.bytes[kEepromOffset139] = kCalibrationPierMid;
        image.bytes[kEepromOffset140] = kCalibrationPierHigh;
        // Synthetic open-loop chain0 measurements; not actual device
        // calibration.
        image.bytes[kEepromOffset141] =
            kNegativeCorrectionEncoded; // -8 correction.
        image.bytes[kEepromOffset142] = kVoltageReferenceOrOffbandBin;
        image.bytes[kEepromOffset143] = kTemperatureReference;
        image.bytes[kEepromOffset147] = kSecondPierCorrection;
        image.bytes[kEepromOffset148] = kSecondPierVoltage;
        image.bytes[kEepromOffset149] = kSecondPierTemperature;
        image.bytes[kEepromOffset153] = kCtlLimitedHalfDbm;
        image.bytes[kEepromOffset154] = kThirdPierVoltage;
        image.bytes[kEepromOffset155] = kThirdPierTemperature;
        image.bytes[kEepromOffset195] = image.bytes[kEepromOffset197] =
            kCalibrationPierLow;
        image.bytes[kEepromOffset196] = image.bytes[kEepromOffset198] =
            kCalibrationPierMid;
        image.bytes[kEepromOffset199] = kCalibrationPierHigh;
        // Same 20-byte EEPROM power target region, with fixed-size bounds.
        __builtin_memset(&image.bytes[kEepromOffset206], kCtlLimitedHalfDbm,
                         kCtlTargetBytes);
        image.bytes[kEepromOffset310] = kCckCtlMode;  // CCK CTL.
        image.bytes[kEepromOffset311] = kOfdmCtlMode; // OFDM CTL.
        // Two CTL rows with identical pier bins but distinct padding bytes.
        image.bytes[kEepromOffset322] = image.bytes[kEepromOffset326] =
            kCalibrationPierLow;
        image.bytes[kEepromOffset323] = image.bytes[kEepromOffset327] =
            kCalibrationPierMid;
        image.bytes[kEepromOffset324] = image.bytes[kEepromOffset328] =
            kCalibrationPierHigh;
        image.bytes[kEepromOffset325] = 0;
        image.bytes[kEepromOffset329] = kErasedByte;
        __builtin_memset(&image.bytes[kEepromOffset370], kCtlEdgeHalfDbm,
                         kTwoCtlRowEdgeBytes);
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::Ok ||
            output.controlMhz != kChannelOneMhz ||
            output.cck[0] != kCtlLimitedHalfDbm ||
            output.ofdm[0] != kCtlLimitedHalfDbm || output.ht20Present ||
            output.ht40Present ||
            output.conductedCeilingHalfDbm != kCeilingHalfDbm ||
            output.channelCalibration.channelMhz != kChannelOneMhz ||
            output.channelCalibration.referenceCorrection !=
                -kReferenceCorrectionMagnitude ||
            output.channelCalibration.voltageMeasurement !=
                kVoltageReferenceOrOffbandBin ||
            output.channelCalibration.temperatureMeasurement !=
                kTemperatureReference ||
            output.channelCalibration.interpolated ||
            output.txModal.powerTableOffsetDb != kPowerOffsetExpected ||
            output.txModal.temperatureSlope != kTemperatureSlopeExpected ||
            output.txModal.voltageSlope != kVoltageSlopeExpected ||
            output.txModal.featureEnable != kTemperatureVoltageFeatures)
        {
            return static_cast<int>(Failure::ValidCalibratedBoard);
        }

        return 0;
    }

    int verifyCtlEdges(BoardFixture &fixture)
    {
        auto &image = fixture.image;
        auto &output = fixture.output;
        const auto &channel = fixture.channel;
        const auto &ceiling = fixture.ceiling;
        // Zero cannot be an interior bin followed by later live edges; a row
        // with only padding cannot grant CTL coverage at any frequency.
        image.bytes[kEepromOffset323] = 0;
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidCtlEdges ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::InteriorCtlZero);
        }
        image.bytes[kEepromOffset322] = 0;
        image.bytes[kEepromOffset324] = 0;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::MissingCtlCoverage ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::CtlCoverageMissing);
        }

        // An out-of-band target bin is not a usable 2.4 GHz interpolation pier.
        // Restore valid CTL rows so the failure is specifically the target
        // curve.
        image.bytes[kEepromOffset322] = kCalibrationPierLow;
        image.bytes[kEepromOffset323] = kCalibrationPierMid;
        image.bytes[kEepromOffset324] = kCalibrationPierHigh;
        image.bytes[kEepromOffset195] =
            kVoltageReferenceOrOffbandBin; // 2400 MHz, not a 2.4 GHz channel
                                           // center.
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidCurve ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::TargetOutOfBand);
        }
        image.bytes[kEepromOffset195] = kCalibrationPierLow;

        // Out-of-band live CTL bins cannot silently authorize a 2.4 GHz
        // channel.
        image.bytes[kEepromOffset322] = kInvalidCtlBin;
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidCtlEdges ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::CtlOutOfBand);
        }
        image.bytes[kEepromOffset322] = kCalibrationPierLow;
        image.bytes[kEepromOffset323] = kVoltageReferenceOrOffbandBin;
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidCtlEdges ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::CtlOutOfOrder);
        }

        // A later live CTL index after a zero sentinel must fail even when the
        // first two rows cover this request; the rest cannot be ignored.
        image.bytes[kEepromOffset323] = kCalibrationPierMid;
        image.bytes[kEepromOffset313] =
            kCckCtlMode; // Index 312 remains zero (table terminator).
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidCtlIndexes ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U))
        {
            return static_cast<int>(Failure::MalformedCtlTable);
        }
        image.bytes[kEepromOffset313] =
            0; // Legitimate trailing zero padding again.
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::Ok ||
            output.cck[0] != kCtlLimitedHalfDbm ||
            output.ofdm[0] != kCtlLimitedHalfDbm)
        {
            return static_cast<int>(Failure::RestoredCtlTable);
        }

        return 0;
    }

    int verifyBoardIdentity(BoardFixture &fixture)
    {
        auto &image = fixture.image;
        auto &output = fixture.output;
        auto &channel = fixture.channel;
        const auto &ceiling = fixture.ceiling;
        // The board summary can be decoded with corrupted calibration-pier
        // bins, but discovery would refuse to publish it as a selected board.
        // The direct power candidate API must also reject that inconsistent
        // geometry rather than return seemingly usable half-dBm limits.
        image.bytes[kEepromOffset140] =
            kCalibrationPierMid; // Duplicate of the second calibration pier.
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidBoard ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
            (output.ofdm[0] != 0U) || (output.conductedCeilingHalfDbm != 0U))
        {
            return static_cast<int>(Failure::DuplicateCalibrationPier);
        }
        image.bytes[kEepromOffset140] = kCalibrationPierHigh;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::Ok ||
            output.cck[0] != kCtlLimitedHalfDbm ||
            output.ofdm[0] != kCtlLimitedHalfDbm)
        {
            return static_cast<int>(Failure::RestoredCalibrationPier);
        }

        // A reconstruction dictionary's built-in placeholder MAC passes the
        // elementary unicast check, but is not a physical board's identity.
        // The direct numerical planner cannot bypass the gain selector's
        // pinned-template exclusion even when targets/CTL/piers look plausible.
        const std::array<uint8_t, 6U> originalMac {
            {
                image.bytes[2],
                image.bytes[3],
                image.bytes[4],
                image.bytes[5],
                image.bytes[6],
                image.bytes[7],
            },
        };
        const std::array<uint8_t, 6U> referenceMac {
            {
                0x00,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
            },
        };
        __builtin_memcpy(&image.bytes[2], referenceMac.data(),
                         referenceMac.size());
        output.cck[0] = kOverCeilingHalfDbm;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::InvalidBoard ||
            (output.controlMhz != 0U) || (output.cck[0] != 0U) ||
            (output.ofdm[0] != 0U) || (output.conductedCeilingHalfDbm != 0U))
        {
            return static_cast<int>(Failure::PlaceholderMacRejected);
        }
        __builtin_memcpy(&image.bytes[2], originalMac.data(),
                         originalMac.size());
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::Ok ||
            output.cck[0] != kCtlLimitedHalfDbm ||
            output.ofdm[0] != kCtlLimitedHalfDbm)
        {
            return static_cast<int>(Failure::RestoredMac);
        }
        // The same plan carries the calibration piers selected for the actual
        // control channel, not an arbitrary stale source or HT40 synth center.
        channel.primary = kChannelSixNumber;
        if (calculatePowerCandidates(image, channel, ceiling, output) !=
                PowerResult::Ok ||
            output.controlMhz != kChannelSixMhz ||
            output.channelCalibration.channelMhz != kChannelSixMhz ||
            output.channelCalibration.lowerPierMhz != kChannelSixMhz ||
            output.channelCalibration.upperPierMhz != kChannelSixMhz ||
            output.channelCalibration.referenceCorrection !=
                kSecondPierCorrection ||
            output.channelCalibration.voltageMeasurement !=
                kSecondPierVoltage ||
            output.channelCalibration.temperatureMeasurement !=
                kSecondPierTemperature ||
            output.channelCalibration.interpolated)
        {
            return static_cast<int>(Failure::Channel6Calibration);
        }
        return 0;
    }

    struct SimulatedTxRegisters
    {
            std::array<uint32_t, kAr9565RatePowerRegisters> rates {};
            uint32_t forcedGain {kTxInitialForcedGain};
            uint32_t automaticTpc {kTxInitialAutoTpc};
            size_t writes {};
            size_t reads {};
            size_t denyAfterWrites {kTxExpectedWrites + 1U};
            bool failAfterFirstWrite {};
            bool failReadback {};
            bool mismatchReadback {};
    };

    bool fakePermit(void *context, uint64_t epoch)
    {
        const auto &state = *static_cast<SimulatedTxRegisters *>(context);
        return epoch == kTxEpoch && state.writes < state.denyAfterWrites;
    }

    bool fakeRead(void *context, uint32_t offset, uint32_t *value)
    {
        auto &state = *static_cast<SimulatedTxRegisters *>(context);
        ++state.reads;
        if (state.failReadback && offset == kTxRateBase)
        {
            return false;
        }
        if (value == nullptr)
        {
            return false;
        }
        if (offset == kTxForcedGain)
        {
            *value = state.forcedGain;
            return true;
        }
        if (offset == kTxAutoTpc)
        {
            *value = state.automaticTpc;
            return true;
        }
        if (offset >= kTxRateBase &&
            offset <
                kTxRateBase + (kAr9565RatePowerRegisters * kTxRateStride) &&
            ((offset - kTxRateBase) % kTxRateStride == 0))
        {
            *value = state.rates.at((offset - kTxRateBase) / kTxRateStride);
            if (state.mismatchReadback && offset == kTxRateBase)
            {
                *value ^= 1U;
            }
            return true;
        }
        return false;
    }

    bool fakeWrite(void *context, uint32_t offset, uint32_t value)
    {
        auto &state = *static_cast<SimulatedTxRegisters *>(context);
        ++state.writes;
        if (offset == kTxForcedGain)
        {
            state.forcedGain = value;
        }
        else if (offset == kTxAutoTpc)
        {
            state.automaticTpc = value;
        }
        else if (offset >= kTxRateBase &&
                 offset < kTxRateBase +
                              (kAr9565RatePowerRegisters * kTxRateStride) &&
                 ((offset - kTxRateBase) % kTxRateStride == 0))
        {
            state.rates.at((offset - kTxRateBase) / kTxRateStride) = value;
        }
        else
        {
            return false;
        }
        return !state.failAfterFirstWrite ||
               state.writes != kFirstCommittedWrite;
    }

    int verifyTxRateProgramming(const BoardFixture &fixture)
    {
        const auto &candidate = fixture.output;
        TxPowerRegisterImage registerImage {};
        if (makeAr9565TxRateRegisters(candidate, registerImage) !=
                TxPowerProgramResult::Ok ||
            registerImage.words[0] != kTxExpectedPacked ||
            registerImage.words[2] != kTxExpectedPackedCck2 ||
            registerImage.words[4] != 0U ||
            registerImage.words[kTxHt40RegisterWord] != 0U ||
            registerImage.ackCtsHalfDbm != kCtlLimitedHalfDbm)
        {
            return static_cast<int>(Failure::TxRatePack);
        }
        PowerCandidates unequal = candidate;
        unequal.cck[0] = kTxClampedCckLow;
        unequal.cck[1] = kTxClampedCckHigh;
        unequal.cck[2] = kTxClampedCckHigh;
        unequal.cck[3] = kTxClampedCckElevenLow;
        if (makeAr9565TxRateRegisters(unequal, registerImage) !=
                TxPowerProgramResult::Ok ||
            registerImage.words[3] != kTxClampedCckWord)
        {
            return static_cast<int>(Failure::TxRatePack);
        }
        PowerCandidates ht40 = candidate;
        ht40.ht20Present = true;
        ht40.ht40Present = true;
        ht40.extensionMhz = kExtensionMhz;
        ht40.synthMhz = kSynthMhz;
        uint8_t nextGroupPower = 1U;
        for (uint8_t &power : ht40.ht20)
        {
            power = nextGroupPower++;
        }
        nextGroupPower = 2U;
        for (uint8_t &power : ht40.ht40)
        {
            power = nextGroupPower++;
        }
        constexpr uint32_t kPackedHt20First = 0x04030201U;
        constexpr uint32_t kPackedHt40First = 0x05040302U;
        constexpr uint32_t kPackedHtMixedLast = 0x0f0e0e0dU;
        if (makeAr9565TxRateRegisters(ht40, registerImage) !=
                TxPowerProgramResult::Ok ||
            registerImage.words[4] != kPackedHt20First ||
            registerImage.words[kTxHt40RegisterWord] != kPackedHt40First ||
            registerImage.words[kTxMixedRateRegisterWord] != kPackedHtMixedLast)
        {
            return static_cast<int>(Failure::TxRateHt40Pack);
        }
        PowerCandidates bad = candidate;
        bad.cck[0] = kOverCeilingHalfDbm;
        registerImage.words[0] = kTxExpectedPacked;
        if (makeAr9565TxRateRegisters(bad, registerImage) !=
                TxPowerProgramResult::InvalidCandidate ||
            registerImage.words[0] != 0U)
        {
            return static_cast<int>(Failure::TxRateRejected);
        }

        SimulatedTxRegisters state {};
        const TxPowerBackend backend {
            &state, kTxEpoch, kTxBarBytes, fakePermit, fakeWrite, fakeRead,
        };
        CalibrationAndRegulatory authority {};
        authority.use = RadioInitialization::TransmitReceive;
        if (programAr9565TxRateRegisters(candidate, authority, backend)
                    .result != TxPowerProgramResult::MissingAuthorization ||
            state.writes != 0U)
        {
            return static_cast<int>(Failure::TxGateRejected);
        }
        authority.eepromContentsVerified = true;
        authority.boardAntennaConfigurationVerified = true;
        authority.localCountryRulesAvailable = true;
        authority.channelPermitted = true;
        authority.txPowerLimitsVerified = true;
        authority.radioKillUnblocked = true;
        authority.coexistenceConfigurationVerified = true;
        const auto completed =
            programAr9565TxRateRegisters(candidate, authority, backend);
        const uint32_t expectedAckCts =
            static_cast<uint32_t>(kCtlLimitedHalfDbm) |
            (static_cast<uint32_t>(kCtlLimitedHalfDbm) << kTxAckCtsShift);
        if (completed.result != TxPowerProgramResult::Ok ||
            completed.requiresReset ||
            completed.completedWrites != kTxExpectedWrites ||
            completed.completedReads != kTxExpectedReads ||
            state.forcedGain != 0U || state.rates.at(0U) != kTxExpectedPacked ||
            (state.automaticTpc & kTxAckCtsMask) != expectedAckCts ||
            (state.automaticTpc & ~kTxAckCtsMask) != kTxInitialAutoTpc)
        {
            return static_cast<int>(Failure::TxRateReadback);
        }
        state = {};
        state.denyAfterWrites = kFirstCommittedWrite;
        const auto revoked =
            programAr9565TxRateRegisters(candidate, authority, backend);
        if (revoked.result != TxPowerProgramResult::OwnershipLost ||
            !revoked.requiresReset ||
            revoked.completedWrites != kFirstCommittedWrite)
        {
            return static_cast<int>(Failure::TxRateEpochLoss);
        }
        state = {};
        state.failAfterFirstWrite = true;
        const auto failed =
            programAr9565TxRateRegisters(candidate, authority, backend);
        if (failed.result != TxPowerProgramResult::WriteFailed ||
            !failed.requiresReset || failed.completedWrites != 0U ||
            state.writes != kFirstCommittedWrite)
        {
            return static_cast<int>(Failure::TxRateWriteFailed);
        }
        state = {};
        state.failReadback = true;
        const auto badRead =
            programAr9565TxRateRegisters(candidate, authority, backend);
        if (badRead.result != TxPowerProgramResult::ReadFailed ||
            !badRead.requiresReset ||
            badRead.completedWrites != kSecondCommittedWrite)
        {
            return static_cast<int>(Failure::TxRateReadFailed);
        }
        state = {};
        state.mismatchReadback = true;
        const auto mismatch =
            programAr9565TxRateRegisters(candidate, authority, backend);
        if (mismatch.result != TxPowerProgramResult::ReadbackMismatch ||
            !mismatch.requiresReset ||
            mismatch.completedWrites != kSecondCommittedWrite)
        {
            return static_cast<int>(Failure::TxRateReadMismatch);
        }
        return 0;
    }

    // Four real AR9565 chain-zero TPC register offsets from ath9k's
    // ar9003_hw_power_control_override() and AR_SM_BASE (0xa200).
    constexpr std::array<uint32_t, 4> kOlpcOffsets {
        0xa420U,
        0xa40cU,
        0xa440U,
        0xa43cU,
    };
    constexpr std::array<uint32_t, 4> kOlpcOriginal {
        0xa5001234U,
        0xc0102030U,
        0xab112233U,
        0xbeef2211U,
    };
    constexpr std::array<uint32_t, 4> kOlpcExpected {
        0xa5f81234U,
        0xc3102030U,
        0xab1122e8U,
        0xbeef2228U,
    };
    constexpr int16_t kOlpcOutOfRangeCorrection = -129;
    constexpr size_t kOlpcWrites = 4U;
    constexpr size_t kOlpcReads = 8U;

    struct OlpcRegisters
    {
            std::array<uint32_t, 4> values {kOlpcOriginal};
            size_t reads {};
            size_t writes {};
            size_t denyAfterWrites {kOlpcWrites + 1U};
            bool failFirstRead {};
            bool failFirstWrite {};
            bool alterReadback {};
    };

    bool olpcPermit(void *context, uint64_t epoch)
    {
        const auto &state = *static_cast<OlpcRegisters *>(context);
        return epoch == kTxEpoch && state.writes < state.denyAfterWrites;
    }

    bool olpcRead(void *context, uint32_t offset, uint32_t *value)
    {
        auto &state = *static_cast<OlpcRegisters *>(context);
        ++state.reads;
        if (state.failFirstRead && state.reads == 1U)
        {
            return false;
        }
        if (value == nullptr)
        {
            return false;
        }
        for (size_t index = 0; index < kOlpcOffsets.size(); ++index)
        {
            if (offset == kOlpcOffsets.at(index))
            {
                *value = state.values.at(index);
                if (state.alterReadback && state.reads == 2U)
                {
                    *value ^= 1U;
                }
                return true;
            }
        }
        return false;
    }

    // Required fixed order by TxPowerBackend's native MMIO callback ABI.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool olpcWrite(void *context, uint32_t offset, uint32_t value)
    {
        auto &state = *static_cast<OlpcRegisters *>(context);
        ++state.writes;
        for (size_t index = 0; index < kOlpcOffsets.size(); ++index)
        {
            if (offset == kOlpcOffsets.at(index))
            {
                state.values.at(index) = value;
                return !state.failFirstWrite || state.writes != 1U;
            }
        }
        return false;
    }

    int verifyOpenLoopCalibration(const BoardFixture &fixture)
    {
        const PowerCandidates &candidate = fixture.output;
        OlpcRegisters fake {};
        const TxPowerBackend backend {
            &fake, kTxEpoch, kTxBarBytes, olpcPermit, olpcWrite, olpcRead,
        };
        CalibrationAndRegulatory authority {};
        authority.use = RadioInitialization::TransmitReceive;
        if (programAr9565TxOpenLoopCalibration(candidate, authority, backend)
                    .result != TxPowerProgramResult::MissingAuthorization ||
            fake.writes != 0U || fake.reads != 0U)
        {
            return static_cast<int>(Failure::OlpcUnauthorized);
        }
        authority.eepromContentsVerified = true;
        authority.boardAntennaConfigurationVerified = true;
        authority.localCountryRulesAvailable = true;
        authority.channelPermitted = true;
        authority.txPowerLimitsVerified = true;
        authority.radioKillUnblocked = true;
        authority.coexistenceConfigurationVerified = true;
        const auto valid =
            programAr9565TxOpenLoopCalibration(candidate, authority, backend);
        if (valid.result != TxPowerProgramResult::Ok || valid.requiresReset ||
            valid.completedWrites != kOlpcWrites ||
            valid.completedReads != kOlpcReads ||
            fake.values != kOlpcExpected || fake.writes != kOlpcWrites)
        {
            return static_cast<int>(Failure::OlpcRegisters);
        }
        auto invalid = candidate;
        invalid.channelCalibration.channelMhz = kChannelSixMhz;
        fake = {};
        if (programAr9565TxOpenLoopCalibration(invalid, authority, backend)
                    .result != TxPowerProgramResult::InvalidCandidate ||
            fake.writes != 0U || fake.reads != 0U)
        {
            return static_cast<int>(Failure::OlpcInvalidCandidate);
        }
        invalid = candidate;
        invalid.channelCalibration.referenceCorrection =
            kOlpcOutOfRangeCorrection;
        if (programAr9565TxOpenLoopCalibration(invalid, authority, backend)
                    .result != TxPowerProgramResult::InvalidCandidate ||
            fake.writes != 0U)
        {
            return static_cast<int>(Failure::OlpcInvalidCandidate);
        }
        invalid = candidate;
        invalid.channelCalibration.lowerPierMhz = kChannelFourteenMhz;
        invalid.channelCalibration.upperPierMhz = kChannelOneMhz;
        if (programAr9565TxOpenLoopCalibration(invalid, authority, backend)
                    .result != TxPowerProgramResult::InvalidCandidate ||
            fake.writes != 0U)
        {
            return static_cast<int>(Failure::OlpcInvalidCandidate);
        }
        TxPowerBackend badBar = backend;
        badBar.barLengthBytes = kOlpcOffsets.at(2U) + 3U;
        if (programAr9565TxOpenLoopCalibration(candidate, authority, badBar)
                    .result != TxPowerProgramResult::InvalidBar ||
            fake.writes != 0U)
        {
            return static_cast<int>(Failure::OlpcInvalidCandidate);
        }
        fake.denyAfterWrites = 1U;
        const auto revoked =
            programAr9565TxOpenLoopCalibration(candidate, authority, backend);
        if (revoked.result != TxPowerProgramResult::OwnershipLost ||
            !revoked.requiresReset || revoked.completedWrites != 1U ||
            fake.writes != 1U)
        {
            return static_cast<int>(Failure::OlpcEpochLost);
        }
        fake = {};
        fake.failFirstRead = true;
        const auto unreadable =
            programAr9565TxOpenLoopCalibration(candidate, authority, backend);
        if (unreadable.result != TxPowerProgramResult::ReadFailed ||
            unreadable.requiresReset || fake.writes != 0U)
        {
            return static_cast<int>(Failure::OlpcReadFailed);
        }
        fake = {};
        fake.failFirstWrite = true;
        const auto failed =
            programAr9565TxOpenLoopCalibration(candidate, authority, backend);
        if (failed.result != TxPowerProgramResult::WriteFailed ||
            !failed.requiresReset || fake.writes != 1U)
        {
            return static_cast<int>(Failure::OlpcWriteFailed);
        }
        fake = {};
        fake.alterReadback = true;
        const auto mismatch =
            programAr9565TxOpenLoopCalibration(candidate, authority, backend);
        if (mismatch.result != TxPowerProgramResult::ReadbackMismatch ||
            !mismatch.requiresReset || fake.writes != 1U)
        {
            return static_cast<int>(Failure::OlpcReadbackMismatch);
        }
        return 0;
    }

    struct CombinedPowerRegisters
    {
            OlpcRegisters olpc {};
            SimulatedTxRegisters rateBank {};
            PowerCandidates *borrowedCandidate {};
    };

    bool combinedPowerPermit(void *context, uint64_t epoch)
    {
        auto &state = *static_cast<CombinedPowerRegisters *>(context);
        return olpcPermit(&state.olpc, epoch) &&
               fakePermit(&state.rateBank, epoch);
    }

    bool combinedPowerRead(void *context, uint32_t offset, uint32_t *value)
    {
        auto &state = *static_cast<CombinedPowerRegisters *>(context);
        for (const auto candidate : kOlpcOffsets)
        {
            if (offset == candidate)
            {
                return olpcRead(&state.olpc, offset, value);
            }
        }
        return fakeRead(&state.rateBank, offset, value);
    }

    // Fixed TxPowerBackend hardware callback argument order.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bool combinedPowerWrite(void *context, uint32_t offset, uint32_t value)
    {
        auto &state = *static_cast<CombinedPowerRegisters *>(context);
        for (const auto candidate : kOlpcOffsets)
        {
            if (offset == candidate)
            {
                const bool wrote = olpcWrite(&state.olpc, offset, value);
                if (wrote && state.olpc.writes == kOlpcWrites &&
                    state.borrowedCandidate != nullptr)
                {
                    // Simulate a caller changing the borrowed candidate
                    // between the OLPC and rate-bank stages. The workflow
                    // must retain its original immutable transaction value.
                    state.borrowedCandidate->cck[0] = kOverCeilingHalfDbm;
                }
                return wrote;
            }
        }
        return fakeWrite(&state.rateBank, offset, value);
    }

    int verifyCombinedTxPower(const BoardFixture &fixture)
    {
        CombinedPowerRegisters fake {};
        const TxPowerBackend backend {
            &fake,
            kTxEpoch,
            kTxBarBytes,
            combinedPowerPermit,
            combinedPowerWrite,
            combinedPowerRead,
        };
        CalibrationAndRegulatory authority {};
        authority.use = RadioInitialization::TransmitReceive;
        auto progress =
            programAr9565TransmitPower(fixture.output, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::OpenLoop ||
            progress.openLoop.result !=
                TxPowerProgramResult::MissingAuthorization ||
            progress.requiresReset || fake.olpc.writes != 0U ||
            fake.rateBank.writes != 0U)
        {
            return static_cast<int>(Failure::TxWorkflowUnauthorized);
        }
        // This BAR fits every OLPC register but not the higher forced-gain
        // rate-bank register. The *combined* preflight must write nothing.
        TxPowerBackend shortBar = backend;
        shortBar.barLengthBytes = kTxForcedGain;
        const auto preflight =
            programAr9565TransmitPower(fixture.output, authority, shortBar);
        if (preflight.phase != TxPowerWorkflowPhase::OpenLoop ||
            preflight.openLoop.result !=
                TxPowerProgramResult::MissingAuthorization ||
            preflight.requiresReset || fake.olpc.writes != 0U ||
            fake.rateBank.writes != 0U)
        {
            return static_cast<int>(Failure::TxWorkflowUnauthorized);
        }
        authority.eepromContentsVerified = true;
        authority.boardAntennaConfigurationVerified = true;
        authority.localCountryRulesAvailable = true;
        authority.channelPermitted = true;
        authority.txPowerLimitsVerified = true;
        authority.radioKillUnblocked = true;
        authority.coexistenceConfigurationVerified = true;
        const auto rejectedBar =
            programAr9565TransmitPower(fixture.output, authority, shortBar);
        if (rejectedBar.phase != TxPowerWorkflowPhase::OpenLoop ||
            rejectedBar.openLoop.result != TxPowerProgramResult::InvalidBar ||
            rejectedBar.requiresReset || fake.olpc.writes != 0U ||
            fake.rateBank.writes != 0U)
        {
            return static_cast<int>(Failure::TxWorkflowPreflightBar);
        }
        progress =
            programAr9565TransmitPower(fixture.output, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::Completed ||
            progress.openLoop.result != TxPowerProgramResult::Ok ||
            progress.rateBank.result != TxPowerProgramResult::Ok ||
            progress.requiresReset ||
            progress.openLoop.completedWrites != kOlpcWrites ||
            progress.rateBank.completedWrites != kTxExpectedWrites ||
            fake.olpc.values != kOlpcExpected ||
            fake.rateBank.rates.at(0U) != kTxExpectedPacked)
        {
            return static_cast<int>(Failure::TxWorkflowSuccessful);
        }
        fake = {};
        PowerCandidates changedCandidate = fixture.output;
        fake.borrowedCandidate = &changedCandidate;
        progress =
            programAr9565TransmitPower(changedCandidate, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::Completed ||
            progress.rateBank.result != TxPowerProgramResult::Ok ||
            progress.requiresReset ||
            changedCandidate.cck[0] != kOverCeilingHalfDbm ||
            fake.rateBank.rates.at(2U) != kTxExpectedPackedCck2)
        {
            return static_cast<int>(Failure::TxWorkflowSourceSnapshot);
        }
        fake = {};
        fake.olpc.failFirstWrite = true;
        progress =
            programAr9565TransmitPower(fixture.output, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::OpenLoop ||
            progress.openLoop.result != TxPowerProgramResult::WriteFailed ||
            !progress.requiresReset || fake.olpc.writes != 1U ||
            fake.rateBank.writes != 0U)
        {
            return static_cast<int>(Failure::TxWorkflowFirstStageFailed);
        }
        fake = {};
        fake.rateBank.failAfterFirstWrite = true;
        progress =
            programAr9565TransmitPower(fixture.output, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::RateBank ||
            progress.openLoop.result != TxPowerProgramResult::Ok ||
            progress.rateBank.result != TxPowerProgramResult::WriteFailed ||
            !progress.requiresReset || fake.olpc.writes != kOlpcWrites ||
            fake.rateBank.writes != 1U)
        {
            return static_cast<int>(Failure::TxWorkflowBankFailed);
        }
        fake = {};
        fake.rateBank.mismatchReadback = true;
        progress =
            programAr9565TransmitPower(fixture.output, authority, backend);
        if (progress.phase != TxPowerWorkflowPhase::RateBank ||
            progress.openLoop.result != TxPowerProgramResult::Ok ||
            progress.rateBank.result !=
                TxPowerProgramResult::ReadbackMismatch ||
            !progress.requiresReset || fake.olpc.writes != kOlpcWrites ||
            fake.rateBank.writes != kSecondCommittedWrite)
        {
            return static_cast<int>(Failure::TxWorkflowBankReadbackFailed);
        }
        return 0;
    }

} // namespace

int main()
{
    RateFixture rates {};
    BoardFixture board {};
    if (const int failure = verifyInitialRate(rates))
    {
        return failure;
    }
    if (const int failure = verifyCckPreambles(rates))
    {
        return failure;
    }
    if (const int failure = verifyHtChannels(rates))
    {
        return failure;
    }
    if (const int failure = verifyBoardSetup(board))
    {
        return failure;
    }
    if (const int failure = verifyTxRateProgramming(board))
    {
        return failure;
    }
    if (const int failure = verifyOpenLoopCalibration(board))
    {
        return failure;
    }
    if (const int failure = verifyCombinedTxPower(board))
    {
        return failure;
    }
    if (const int failure = verifyCtlEdges(board))
    {
        return failure;
    }
    return verifyBoardIdentity(board);
}
