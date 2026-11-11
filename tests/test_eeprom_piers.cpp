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
//   - Offline regression cases for eeprom piers.
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
//   - Offline regression cases for eeprom piers.
// - Description:
//   - Implements or verifies the test_eeprom_piers source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for eeprom piers.
// Synthetic packed EEPROM image; never sourced from hardware or RF.
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565InitCatalog.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    using namespace simpleath;

    // Pinned source-only EEPROM offsets and synthetic calibration values.
    constexpr auto kBelowBandBin = 111;
    constexpr auto kBelowBandMhz = 2411;
    constexpr auto kBorrowedFrameBytes = 1120U;
    constexpr auto kBorrowedFrameOffset = 8U;
    constexpr auto kBorrowedImageSentinel = 0x77;
    constexpr auto kBorrowedPayloadCheckOffset = 14U;
    constexpr auto kByteSix = 6;
    constexpr auto kChangedChecksumByte = 0x21;
    constexpr auto kChangedTemplateReference = 0x63;
    constexpr auto kDeltaFrameBytes = 9;
    constexpr auto kDeltaHeader = 0x62;
    constexpr auto kDeltaMutationOffset = 5U;
    constexpr auto kDeltaPayloadIndex = 6U;
    constexpr auto kDeltaPayloadLastByte = 0x23;
    constexpr auto kDeltaSizeCode = 0x30;
    constexpr auto kEepromByte138 = 138;
    constexpr auto kEepromByte139 = 139;
    constexpr auto kEepromByte140 = 140;
    constexpr auto kEepromByte141 = 141;
    constexpr auto kEepromByte142 = 142;
    constexpr auto kEepromByte143 = 143;
    constexpr auto kEepromByte144 = 144;
    constexpr auto kEepromByte145 = 145;
    constexpr auto kEepromByte146 = 146;
    constexpr auto kEepromByte147 = 147;
    constexpr auto kEepromByte148 = 148;
    constexpr auto kEepromByte149 = 149;
    constexpr auto kEepromByte150 = 150;
    constexpr auto kEepromByte151 = 151;
    constexpr auto kEepromByte152 = 152;
    constexpr auto kEepromByte153 = 153;
    constexpr auto kEepromByte154 = 154;
    constexpr auto kEepromByte155 = 155;
    constexpr auto kEepromByte156 = 156;
    constexpr auto kEepromByte157 = 157;
    constexpr auto kEepromByte158 = 158;
    constexpr auto kEepromByte32 = 32;
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
    constexpr auto kInvalidSlopeSentinel = 45;
    constexpr auto kEepromByte33 = 33;
    constexpr auto kEepromByte5 = 5;
    constexpr auto kEepromByte6 = 6;
    constexpr auto kEepromByte7 = 7;
    constexpr auto kEepromByte99 = 99;
    constexpr auto kEepromOrigin = 0x3ff;
    constexpr auto kErasedByte = 0xff;
    constexpr auto kFifthMacByte = 0x55;
    constexpr auto kFourthMacByte = 0x44;
    constexpr auto kHighCorrectionMagnitude = 128;
    constexpr auto kHighCorrectionMinus128 = 0x80;
    constexpr auto kHighMhz = 2462;
    constexpr auto kHighPierBin = 162;
    constexpr auto kHighTemperature = 10;
    constexpr auto kHighVoltage = 130;
    constexpr auto kInitialUnsafeInfo = 91;
    constexpr auto kInterpolatedCorrection = 46;
    constexpr auto kInterpolatedMhz = 2422;
    constexpr auto kInterpolatedTemperature = 38;
    constexpr auto kInterpolatedVoltage = 92;
    constexpr auto kLateFrameBytes = 300U;
    constexpr auto kLowCorrectionMagnitude = 8;
    constexpr auto kLowMhz = 2412;
    constexpr auto kLowPierBin = 112;
    constexpr auto kLowTemperature = 40;
    constexpr auto kLowVoltage = 100;
    constexpr auto kMacOrChainMask = 0x11;
    constexpr auto kMaliciousMutationByte = 0x99;
    constexpr auto kMetadataSentinel = 99;
    constexpr auto kMidCorrection = 127;
    constexpr auto kMidMhz = 2437;
    constexpr auto kMidPierBin = 137;
    constexpr auto kMidTemperature = 36;
    constexpr auto kMidVoltage = 80;
    constexpr auto kMismatchedMiddleBin = 113;
    constexpr auto kMismatchedMiddleMhz = 2438;
    constexpr auto kMismatchedUpperMhz = 2483;
    constexpr auto kMutatedByteIndex = 5;
    constexpr auto kNoiseCalibrationMagnitude = 90;
    constexpr auto kNoiseCalibrationMinusNinety = 0xa6;
    constexpr auto kNoiseCorrectionMinusTwo = 0xfe;
    constexpr auto kNoisePowerMagnitude = 93;
    constexpr auto kNoisePowerMinusNinetyThree = 0xa3;
    constexpr auto kOffRasterMhz = 2421;
    constexpr auto kScratchSentinel = 0xa5;
    constexpr auto kSignedCorrectionMinusEight = 0xf8;
    constexpr auto kStorageBytes = 1024U;
    constexpr auto kSyntheticMacOrDeltaByte = 0x22;
    constexpr auto kTemplateReferenceOffset = 7U;
    constexpr auto kThirdMacByte = 0x33;
    constexpr auto kUnsupportedFiveGhz = 5180;
    constexpr auto kUntrustedImageSentinel = 0x7e;
    constexpr auto kUpperEdgeBin = 184;
    constexpr auto kUpperEdgeMhz = 2484;

    enum class Failure : int
    {
        Summary = 1,
        PierMeasurements = 2,
        GainProfile = 3,
        DuplicatePier = 4,
        UpperEdgePier = 5,
        ImageAlias = 6,
        BlockInfoAlias = 7,
        ScratchAlias = 8,
        StatusAlias = 9,
        InvalidImageVersion = 10,
        UninitializedGain = 11,
        MulticastMac = 12,
        UnsupportedChain = 13,
        UnsupportedBand = 14,
        UnsupportedVersion = 15,
        MutableDeltaAlias = 16,
        CallbackTableAlias = 17,
        DumpInputAlias = 18,
        DumpTableAlias = 19,
        BorrowedTemplateAlias = 20,
        InvalidPierProfile = 21,
        GenericTemplateMac = 22,
        ForgedPierSummary = 23,
        BadLowerPier = 24,
        BadMiddlePier = 25,
        BadUpperPier = 26,
        ValidGainRecovery = 27,
        LateMutationLength = 28,
        LateMutationChecksum = 29,
        LateMutationReference = 30,
        MetadataReferenceMutation = 31,
        MetadataBlockMutation = 32,
        LowCalibration = 33,
        InterpolatedCalibration = 34,
        MiddleCalibration = 35,
        UpperCalibration = 36,
        UnsupportedCalibrationChannel = 37,
        InvalidCalibrationGeometry = 38,
        InvalidCalibrationIdentity = 39,
        InvalidTxModal = 40,
        InvalidTxModalIdentity = 41,
    };

    struct BorrowedTemplateReturn
    {
            const uint8_t *base;
    };

    const uint8_t *borrowedTemplateLookup(void *context, uint8_t /*unused*/,
                                          size_t *length)
    {
        if ((context == nullptr) || (length == nullptr))
        {
            return nullptr;
        }
        *length = simpleath::kAr9300EepromImageBytes;
        return static_cast<BorrowedTemplateReturn *>(context)->base;
    }

    struct PostValidationMutation
    {
            std::array<uint8_t, kLateFrameBytes> *frame {};
            unsigned calls = 0;
            unsigned changedByte = kMutatedByteIndex;
            uint8_t changedValue = kErasedByte;
    };

    const uint8_t *lateMutatingTemplateLookup(void *context, uint8_t reference,
                                              size_t *length)
    {
        auto &mutation = *static_cast<PostValidationMutation *>(context);
        ++mutation.calls;
        // Broken provider rewrites the separately borrowed frame, even
        // though its own callback context does not alias the frame.
        mutation.frame->at(mutation.changedByte) = mutation.changedValue;
        return simpleath::pinnedEepromTemplates().find(nullptr, reference,
                                                       length);
    }

    struct OutputMetadataMutation
    {
            simpleath::EepromBlockInfo *info {};
            simpleath::EepromImage *image {};
            bool mutateReference {};
            unsigned calls = 0;
    };

    const uint8_t *metadataMutatingTemplateLookup(void *context,
                                                  uint8_t reference,
                                                  size_t *length)
    {
        auto &mutation = *static_cast<OutputMetadataMutation *>(context);
        ++mutation.calls;
        if (mutation.mutateReference)
        {
            mutation.info->reference = 3;
            return simpleath::pinnedEepromTemplates().find(nullptr, 3, length);
        }
        mutation.image->appliedBlocks = kMetadataSentinel;
        return simpleath::pinnedEepromTemplates().find(nullptr, reference,
                                                       length);
    }

    const uint8_t *mutatingTemplateLookup(void *context, uint8_t reference,
                                          size_t *length)
    {
        // A provider legitimately mutates its own context, which the caller
        // has forged to refer to a checksum-verified input delta frame.
        auto &borrowedFrame =
            *static_cast<std::array<uint8_t, kDeltaFrameBytes> *>(context);
        borrowedFrame.at(kDeltaPayloadIndex) = kMaliciousMutationByte;
        return simpleath::pinnedEepromTemplates().find(nullptr, reference,
                                                       length);
    }

    struct Fixture
    {
            EepromImage image {};
            BoardDataSummary board {};
            TxGainProfile tx {TxGainProfile::Unknown};
            RxGainProfile rx {RxGainProfile::Unknown};
            EepromTemplates templates {};
            EepromBlockInfo blockInfo {};
            std::array<uint8_t, kStorageBytes> storage {};
            std::array<uint8_t, kAr9565EepromScratchBytes> scratch {};
            EepromRestoreStatus restoreStatus {};
    };

    int verifyPierGeometry(Fixture &fixture)
    {
        auto &image = fixture.image;
        auto &board = fixture.board;
        auto &tx = fixture.tx;
        auto &rx = fixture.rx;
        image.restored = true;
        image.appliedBlocks = 1;
        image.bytes[0] = 2; // Supported AR9300 image format.
        image.bytes[1] = 3; // Informational template-version marker only.
        image.bytes[2] =
            0x02; // Permanent unicast MAC, not a real board address.
        image.bytes[3] = kMacOrChainMask;
        image.bytes[4] = kSyntheticMacOrDeltaByte;
        image.bytes[kEepromByte5] = kThirdMacByte;
        image.bytes[kEepromByte6] = kFourthMacByte;
        image.bytes[kEepromByte7] = kFifthMacByte;
        image.bytes[kEepromByte32] =
            kMacOrChainMask; // Single AR9565 transmit/receive chain.
        image.bytes[kEepromByte33] = 0x02; // Supported 2.4-GHz operation flag.
        image.bytes[kEepromPowerTableOffset] = kPowerTableOffsetMinusSix;
        image.bytes[kEepromFeatureEnable] = kTemperatureVoltageFeatures;
        image.bytes[kEepromModalTempSlope] =
            kModalTemperatureSlopeMinusTwentyFour;
        image.bytes[kEepromModalVoltSlope] = kModalVoltageSlopeSeven;
        image.bytes[kEepromByte99] =
            kErasedByte; // Negative antenna-gain diagnostic.

        // ath9k packed op-loop chain0: 3 frequency bins at offset 138 and
        // six bytes per pier at offset 141; all values are deliberately
        // synthetic.
        image.bytes[kEepromByte138] = kLowPierBin;  // 2412 MHz.
        image.bytes[kEepromByte139] = kMidPierBin;  // 2437 MHz.
        image.bytes[kEepromByte140] = kHighPierBin; // 2462 MHz.
        image.bytes[kEepromByte141] =
            kSignedCorrectionMinusEight; // signed reference correction: -8.
        image.bytes[kEepromByte142] = kLowVoltage;     // voltage.
        image.bytes[kEepromByte143] = kLowTemperature; // temperature.
        image.bytes[kEepromByte144] =
            kNoiseCalibrationMinusNinety; // signed raw noise calibration: -90.
        image.bytes[kEepromByte145] =
            kNoisePowerMinusNinetyThree; // signed raw noise power: -93.
        image.bytes[kEepromByte146] =
            0; // zero rxTempMeas disables noise measurements.
        image.bytes[kEepromByte147] = kMidCorrection;
        image.bytes[kEepromByte148] = kMidVoltage;
        image.bytes[kEepromByte149] = kMidTemperature;
        image.bytes[kEepromByte150] =
            kNoiseCorrectionMinusTwo;       // signed noise calibration: -2.
        image.bytes[kEepromByte151] = 0x02; // signed noise power: 2.
        image.bytes[kEepromByte152] = 1;
        image.bytes[kEepromByte153] =
            kHighCorrectionMinus128; // signed correction: -128.
        image.bytes[kEepromByte154] = kHighVoltage;
        image.bytes[kEepromByte155] = kHighTemperature;
        image.bytes[kEepromByte156] = 0;
        image.bytes[kEepromByte157] = 0;
        image.bytes[kEepromByte158] = 2;

        if (summarizeBoardData(image, board) != EepromResult::Ok ||
            board.eepromVersion != 2 || board.templateVersion != 3 ||
            !board.calibrationPierBinsPlausible || board.antennaGainDb != -1 ||
            board.calibrationValidated || board.regulatoryAuthorized)
        {
            return 1;
        }
        const auto &first = board.calibrationPiers2G[0];
        const auto &second = board.calibrationPiers2G[1];
        const auto &third = board.calibrationPiers2G[2];
        if (first.frequencyBin != kLowPierBin || first.centerMhz != kLowMhz ||
            first.referencePower != -kLowCorrectionMagnitude ||
            first.voltageMeasurement != kLowVoltage ||
            first.temperatureMeasurement != kLowTemperature ||
            first.noiseFloorCalibrationRaw != -kNoiseCalibrationMagnitude ||
            first.noiseFloorPowerRaw != -kNoisePowerMagnitude ||
            first.noiseTemperatureMeasurement != 0 ||
            first.noiseMeasurementsPresent ||
            second.frequencyBin != kMidPierBin || second.centerMhz != kMidMhz ||
            second.referencePower != kMidCorrection ||
            second.noiseFloorCalibrationRaw != -2 ||
            second.noiseFloorPowerRaw != 2 ||
            !second.noiseMeasurementsPresent ||
            third.frequencyBin != kHighPierBin || third.centerMhz != kHighMhz ||
            third.referencePower != -kHighCorrectionMagnitude ||
            !third.noiseMeasurementsPresent)
        {
            return 2;
        }

        if (selectBoardGainProfiles(board, tx, rx) != EepromResult::Ok ||
            tx != TxGainProfile::LowOb || rx != RxGainProfile::Standard ||
            board.calibrationValidated || board.regulatoryAuthorized)
        {
            return 3;
        }

        // Bad frequency geometry remains readable as *diagnostics* but never
        // confers calibration/readiness. Both outputs reset on ordinary
        // failures.
        image.bytes[kEepromByte140] = kMidPierBin;
        if (summarizeBoardData(image, board) != EepromResult::Ok ||
            board.calibrationPierBinsPlausible || board.calibrationValidated ||
            board.regulatoryAuthorized)
        {
            return 4;
        }
        image.bytes[kEepromByte140] =
            kUpperEdgeBin; // 2484 MHz upper 2.4-GHz edge.
        if (summarizeBoardData(image, board) != EepromResult::Ok ||
            !board.calibrationPierBinsPlausible ||
            board.calibrationPiers2G[2].centerMhz != kUpperEdgeMhz)
        {
            return static_cast<int>(Failure::UpperEdgePier);
        }
        return 0;
    }

    int verifyOutputAliases(Fixture &fixture)
    {
        auto &image = fixture.image;
        auto &templates = fixture.templates;
        auto &blockInfo = fixture.blockInfo;
        auto &storage = fixture.storage;
        auto &scratch = fixture.scratch;
        auto &restoreStatus = fixture.restoreStatus;
        // Template callback context is opaque, but must never begin in mutable
        // block output: an aliased callback could corrupt the image or
        // metadata.
        templates = pinnedEepromTemplates();
        blockInfo.major = kMetadataSentinel;
        image.bytes[0] = 2;
        templates.context = &image.bytes[sizeof(image.bytes) - 1];
        const std::array<uint8_t, 7U> frame {
            {
                0x62,
                0,
                0x10,
                1,
                0,
                0,
                0,
            },
        };
        if (applyEepromBlock(frame.data(), frame.size(), templates, image,
                             blockInfo) != EepromResult::InvalidArgument ||
            image.bytes[0] != 2 || blockInfo.major != kMetadataSentinel)
        {
            return static_cast<int>(Failure::ImageAlias);
        }
        templates.context = &blockInfo.major;
        if (applyEepromBlock(frame.data(), frame.size(), templates, image,
                             blockInfo) != EepromResult::InvalidArgument ||
            blockInfo.major != kMetadataSentinel)
        {
            return static_cast<int>(Failure::BlockInfoAlias);
        }

        // Fail before clearing any scratch/status or erasing a recovered board.
        scratch.at(0U) = kScratchSentinel;
        restoreStatus.result = EepromResult::BadChecksum;
        templates.context = &scratch.at(scratch.size() - 1U);
        if (restoreEepromDump(storage.data(), storage.size(), kEepromOrigin,
                              templates, scratch.data(), scratch.size(), image,
                              restoreStatus) != EepromResult::InvalidArgument ||
            scratch.at(0U) != kScratchSentinel || !image.restored ||
            restoreStatus.result != EepromResult::BadChecksum)
        {
            return static_cast<int>(Failure::ScratchAlias);
        }
        templates.context = &restoreStatus.result;
        if (restoreEepromDump(storage.data(), storage.size(), kEepromOrigin,
                              templates, scratch.data(), scratch.size(), image,
                              restoreStatus) != EepromResult::InvalidArgument ||
            restoreStatus.result != EepromResult::BadChecksum)
        {
            return static_cast<int>(Failure::StatusAlias);
        }

        return 0;
    }

    int verifyInputAliases(Fixture &fixture)
    {
        auto &image = fixture.image;
        auto &storage = fixture.storage;
        auto &scratch = fixture.scratch;
        auto &restoreStatus = fixture.restoreStatus;
        // The callback is allowed to mutate its opaque context. If that context
        // points inside a validated delta, its find() can silently replace
        // bytes AFTER checksum + delta-bounds validation but BEFORE delta
        // application. Reject the alias before invoking any callback or
        // changing frame/image.
        std::array<uint8_t, kDeltaFrameBytes> mutableDelta {
            {
                kDeltaHeader,
                0x00,
                kDeltaSizeCode,
                0x01,
                0x00,
                0x01,
                kSyntheticMacOrDeltaByte,
                kDeltaPayloadLastByte,
                0x00,
            },
        };
        const EepromTemplates hostile {&mutableDelta, mutatingTemplateLookup};
        static EepromImage borrowedImage {};
        borrowedImage.bytes[0] = kBorrowedImageSentinel;
        EepromBlockInfo borrowedInfo {};
        borrowedInfo.major = kMetadataSentinel;
        if (applyEepromBlock(mutableDelta.data(), mutableDelta.size(), hostile,
                             borrowedImage,
                             borrowedInfo) != EepromResult::InvalidArgument ||
            mutableDelta.at(kDeltaPayloadIndex) != kSyntheticMacOrDeltaByte ||
            borrowedImage.bytes[0] != kBorrowedImageSentinel ||
            borrowedImage.restored || borrowedInfo.major != kMetadataSentinel)
        {
            return static_cast<int>(Failure::MutableDeltaAlias);
        }
        // The provider table itself cannot be writable callback context either.
        EepromTemplates tableAlias = pinnedEepromTemplates();
        tableAlias.context = &tableAlias;
        if (applyEepromBlock(mutableDelta.data(), mutableDelta.size(),
                             tableAlias, borrowedImage,
                             borrowedInfo) != EepromResult::InvalidArgument ||
            borrowedImage.bytes[0] != kBorrowedImageSentinel ||
            borrowedImage.restored || borrowedInfo.major != kMetadataSentinel)
        {
            return static_cast<int>(Failure::CallbackTableAlias);
        }

        // Raw multi-block restoration likewise cannot let its callback rewrite
        // borrowed NVM storage or its own callback function table. Fail before
        // erasing the previously restored board, scratch or diagnostics.
        EepromTemplates dumpAlias = pinnedEepromTemplates();
        dumpAlias.context = &storage.at(storage.size() - 1U);
        if (restoreEepromDump(storage.data(), storage.size(), kEepromOrigin,
                              dumpAlias, scratch.data(), scratch.size(), image,
                              restoreStatus) != EepromResult::InvalidArgument ||
            image.bytes[0] != 2 || !image.restored ||
            scratch.at(0U) != kScratchSentinel ||
            restoreStatus.result != EepromResult::BadChecksum)
        {
            return static_cast<int>(Failure::DumpInputAlias);
        }
        dumpAlias.context = &dumpAlias;
        if (restoreEepromDump(storage.data(), storage.size(), kEepromOrigin,
                              dumpAlias, scratch.data(), scratch.size(), image,
                              restoreStatus) != EepromResult::InvalidArgument ||
            image.bytes[0] != 2 || !image.restored ||
            scratch.at(0U) != kScratchSentinel ||
            restoreStatus.result != EepromResult::BadChecksum)
        {
            return static_cast<int>(Failure::DumpTableAlias);
        }

        return 0;
    }

    int verifyBorrowedTemplates(Fixture & /*unused*/)
    {
        // A provider can also return a supposedly immutable template pointer
        // into the already authenticated input block while its own context is
        // separate. Never accept input bytes as a trusted template baseline.
        // The synthetic base has a real 1088-byte backing allocation so this
        // negative-before regression is defined behavior, even without a guard.
        static std::array<uint8_t, kBorrowedFrameBytes> frameBacking {};
        const uint8_t *aliasedFrame = &frameBacking.at(kBorrowedFrameOffset);
        const std::array<uint8_t, 9U> validDelta {
            {
                0x62,
                0x00,
                0x30,
                0x01,
                0x00,
                0x01,
                0x22,
                0x23,
                0x00,
            },
        };
        static_assert(kBorrowedFrameOffset + kDeltaFrameBytes <=
                          kBorrowedFrameBytes,
                      "borrowed delta must fit inside its backing storage");
        std::copy(validDelta.begin(), validDelta.end(),
                  &frameBacking.at(kBorrowedFrameOffset));
        frameBacking.at(kTemplateReferenceOffset) =
            2; // Base's template ID matches reference 2.
        BorrowedTemplateReturn baseContext {
            &frameBacking.at(kDeltaPayloadIndex),
        };
        const EepromTemplates badBase {&baseContext, borrowedTemplateLookup};
        static EepromImage unsafeBaseImage {};
        unsafeBaseImage.bytes[0] = kUntrustedImageSentinel;
        EepromBlockInfo unsafeBaseInfo {};
        unsafeBaseInfo.major = kInitialUnsafeInfo;
        if (applyEepromBlock(aliasedFrame, validDelta.size(), badBase,
                             unsafeBaseImage,
                             unsafeBaseInfo) != EepromResult::InvalidArgument ||
            // The metadata was parsed before the provider returned its base;
            // the image must remain intact but lastBlock reports that header.
            unsafeBaseInfo.major != 0 || unsafeBaseInfo.minor != 1 ||
            unsafeBaseImage.bytes[0] != kUntrustedImageSentinel ||
            unsafeBaseImage.restored ||
            frameBacking.at(kBorrowedPayloadCheckOffset) !=
                kSyntheticMacOrDeltaByte)
        {
            return static_cast<int>(Failure::BorrowedTemplateAlias);
        }

        // A template lookup can mutate a frame through a separately retained
        // pointer after its checksum/delta bounds have already been checked.
        // Make the actual backing allocation large enough so that the old
        // post-validation overread is detected as a wrong result, not UB.
        static std::array<uint8_t, kLateFrameBytes> lateFrame {
            {
                kDeltaHeader,
                0,
                kDeltaSizeCode,
                1,
                0,
                1,
                kSyntheticMacOrDeltaByte,
                kDeltaPayloadLastByte,
                0,
            },
        };
        static EepromImage lateImage {};
        EepromBlockInfo lateInfo {};
        PostValidationMutation mutation {&lateFrame};
        const EepromTemplates mutableProvider {
            &mutation,
            lateMutatingTemplateLookup,
        };
        lateImage.bytes[0] = kUntrustedImageSentinel;
        if (applyEepromBlock(lateFrame.data(), kDeltaFrameBytes,
                             mutableProvider, lateImage,
                             lateInfo) != EepromResult::InvalidDelta ||
            mutation.calls != 1 ||
            lateImage.bytes[0] != kUntrustedImageSentinel ||
            lateImage.restored || (lateImage.appliedBlocks != 0U))
        {
            return static_cast<int>(Failure::LateMutationLength);
        }
        // A same-length mutation is delta-safe, but invalidates the previously
        // verified additive checksum. Refuse it before loading a template.
        lateFrame.at(kDeltaMutationOffset) = 1;
        mutation.changedByte = kByteSix;
        mutation.changedValue = kChangedChecksumByte;
        if (applyEepromBlock(lateFrame.data(), kDeltaFrameBytes,
                             mutableProvider, lateImage,
                             lateInfo) != EepromResult::BadChecksum ||
            mutation.calls != 2 ||
            lateImage.bytes[0] != kUntrustedImageSentinel || lateImage.restored)
        {
            return static_cast<int>(Failure::LateMutationChecksum);
        }
        lateFrame.at(kDeltaPayloadIndex) = kSyntheticMacOrDeltaByte;
        mutation.changedByte = 0;
        mutation.changedValue =
            kChangedTemplateReference; // Rebind checked template reference.
        if (applyEepromBlock(lateFrame.data(), kDeltaFrameBytes,
                             mutableProvider, lateImage,
                             lateInfo) != EepromResult::InvalidDelta ||
            mutation.calls != 3 ||
            lateImage.bytes[0] != kUntrustedImageSentinel || lateImage.restored)
        {
            return static_cast<int>(Failure::LateMutationReference);
        }

        // A template callback can retain separately borrowed output pointers.
        // Neither a substituted parsed reference nor a forged restored block
        // count may authorize copying an unverified baseline into the image.
        static EepromImage metadataImage {};
        metadataImage.bytes[0] = kUntrustedImageSentinel;
        EepromBlockInfo metadataInfo {};
        OutputMetadataMutation metadataMutation {
            &metadataInfo,
            &metadataImage,
            true,
        };
        const EepromTemplates metadataProvider {
            &metadataMutation,
            metadataMutatingTemplateLookup,
        };
        if (applyEepromBlock(validDelta.data(), validDelta.size(),
                             metadataProvider, metadataImage,
                             metadataInfo) != EepromResult::InvalidArgument ||
            metadataMutation.calls != 1 || metadataInfo.reference != 2 ||
            (metadataImage.bytes[0] != 0U) || metadataImage.restored ||
            (metadataImage.appliedBlocks != 0U))
        {
            return static_cast<int>(Failure::MetadataReferenceMutation);
        }
        metadataImage.bytes[0] = kUntrustedImageSentinel;
        metadataMutation.mutateReference = false;
        if (applyEepromBlock(validDelta.data(), validDelta.size(),
                             metadataProvider, metadataImage,
                             metadataInfo) != EepromResult::InvalidArgument ||
            metadataMutation.calls != 2 || metadataInfo.reference != 2 ||
            (metadataImage.bytes[0] != 0U) || metadataImage.restored ||
            (metadataImage.appliedBlocks != 0U))
        {
            return static_cast<int>(Failure::MetadataBlockMutation);
        }

        return 0;
    }

    int verifyBoardProfiles(Fixture &fixture)
    {
        const auto &board = fixture.board;
        auto &tx = fixture.tx;
        auto &rx = fixture.rx;
        // An empty or tampered diagnostic summary must never choose apparently
        // supported zero-index gain tables. Reject without retaining old gains.
        const BoardDataSummary accepted = board;
        BoardDataSummary invalid {};
        tx = TxGainProfile::HighOb;
        rx = RxGainProfile::WithoutExternalLna;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
                EepromResult::InvalidBoardIdentity ||
            tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        {
            return static_cast<int>(Failure::UninitializedGain);
        }
        invalid = accepted;
        invalid.mac[0] |=
            1U; // Multicast MAC is not a permanent station address.
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity)
        {
            return static_cast<int>(Failure::MulticastMac);
        }
        invalid = accepted;
        invalid.txChainMask = 2; // Unsupported multi-chain board.
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity)
        {
            return static_cast<int>(Failure::UnsupportedChain);
        }
        invalid = accepted;
        invalid.operationFlags = 0; // No 2.4 GHz operation capability.
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity)
        {
            return static_cast<int>(Failure::UnsupportedBand);
        }
        invalid = accepted;
        invalid.eepromVersion = 1;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity)
        {
            return static_cast<int>(Failure::UnsupportedVersion);
        }
        // A pinned dictionary's generic MAC is not a physical board identity.
        // Discovery rejects such placeholders, but a direct gain-table caller
        // must not bypass that rejection by constructing a valid-looking
        // summary.
        invalid = accepted;
        const std::array<uint8_t, 6U> genericMac {
            {
                0,
                2,
                3,
                4,
                5,
                6,
            },
        };
        std::copy(genericMac.begin(), genericMac.end(), &invalid.mac[0]);
        tx = TxGainProfile::HighOb;
        rx = RxGainProfile::WithoutExternalLna;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
                EepromResult::InvalidBoardIdentity ||
            tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        {
            return static_cast<int>(Failure::GenericTemplateMac);
        }

        // Gain selection may be called directly on a diagnostic summary. A
        // malformed-pier board must not supply a seemingly usable gain profile.
        invalid = accepted;
        invalid.calibrationPierBinsPlausible = false;
        tx = TxGainProfile::HighOb;
        rx = RxGainProfile::WithoutExternalLna;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
                EepromResult::UnsupportedFormat ||
            tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        {
            return static_cast<int>(Failure::InvalidPierProfile);
        }

        // This is a public diagnostic summary. A forged true plausibility flag
        // cannot replace checking the actual three bin/pier records again.
        invalid = accepted;
        invalid.calibrationFrequencyBins2G[1] = kLowPierBin;
        invalid.calibrationPiers2G[1].frequencyBin = kLowPierBin;
        invalid.calibrationPiers2G[1].centerMhz = kLowMhz;
        tx = TxGainProfile::HighOb;
        rx = RxGainProfile::WithoutExternalLna;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
                EepromResult::UnsupportedFormat ||
            tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        {
            return static_cast<int>(Failure::ForgedPierSummary);
        }
        invalid = accepted;
        invalid.calibrationFrequencyBins2G[0] = kBelowBandBin;
        invalid.calibrationPiers2G[0].frequencyBin = kBelowBandBin;
        invalid.calibrationPiers2G[0].centerMhz = kBelowBandMhz;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::UnsupportedFormat)
        {
            return static_cast<int>(Failure::BadLowerPier);
        }
        invalid = accepted;
        invalid.calibrationPiers2G[1].frequencyBin = kMismatchedMiddleBin;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::UnsupportedFormat)
        {
            return static_cast<int>(Failure::BadMiddlePier);
        }
        invalid = accepted;
        invalid.calibrationPiers2G[2].centerMhz = kMismatchedUpperMhz;
        if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::UnsupportedFormat)
        {
            return static_cast<int>(Failure::BadUpperPier);
        }
        if (selectBoardGainProfiles(accepted, tx, rx) != EepromResult::Ok ||
            tx != TxGainProfile::LowOb || rx != RxGainProfile::Standard)
        {
            return static_cast<int>(Failure::ValidGainRecovery);
        }

        return 0;
    }

    int verifyTxModal(const Fixture &fixture)
    {
        BoardTxModal2G modal {};
        if (readBoardTxModal2G(fixture.image, modal) != EepromResult::Ok ||
            modal.powerTableOffsetDb != kPowerOffsetExpected ||
            modal.temperatureSlope != kTemperatureSlopeExpected ||
            modal.voltageSlope != kVoltageSlopeExpected ||
            modal.featureEnable != kTemperatureVoltageFeatures)
        {
            return static_cast<int>(Failure::InvalidTxModal);
        }
        EepromImage untrusted = fixture.image;
        untrusted.bytes[0] = 0; // No valid AR9300 layout.
        modal.temperatureSlope = kInvalidSlopeSentinel;
        if (readBoardTxModal2G(untrusted, modal) !=
                EepromResult::InvalidBoardIdentity ||
            modal.temperatureSlope != 0 || modal.featureEnable != 0)
        {
            return static_cast<int>(Failure::InvalidTxModalIdentity);
        }
        return 0;
    }

    int verifyCalibration(const Fixture &fixture)
    {
        const auto &accepted = fixture.board;
        BoardDataSummary invalid {};
        BoardChannelCalibration2G calibration {};
        // Source-only AR9565 2G op-loop correction/voltage/temperature inputs:
        // exact pier, signed ath9k interpolation, and endpoint clamping. These
        // measurements do not establish calibrated RF or transmit permission.
        if (calculateBoardCalibration2G(accepted, kLowMhz, calibration) !=
                EepromResult::Ok ||
            calibration.channelMhz != kLowMhz ||
            calibration.lowerPierMhz != kLowMhz ||
            calibration.upperPierMhz != kLowMhz || calibration.interpolated ||
            calibration.referenceCorrection != -kLowCorrectionMagnitude ||
            calibration.voltageMeasurement != kLowVoltage ||
            calibration.temperatureMeasurement != kLowTemperature)
        {
            return static_cast<int>(Failure::LowCalibration);
        }
        if (calculateBoardCalibration2G(accepted, kInterpolatedMhz,
                                        calibration) != EepromResult::Ok ||
            calibration.lowerPierMhz != kLowMhz ||
            calibration.upperPierMhz != kMidMhz || !calibration.interpolated ||
            calibration.referenceCorrection != kInterpolatedCorrection ||
            calibration.voltageMeasurement != kInterpolatedVoltage ||
            calibration.temperatureMeasurement != kInterpolatedTemperature)
        {
            return static_cast<int>(Failure::InterpolatedCalibration);
        }
        if (calculateBoardCalibration2G(accepted, kMidMhz, calibration) !=
                EepromResult::Ok ||
            calibration.interpolated ||
            calibration.referenceCorrection != kMidCorrection ||
            calibration.voltageMeasurement != kMidVoltage ||
            calibration.temperatureMeasurement != kMidTemperature)
        {
            return static_cast<int>(Failure::MiddleCalibration);
        }
        if (calculateBoardCalibration2G(accepted, kUpperEdgeMhz, calibration) !=
                EepromResult::Ok ||
            calibration.interpolated ||
            calibration.lowerPierMhz != kUpperEdgeMhz ||
            calibration.upperPierMhz != kUpperEdgeMhz ||
            calibration.referenceCorrection != -kHighCorrectionMagnitude ||
            calibration.voltageMeasurement != kHighVoltage ||
            calibration.temperatureMeasurement != kHighTemperature)
        {
            return static_cast<int>(Failure::UpperCalibration);
        }
        if (calculateBoardCalibration2G(accepted, kUnsupportedFiveGhz,
                                        calibration) !=
                EepromResult::UnsupportedChannel ||
            calibration.channelMhz != 0 || calibration.interpolated ||
            calculateBoardCalibration2G(accepted, kOffRasterMhz, calibration) !=
                EepromResult::UnsupportedChannel ||
            calibration.channelMhz != 0)
        {
            return static_cast<int>(Failure::UnsupportedCalibrationChannel);
        }
        invalid = accepted;
        invalid.calibrationPiers2G[1].centerMhz = kMismatchedMiddleMhz;
        calibration.channelMhz =
            kLowMhz; // Invalid board must clear stale values.
        if (calculateBoardCalibration2G(invalid, kLowMhz, calibration) !=
                EepromResult::UnsupportedFormat ||
            calibration.channelMhz != 0 || calibration.referenceCorrection != 0)
        {
            return static_cast<int>(Failure::InvalidCalibrationGeometry);
        }
        invalid = accepted;
        invalid.mac[0] |= 1U;
        if (calculateBoardCalibration2G(invalid, kMidMhz, calibration) !=
            EepromResult::InvalidBoardIdentity)
        {
            return static_cast<int>(Failure::InvalidCalibrationIdentity);
        }

        return 0;
    }

    int verifyImageVersion(Fixture &fixture)
    {
        auto &image = fixture.image;
        auto &board = fixture.board;
        image.bytes[0] = 1; // Invalid image version.
        if (summarizeBoardData(image, board) !=
                EepromResult::UnsupportedFormat ||
            board.eepromVersion != 0 || board.calibrationPierBinsPlausible ||
            board.calibrationValidated || board.regulatoryAuthorized)
        {
            return static_cast<int>(Failure::InvalidImageVersion);
        }
        return 0;
    }

} // namespace

int main()
{
    static Fixture fixture {};
    if (const int failure = verifyPierGeometry(fixture))
    {
        return failure;
    }
    if (const int failure = verifyOutputAliases(fixture))
    {
        return failure;
    }
    if (const int failure = verifyInputAliases(fixture))
    {
        return failure;
    }
    if (const int failure = verifyBorrowedTemplates(fixture))
    {
        return failure;
    }
    if (const int failure = verifyBoardProfiles(fixture))
    {
        return failure;
    }
    if (const int failure = verifyCalibration(fixture))
    {
        return failure;
    }
    if (const int failure = verifyTxModal(fixture))
    {
        return failure;
    }
    return verifyImageVersion(fixture);
}
