// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Synthetic packed EEPROM image; never sourced from hardware or RF.
#include "hardware/Ar9565Eeprom.hpp"

namespace
{
    struct BorrowedTemplateReturn
    {
            const uint8_t *base;
    };

    const uint8_t *borrowedTemplateLookup(void *context, uint8_t,
                                          size_t *length)
    {
        if (!context || !length)
            return nullptr;
        *length = simpleath::kAr9300EepromImageBytes;
        return static_cast<BorrowedTemplateReturn *>(context)->base;
    }

    const uint8_t *mutatingTemplateLookup(void *context, uint8_t reference,
                                          size_t *length)
    {
        // A provider legitimately mutates its own context, which the caller
        // has forged to refer to a checksum-verified input delta frame.
        auto *borrowedFrame = static_cast<uint8_t *>(context);
        borrowedFrame[6] = 0x99;
        return simpleath::pinnedEepromTemplates().find(nullptr, reference,
                                                       length);
    }
} // namespace

int main()
{
    using namespace simpleath;
    static EepromImage image {};
    image.restored = true;
    image.appliedBlocks = 1;
    image.bytes[0] = 2;    // Supported AR9300 image format.
    image.bytes[1] = 3;    // Informational template-version marker only.
    image.bytes[2] = 0x02; // Permanent unicast MAC, not a real board address.
    image.bytes[3] = 0x11;
    image.bytes[4] = 0x22;
    image.bytes[5] = 0x33;
    image.bytes[6] = 0x44;
    image.bytes[7] = 0x55;
    image.bytes[32] = 0x11; // Single AR9565 transmit/receive chain.
    image.bytes[33] = 0x02; // Supported 2.4-GHz operation flag.
    image.bytes[99] = 0xff; // Negative antenna-gain diagnostic.

    // ath9k packed op-loop chain0: 3 frequency bins at offset 138 and
    // six bytes per pier at offset 141; all values are deliberately synthetic.
    image.bytes[138] = 112;  // 2412 MHz.
    image.bytes[139] = 137;  // 2437 MHz.
    image.bytes[140] = 162;  // 2462 MHz.
    image.bytes[141] = 0xf8; // signed reference correction: -8.
    image.bytes[142] = 100;  // voltage.
    image.bytes[143] = 40;   // temperature.
    image.bytes[144] = 0xa6; // signed raw noise calibration: -90.
    image.bytes[145] = 0xa3; // signed raw noise power: -93.
    image.bytes[146] = 0;    // zero rxTempMeas disables noise measurements.
    image.bytes[147] = 127;
    image.bytes[148] = 80;
    image.bytes[149] = 36;
    image.bytes[150] = 0xfe; // signed noise calibration: -2.
    image.bytes[151] = 0x02; // signed noise power: 2.
    image.bytes[152] = 1;
    image.bytes[153] = 0x80; // signed correction: -128.
    image.bytes[154] = 130;
    image.bytes[155] = 10;
    image.bytes[156] = 0;
    image.bytes[157] = 0;
    image.bytes[158] = 2;

    BoardDataSummary board {};
    if (summarizeBoardData(image, board) != EepromResult::Ok ||
        board.eepromVersion != 2 || board.templateVersion != 3 ||
        !board.calibrationPierBinsPlausible || board.antennaGainDb != -1 ||
        board.calibrationValidated || board.regulatoryAuthorized)
        return 1;
    const auto &first = board.calibrationPiers2G[0];
    const auto &second = board.calibrationPiers2G[1];
    const auto &third = board.calibrationPiers2G[2];
    if (first.frequencyBin != 112 || first.centerMhz != 2412 ||
        first.referencePower != -8 || first.voltageMeasurement != 100 ||
        first.temperatureMeasurement != 40 ||
        first.noiseFloorCalibrationRaw != -90 ||
        first.noiseFloorPowerRaw != -93 ||
        first.noiseTemperatureMeasurement != 0 ||
        first.noiseMeasurementsPresent || second.frequencyBin != 137 ||
        second.centerMhz != 2437 || second.referencePower != 127 ||
        second.noiseFloorCalibrationRaw != -2 ||
        second.noiseFloorPowerRaw != 2 || !second.noiseMeasurementsPresent ||
        third.frequencyBin != 162 || third.centerMhz != 2462 ||
        third.referencePower != -128 || !third.noiseMeasurementsPresent)
        return 2;

    TxGainProfile tx = TxGainProfile::Unknown;
    RxGainProfile rx = RxGainProfile::Unknown;
    if (selectBoardGainProfiles(board, tx, rx) != EepromResult::Ok ||
        tx != TxGainProfile::LowOb || rx != RxGainProfile::Standard ||
        board.calibrationValidated || board.regulatoryAuthorized)
        return 3;

    // Bad frequency geometry remains readable as *diagnostics* but never
    // confers calibration/readiness. Both outputs reset on ordinary failures.
    image.bytes[140] = 137;
    if (summarizeBoardData(image, board) != EepromResult::Ok ||
        board.calibrationPierBinsPlausible || board.calibrationValidated ||
        board.regulatoryAuthorized)
        return 4;
    image.bytes[140] = 184; // 2484 MHz upper 2.4-GHz edge.
    if (summarizeBoardData(image, board) != EepromResult::Ok ||
        !board.calibrationPierBinsPlausible ||
        board.calibrationPiers2G[2].centerMhz != 2484)
        return 5;
    // Template callback context is opaque, but must never begin in mutable
    // block output: an aliased callback could corrupt the image or metadata.
    EepromTemplates templates = pinnedEepromTemplates();
    EepromBlockInfo blockInfo {};
    blockInfo.major = 99;
    image.bytes[0] = 2;
    templates.context = &image.bytes[sizeof(image.bytes) - 1];
    const uint8_t frame[] = {0x62, 0, 0x10, 1, 0, 0, 0};
    if (applyEepromBlock(frame, sizeof(frame), templates, image, blockInfo) !=
            EepromResult::InvalidArgument ||
        image.bytes[0] != 2 || blockInfo.major != 99)
        return 6;
    templates.context = &blockInfo.major;
    if (applyEepromBlock(frame, sizeof(frame), templates, image, blockInfo) !=
            EepromResult::InvalidArgument ||
        blockInfo.major != 99)
        return 7;

    // Fail before clearing any scratch/status or erasing a recovered board.
    uint8_t storage[1024] {};
    uint8_t scratch[kAr9565EepromScratchBytes] {};
    scratch[0] = 0xa5;
    EepromRestoreStatus restoreStatus {};
    restoreStatus.result = EepromResult::BadChecksum;
    templates.context = &scratch[sizeof(scratch) - 1];
    if (restoreEepromDump(storage, sizeof(storage), 0x3ff, templates, scratch,
                          sizeof(scratch), image,
                          restoreStatus) != EepromResult::InvalidArgument ||
        scratch[0] != 0xa5 || image.restored != true ||
        restoreStatus.result != EepromResult::BadChecksum)
        return 8;
    templates.context = &restoreStatus.result;
    if (restoreEepromDump(storage, sizeof(storage), 0x3ff, templates, scratch,
                          sizeof(scratch), image,
                          restoreStatus) != EepromResult::InvalidArgument ||
        restoreStatus.result != EepromResult::BadChecksum)
        return 9;

    // The callback is allowed to mutate its opaque context. If that context
    // points inside a validated delta, its find() can silently replace bytes
    // AFTER checksum + delta-bounds validation but BEFORE delta application.
    // Reject the alias before invoking any callback or changing frame/image.
    uint8_t mutableDelta[] = {0x62, 0x00, 0x30, 0x01, 0x00,
                              0x01, 0x22, 0x23, 0x00};
    EepromTemplates hostile {mutableDelta, mutatingTemplateLookup};
    static EepromImage borrowedImage {};
    borrowedImage.bytes[0] = 0x77;
    EepromBlockInfo borrowedInfo {};
    borrowedInfo.major = 99;
    if (applyEepromBlock(mutableDelta, sizeof(mutableDelta), hostile,
                         borrowedImage,
                         borrowedInfo) != EepromResult::InvalidArgument ||
        mutableDelta[6] != 0x22 || borrowedImage.bytes[0] != 0x77 ||
        borrowedImage.restored || borrowedInfo.major != 99)
        return 16;
    // The provider table itself cannot be writable callback context either.
    EepromTemplates tableAlias = pinnedEepromTemplates();
    tableAlias.context = &tableAlias;
    if (applyEepromBlock(mutableDelta, sizeof(mutableDelta), tableAlias,
                         borrowedImage,
                         borrowedInfo) != EepromResult::InvalidArgument ||
        borrowedImage.bytes[0] != 0x77 || borrowedImage.restored ||
        borrowedInfo.major != 99)
        return 17;

    // Raw multi-block restoration likewise cannot let its callback rewrite
    // borrowed NVM storage or its own callback function table. Fail before
    // erasing the previously restored board, scratch or diagnostics.
    EepromTemplates dumpAlias = pinnedEepromTemplates();
    dumpAlias.context = &storage[sizeof(storage) - 1];
    if (restoreEepromDump(storage, sizeof(storage), 0x3ff, dumpAlias, scratch,
                          sizeof(scratch), image,
                          restoreStatus) != EepromResult::InvalidArgument ||
        image.bytes[0] != 2 || !image.restored || scratch[0] != 0xa5 ||
        restoreStatus.result != EepromResult::BadChecksum)
        return 18;
    dumpAlias.context = &dumpAlias;
    if (restoreEepromDump(storage, sizeof(storage), 0x3ff, dumpAlias, scratch,
                          sizeof(scratch), image,
                          restoreStatus) != EepromResult::InvalidArgument ||
        image.bytes[0] != 2 || !image.restored || scratch[0] != 0xa5 ||
        restoreStatus.result != EepromResult::BadChecksum)
        return 19;

    // A provider can also return a supposedly immutable template pointer
    // into the already authenticated input block while its own context is
    // separate. Never accept input bytes as a trusted template baseline.
    // The synthetic base has a real 1088-byte backing allocation so this
    // negative-before regression is defined behavior, even without a guard.
    static uint8_t frameBacking[1120] {};
    uint8_t *aliasedFrame = frameBacking + 8;
    const uint8_t validDelta[] = {0x62, 0x00, 0x30, 0x01, 0x00,
                                  0x01, 0x22, 0x23, 0x00};
    for (size_t i = 0; i < sizeof(validDelta); ++i)
        aliasedFrame[i] = validDelta[i];
    frameBacking[7] = 2; // Base's template ID matches reference 2.
    BorrowedTemplateReturn baseContext {frameBacking + 6};
    EepromTemplates badBase {&baseContext, borrowedTemplateLookup};
    static EepromImage unsafeBaseImage {};
    unsafeBaseImage.bytes[0] = 0x7e;
    EepromBlockInfo unsafeBaseInfo {};
    unsafeBaseInfo.major = 91;
    if (applyEepromBlock(aliasedFrame, sizeof(validDelta), badBase,
                         unsafeBaseImage,
                         unsafeBaseInfo) != EepromResult::InvalidArgument ||
        // The metadata was parsed before the provider returned its base;
        // the image must remain intact but lastBlock reports that header.
        unsafeBaseInfo.major != 0 || unsafeBaseInfo.minor != 1 ||
        unsafeBaseImage.bytes[0] != 0x7e || unsafeBaseImage.restored ||
        aliasedFrame[6] != 0x22)
        return 20;

    // An empty or tampered diagnostic summary must never choose apparently
    // supported zero-index gain tables. Reject without retaining old gains.
    const BoardDataSummary accepted = board;
    BoardDataSummary invalid {};
    tx = TxGainProfile::HighOb;
    rx = RxGainProfile::WithoutExternalLna;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity ||
        tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        return 11;
    invalid = accepted;
    invalid.mac[0] |= 1; // Multicast MAC is not a permanent station address.
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::InvalidBoardIdentity)
        return 12;
    invalid = accepted;
    invalid.txChainMask = 2; // Unsupported multi-chain board.
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::InvalidBoardIdentity)
        return 13;
    invalid = accepted;
    invalid.operationFlags = 0; // No 2.4 GHz operation capability.
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::InvalidBoardIdentity)
        return 14;
    invalid = accepted;
    invalid.eepromVersion = 1;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::InvalidBoardIdentity)
        return 15;
    // A pinned dictionary's generic MAC is not a physical board identity.
    // Discovery rejects such placeholders, but a direct gain-table caller
    // must not bypass that rejection by constructing a valid-looking summary.
    invalid = accepted;
    const uint8_t genericMac[] {0, 2, 3, 4, 5, 6};
    for (size_t i = 0; i < sizeof(genericMac); ++i)
        invalid.mac[i] = genericMac[i];
    tx = TxGainProfile::HighOb;
    rx = RxGainProfile::WithoutExternalLna;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::InvalidBoardIdentity ||
        tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        return 22;

    // Gain selection may be called directly on a diagnostic summary. A
    // malformed-pier board must not supply a seemingly usable gain profile.
    invalid = accepted;
    invalid.calibrationPierBinsPlausible = false;
    tx = TxGainProfile::HighOb;
    rx = RxGainProfile::WithoutExternalLna;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::UnsupportedFormat ||
        tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        return 21;

    // This is a public diagnostic summary. A forged true plausibility flag
    // cannot replace checking the actual three bin/pier records again.
    invalid = accepted;
    invalid.calibrationFrequencyBins2G[1] = 112;
    invalid.calibrationPiers2G[1].frequencyBin = 112;
    invalid.calibrationPiers2G[1].centerMhz = 2412;
    tx = TxGainProfile::HighOb;
    rx = RxGainProfile::WithoutExternalLna;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
            EepromResult::UnsupportedFormat ||
        tx != TxGainProfile::Unknown || rx != RxGainProfile::Unknown)
        return 23;
    invalid = accepted;
    invalid.calibrationFrequencyBins2G[0] = 111;
    invalid.calibrationPiers2G[0].frequencyBin = 111;
    invalid.calibrationPiers2G[0].centerMhz = 2411;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::UnsupportedFormat)
        return 24;
    invalid = accepted;
    invalid.calibrationPiers2G[1].frequencyBin = 113;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::UnsupportedFormat)
        return 25;
    invalid = accepted;
    invalid.calibrationPiers2G[2].centerMhz = 2483;
    if (selectBoardGainProfiles(invalid, tx, rx) !=
        EepromResult::UnsupportedFormat)
        return 26;
    if (selectBoardGainProfiles(accepted, tx, rx) != EepromResult::Ok ||
        tx != TxGainProfile::LowOb || rx != RxGainProfile::Standard)
        return 27;

    image.bytes[0] = 1; // Invalid image version.
    if (summarizeBoardData(image, board) != EepromResult::UnsupportedFormat ||
        board.eepromVersion != 0 || board.calibrationPierBinsPlausible ||
        board.calibrationValidated || board.regulatoryAuthorized)
        return 10;
    return 0;
}
