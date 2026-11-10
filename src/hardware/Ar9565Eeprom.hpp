// SPDX-License-Identifier: GPL-2.0-only
#ifndef SIMPLEATH_AR9565_EEPROM_HPP
#define SIMPLEATH_AR9565_EEPROM_HPP

#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"

namespace simpleath
{

    constexpr size_t kAr9300EepromImageBytes = 1088;
    constexpr size_t kAr9565EepromScratchBytes =
        1029; // max payload 1023 + framing

    enum class EepromResult : uint8_t
    {
        Ok,
        InvalidArgument,
        EmptyHeader,
        TruncatedBlock,
        BadChecksum,
        UnsupportedCompression,
        MissingTemplate,
        MissingBaseImage,
        InvalidDelta,
        WrongImageSize,
        UnsupportedFormat,
        InvalidBoardIdentity,
        UnsupportedGainConfiguration,
        UnsupportedChannel,
    };

    struct EepromBlockInfo
    {
            uint8_t compression;
            uint8_t reference;
            uint16_t payloadBytes;
            uint8_t major;
            uint8_t minor;
    };

    struct EepromImage
    {
            uint8_t bytes[kAr9300EepromImageBytes];
            uint16_t appliedBlocks;
            // Means reconstructed bytes only, NEVER calibration/regulatory
            // approval.
            bool restored;
    };

    // Caller supplies a pinned, immutable upstream template catalog. It is not
    // a board fallback. Returns exactly 1088 bytes for the requested template
    // ID. The pinned source catalog below is explicit; missing IDs fail closed.
    struct EepromTemplates
    {
            void *context;
            const uint8_t *(*find)(void *context, uint8_t reference,
                                   size_t *length);
    };

    // Five exact ath9k reconstruction dictionaries. Calling this does not
    // select a fallback board or authorize transmitting with template
    // calibration data.
    EepromTemplates pinnedEepromTemplates();

    // The first byte is the byte at the highest NVM address; following bytes
    // descend, as in ath9k ar9300_read_eeprom/read_otp. Caller normalizes the
    // EEPROM/OTP word stream first. Exact frame: header(4), payload,
    // checksum(2). Supports ath9k None and Block compression. Rejects malformed
    // delta streams before modifying image bytes. Initialize EepromImage to
    // zero or call discardEepromImage before the first direct block apply;
    // contradictory restored/applied-block metadata is rejected. Ordinary
    // failures leave an existing image intact; if a template callback alters
    // parsed output metadata or image restoration flags, the image is wiped
    // and InvalidArgument is returned. Caller must discard the entire restore
    // chain on ANY failure. Frame and template storage must
    // be immutable and disjoint from image/info; the caller owns their
    // lifetime for the duration of this serialized call. The opaque template
    // callback context must not point into writable outputs, the validated
    // frame, or its own callback table; its complete allocation must remain
    // disjoint. If info aliases frame/image/templates, image aliases templates
    // or the context starts in image/info/frame/templates, InvalidArgument is
    // returned before invoking callbacks or mutating image/info. A returned
    // template base may not alias the source frame, callback table, image or
    // diagnostics; its reported 1088-byte extent is checked before reading.
    EepromResult applyEepromBlock(const uint8_t *frame, size_t frameBytes,
                                  const EepromTemplates &templates,
                                  EepromImage &image, EepromBlockInfo &info);

    // No MMIO and no EEPROM defaults. Wipes bytes and validity before a new
    // chain and after an error. Caller must not put EepromImage on a small IRQ
    // stack.
    void discardEepromImage(EepromImage &image);

    struct EepromRestoreStatus
    {
            EepromResult result;
            EepromBlockInfo lastBlock;
            uint16_t origin;
            uint16_t appliedBlocks;
            uint16_t nextAddress;
    };

    // Restore an ALREADY ACQUIRED ascending-address byte dump. The caller must
    // establish its hardware source and word normalization. Explicit origin
    // must be 0x3ff, 0xfff or 0x1ff; no speculative fallback or default image
    // is used. Scratch is caller-owned (at least kAr9565EepromScratchBytes),
    // and all mutable buffers and template metadata must be disjoint from
    // each other and the input storage. Malformed chains invalidate/wipe the
    // image. Storage/scratch/image/status/template aliasing, including a
    // callback context pointing into writable outputs, source storage or its
    // own template table, returns InvalidArgument without modifying any
    // aliased output. Keep the full opaque context
    // allocation disjoint. The caller must separately discard the image.
    // No hardware operations, storage acquisition or regulatory approval.
    EepromResult restoreEepromDump(const uint8_t *storage, size_t storageBytes,
                                   uint16_t origin,
                                   const EepromTemplates &templates,
                                   uint8_t *scratch, size_t scratchBytes,
                                   EepromImage &image,
                                   EepromRestoreStatus &status);

    // Diagnostic interpretation of a completely reconstructed little-endian
    // image. Includes raw regulatory/antenna/calibration fields for later
    // policy and calibration code, not a validation of those fields for
    // transmission. Output is cleared on ordinary failure, but an output
    // overlapping the image is rejected untouched with InvalidArgument.
    // ath9k ar9300_cal_data_per_freq_op_loop, chain zero only. These are raw
    // factory-supplied measurements, not calibrated register/TPC settings.
    // A zero noise temperature indicates that ath9k does not use the two
    // noise-floor values, even when their raw bytes are nonzero.
    struct BoardCalibrationPier2G
    {
            uint8_t frequencyBin;
            uint16_t centerMhz; // 0 for a non-2.4-GHz frequency bin.
            int8_t referencePower;
            uint8_t voltageMeasurement;
            uint8_t temperatureMeasurement;
            int8_t noiseFloorCalibrationRaw;
            int8_t noiseFloorPowerRaw;
            uint8_t noiseTemperatureMeasurement;
            bool noiseMeasurementsPresent;
    };

    struct BoardDataSummary
    {
            uint8_t eepromVersion;
            uint8_t templateVersion;
            uint8_t mac[kPermanentMacBytes];
            uint16_t regulatoryDomains[2];
            uint8_t txChainMask;
            uint8_t rxChainMask;
            uint8_t operationFlags;
            uint8_t rfSilent;
            bool rfKillConfigured;
            bool rfKillPolarity;
            uint8_t rfKillGpio;
            uint8_t bluetoothOptions;
            uint8_t wlanDisableGpio;
            uint8_t txGainIndex;
            uint8_t rxGainIndex;
            uint32_t antennaControlCommon;
            uint32_t antennaControlCommon2;
            uint16_t antennaControlChain0;
            int8_t antennaGainDb;
            uint8_t storedAntennaDiversity;
            uint8_t ar9565AntennaDiversity;
            uint8_t calibrationFrequencyBins2G[3];
            BoardCalibrationPier2G calibrationPiers2G[3];
            // Frequency-bin sanity only; not an EEPROM provenance check.
            bool calibrationPierBinsPlausible;
            bool calibrationValidated;
            bool regulatoryAuthorized;
    };

    EepromResult summarizeBoardData(const EepromImage &image,
                                    BoardDataSummary &out);

    // AR9565-specific ath9k EEPROM gain-index mapping. Requires the basic
    // version, permanent unicast MAC, single-chain, 2 GHz operation and
    // plausible ordered calibration pier bins before choosing tables.
    // A direct caller cannot bypass discovery's malformed-pier rejection.
    // This is not physical board provenance or calibration verification.
    // Unknown indexes are rejected instead of generic AR9300 tables.
    // Outputs become Unknown on ordinary failure and cannot be passed to
    // createInitRecipe.
    // Aliasing either output with the board or the other output returns
    // InvalidArgument without writing either. No TX permission.
    EepromResult selectBoardGainProfiles(const BoardDataSummary &board,
                                         TxGainProfile &tx, RxGainProfile &rx);

    // Channel-specific, single-chain AR9565 open-loop calibration inputs from
    // the three 2-GHz piers. Matches ath9k's signed interpolation/nearest-end
    // calculation, but deliberately DOES NOT validate the factory measurements
    // or authorize programming TPC, temperature compensation, RF or TX. The
    // caller must retain a verified, epoch-current reconstructed board under
    // its native ownership gate. Output is cleared on ordinary failure; an
    // output overlapping the diagnostic board is rejected untouched.
    struct BoardChannelCalibration2G
    {
            uint16_t channelMhz;
            uint16_t lowerPierMhz;
            uint16_t upperPierMhz;
            int16_t referenceCorrection;
            uint8_t voltageMeasurement;
            uint8_t temperatureMeasurement;
            bool interpolated;
    };

    EepromResult calculateBoardCalibration2G(const BoardDataSummary &board,
                                             uint16_t channelMhz,
                                             BoardChannelCalibration2G &out);

} // namespace simpleath
#endif
