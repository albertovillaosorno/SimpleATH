// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_EEPROM_HPP
#define SIMPLEATH_AR9565_EEPROM_HPP

#include "Ar9565Core.hpp"

namespace simpleath {

constexpr size_t kAr9300EepromImageBytes = 1088;

enum class EepromResult : uint8_t {
    Ok, InvalidArgument, EmptyHeader, TruncatedBlock, BadChecksum,
    UnsupportedCompression, MissingTemplate, MissingBaseImage,
    InvalidDelta, WrongImageSize, UnsupportedFormat, InvalidBoardIdentity
};

struct EepromBlockInfo {
    uint8_t compression;
    uint8_t reference;
    uint16_t payloadBytes;
    uint8_t major;
    uint8_t minor;
};

struct EepromImage {
    uint8_t bytes[kAr9300EepromImageBytes];
    uint16_t appliedBlocks;
    // Means reconstructed bytes only, NEVER calibration/regulatory approval.
    bool restored;
};

// Caller supplies a pinned, immutable upstream template catalog. It is not a
// board fallback. Returns exactly 1088 bytes for the requested template ID.
// No catalog is supplied by the current driver. Missing templates fail closed.
struct EepromTemplates {
    void *context;
    const uint8_t *(*find)(void *context, uint8_t reference, size_t *length);
};

// The first byte is the byte at the highest NVM address; following bytes
// descend, as in ath9k ar9300_read_eeprom/read_otp. Caller normalizes the
// EEPROM/OTP word stream first. Exact frame: header(4), payload, checksum(2).
// Supports ath9k None and Block compression. Rejects malformed delta streams
// before modifying image bytes. Other failures leave an existing image intact;
// caller must discard the entire restore chain on ANY failure.
// Frame and template storage must be immutable and disjoint from image/info;
// the caller owns their lifetime for the duration of this serialized call.
EepromResult applyEepromBlock(const uint8_t *frame, size_t frameBytes,
                              const EepromTemplates &templates,
                              EepromImage &image, EepromBlockInfo &info);

// No MMIO and no EEPROM defaults. Wipes bytes and validity before a new chain
// and after an error. Caller must not put EepromImage on a small IRQ stack.
void discardEepromImage(EepromImage &image);

// Diagnostic interpretation of a completely reconstructed little-endian
// image. Includes raw regulatory/antenna/calibration fields for later policy
// and calibration code, not a validation of those fields for transmission.
struct BoardDataSummary {
    uint8_t eepromVersion;
    uint8_t templateVersion;
    uint8_t mac[6];
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
    bool calibrationValidated;
    bool regulatoryAuthorized;
};

EepromResult summarizeBoardData(const EepromImage &image, BoardDataSummary &out);

} // namespace simpleath
#endif
