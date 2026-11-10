// SPDX-License-Identifier: AGPL-3.0-only
// New bounded parser adapted from the permissively licensed Linux ath9k
// ar9003_eeprom.c/.h. Preserve their upstream permission and copyright:
// Local reference SHA-256:
// ar9003_eeprom.c:
// 9af461f68c73fdbe553619534f0474dca637a7c5191729251fa479af2ad75dc6
// ar9003_eeprom.h:
// 4de071df42f0d91df022c91779f9bb7d0aac57fa7803f240530b4f0acd457bbd
//
// eeprom.h:
// b6bc5f1bffd56f5b8828d14635eac4846487ff6f2ef06344d474ac4c1c11b7b0
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "Ar9565Eeprom.hpp"
#include "Ar9565Core.hpp"
#include "Ar9565InitCatalog.hpp"
#include "generated/Ar9300EepromTemplates.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kUnsignedByteSignBit = 128;
        constexpr int kUnsignedByteSpan = 256;
        constexpr uint32_t kBitsPerByte = 8;
        constexpr uint32_t kBitsPerHalfword = 16;
        constexpr uint32_t kErasedHeader = UINT32_MAX;
        constexpr size_t kFrameHeaderBytes = 4;
        constexpr size_t kFrameChecksumBytes = 2;
        constexpr size_t kFrameOverheadBytes =
            kFrameHeaderBytes + kFrameChecksumBytes;
        constexpr uint8_t kCompressionShift = 5;
        constexpr uint8_t kCompressionMask = 7;
        constexpr uint8_t kReferenceMask = 0x1f;
        constexpr uint8_t kReferenceHighMask = 0x20;
        constexpr uint8_t kReferenceHighShift = 2;
        constexpr uint16_t kPayloadLengthMask = 0x7f0;
        constexpr uint8_t kHighNibbleShift = 4;
        constexpr uint8_t kHeaderMajorMask = 0x0f;
        constexpr uint16_t kMaximumBlocks = 100;
        constexpr size_t kMaximumRawNvmBytes = 16384;
        constexpr uint16_t kEepromOrigin1K = 0x3ff;
        constexpr uint16_t kEepromOrigin4K = 0xfff;
        constexpr uint16_t kOtpOrigin512 = 0x1ff;
        constexpr size_t kMaximumCompressedPayload = 1024;

        // Offsets in the packed AR9300 EEPROM v2 layout, not C++ struct
        // offsets.
        constexpr uint8_t kSupportedFormat = 2;
        constexpr size_t kVersionOffset = 0;
        constexpr size_t kTemplateVersionOffset = 1;
        constexpr size_t kMacOffset = 2;
        constexpr size_t kRegulatoryDomain0Offset = 28;
        constexpr size_t kRegulatoryDomain1Offset = 30;
        constexpr size_t kChainMaskOffset = 32;
        constexpr size_t kOperatingFlagsOffset = 33;
        constexpr size_t kMiscFlagsOffset = 34;
        constexpr size_t kRfSilentOffset = 35;
        constexpr size_t kBluetoothOptionsOffset = 36;
        constexpr size_t kWlanDisableGpioOffset = 45;
        constexpr size_t kGainIndexOffset = 48;
        constexpr size_t kAntennaControlCommonOffset = 53;
        constexpr size_t kAntennaControlCommon2Offset = 57;
        constexpr size_t kAntennaControlChain0Offset = 61;
        constexpr size_t kAntennaGainOffset = 99;
        constexpr size_t kStoredAntennaDiversityOffset = 124;
        constexpr size_t kCalibrationFrequencyBinsOffset = 138;
        constexpr size_t kCalibrationPiersOffset = 141;
        constexpr size_t kCalibrationPierBytes = 6;
        constexpr size_t kNoiseTemperatureOffset = 5;
        constexpr size_t kCalibrationPiers = 3;
        constexpr uint8_t kSingleChainMask = 0x11;
        constexpr uint8_t kTwoGigahertzOperation = 0x02;
        constexpr uint8_t kMiscBigEndianFlag = 1;
        constexpr uint8_t kRfSilentGpioMask = 0xfc;
        constexpr uint8_t kRfSilentGpioShift = 2;
        constexpr uint8_t kAntennaDiversityOverride = 0xc9;
        constexpr uint8_t kFirstTwoGigahertzPierBin = 112;
        constexpr uint8_t kLastTwoGigahertzPierBin = 184;
        constexpr uint16_t kPierFrequencyBaseMhz = 2300;

        const uint8_t *findPinnedTemplate(void * /*unused*/, uint8_t reference,
                                          size_t *length)
        {
            if (length == nullptr)
            {
                return nullptr;
            }
            *length = 0;
            for (const auto &entry : eeprom_templates::kCatalog)
            {
                if (entry.id == reference)
                {
                    *length = entry.length;
                    return entry.bytes;
                }
            }
            return nullptr;
        }

        int8_t signedByte(uint8_t value)
        {
            return static_cast<int8_t>(value < kUnsignedByteSignBit
                                           ? static_cast<int>(value)
                                           : static_cast<int>(value) -
                                                 kUnsignedByteSpan);
        }

        uint16_t readLittle16(const uint8_t *bytes)
        {
            return static_cast<uint16_t>(
                static_cast<uint32_t>(bytes[0]) |
                (static_cast<uint32_t>(bytes[1]) << kBitsPerByte));
        }

        uint32_t readLittle32(const uint8_t *bytes)
        {
            return static_cast<uint32_t>(readLittle16(bytes)) |
                   (static_cast<uint32_t>(readLittle16(bytes + 2))
                    << kBitsPerHalfword);
        }

        void copyBytes(uint8_t *destination, const uint8_t *source,
                       size_t length)
        {
            for (size_t i = 0; i < length; ++i)
            {
                destination[i] = source[i];
            }
        }

        bool overlaps(const void *source, size_t length,
                      const void *destination, size_t destinationLength)
        {
            const auto src = reinterpret_cast<uintptr_t>(source);
            const auto dst = reinterpret_cast<uintptr_t>(destination);
            return (length != 0U) && (destinationLength != 0U) &&
                   (src >= dst ? src - dst < destinationLength
                               : dst - src < length);
        }

        bool overlapsImage(const uint8_t *source, size_t length,
                           const EepromImage &image)
        {
            return overlaps(source, length, &image, sizeof(image));
        }

        // A pinned reference image contains a generic MAC, not physical
        // board identity. Discovery rejects these; reject them again for
        // direct gain selectors that only receive a diagnostic summary.
        bool isPinnedPlaceholderMac(const uint8_t mac[kPermanentMacBytes])
        {
            for (const auto &entry : eeprom_templates::kCatalog)
            {
                if (entry.length != kAr9300EepromImageBytes)
                {
                    continue;
                }
                bool matches = true;
                for (size_t i = 0; i < kPermanentMacBytes; ++i)
                {
                    matches = matches && mac[i] == entry.bytes[kMacOffset + i];
                }
                if (matches)
                {
                    return true;
                }
            }
            return false;
        }

        bool plausiblePierGeometry(const BoardDataSummary &board)
        {
            // The summary is public caller-owned data. The boolean cached by
            // summarizeBoardData is only a diagnostic hint: a direct gain
            // caller must verify the raw frequency bins and pier records.
            for (size_t i = 0; i < kCalibrationPiers; ++i)
            {
                const uint8_t bin = board.calibrationFrequencyBins2G[i];
                const BoardCalibrationPier2G &pier =
                    board.calibrationPiers2G[i];
                if (bin < kFirstTwoGigahertzPierBin ||
                    bin > kLastTwoGigahertzPierBin ||
                    (i != 0 &&
                     bin <= board.calibrationFrequencyBins2G[i - 1]) ||
                    pier.frequencyBin != bin ||
                    pier.centerMhz !=
                        static_cast<uint16_t>(kPierFrequencyBaseMhz + bin))
                {
                    return false;
                }
            }
            return true;
        }

        // ath9k ar9003_eeprom.c interpolate(): double the ratio before
        // rounding, preserving C++ signed-division/remainder semantics on
        // descending curves. With 2G piers the largest intermediate is well
        // inside int32_t (255 units * 2 * 72 MHz).
        int32_t interpolatePier(int32_t frequency, int32_t lowFrequency,
                                int32_t highFrequency, int32_t lowValue,
                                int32_t highValue)
        {
            const int32_t scaled = 2 * (highValue - lowValue) *
                                   (frequency - lowFrequency) /
                                   (highFrequency - lowFrequency);
            return lowValue + (scaled / 2) + (scaled % 2);
        }

        // Unlike upstream's permissive restoration, reject truncated records
        // and propagate every bounds failure. Validate the ENTIRE delta before
        // applying.
        bool validDelta(const uint8_t *payload, size_t length)
        {
            size_t cursor = 0;
            size_t spot = 0;
            while (cursor < length)
            {
                if (length - cursor < 2)
                {
                    return false;
                }
                const size_t skip = payload[cursor++];
                const size_t count = payload[cursor++];
                if (skip > kAr9300EepromImageBytes - spot)
                {
                    return false;
                }
                spot += skip;
                if (count > length - cursor ||
                    count > kAr9300EepromImageBytes - spot)
                {
                    return false;
                }
                cursor += count;
                spot += count;
            }
            return true;
        }
    } // namespace

    void discardEepromImage(EepromImage &image)
    {
        for (unsigned char &byte : image.bytes)
        {
            byte = 0;
        }
        image.restored = false;
        image.appliedBlocks = 0;
    }

    EepromTemplates pinnedEepromTemplates()
    {
        return {nullptr, findPinnedTemplate};
    }

    EepromResult applyEepromBlock(const uint8_t *frame, size_t frameBytes,
                                  const EepromTemplates &templates,
                                  EepromImage &image, EepromBlockInfo &info)
    {
        // Check aliases before clearing diagnostics: an overlapping info
        // reference could otherwise clobber the frame or board image first.
        // The opaque template context must also start outside writable output;
        // its complete allocation must remain disjoint by caller contract.
        // The returned error itself is authoritative on this contract breach.
        if (overlaps(&info, sizeof(info), frame, frameBytes) ||
            overlaps(&info, sizeof(info), &image, sizeof(image)) ||
            overlaps(&info, sizeof(info), &templates, sizeof(templates)) ||
            overlaps(&image, sizeof(image), &templates, sizeof(templates)) ||
            overlaps(&info, sizeof(info), templates.context, 1) ||
            overlaps(&image, sizeof(image), templates.context, 1) ||
            // The callback may mutate its context after the frame checksum
            // and delta bounds have been validated. Do not let it rewrite
            // validated input bytes before applying an unchecked delta copy,
            // or overwrite the callback table itself.
            overlaps(frame, frameBytes, templates.context, 1) ||
            overlaps(&templates, sizeof(templates), templates.context, 1))
        {
            return EepromResult::InvalidArgument;
        }
        info = {};
        if (frame == nullptr)
        {
            return EepromResult::InvalidArgument;
        }
        if (overlapsImage(frame, frameBytes, image))
        {
            return EepromResult::InvalidArgument;
        }
        if (frameBytes < kFrameHeaderBytes)
        {
            return EepromResult::TruncatedBlock;
        }
        if (readLittle32(frame) == 0 || readLittle32(frame) == kErasedHeader)
        {
            return EepromResult::EmptyHeader;
        }
        info.compression =
            (static_cast<uint32_t>(frame[0]) >> kCompressionShift) &
            kCompressionMask;
        info.reference =
            (static_cast<uint32_t>(frame[0]) & kReferenceMask) |
            ((static_cast<uint32_t>(frame[1]) >> kReferenceHighShift) &
             kReferenceHighMask);
        info.payloadBytes = static_cast<uint16_t>(
            ((static_cast<uint32_t>(frame[1]) << kHighNibbleShift) &
             kPayloadLengthMask) |
            (static_cast<uint32_t>(frame[2]) >> kHighNibbleShift));
        info.major = frame[2] & kHeaderMajorMask;
        info.minor = frame[3];
        const size_t length = info.payloadBytes;
        const uint32_t validatedHeader = readLittle32(frame);
        if (frameBytes != length + kFrameOverheadBytes)
        {
            return EepromResult::TruncatedBlock;
        }
        // Callers must start from a discarded/zero-initialized image. A
        // restored flag without an applied block (or vice versa) must not
        // authorize a reference-free delta to use stale board data.
        if (image.appliedBlocks >= kMaximumBlocks ||
            image.restored != (image.appliedBlocks != 0))
        {
            return EepromResult::InvalidArgument;
        }
        uint16_t checksum = 0;
        for (size_t i = 0; i < length; ++i)
        {
            checksum =
                static_cast<uint16_t>(checksum + frame[kFrameHeaderBytes + i]);
        }
        if (checksum != readLittle16(frame + kFrameHeaderBytes + length))
        {
            return EepromResult::BadChecksum;
        }
        const uint8_t *payload = frame + kFrameHeaderBytes;
        if (info.compression == 0)
        {
            if (length != sizeof(image.bytes))
            {
                return EepromResult::WrongImageSize;
            }
            copyBytes(image.bytes, payload, length);
        }
        else if (info.compression == 3)
        {
            if (!validDelta(payload, length))
            {
                return EepromResult::InvalidDelta;
            }
            const uint8_t *base = nullptr;
            if (info.reference != 0U)
            {
                const EepromBlockInfo parsedInfo = info;
                const uint16_t previousBlocks = image.appliedBlocks;
                const bool previouslyRestored = image.restored;
                size_t baseLength = 0;
                if (templates.find != nullptr)
                {
                    base = templates.find(templates.context, info.reference,
                                          &baseLength);
                }
                // A callback retaining unrelated output pointers must not
                // replace the verified reference or forge restoration state.
                if (info.compression != parsedInfo.compression ||
                    info.reference != parsedInfo.reference ||
                    info.payloadBytes != parsedInfo.payloadBytes ||
                    info.major != parsedInfo.major ||
                    info.minor != parsedInfo.minor ||
                    image.appliedBlocks != previousBlocks ||
                    image.restored != previouslyRestored)
                {
                    info = parsedInfo;
                    discardEepromImage(image);
                    return EepromResult::InvalidArgument;
                }
                if ((base == nullptr) || baseLength != sizeof(image.bytes))
                {
                    return EepromResult::MissingTemplate;
                }
                // The callback's returned base is separately borrowed from
                // its context. A forged 1088-byte length cannot turn a short
                // verified delta or our own metadata into trusted template
                // data, nor let its copy read beyond those allocations.
                // Check known aliases before even reading the template ID.
                if (overlaps(base, baseLength, frame, frameBytes) ||
                    overlaps(base, baseLength, &templates, sizeof(templates)) ||
                    overlaps(base, baseLength, &info, sizeof(info)) ||
                    overlapsImage(base, baseLength, image))
                {
                    return EepromResult::InvalidArgument;
                }
                if (base[1] != info.reference)
                {
                    return EepromResult::MissingTemplate;
                }
            }
            else if (!image.restored)
            {
                return EepromResult::MissingBaseImage;
            }
            // The external dictionary provider has just run after our first
            // checksum and delta-bounds pass. It may violate its borrowed
            // frame's const contract using a separate retained pointer.
            // Revalidate BEFORE applying its return value, so a rewritten
            // skip/count cannot overrun the image or read past the frame.
            if (readLittle32(frame) != validatedHeader ||
                !validDelta(payload, length))
            {
                return EepromResult::InvalidDelta;
            }
            uint16_t checkedChecksum = 0;
            for (size_t i = 0; i < length; ++i)
            {
                checkedChecksum =
                    static_cast<uint16_t>(checkedChecksum + payload[i]);
            }
            if (checkedChecksum != checksum ||
                checkedChecksum !=
                    readLittle16(frame + kFrameHeaderBytes + length))
            {
                return EepromResult::BadChecksum;
            }
            if (base != nullptr)
            {
                copyBytes(image.bytes, base, sizeof(image.bytes));
            }
            size_t cursor = 0;
            size_t spot = 0;
            while (cursor < length)
            {
                spot += payload[cursor++];
                const size_t count = payload[cursor++];
                copyBytes(image.bytes + spot, payload + cursor, count);
                spot += count;
                cursor += count;
            }
        }
        else
        {
            return EepromResult::UnsupportedCompression;
        }
        ++image.appliedBlocks;
        image.restored = true;
        return EepromResult::Ok;
    }

    EepromResult restoreEepromDump(const uint8_t *storage, size_t storageBytes,
                                   uint16_t origin,
                                   const EepromTemplates &templates,
                                   uint8_t *scratch, size_t scratchBytes,
                                   EepromImage &image,
                                   EepromRestoreStatus &status)
    {
        // Check all mutable buffers against input and callback metadata
        // BEFORE initializing diagnostics or discarding the image. Otherwise,
        // even an error cleanup could overwrite an aliased source dump.
        // The template callback's opaque context must not begin inside any
        // writable output; the caller keeps its entire allocation disjoint.
        // On a contract breach only the return code reports the failure.
        if (overlaps(&status, sizeof(status), storage, storageBytes) ||
            overlaps(&status, sizeof(status), scratch, scratchBytes) ||
            overlaps(&status, sizeof(status), &image, sizeof(image)) ||
            overlaps(&status, sizeof(status), &templates, sizeof(templates)) ||
            overlapsImage(storage, storageBytes, image) ||
            overlapsImage(scratch, scratchBytes, image) ||
            overlaps(&image, sizeof(image), &templates, sizeof(templates)) ||
            overlaps(storage, storageBytes, scratch, scratchBytes) ||
            overlaps(scratch, scratchBytes, &templates, sizeof(templates)) ||
            overlaps(&status, sizeof(status), templates.context, 1) ||
            overlaps(&image, sizeof(image), templates.context, 1) ||
            overlaps(scratch, scratchBytes, templates.context, 1) ||
            // A callback cannot rewrite future unparsed input blocks or its
            // own callback table during a multi-block reconstruction.
            overlaps(storage, storageBytes, templates.context, 1) ||
            overlaps(&templates, sizeof(templates), templates.context, 1))
        {
            return EepromResult::InvalidArgument;
        }
        // No frame-sized allocation is made on the kernel stack.
        status = {};
        status.origin = origin;
        status.nextAddress = origin;
        if ((storage == nullptr) || (scratch == nullptr) ||
            storageBytes > kMaximumRawNvmBytes || origin >= storageBytes ||
            scratchBytes < kAr9565EepromScratchBytes ||
            (origin != kEepromOrigin1K && origin != kEepromOrigin4K &&
             origin != kOtpOrigin512))
        {
            discardEepromImage(image);
            return status.result = EepromResult::InvalidArgument;
        }
        discardEepromImage(image);
        size_t remaining = static_cast<size_t>(origin) + 1;
        while (remaining != 0U)
        {
            status.nextAddress = static_cast<uint16_t>(remaining - 1);
            if (remaining < kFrameHeaderBytes)
            {
                discardEepromImage(image);
                return status.result = EepromResult::TruncatedBlock;
            }
            for (size_t i = 0; i < kFrameHeaderBytes; ++i)
            {
                scratch[i] = storage[remaining - 1 - i];
            }
            const uint32_t header = readLittle32(scratch);
            if (header == 0 || header == kErasedHeader)
            {
                // Erased padding terminates a chain only after a recovered
                // block.
                if (image.restored)
                {
                    return status.result = EepromResult::Ok;
                }
                return status.result = EepromResult::EmptyHeader;
            }
            const size_t payloadBytes =
                ((static_cast<size_t>(scratch[1]) << kHighNibbleShift) &
                 kPayloadLengthMask) |
                (static_cast<uint32_t>(scratch[2]) >> kHighNibbleShift);
            const size_t frameBytes = payloadBytes + kFrameOverheadBytes;
            // ath9k's non-AR9485 (including AR9565) storage-chain limit is
            // <1024. Do not resynchronize past corrupt headers into arbitrary
            // NVM bytes.
            if (payloadBytes >= kMaximumCompressedPayload ||
                frameBytes > remaining)
            {
                discardEepromImage(image);
                return status.result = EepromResult::TruncatedBlock;
            }
            for (size_t i = kFrameHeaderBytes; i < frameBytes; ++i)
            {
                scratch[i] = storage[remaining - 1 - i];
            }
            const EepromResult result = applyEepromBlock(
                scratch, frameBytes, templates, image, status.lastBlock);
            if (result != EepromResult::Ok)
            {
                discardEepromImage(image);
                return status.result = result;
            }
            status.appliedBlocks = image.appliedBlocks;
            remaining -= frameBytes;
        }
        status.nextAddress = 0;
        return status.result = EepromResult::Ok;
    }

    EepromResult summarizeBoardData(const EepromImage &image,
                                    BoardDataSummary &out)
    {
        // Clearing an output that aliases the reconstructed image would
        // invalidate the very board data we are about to inspect.
        if (overlaps(&out, sizeof(out), &image, sizeof(image)))
        {
            return EepromResult::InvalidArgument;
        }
        out = {};
        if (!image.restored || image.appliedBlocks == 0)
        {
            return EepromResult::MissingBaseImage;
        }
        const auto *const bytes = image.bytes;
        // ar9300_eeprom packed layout: prefix 28, base header 25, 2G modal 71,
        // base extension 14, 2G pier frequencies at 138. Never cast packed
        // data.
        if (bytes[kVersionOffset] != kSupportedFormat ||
            ((static_cast<uint32_t>(bytes[kMiscFlagsOffset]) &
              kMiscBigEndianFlag) != 0U))
        {
            return EepromResult::UnsupportedFormat;
        }
        // AR9565 has one TX/RX chain. Generic 0x77 template masks are not a
        // recovered AR9565 board identity. This is still only a structural
        // check.
        if (!validatePermanentMac(bytes + kMacOffset) ||
            bytes[kChainMaskOffset] != kSingleChainMask ||
            ((static_cast<uint32_t>(bytes[kOperatingFlagsOffset]) &
              kTwoGigahertzOperation) == 0U))
        {
            return EepromResult::InvalidBoardIdentity;
        }
        out.eepromVersion = bytes[kVersionOffset];
        out.templateVersion = bytes[kTemplateVersionOffset];
        copyBytes(out.mac, bytes + kMacOffset, sizeof(out.mac));
        out.regulatoryDomains[0] =
            readLittle16(bytes + kRegulatoryDomain0Offset);
        out.regulatoryDomains[1] =
            readLittle16(bytes + kRegulatoryDomain1Offset);
        out.txChainMask = bytes[kChainMaskOffset] >> kHighNibbleShift;
        out.rxChainMask = bytes[kChainMaskOffset] & kHeaderMajorMask;
        out.operationFlags = bytes[kOperatingFlagsOffset];
        out.rfSilent = bytes[kRfSilentOffset];
        out.rfKillConfigured = (out.rfSilent & 1U) != 0;
        out.rfKillPolarity = (out.rfSilent & 2U) != 0;
        out.rfKillGpio =
            (static_cast<uint32_t>(out.rfSilent) & kRfSilentGpioMask) >>
            kRfSilentGpioShift;
        out.bluetoothOptions = bytes[kBluetoothOptionsOffset];
        out.wlanDisableGpio = bytes[kWlanDisableGpioOffset];
        out.txGainIndex = bytes[kGainIndexOffset] >> kHighNibbleShift;
        out.rxGainIndex = bytes[kGainIndexOffset] & kHeaderMajorMask;
        out.antennaControlCommon =
            readLittle32(bytes + kAntennaControlCommonOffset);
        out.antennaControlCommon2 =
            readLittle32(bytes + kAntennaControlCommon2Offset);
        out.antennaControlChain0 =
            readLittle16(bytes + kAntennaControlChain0Offset);
        // Explicit sign extension avoids implementation-defined
        // uint8_t->int8_t.
        out.antennaGainDb = signedByte(bytes[kAntennaGainOffset]);
        out.storedAntennaDiversity = bytes[kStoredAntennaDiversityOffset];
        // ath9k EEP_ANT_DIV_CTL1 overrides the EEPROM value for AR9565.
        out.ar9565AntennaDiversity = kAntennaDiversityOverride;
        copyBytes(out.calibrationFrequencyBins2G,
                  bytes + kCalibrationFrequencyBinsOffset,
                  sizeof(out.calibrationFrequencyBins2G));
        // The packed AR9300 layout places the single AR9565 chain's three
        // six-byte op-loop calibration records at byte 141. The Linux source
        // uses these separately for correction/temperature/voltage and gates
        // noise floor on rxTempMeas; report them without applying TPC values.
        for (size_t i = 0; i < kCalibrationPiers; ++i)
        {
            const uint8_t bin = out.calibrationFrequencyBins2G[i];
            const uint8_t *pier =
                bytes + kCalibrationPiersOffset + (i * kCalibrationPierBytes);
            auto &entry = out.calibrationPiers2G[i];
            entry.frequencyBin = bin;
            // Legal 2.4 GHz channel center frequencies span 2412..2484 MHz.
            // This is a structural bin sanity check, not regulatory approval.
            entry.centerMhz = bin >= kFirstTwoGigahertzPierBin &&
                                      bin <= kLastTwoGigahertzPierBin
                                  ? kPierFrequencyBaseMhz + bin
                                  : 0;
            entry.referencePower = signedByte(pier[0]);
            entry.voltageMeasurement = pier[1];
            entry.temperatureMeasurement = pier[2];
            entry.noiseFloorCalibrationRaw = signedByte(pier[3]);
            entry.noiseFloorPowerRaw = signedByte(pier[4]);
            entry.noiseTemperatureMeasurement = pier[kNoiseTemperatureOffset];
            entry.noiseMeasurementsPresent = pier[kNoiseTemperatureOffset] != 0;
        }
        out.calibrationPierBinsPlausible = plausiblePierGeometry(out);
        // No calibration, regulatory authority, power limit, RF-kill GPIO
        // sample, antenna routing or coexistence programming follows from
        // parsing bytes.
        out.calibrationValidated = false;
        out.regulatoryAuthorized = false;
        return EepromResult::Ok;
    }

    EepromResult selectBoardGainProfiles(const BoardDataSummary &board,
                                         TxGainProfile &tx, RxGainProfile &rx)
    {
        // Reject aliases before invalidating outputs: a one-byte gain output
        // may otherwise overwrite the board index or the other output.
        if (overlaps(&tx, sizeof(tx), &board, sizeof(board)) ||
            overlaps(&rx, sizeof(rx), &board, sizeof(board)) ||
            overlaps(&tx, sizeof(tx), &rx, sizeof(rx)))
        {
            return EepromResult::InvalidArgument;
        }
        // Never leave a prior valid gain selection in either output when the
        // board's index is unsupported. Unknown is rejected by the INI catalog.
        tx = TxGainProfile::Unknown;
        rx = RxGainProfile::Unknown;
        // A default-initialized or mutated diagnostic summary must not select
        // working radio gain tables merely because both index nibbles are zero.
        // This only checks structural provenance; it does not establish that
        // the NVM was acquired from the physical board or calibrated.
        if (board.eepromVersion != kSupportedFormat ||
            !validatePermanentMac(board.mac) ||
            isPinnedPlaceholderMac(board.mac) || board.txChainMask != 1 ||
            board.rxChainMask != 1 ||
            ((static_cast<uint32_t>(board.operationFlags) &
              kTwoGigahertzOperation) == 0U))
        {
            return EepromResult::InvalidBoardIdentity;
        }
        // A direct gain-map caller must not bypass discovery's structural
        // 2-GHz pier check. A raw summary is still only diagnostic and does
        // not make the board calibrated or regulatory-authorized.
        if (!board.calibrationPierBinsPlausible ||
            !plausiblePierGeometry(board))
        {
            return EepromResult::UnsupportedFormat;
        }
        // ar9003_hw.c mode0/mode2 both select AR9565 low-OB; mode1 is high-OB,
        // mode3 is high-power. The 1.1 header aliases these gains to 1.0
        // arrays. Higher generic indexes are not a verified AR9565 board
        // configuration.
        if (board.txGainIndex > 3 || board.rxGainIndex > 1)
        {
            return EepromResult::UnsupportedGainConfiguration;
        }
        TxGainProfile selectedTx = TxGainProfile::LowOb;
        if (board.txGainIndex == 1)
        {
            selectedTx = TxGainProfile::HighOb;
        }
        else if (board.txGainIndex == 3)
        {
            selectedTx = TxGainProfile::HighPower;
        }
        const RxGainProfile selectedRx = board.rxGainIndex == 1
                                             ? RxGainProfile::WithoutExternalLna
                                             : RxGainProfile::Standard;
        tx = selectedTx;
        rx = selectedRx;
        return EepromResult::Ok;
    }

    EepromResult calculateBoardCalibration2G(const BoardDataSummary &board,
                                             uint16_t channelMhz,
                                             BoardChannelCalibration2G &out)
    {
        if (overlaps(&board, sizeof(board), &out, sizeof(out)))
        {
            return EepromResult::InvalidArgument;
        }
        out = {};
        TxGainProfile tx = TxGainProfile::Unknown;
        RxGainProfile rx = RxGainProfile::Unknown;
        const EepromResult boardResult = selectBoardGainProfiles(board, tx, rx);
        if (boardResult != EepromResult::Ok)
        {
            return boardResult;
        }
        // Only exact mapped 2G channel centers, not arbitrary frequencies or
        // 5-GHz samples. The country/regulatory owner must still approve the
        // chosen channel and the radio must remain silent until then.
        bool supportedChannel = false;
        for (uint8_t number = 1; number <= 14; ++number)
        {
            Channel channel {};
            if (mapChannel(number, channel) == Result::Ok &&
                channel.centerMhz == channelMhz)
            {
                supportedChannel = true;
                break;
            }
        }
        if (!supportedChannel)
        {
            return EepromResult::UnsupportedChannel;
        }

        const auto *const piers = board.calibrationPiers2G;
        size_t lower = 0;
        size_t upper = kCalibrationPiers - 1;
        for (size_t i = 0; i < kCalibrationPiers; ++i)
        {
            if (piers[i].centerMhz <= channelMhz)
            {
                lower = i;
            }
            if (piers[i].centerMhz >= channelMhz)
            {
                upper = i;
                break;
            }
        }
        if (channelMhz <= piers[0].centerMhz)
        {
            lower = upper = 0;
        }
        else if (channelMhz >= piers[kCalibrationPiers - 1].centerMhz)
        {
            lower = upper = kCalibrationPiers - 1;
        }

        BoardChannelCalibration2G result {};
        result.channelMhz = channelMhz;
        result.lowerPierMhz = piers[lower].centerMhz;
        result.upperPierMhz = piers[upper].centerMhz;
        result.interpolated = lower != upper;
        if (result.interpolated)
        {
            const auto correction = interpolatePier(
                channelMhz, result.lowerPierMhz, result.upperPierMhz,
                piers[lower].referencePower, piers[upper].referencePower);
            const auto voltage = interpolatePier(
                channelMhz, result.lowerPierMhz, result.upperPierMhz,
                piers[lower].voltageMeasurement,
                piers[upper].voltageMeasurement);
            const auto temperature = interpolatePier(
                channelMhz, result.lowerPierMhz, result.upperPierMhz,
                piers[lower].temperatureMeasurement,
                piers[upper].temperatureMeasurement);
            result.referenceCorrection = static_cast<int16_t>(correction);
            result.voltageMeasurement = static_cast<uint8_t>(voltage);
            result.temperatureMeasurement = static_cast<uint8_t>(temperature);
        }
        else
        {
            result.referenceCorrection = piers[lower].referencePower;
            result.voltageMeasurement = piers[lower].voltageMeasurement;
            result.temperatureMeasurement = piers[lower].temperatureMeasurement;
        }
        out = result;
        return EepromResult::Ok;
    }

} // namespace simpleath
