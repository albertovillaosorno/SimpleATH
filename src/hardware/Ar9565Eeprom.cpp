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
#include "generated/Ar9300EepromTemplates.hpp"

namespace simpleath
{
    namespace
    {
        const uint8_t *findPinnedTemplate(void *, uint8_t reference,
                                          size_t *length)
        {
            if (!length)
                return nullptr;
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
            return static_cast<int8_t>(value < 128
                                           ? static_cast<int>(value)
                                           : static_cast<int>(value) - 256);
        }

        uint16_t le16(const uint8_t *p)
        {
            return static_cast<uint16_t>(p[0] |
                                         (static_cast<uint16_t>(p[1]) << 8));
        }

        uint32_t le32(const uint8_t *p)
        {
            return static_cast<uint32_t>(le16(p)) |
                   (static_cast<uint32_t>(le16(p + 2)) << 16);
        }

        void copyBytes(uint8_t *destination, const uint8_t *source,
                       size_t length)
        {
            for (size_t i = 0; i < length; ++i)
                destination[i] = source[i];
        }

        bool overlaps(const void *source, size_t length,
                      const void *destination, size_t destinationLength)
        {
            const auto src = reinterpret_cast<uintptr_t>(source);
            const auto dst = reinterpret_cast<uintptr_t>(destination);
            return length && destinationLength &&
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
        bool isPinnedPlaceholderMac(const uint8_t mac[6])
        {
            for (const auto &entry : eeprom_templates::kCatalog)
            {
                if (entry.length != kAr9300EepromImageBytes)
                    continue;
                bool matches = true;
                for (size_t i = 0; i < 6; ++i)
                    matches = matches && mac[i] == entry.bytes[2 + i];
                if (matches)
                    return true;
            }
            return false;
        }

        bool plausiblePierGeometry(const BoardDataSummary &board)
        {
            // The summary is public caller-owned data. The boolean cached by
            // summarizeBoardData is only a diagnostic hint: a direct gain
            // caller must verify the raw frequency bins and pier records.
            for (size_t i = 0; i < 3; ++i)
            {
                const uint8_t bin = board.calibrationFrequencyBins2G[i];
                const BoardCalibrationPier2G &pier =
                    board.calibrationPiers2G[i];
                if (bin < 112 || bin > 184 ||
                    (i != 0 &&
                     bin <= board.calibrationFrequencyBins2G[i - 1]) ||
                    pier.frequencyBin != bin ||
                    pier.centerMhz != static_cast<uint16_t>(2300u + bin))
                    return false;
            }
            return true;
        }

        // Unlike upstream's permissive restoration, reject truncated records
        // and propagate every bounds failure. Validate the ENTIRE delta before
        // applying.
        bool validDelta(const uint8_t *payload, size_t length)
        {
            size_t cursor = 0, spot = 0;
            while (cursor < length)
            {
                if (length - cursor < 2)
                    return false;
                const size_t skip = payload[cursor++];
                const size_t count = payload[cursor++];
                if (skip > kAr9300EepromImageBytes - spot)
                    return false;
                spot += skip;
                if (count > length - cursor ||
                    count > kAr9300EepromImageBytes - spot)
                    return false;
                cursor += count;
                spot += count;
            }
            return true;
        }
    } // namespace

    void discardEepromImage(EepromImage &image)
    {
        for (size_t i = 0; i < sizeof(image.bytes); ++i)
            image.bytes[i] = 0;
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
            return EepromResult::InvalidArgument;
        info = {};
        if (!frame)
            return EepromResult::InvalidArgument;
        if (overlapsImage(frame, frameBytes, image))
            return EepromResult::InvalidArgument;
        if (frameBytes < 4)
            return EepromResult::TruncatedBlock;
        if (le32(frame) == 0 || le32(frame) == 0xffffffffu)
            return EepromResult::EmptyHeader;
        info.compression = (frame[0] >> 5) & 7u;
        info.reference = (frame[0] & 0x1fu) | ((frame[1] >> 2) & 0x20u);
        info.payloadBytes = static_cast<uint16_t>(
            ((static_cast<uint16_t>(frame[1]) << 4) & 0x7f0u) |
            (frame[2] >> 4));
        info.major = frame[2] & 0x0fu;
        info.minor = frame[3];
        const size_t length = info.payloadBytes;
        if (frameBytes != length + 6)
            return EepromResult::TruncatedBlock;
        // Callers must start from a discarded/zero-initialized image. A
        // restored flag without an applied block (or vice versa) must not
        // authorize a reference-free delta to use stale board data.
        if (image.appliedBlocks >= 100 ||
            image.restored != (image.appliedBlocks != 0))
            return EepromResult::InvalidArgument;
        uint16_t checksum = 0;
        for (size_t i = 0; i < length; ++i)
            checksum = static_cast<uint16_t>(checksum + frame[4 + i]);
        if (checksum != le16(frame + 4 + length))
            return EepromResult::BadChecksum;
        const uint8_t *payload = frame + 4;
        if (info.compression == 0)
        {
            if (length != sizeof(image.bytes))
                return EepromResult::WrongImageSize;
            copyBytes(image.bytes, payload, length);
        }
        else if (info.compression == 3)
        {
            if (!validDelta(payload, length))
                return EepromResult::InvalidDelta;
            const uint8_t *base = nullptr;
            if (info.reference)
            {
                size_t baseLength = 0;
                if (templates.find)
                    base = templates.find(templates.context, info.reference,
                                          &baseLength);
                if (!base || baseLength != sizeof(image.bytes))
                    return EepromResult::MissingTemplate;
                // The callback's returned base is separately borrowed from
                // its context. A forged 1088-byte length cannot turn a short
                // verified delta or our own metadata into trusted template
                // data, nor let its copy read beyond those allocations.
                // Check known aliases before even reading the template ID.
                if (overlaps(base, baseLength, frame, frameBytes) ||
                    overlaps(base, baseLength, &templates, sizeof(templates)) ||
                    overlaps(base, baseLength, &info, sizeof(info)) ||
                    overlapsImage(base, baseLength, image))
                    return EepromResult::InvalidArgument;
                if (base[1] != info.reference)
                    return EepromResult::MissingTemplate;
            }
            else if (!image.restored)
            {
                return EepromResult::MissingBaseImage;
            }
            if (base)
                copyBytes(image.bytes, base, sizeof(image.bytes));
            size_t cursor = 0, spot = 0;
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
            return EepromResult::InvalidArgument;
        // No frame-sized allocation is made on the kernel stack.
        status = {};
        status.origin = origin;
        status.nextAddress = origin;
        if (!storage || !scratch || storageBytes > 16384 ||
            origin >= storageBytes ||
            scratchBytes < kAr9565EepromScratchBytes ||
            (origin != 0x3ff && origin != 0xfff && origin != 0x1ff))
        {
            discardEepromImage(image);
            return status.result = EepromResult::InvalidArgument;
        }
        discardEepromImage(image);
        size_t remaining = static_cast<size_t>(origin) + 1;
        while (remaining)
        {
            status.nextAddress = static_cast<uint16_t>(remaining - 1);
            if (remaining < 4)
            {
                discardEepromImage(image);
                return status.result = EepromResult::TruncatedBlock;
            }
            for (size_t i = 0; i < 4; ++i)
                scratch[i] = storage[remaining - 1 - i];
            const uint32_t header = le32(scratch);
            if (header == 0 || header == 0xffffffffu)
            {
                // Erased padding terminates a chain only after a recovered
                // block.
                if (image.restored)
                    return status.result = EepromResult::Ok;
                return status.result = EepromResult::EmptyHeader;
            }
            const size_t payloadBytes =
                ((static_cast<size_t>(scratch[1]) << 4) & 0x7f0u) |
                (scratch[2] >> 4);
            const size_t frameBytes = payloadBytes + 6;
            // ath9k's non-AR9485 (including AR9565) storage-chain limit is
            // <1024. Do not resynchronize past corrupt headers into arbitrary
            // NVM bytes.
            if (payloadBytes >= 1024 || frameBytes > remaining)
            {
                discardEepromImage(image);
                return status.result = EepromResult::TruncatedBlock;
            }
            for (size_t i = 4; i < frameBytes; ++i)
                scratch[i] = storage[remaining - 1 - i];
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
            return EepromResult::InvalidArgument;
        out = {};
        if (!image.restored || image.appliedBlocks == 0)
            return EepromResult::MissingBaseImage;
        const auto bytes = image.bytes;
        // ar9300_eeprom packed layout: prefix 28, base header 25, 2G modal 71,
        // base extension 14, 2G pier frequencies at 138. Never cast packed
        // data.
        if (bytes[0] != 2 || (bytes[34] & 1u))
            return EepromResult::UnsupportedFormat;
        // AR9565 has one TX/RX chain. Generic 0x77 template masks are not a
        // recovered AR9565 board identity. This is still only a structural
        // check.
        if (!validatePermanentMac(bytes + 2) || bytes[32] != 0x11 ||
            !(bytes[33] & 0x02u))
            return EepromResult::InvalidBoardIdentity;
        out.eepromVersion = bytes[0];
        out.templateVersion = bytes[1];
        copyBytes(out.mac, bytes + 2, sizeof(out.mac));
        out.regulatoryDomains[0] = le16(bytes + 28);
        out.regulatoryDomains[1] = le16(bytes + 30);
        out.txChainMask = bytes[32] >> 4;
        out.rxChainMask = bytes[32] & 0x0fu;
        out.operationFlags = bytes[33];
        out.rfSilent = bytes[35];
        out.rfKillConfigured = (out.rfSilent & 1u) != 0;
        out.rfKillPolarity = (out.rfSilent & 2u) != 0;
        out.rfKillGpio = (out.rfSilent & 0xfcu) >> 2;
        out.bluetoothOptions = bytes[36];
        out.wlanDisableGpio = bytes[45];
        out.txGainIndex = bytes[48] >> 4;
        out.rxGainIndex = bytes[48] & 0x0fu;
        out.antennaControlCommon = le32(bytes + 53);
        out.antennaControlCommon2 = le32(bytes + 57);
        out.antennaControlChain0 = le16(bytes + 61);
        // Explicit sign extension avoids implementation-defined
        // uint8_t->int8_t.
        out.antennaGainDb = signedByte(bytes[99]);
        out.storedAntennaDiversity = bytes[124];
        // ath9k EEP_ANT_DIV_CTL1 overrides the EEPROM value for AR9565.
        out.ar9565AntennaDiversity = 0xc9;
        copyBytes(out.calibrationFrequencyBins2G, bytes + 138,
                  sizeof(out.calibrationFrequencyBins2G));
        // The packed AR9300 layout places the single AR9565 chain's three
        // six-byte op-loop calibration records at byte 141. The Linux source
        // uses these separately for correction/temperature/voltage and gates
        // noise floor on rxTempMeas; report them without applying TPC values.
        for (size_t i = 0; i < 3; ++i)
        {
            const uint8_t bin = out.calibrationFrequencyBins2G[i];
            const uint8_t *pier = bytes + 141 + i * 6;
            auto &entry = out.calibrationPiers2G[i];
            entry.frequencyBin = bin;
            // Legal 2.4 GHz channel center frequencies span 2412..2484 MHz.
            // This is a structural bin sanity check, not regulatory approval.
            entry.centerMhz = bin >= 112 && bin <= 184 ? 2300u + bin : 0;
            entry.referencePower = signedByte(pier[0]);
            entry.voltageMeasurement = pier[1];
            entry.temperatureMeasurement = pier[2];
            entry.noiseFloorCalibrationRaw = signedByte(pier[3]);
            entry.noiseFloorPowerRaw = signedByte(pier[4]);
            entry.noiseTemperatureMeasurement = pier[5];
            entry.noiseMeasurementsPresent = pier[5] != 0;
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
            return EepromResult::InvalidArgument;
        // Never leave a prior valid gain selection in either output when the
        // board's index is unsupported. Unknown is rejected by the INI catalog.
        tx = TxGainProfile::Unknown;
        rx = RxGainProfile::Unknown;
        // A default-initialized or mutated diagnostic summary must not select
        // working radio gain tables merely because both index nibbles are zero.
        // This only checks structural provenance; it does not establish that
        // the NVM was acquired from the physical board or calibrated.
        if (board.eepromVersion != 2 || !validatePermanentMac(board.mac) ||
            isPinnedPlaceholderMac(board.mac) || board.txChainMask != 1 ||
            board.rxChainMask != 1 || !(board.operationFlags & 0x02u))
            return EepromResult::InvalidBoardIdentity;
        // A direct gain-map caller must not bypass discovery's structural
        // 2-GHz pier check. A raw summary is still only diagnostic and does
        // not make the board calibrated or regulatory-authorized.
        if (!board.calibrationPierBinsPlausible ||
            !plausiblePierGeometry(board))
            return EepromResult::UnsupportedFormat;
        // ar9003_hw.c mode0/mode2 both select AR9565 low-OB; mode1 is high-OB,
        // mode3 is high-power. The 1.1 header aliases these gains to 1.0
        // arrays. Higher generic indexes are not a verified AR9565 board
        // configuration.
        if (board.txGainIndex > 3 || board.rxGainIndex > 1)
            return EepromResult::UnsupportedGainConfiguration;
        const TxGainProfile selectedTx =
            board.txGainIndex == 1   ? TxGainProfile::HighOb
            : board.txGainIndex == 3 ? TxGainProfile::HighPower
                                     : TxGainProfile::LowOb;
        const RxGainProfile selectedRx = board.rxGainIndex == 1
                                             ? RxGainProfile::WithoutExternalLna
                                             : RxGainProfile::Standard;
        tx = selectedTx;
        rx = selectedRx;
        return EepromResult::Ok;
    }

} // namespace simpleath
