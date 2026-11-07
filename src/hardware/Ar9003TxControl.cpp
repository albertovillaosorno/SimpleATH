// SPDX-License-Identifier: AGPL-3.0-only
// Hardware descriptor field reference: Linux ath9k ar9003_mac.c / mac.h.
// Linux reference copyrights and licensing are reproduced for provenance.
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
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
// Reference SHA-256:
// ar9003_mac.c:
// a99f8fb18052510161232331e5fc98757619713e6f2ad69d1897f77597c0188b mac.h:
// 10025cb48d6443f8c21a841326742562b6394a6df820c1499a5370f059ed9cd9
#include "Ar9003TxControl.hpp"

namespace simpleath
{
    namespace edma
    {
        namespace
        {

            constexpr uint32_t kInfoVendor = 0x168c0000u;
            constexpr uint8_t kMaximumQcu = 9u;

            bool overlapsStorage(const void *first, size_t firstBytes,
                                 const void *second, size_t secondBytes)
            {
                const auto left = reinterpret_cast<uintptr_t>(first);
                const auto right = reinterpret_cast<uintptr_t>(second);
                return firstBytes && secondBytes &&
                       (left >= right ? left - right < secondBytes
                                      : right - left < firstBytes);
            }

            bool packetTypeValid(TxPacketType type)
            {
                return type == TxPacketType::Normal ||
                       type == TxPacketType::Beacon ||
                       type == TxPacketType::ProbeResponse;
            }

            bool legacyRateValid(uint8_t code)
            {
                switch (code)
                {
                    case 0x1b:
                    case 0x1a:
                    case 0x19:
                    case 0x1e:
                    case 0x1d:
                    case 0x18:
                    case 0x1c:
                    case 0x0b:
                    case 0x0f:
                    case 0x0a:
                    case 0x0e:
                    case 0x09:
                    case 0x0d:
                    case 0x08:
                    case 0x0c:
                        return true;
                    default:
                        return false;
                }
            }

            bool htRateValid(uint8_t code)
            {
                // AR9565 is 1x1: only MCS0..7 is representable.
                return code >= 0x80u && code <= 0x87u;
            }

        } // namespace

        TxControlError encodeTxControls(const TxControlRequest &request,
                                        const TxSafetyPolicy &policy,
                                        TxDescriptor &descriptor)
        {
            // Control encoding must not overwrite its request or policy.
            if (overlapsStorage(&request, sizeof(request), &descriptor,
                                sizeof(descriptor)) ||
                overlapsStorage(&policy, sizeof(policy), &descriptor,
                                sizeof(descriptor)))
                return TxControlError::OverlappingBuffers;
            // A vendor tag and valid checksum alone do not prove that any
            // bounded payload pointer was prepared by the pointer codec.
            if (!validTxPointerDescriptor(descriptor))
                return TxControlError::UninitializedPointerDescriptor;
            if (request.onAirFrameLength == 0 ||
                request.onAirFrameLength > 0x0fffu)
                return TxControlError::FrameLengthInvalid;

            if (!policy.siliconIdentified ||
                !policy.boardCalibrationValidated ||
                !policy.channelRegulatoryAuthorized ||
                !policy.transmitPowerLimitsValidated)
                return TxControlError::RegulatoryNotVerified;
            if (!policy.radioAwake || !policy.rfKillUnblocked ||
                !policy.dmaMappingValid)
                return TxControlError::RadioNotReady;
            if (!packetTypeValid(request.packetType) ||
                (request.rts && request.cts) ||
                ((request.rts || request.cts)
                     ? !legacyRateValid(request.rtsCtsRateCode)
                     : request.rtsCtsRateCode != 0))
                return TxControlError::UnsupportedControl;
            if (request.crypto != TxCrypto::Clear &&
                request.crypto != TxCrypto::Ccmp)
                return TxControlError::UnsupportedCipher;
            if (request.crypto == TxCrypto::Clear &&
                request.keyCacheIndex != 0xffu)
                return TxControlError::UnsupportedCipher;
            if (request.crypto == TxCrypto::Ccmp &&
                (!policy.hardwareKeyInstalled || request.keyCacheIndex >= 128u))
                return TxControlError::KeyUnavailable;

            uint32_t tries = 0;
            uint32_t rates = 0;
            uint32_t durations[2] {};
            uint32_t rateFlags = static_cast<uint32_t>(request.rtsCtsRateCode)
                                 << 20u;
            uint32_t powers[4] {};
            bool foundGap = false;
            if (request.rate[0].attempts == 0)
                return TxControlError::InvalidRate;

            for (size_t i = 0; i < 4; ++i)
            {
                const TxRate &series = request.rate[i];
                if (series.attempts == 0)
                {
                    foundGap = true;
                    // Don't allow phantom rates or unchecked power/flags in a
                    // gap.
                    if (series.rateCode != 0 || series.rtsCtsDuration != 0 ||
                        series.antennaChainMask != 0 ||
                        series.powerIndex != 0 || series.ht40 ||
                        series.shortGuardInterval || series.stbc ||
                        series.rtsCtsQualified)
                        return TxControlError::InvalidRate;
                    continue;
                }
                if (foundGap || series.attempts > 15 || series.rateCode == 0)
                    return TxControlError::InvalidRate;
                // This target is AR9565, not a generic 2/3-chain AR9003.
                // Reject unsupported stream/rate combinations even if a
                // caller manufactures every radio-ready policy boolean.
                if (series.antennaChainMask != 1)
                    return TxControlError::InvalidChain;
                const bool htRate = htRateValid(series.rateCode);
                if (!htRate && !legacyRateValid(series.rateCode))
                    return TxControlError::InvalidRate;
                if (series.stbc ||
                    (!htRate && (series.ht40 || series.shortGuardInterval)))
                    return TxControlError::UnsupportedControl;
                if (series.rtsCtsDuration > 0x7fffu)
                    return TxControlError::InvalidDuration;
                if (series.powerIndex > 63u ||
                    series.powerIndex > policy.maximumTxPowerIndex[i])
                    return TxControlError::InvalidPower;
                if ((series.ht40 && !policy.ht40Authorized) ||
                    (series.shortGuardInterval &&
                     !policy.shortGuardIntervalAuthorized) ||
                    (series.stbc && !policy.stbcSupported))
                    return TxControlError::UnsupportedControl;
                if (series.rtsCtsQualified && !request.rts && !request.cts)
                    return TxControlError::UnsupportedControl;

                tries |= static_cast<uint32_t>(series.attempts)
                         << (16u + 4u * i);
                rates |= static_cast<uint32_t>(series.rateCode) << (8u * i);
                const uint32_t durationSlot =
                    (static_cast<uint32_t>(series.rtsCtsDuration) |
                     (series.rtsCtsQualified ? 0x8000u : 0u));
                durations[i / 2u] |= durationSlot << (16u * (i & 1u));
                if (series.ht40)
                    rateFlags |= 1u << (5u * i);
                if (series.shortGuardInterval)
                    rateFlags |= 1u << (5u * i + 1u);
                rateFlags |= static_cast<uint32_t>(series.antennaChainMask)
                             << (5u * i + 2u);
                if (series.stbc)
                    rateFlags |= 1u << (28u + i);
                powers[i] = static_cast<uint32_t>(series.powerIndex);
            }
            if (request.durationUpdate)
                tries |= 0x00008000u;

            // Commit only after all validation. Pointer/checksum fields remain
            // untouched, because ar9003_mac.c excludes ctl11..23 from the
            // pointer checksum. The platform must synchronize the descriptor
            // before DMA.
            TxDescriptor staged = descriptor;
            staged.word[11] =
                (static_cast<uint32_t>(request.onAirFrameLength) & 0xfffu) |
                (powers[0] << 16u) | (request.rts ? 0x00400000u : 0u) |
                (request.cts ? 0x80000000u : 0u) |
                (request.crypto != TxCrypto::Clear ? 0x40000000u : 0u);
            staged.word[12] =
                (request.crypto != TxCrypto::Clear
                     ? static_cast<uint32_t>(request.keyCacheIndex) << 13u
                     : 0u) |
                (static_cast<uint32_t>(request.packetType) << 20u) |
                (request.noAck ? 0x01000000u : 0u);
            staged.word[13] = tries;
            staged.word[14] = rates;
            staged.word[15] = durations[0];
            staged.word[16] = durations[1];
            staged.word[17] = static_cast<uint32_t>(request.crypto) << 26u;
            staged.word[18] = rateFlags;
            staged.word[19] = 0x20000000u; // AR_Not_Sounding
            staged.word[20] = powers[1] << 24u;
            staged.word[21] = powers[2] << 24u;
            staged.word[22] = powers[3] << 24u;
            staged.word[23] = 0u;
            descriptor = staged;
            return TxControlError::Ok;
        }

        DescriptorError decodeTxCompletion(const TxCompletionWords &raw,
                                           TxCompletion &out)
        {
            // A DMA status ring cannot be zeroed by a forged output alias.
            if (overlapsStorage(&raw, sizeof(raw), &out, sizeof(out)))
                return DescriptorError::OverlappingBuffers;
            // The ring status may still hold an earlier result. Never leave
            // a valid-looking prior completion after any ordinary failure.
            out = {};
            // ath9k checks AR_TxDone before inspecting ds_info; an unfilled
            // status slot is pending, not evidence of a wrong PCI vendor.
            const uint32_t final = raw.word[8];
            if ((final & 1u) == 0)
                return DescriptorError::Incomplete;
            const uint32_t info = raw.word[0];
            if ((info & 0xffff0000u) != kInfoVendor || (info & 0x8000u) == 0)
                return DescriptorError::InvalidVendor;

            TxCompletion complete {};
            complete.queue = static_cast<uint8_t>((info >> 8u) & 0x0fu);
            if (complete.queue > kMaximumQcu)
                return DescriptorError::CorruptStatus;
            complete.finalRateSeries =
                static_cast<uint8_t>((final >> 21u) & 3u);
            complete.sequenceNumber =
                static_cast<uint16_t>((final >> 1u) & 0x0fffu);
            complete.timestamp = raw.word[4];
            const uint32_t flags = raw.word[3];
            complete.frameTransmitOk = (flags & 0x00000001u) != 0;
            complete.excessiveRetries = (flags & 0x00000002u) != 0;
            complete.fifoUnderrun = (flags & 0x00000004u) != 0;
            complete.filtered = (flags & 0x00000008u) != 0;
            complete.configError = (flags & 0x00040000u) != 0;
            complete.expired = (flags & 0x00080000u) != 0;
            complete.txOpportunityExceeded = (final & 0x00020000u) != 0;
            complete.shortRetries = static_cast<uint8_t>((flags >> 4u) & 0xfu);
            complete.longRetries = static_cast<uint8_t>((flags >> 8u) & 0xfu);
            out = complete;
            return DescriptorError::Ok;
        }

    } // namespace edma
} // namespace simpleath
