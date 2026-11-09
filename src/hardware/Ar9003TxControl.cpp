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

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace edma
    {
        static constexpr uint8_t kHtMcs0 = 0x80U;
        static constexpr uint8_t kHtMcs7 = 0x87U;
        static constexpr uint32_t kInfoVendor = 0x168c0000U;
        static constexpr uint8_t kMaximumQcu = 9U;

        static bool overlapsStorage(const void *const first, size_t firstBytes,
                                    const void *const second,
                                    size_t secondBytes)
        {
            const auto left = reinterpret_cast<uintptr_t>(first);
            const auto right = reinterpret_cast<uintptr_t>(second);
            return firstBytes != 0 && secondBytes != 0 &&
                   (left >= right ? left - right < secondBytes
                                  : right - left < firstBytes);
        }

        static bool packetTypeValid(TxPacketType type)
        {
            return type == TxPacketType::Normal ||
                   type == TxPacketType::Beacon ||
                   type == TxPacketType::ProbeResponse;
        }

        static bool legacyRateValid(uint8_t code)
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

        static bool htRateValid(uint8_t code)
        {
            // AR9565 is 1x1: only MCS0..7 is representable.
            return code >= kHtMcs0 && code <= kHtMcs7;
        }

        TxControlError encodeTxControls(const TxControlRequest &request,
                                        const TxSafetyPolicy &policy,
                                        TxDescriptor &descriptor)
        {
            // Control encoding must not overwrite its request or policy.
            if (overlapsStorage(&request, sizeof(request), &descriptor,
                                sizeof(descriptor)) ||
                overlapsStorage(&policy, sizeof(policy), &descriptor,
                                sizeof(descriptor)))
            {
                return TxControlError::OverlappingBuffers;
            }
            // A vendor tag and valid checksum alone do not prove that any
            // bounded payload pointer was prepared by the pointer codec.
            if (!validTxPointerDescriptor(descriptor))
            {
                return TxControlError::UninitializedPointerDescriptor;
            }
            // Only standalone, nonaggregated 802.11 MPDUs are represented by
            // this codec. A 12-bit hardware length field is not permission to
            // emit jumbo frames without a reviewed aggregation/fragment path.
            // ACK and CTS have the shortest 802.11 MAC header (ten bytes).
            // The radio generates a further four FCS bytes on air. A matching
            // pointer/payload length cannot authorize a shorter frame.
            constexpr uint16_t kMinimumMpduBytesIncludingFcs = 14U;
            constexpr uint16_t kMaximumMpduBytesIncludingFcs = 2346U;
            if (request.onAirFrameLength < kMinimumMpduBytesIncludingFcs ||
                request.onAirFrameLength > kMaximumMpduBytesIncludingFcs)
            {
                return TxControlError::FrameLengthInvalid;
            }

            // The validated pointer descriptor carries at most four
            // nonaggregated DMA payload segments. Its control word must
            // describe those mapped bytes, including the 4-byte FCS the
            // radio appends. Linux ath9k beacon.c maps roundup(skb->len, 4)
            // while announcing skb->len + FCS_LEN on air: only Beacon may
            // carry 0..3 octets of mapped DMA tail padding. That padding
            // must be initialized by the future hardware owner.
            constexpr uint32_t kHardwareFcsBytes = 4U;
            uint32_t mappedPayloadBytes = 0;
            for (size_t slot = 0; slot < 4; ++slot)
            {
                mappedPayloadBytes += descriptor.word[3U + 2U * slot] >> 16U;
            }
            const uint32_t payloadBytes =
                static_cast<uint32_t>(request.onAirFrameLength) -
                kHardwareFcsBytes;
            const uint32_t expectedMappedBytes =
                request.packetType == TxPacketType::Beacon
                    ? (payloadBytes + 3U) & ~3U
                    : payloadBytes;
            if (mappedPayloadBytes != expectedMappedBytes)
            {
                return TxControlError::FrameLengthInvalid;
            }

            if (!policy.siliconIdentified ||
                !policy.boardCalibrationValidated ||
                !policy.channelRegulatoryAuthorized ||
                !policy.transmitPowerLimitsValidated)
            {
                return TxControlError::RegulatoryNotVerified;
            }
            if (!policy.radioAwake || !policy.rfKillUnblocked ||
                !policy.dmaMappingValid)
            {
                return TxControlError::RadioNotReady;
            }
            if (!packetTypeValid(request.packetType) ||
                (request.rts && request.cts) ||
                ((request.rts || request.cts)
                     ? !legacyRateValid(request.rtsCtsRateCode)
                     : request.rtsCtsRateCode != 0))
            {
                return TxControlError::UnsupportedControl;
            }
            if (request.crypto != TxCrypto::Clear &&
                request.crypto != TxCrypto::Ccmp)
            {
                return TxControlError::UnsupportedCipher;
            }
            // Beacon and Probe Response are ordinary unprotected management
            // frames. CCMP is for authorized data; PMF/BIP protection needs
            // an independently implemented management-frame path, not the
            // encrypted-data/keycache bit in this AR9565 TX descriptor.
            if (request.packetType != TxPacketType::Normal &&
                request.crypto != TxCrypto::Clear)
            {
                return TxControlError::UnsupportedCipher;
            }
            // Beacons are broadcast management announcements. They cannot
            // solicit ACKs or an RTS/CTS exchange, irrespective of whether
            // the caller marked the radio and policy fields as ready.
            if (request.packetType == TxPacketType::Beacon &&
                (!request.noAck || request.rts || request.cts ||
                 request.rate[0].attempts != 1 ||
                 request.rate[1].attempts != 0 ||
                 request.rate[2].attempts != 0 ||
                 request.rate[3].attempts != 0))
            {
                // Broadcast Beacon has no ACK-driven retransmission: exactly
                // one attempt with one legacy rate, as in ath9k beacon.c.
                return TxControlError::UnsupportedControl;
            }
            if (request.crypto == TxCrypto::Clear &&
                request.keyCacheIndex != 0xffU)
            {
                return TxControlError::UnsupportedCipher;
            }
            if (request.crypto == TxCrypto::Ccmp &&
                (!policy.hardwareKeyInstalled || request.keyCacheIndex >= 128U))
            {
                return TxControlError::KeyUnavailable;
            }

            uint32_t tries = 0;
            uint32_t rates = 0;
            uint32_t durations[2] {};
            uint32_t rateFlags = static_cast<uint32_t>(request.rtsCtsRateCode)
                                 << 20U;
            uint32_t powers[4] {};
            bool foundGap = false;
            if (request.rate[0].attempts == 0)
            {
                return TxControlError::InvalidRate;
            }

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
                    {
                        return TxControlError::InvalidRate;
                    }
                    continue;
                }
                if (foundGap || series.attempts > 15 || series.rateCode == 0)
                {
                    return TxControlError::InvalidRate;
                }
                // This target is AR9565, not a generic 2/3-chain AR9003.
                // Reject unsupported stream/rate combinations even if a
                // caller manufactures every radio-ready policy boolean.
                if (series.antennaChainMask != 1)
                {
                    return TxControlError::InvalidChain;
                }
                const bool htRate = htRateValid(series.rateCode);
                // Both Beacon and Probe Response are emitted before the
                // recipient's HT capabilities are negotiated. Management TX
                // must use a legacy PHY rate that a scanning STA can decode.
                if (request.packetType != TxPacketType::Normal && htRate)
                {
                    return TxControlError::UnsupportedControl;
                }
                if (!htRate && !legacyRateValid(series.rateCode))
                {
                    return TxControlError::InvalidRate;
                }
                if (series.stbc ||
                    (!htRate && (series.ht40 || series.shortGuardInterval)))
                {
                    return TxControlError::UnsupportedControl;
                }
                if (series.rtsCtsDuration > 0x7fffU)
                {
                    return TxControlError::InvalidDuration;
                }
                if (series.powerIndex > 63U ||
                    series.powerIndex > policy.maximumTxPowerIndex[i])
                {
                    return TxControlError::InvalidPower;
                }
                if ((series.ht40 && !policy.ht40Authorized) ||
                    (series.shortGuardInterval &&
                     !policy.shortGuardIntervalAuthorized) ||
                    (series.stbc && !policy.stbcSupported))
                {
                    return TxControlError::UnsupportedControl;
                }
                if (series.rtsCtsQualified && !request.rts && !request.cts)
                {
                    return TxControlError::UnsupportedControl;
                }

                tries |= static_cast<uint32_t>(series.attempts)
                         << (16U + 4U * i);
                rates |= static_cast<uint32_t>(series.rateCode) << (8U * i);
                const uint32_t durationSlot =
                    (static_cast<uint32_t>(series.rtsCtsDuration) |
                     (series.rtsCtsQualified ? 0x8000U : 0U));
                durations[i / 2U] |= durationSlot << (16U * (i & 1U));
                if (series.ht40)
                {
                    rateFlags |= 1U << (5U * i);
                }
                if (series.shortGuardInterval)
                {
                    rateFlags |= 1U << (5U * i + 1U);
                }
                rateFlags |= static_cast<uint32_t>(series.antennaChainMask)
                             << (5U * i + 2U);
                if (series.stbc)
                {
                    rateFlags |= 1U << (28U + i);
                }
                powers[i] = static_cast<uint32_t>(series.powerIndex);
            }
            if (request.durationUpdate)
            {
                tries |= 0x00008000U;
            }

            // Commit only after all validation. Pointer/checksum fields remain
            // untouched, because ar9003_mac.c excludes ctl11..23 from the
            // pointer checksum. The platform must synchronize the descriptor
            // before DMA.
            TxDescriptor staged = descriptor;
            staged.word[11] =
                (static_cast<uint32_t>(request.onAirFrameLength) & 0xfffU) |
                (powers[0] << 16U) | (request.rts ? 0x00400000U : 0U) |
                (request.cts ? 0x80000000U : 0U) |
                (request.crypto != TxCrypto::Clear ? 0x40000000U : 0U);
            staged.word[12] =
                (request.crypto != TxCrypto::Clear
                     ? static_cast<uint32_t>(request.keyCacheIndex) << 13U
                     : 0U) |
                (static_cast<uint32_t>(request.packetType) << 20U) |
                (request.noAck ? 0x01000000U : 0U);
            staged.word[13] = tries;
            staged.word[14] = rates;
            staged.word[15] = durations[0];
            staged.word[16] = durations[1];
            staged.word[17] = static_cast<uint32_t>(request.crypto) << 26U;
            staged.word[18] = rateFlags;
            staged.word[19] = 0x20000000U; // AR_Not_Sounding
            staged.word[20] = powers[1] << 24U;
            staged.word[21] = powers[2] << 24U;
            staged.word[22] = powers[3] << 24U;
            staged.word[23] = 0U;
            descriptor = staged;
            return TxControlError::Ok;
        }

        DescriptorError decodeTxCompletion(const TxCompletionWords &raw,
                                           TxCompletion &out)
        {
            // A DMA status ring cannot be zeroed by a forged output alias.
            if (overlapsStorage(&raw, sizeof(raw), &out, sizeof(out)))
            {
                return DescriptorError::OverlappingBuffers;
            }
            // The ring status may still hold an earlier result. Never leave
            // a valid-looking prior completion after any ordinary failure.
            out = {};
            // ath9k checks AR_TxDone before inspecting ds_info; an unfilled
            // status slot is pending, not evidence of a wrong PCI vendor.
            const uint32_t final = raw.word[8];
            if ((final & 1U) == 0)
            {
                return DescriptorError::Incomplete;
            }
            const uint32_t info = raw.word[0];
            if ((info & 0xffff0000U) != kInfoVendor || (info & 0x8000U) == 0)
            {
                return DescriptorError::InvalidVendor;
            }

            TxCompletion complete {};
            complete.queue = static_cast<uint8_t>((info >> 8U) & 0x0fU);
            if (complete.queue > kMaximumQcu)
            {
                return DescriptorError::CorruptStatus;
            }
            complete.finalRateSeries =
                static_cast<uint8_t>((final >> 21U) & 3U);
            complete.sequenceNumber =
                static_cast<uint16_t>((final >> 1U) & 0x0fffU);
            complete.timestamp = raw.word[4];
            const uint32_t flags = raw.word[3];
            complete.frameTransmitOk = (flags & 0x00000001U) != 0;
            complete.excessiveRetries = (flags & 0x00000002U) != 0;
            complete.fifoUnderrun = (flags & 0x00000004U) != 0;
            complete.filtered = (flags & 0x00000008U) != 0;
            complete.delimiterUnderrun = (flags & 0x00010000U) != 0;
            complete.dataUnderrun = (flags & 0x00020000U) != 0;
            complete.configError = (flags & 0x00040000U) != 0;
            complete.expired = (flags & 0x00080000U) != 0;
            complete.txOpportunityExceeded = (final & 0x00020000U) != 0;
            complete.shortRetries = static_cast<uint8_t>((flags >> 4U) & 0xfU);
            complete.longRetries = static_cast<uint8_t>((flags >> 8U) & 0xfU);
            // AR_FrmXmitOK is a terminal success. A DMA status also claiming
            // exhausted retries, FIFO underrun, filtering,
            // configuration/expiry failure, or TXOP exhaustion is incoherent;
            // a forged status must not become successful TX completion.
            if (complete.frameTransmitOk &&
                (complete.excessiveRetries || complete.fifoUnderrun ||
                 complete.filtered || complete.configError ||
                 complete.expired || complete.txOpportunityExceeded))
            {
                return DescriptorError::CorruptStatus;
            }
            out = complete;
            return DescriptorError::Ok;
        }

    } // namespace edma
} // namespace simpleath
