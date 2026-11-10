// SPDX-License-Identifier: GPL-2.0-only
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
#include "Ar9003Descriptors.hpp"

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

        // AR9003 TX pointer, control, and status word layouts. Keep these
        // names tied to their hardware roles, not to incidental literals.
        static constexpr uint32_t kSegmentLengthWordBase = 3U;
        static constexpr uint32_t kSegmentWordStride = 2U;
        static constexpr uint32_t kHighHalfShift = 16U;
        static constexpr uint32_t kByteShift = 8U;
        static constexpr uint32_t kNibbleShift = 4U;
        static constexpr uint32_t kNibbleMask = 0x0fU;
        static constexpr uint32_t kTwelveBitMask = 0x0fffU;
        static constexpr uint32_t kBeaconMappingAlignmentMask = 3U;
        static constexpr uint32_t kNoEncryptionKeyIndex = 0xffU;
        static constexpr uint32_t kKeyCacheEntries = 128U;
        static constexpr uint32_t kRtsCtsControlRateShift = 20U;
        static constexpr uint32_t kRtsCtsDurationMax = 0x7fffU;
        static constexpr uint32_t kHardwarePowerIndexMax = 63U;
        static constexpr uint32_t kRetryAttemptsMax = 15U;
        static constexpr uint32_t kRetryFieldShift = 16U;
        static constexpr uint32_t kRetrySeriesFieldWidth = 4U;
        static constexpr uint32_t kDurationSlotsPerWord = 2U;
        static constexpr uint32_t kRtsCtsDurationQualifiedBit = 0x8000U;
        static constexpr uint32_t kRateFlagsFieldWidth = 5U;
        static constexpr uint32_t kStbcSeriesShift = 28U;
        static constexpr uint32_t kDurationUpdateFlag = 0x00008000U;
        static constexpr uint32_t kTxControlLengthWord = 11U;
        static constexpr uint32_t kTxControlKeyWord = 12U;
        static constexpr uint32_t kTxControlRetriesWord = 13U;
        static constexpr uint32_t kTxControlRatesWord = 14U;
        static constexpr uint32_t kTxControlFirstDurationWord = 15U;
        static constexpr uint32_t kTxControlSecondDurationWord = 16U;
        static constexpr uint32_t kTxControlEncryptionWord = 17U;
        static constexpr uint32_t kTxControlRateFlagsWord = 18U;
        static constexpr uint32_t kTxControlNotSoundingWord = 19U;
        static constexpr uint32_t kTxControlPower1Word = 20U;
        static constexpr uint32_t kTxControlPower2Word = 21U;
        static constexpr uint32_t kTxControlPower3Word = 22U;
        static constexpr uint32_t kTxControlReservedWord = 23U;
        static constexpr uint32_t kTxControlRtsFlag = 0x00400000U;
        static constexpr uint32_t kTxControlCtsFlag = 0x80000000U;
        static constexpr uint32_t kTxControlEncryptFlag = 0x40000000U;
        static constexpr uint32_t kTxControlNoAckFlag = 0x01000000U;
        static constexpr uint32_t kTxControlNotSoundingFlag = 0x20000000U;
        static constexpr uint32_t kTxControlKeyIndexShift = 13U;
        static constexpr uint32_t kTxControlEncryptionShift = 26U;
        static constexpr uint32_t kTxControlPowerShift = 24U;
        static constexpr uint32_t kCompletionDoneWord = 8U;
        static constexpr uint32_t kCompletionDoneFlag = 1U;
        static constexpr uint32_t kCompletionVendorMask = 0xffff0000U;
        static constexpr uint32_t kCompletionValidDescriptorFlag = 0x8000U;
        static constexpr uint32_t kCompletionFinalSeriesShift = 21U;
        static constexpr uint32_t kCompletionTxStatusWord = 3U;
        static constexpr uint32_t kCompletionTimestampWord = 4U;
        static constexpr uint32_t kCompletionFinalRateMask = 3U;
        static constexpr uint32_t kCompletionTxOkFlag = 0x00000001U;
        static constexpr uint32_t kCompletionRetriesExhaustedFlag = 0x00000002U;
        static constexpr uint32_t kCompletionFifoUnderrunFlag = 0x00000004U;
        static constexpr uint32_t kCompletionFilteredFlag = 0x00000008U;
        static constexpr uint32_t kCompletionDelimiterUnderrunFlag =
            0x00010000U;
        static constexpr uint32_t kCompletionDataUnderrunFlag = 0x00020000U;
        static constexpr uint32_t kCompletionConfigErrorFlag = 0x00040000U;
        static constexpr uint32_t kCompletionExpiredFlag = 0x00080000U;
        static constexpr uint32_t kCompletionTxopExceededFlag = 0x00020000U;

        template <typename T, size_t N>
        static T &boundedElement(T (&items)[N], size_t index)
        {
            for (T &element : items)
            {
                if (index == 0)
                {
                    return element;
                }
                --index;
            }
            __builtin_trap(); // All callers validate rate/descriptor limits.
        }

        static uintptr_t pointerAddress(const void *pointer)
        {
            static_assert(sizeof(uintptr_t) == sizeof(pointer),
                          "host pointer and address widths must agree");
            uintptr_t address = 0;
            __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                             sizeof(pointer));
            return address;
        }

        static bool overlapsStorage(const void *const first, size_t firstBytes,
                                    const void *const second,
                                    size_t secondBytes)
        {
            if (first == nullptr || second == nullptr || firstBytes == 0 ||
                secondBytes == 0)
            {
                return false;
            }
            const uintptr_t left = pointerAddress(first);
            const uintptr_t right = pointerAddress(second);
            return left >= right ? left - right < secondBytes
                                 : right - left < firstBytes;
        }

        static bool packetTypeValid(TxPacketType type)
        {
            return type == TxPacketType::Normal ||
                   type == TxPacketType::Beacon ||
                   type == TxPacketType::ProbeResponse;
        }

        static bool htRateValid(uint8_t code)
        {
            // AR9565 is 1x1: only MCS0..7 is representable.
            return code >= kHtMcs0 && code <= kHtMcs7;
        }

        namespace
        {
            struct EncodedRateWords
            {
                    uint32_t tries;
                    uint32_t rates;
                    uint32_t durations[2];
                    uint32_t rateFlags;
                    uint32_t powers[4];
            };
        } // namespace

        static TxControlError
        validateFrameMapping(const TxControlRequest &request,
                             const TxDescriptor &descriptor)
        {
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
                mappedPayloadBytes +=
                    boundedElement(descriptor.word,
                                   kSegmentLengthWordBase +
                                       (kSegmentWordStride * slot)) >>
                    kHighHalfShift;
            }
            const uint32_t payloadBytes =
                static_cast<uint32_t>(request.onAirFrameLength) -
                kHardwareFcsBytes;
            const uint32_t expectedMappedBytes =
                request.packetType == TxPacketType::Beacon
                    ? (payloadBytes + kBeaconMappingAlignmentMask) &
                          ~kBeaconMappingAlignmentMask
                    : payloadBytes;
            if (mappedPayloadBytes != expectedMappedBytes)
            {
                return TxControlError::FrameLengthInvalid;
            }

            return TxControlError::Ok;
        }

        static TxControlError
        validateTransmitPolicy(const TxControlRequest &request,
                               const TxSafetyPolicy &policy)
        {
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
                     ? !supportedAr9565LegacyRate(request.rtsCtsRateCode)
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
                request.keyCacheIndex != kNoEncryptionKeyIndex)
            {
                return TxControlError::UnsupportedCipher;
            }
            if (request.crypto == TxCrypto::Ccmp &&
                (!policy.hardwareKeyInstalled ||
                 request.keyCacheIndex >= kKeyCacheEntries))
            {
                return TxControlError::KeyUnavailable;
            }

            return TxControlError::Ok;
        }

        static bool unusedRateFieldsClear(const TxRate &series)
        {
            // A gap must not contain a phantom power, rate, or HT flag.
            return series.rateCode == 0 && series.rtsCtsDuration == 0 &&
                   series.antennaChainMask == 0 && series.powerIndex == 0 &&
                   !series.ht40 && !series.shortGuardInterval && !series.stbc &&
                   !series.rtsCtsQualified;
        }

        static TxControlError
        validateNonemptyRate(const TxControlRequest &request,
                             const TxSafetyPolicy &policy, const TxRate &series,
                             size_t i, bool foundGap)
        {
            if (foundGap || series.attempts > kRetryAttemptsMax ||
                series.rateCode == 0)
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
            if (!htRate && !supportedAr9565LegacyRate(series.rateCode))
            {
                return TxControlError::InvalidRate;
            }
            if (series.stbc ||
                (!htRate && (series.ht40 || series.shortGuardInterval)))
            {
                return TxControlError::UnsupportedControl;
            }
            if (series.rtsCtsDuration > kRtsCtsDurationMax)
            {
                return TxControlError::InvalidDuration;
            }
            if (series.powerIndex > kHardwarePowerIndexMax ||
                series.powerIndex >
                    boundedElement(policy.maximumTxPowerIndex, i))
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

            return TxControlError::Ok;
        }

        static void packRateSeries(const TxRate &series, size_t i,
                                   EncodedRateWords &encoded)
        {
            encoded.tries |=
                static_cast<uint32_t>(series.attempts)
                << (kRetryFieldShift + (kRetrySeriesFieldWidth * i));
            encoded.rates |= static_cast<uint32_t>(series.rateCode)
                             << (kByteShift * i);
            const uint32_t durationSlot =
                (static_cast<uint32_t>(series.rtsCtsDuration) |
                 (series.rtsCtsQualified ? kRtsCtsDurationQualifiedBit : 0U));
            boundedElement(encoded.durations, i / kDurationSlotsPerWord) |=
                durationSlot << (kHighHalfShift * (i & 1U));
            if (series.ht40)
            {
                encoded.rateFlags |= 1U << (kRateFlagsFieldWidth * i);
            }
            if (series.shortGuardInterval)
            {
                encoded.rateFlags |= 1U << ((kRateFlagsFieldWidth * i) + 1U);
            }
            encoded.rateFlags |= static_cast<uint32_t>(series.antennaChainMask)
                                 << ((kRateFlagsFieldWidth * i) + 2U);
            if (series.stbc)
            {
                encoded.rateFlags |= 1U << (kStbcSeriesShift + i);
            }
            boundedElement(encoded.powers, i) =
                static_cast<uint32_t>(series.powerIndex);
        }

        static TxControlError packRateWords(const TxControlRequest &request,
                                            const TxSafetyPolicy &policy,
                                            EncodedRateWords &encoded)
        {
            encoded.rateFlags = static_cast<uint32_t>(request.rtsCtsRateCode)
                                << kRtsCtsControlRateShift;
            bool foundGap = false;
            if (request.rate[0].attempts == 0)
            {
                return TxControlError::InvalidRate;
            }
            for (size_t i = 0; i < 4; ++i)
            {
                const TxRate &series = boundedElement(request.rate, i);
                if (series.attempts == 0)
                {
                    foundGap = true;
                    if (!unusedRateFieldsClear(series))
                    {
                        return TxControlError::InvalidRate;
                    }
                    continue;
                }
                const TxControlError validity =
                    validateNonemptyRate(request, policy, series, i, foundGap);
                if (validity != TxControlError::Ok)
                {
                    return validity;
                }
                packRateSeries(series, i, encoded);
            }
            if (request.durationUpdate)
            {
                encoded.tries |= kDurationUpdateFlag;
            }
            return TxControlError::Ok;
        }

        static void writeTxControlWords(const TxControlRequest &request,
                                        const EncodedRateWords &encoded,
                                        TxDescriptor &descriptor)
        {
            // Commit only after all validation. Pointer/checksum fields remain
            // untouched, because ar9003_mac.c excludes ctl11..23 from the
            // pointer checksum. The platform must synchronize the descriptor
            // before DMA.
            TxDescriptor staged = descriptor;
            staged.word[kTxControlLengthWord] =
                (static_cast<uint32_t>(request.onAirFrameLength) &
                 kTwelveBitMask) |
                (encoded.powers[0] << kHighHalfShift) |
                (request.rts ? kTxControlRtsFlag : 0U) |
                (request.cts ? kTxControlCtsFlag : 0U) |
                (request.crypto != TxCrypto::Clear ? kTxControlEncryptFlag
                                                   : 0U);
            staged.word[kTxControlKeyWord] =
                (request.crypto != TxCrypto::Clear
                     ? static_cast<uint32_t>(request.keyCacheIndex)
                           << kTxControlKeyIndexShift
                     : 0U) |
                (static_cast<uint32_t>(request.packetType)
                 << kRtsCtsControlRateShift) |
                (request.noAck ? kTxControlNoAckFlag : 0U);
            staged.word[kTxControlRetriesWord] = encoded.tries;
            staged.word[kTxControlRatesWord] = encoded.rates;
            staged.word[kTxControlFirstDurationWord] = encoded.durations[0];
            staged.word[kTxControlSecondDurationWord] = encoded.durations[1];
            staged.word[kTxControlEncryptionWord] =
                static_cast<uint32_t>(request.crypto)
                << kTxControlEncryptionShift;
            staged.word[kTxControlRateFlagsWord] = encoded.rateFlags;
            staged.word[kTxControlNotSoundingWord] =
                kTxControlNotSoundingFlag; // AR_Not_Sounding
            staged.word[kTxControlPower1Word] = encoded.powers[1]
                                                << kTxControlPowerShift;
            staged.word[kTxControlPower2Word] = encoded.powers[2]
                                                << kTxControlPowerShift;
            staged.word[kTxControlPower3Word] = encoded.powers[3]
                                                << kTxControlPowerShift;
            staged.word[kTxControlReservedWord] = 0U;
            descriptor = staged;
        }

        TxControlError encodeTxControls(const TxControlRequest &request,
                                        const TxSafetyPolicy &policy,
                                        TxDescriptor &descriptor)
        {
            // Never write a descriptor before all trust and rate checks pass.
            if (overlapsStorage(&request, sizeof(request), &descriptor,
                                sizeof(descriptor)) ||
                overlapsStorage(&policy, sizeof(policy), &descriptor,
                                sizeof(descriptor)))
            {
                return TxControlError::OverlappingBuffers;
            }
            const TxControlError mapping =
                validateFrameMapping(request, descriptor);
            if (mapping != TxControlError::Ok)
            {
                return mapping;
            }
            const TxControlError authorization =
                validateTransmitPolicy(request, policy);
            if (authorization != TxControlError::Ok)
            {
                return authorization;
            }
            EncodedRateWords encoded {};
            const TxControlError rates =
                packRateWords(request, policy, encoded);
            if (rates != TxControlError::Ok)
            {
                return rates;
            }
            writeTxControlWords(request, encoded, descriptor);
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
            const uint32_t final = raw.word[kCompletionDoneWord];
            if ((final & kCompletionDoneFlag) == 0)
            {
                return DescriptorError::Incomplete;
            }
            const uint32_t info = raw.word[0];
            if ((info & kCompletionVendorMask) != kInfoVendor ||
                (info & kCompletionValidDescriptorFlag) == 0)
            {
                return DescriptorError::InvalidVendor;
            }

            TxCompletion complete {};
            complete.queue =
                static_cast<uint8_t>((info >> kByteShift) & kNibbleMask);
            if (complete.queue > kMaximumQcu)
            {
                return DescriptorError::CorruptStatus;
            }
            complete.finalRateSeries =
                static_cast<uint8_t>((final >> kCompletionFinalSeriesShift) &
                                     kCompletionFinalRateMask);
            complete.sequenceNumber =
                static_cast<uint16_t>((final >> 1U) & kTwelveBitMask);
            complete.timestamp = raw.word[kCompletionTimestampWord];
            const uint32_t flags = raw.word[kCompletionTxStatusWord];
            complete.frameTransmitOk = (flags & kCompletionTxOkFlag) != 0;
            complete.excessiveRetries =
                (flags & kCompletionRetriesExhaustedFlag) != 0;
            complete.fifoUnderrun = (flags & kCompletionFifoUnderrunFlag) != 0;
            complete.filtered = (flags & kCompletionFilteredFlag) != 0;
            complete.delimiterUnderrun =
                (flags & kCompletionDelimiterUnderrunFlag) != 0;
            complete.dataUnderrun = (flags & kCompletionDataUnderrunFlag) != 0;
            complete.configError = (flags & kCompletionConfigErrorFlag) != 0;
            complete.expired = (flags & kCompletionExpiredFlag) != 0;
            complete.txOpportunityExceeded =
                (final & kCompletionTxopExceededFlag) != 0;
            complete.shortRetries =
                static_cast<uint8_t>((flags >> kNibbleShift) & kNibbleMask);
            complete.longRetries =
                static_cast<uint8_t>((flags >> kByteShift) & kNibbleMask);
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
